#[cfg(feature = "install")]
use std::{fs, fs::Permissions, os::unix::fs::PermissionsExt};

use std::{os::unix::fs::MetadataExt, path::{Path, PathBuf}, process::Command};
use log::warn;
use crate::{
    config::Config,
    presence_verification::PresenceVerificationMethod,
    privileges::{is_effective_user, is_root, with_uid_as_euid},
    result::{Error, Result},
    totp_store::TotpStore
};

const EXE_NAME: &str = "totpm";

pub fn run(
    cfg_path: &Path,
    mut config: Config,
    user: &str,
    local: bool,
    exe_install_dir: &Path,
) -> Result<()> {
    if needs_root(cfg_path, &config, user, local, &exe_install_dir.join(EXE_NAME)) && !is_root() {
        return Err(Error::RootRequired);
    }

    if local {
        warn!(
            "{} {}",
            "Local installation is UNSAFE, as a local attacker with access to your account",
            "could generate an unlimited number of one-time codes. Proceed at your own risk!"
        )
    }

    log::info!("initializing secret store");
    config.pv_method = PresenceVerificationMethod::None;
    TotpStore::init(config.clone())?;

    if !local {
        with_uid_as_euid(||{
            install(&config, cfg_path, user, exe_install_dir)?;
            Ok::<(), Error>(())
        })?;
    }

    Ok(())
}

#[cfg(feature = "install")]
fn install(config: &Config, cfg_path: &Path, user: &str, exe_install_dir: &Path) -> Result<u32> {
    log::info!("creating config parent directory at {}", cfg_path.parent().unwrap().to_str().unwrap());
    fs::create_dir_all(cfg_path.parent().unwrap())?;

    log::info!("writing config to {}", cfg_path.to_str().unwrap());
    fs::write(cfg_path, toml::to_string(config)?)?;

    log::info!("creating user '{}'", user);
    let useradd_result = Command::new("/usr/sbin/useradd")
        .arg("-r")
        .arg(user)
        .arg("-s")
        .arg("/usr/sbin/nologin")
        .output();
    let uid = get_user_id(user)?;

    match useradd_result {
        Ok(_) => {},
        Err(e) => { log::warn!("unable to create user '{}': {:#?}", user, e) },
    }

    let executable_path = std::env::current_exe()?;
    let moved_executable_path = exe_install_dir.join(EXE_NAME);

    log::info!(
        "installing executable {} as {} with permissions 4755",
        executable_path.to_str().unwrap(),
        moved_executable_path.to_str().unwrap(),
    );
    std::fs::copy(&executable_path, &moved_executable_path)?;
    std::os::unix::fs::chown(&moved_executable_path, Some(uid), None)?;
    std::fs::set_permissions(&moved_executable_path, Permissions::from_mode(0o4755))?;
    Ok(uid)
}

#[cfg(not(feature = "install"))]
fn install(_config: &Config, _cfg_path: &Path, user: &str, _exe_install_dir: &Path) -> Result<u32> {
    get_user_id(user)
}

fn needs_root(cfg_path: &Path, config: &Config, user: &str, local: bool, exe_install_path: &Path) -> bool {
    if local {
        log::info!("does not need root because we're doing local init");
        return false;
    }
    let totpm_user_id = get_user_id(user).unwrap();
    if !is_effective_user(totpm_user_id) {
        log::info!("needs root because we're not the totpm user");
        return true;
    }
    if cfg!(feature = "install") && !can_create_file(totpm_user_id, exe_install_path) {
        log::info!(
            "needs root because install is enabled and we can't install executable to {}",
            exe_install_path.to_str().unwrap()
        );
        return true;
    }
    if cfg!(feature = "install") && !can_create_file(totpm_user_id, cfg_path) {
        log::info!(
            "needs root because install is enabled and we can't install config to {}",
            cfg_path.to_str().unwrap()
        );
        return true;
    }
    if !can_create_dir(totpm_user_id, &config.system_data_path) {
        return true;
    }
    false
}

fn longest_existing_prefix(path: &Path) -> Option<PathBuf> {
    if path.exists() {
        return std::fs::canonicalize(path).ok();
    }
    match path.parent() {
        Some(p) => longest_existing_prefix(p),
        None => None,
    }
}

fn can_create_file(uid: u32, path: &Path) -> bool {
    if path.is_file() {
        return path.metadata().unwrap().uid() == uid;
    }
    if path.exists() {
        return false;
    }
    match longest_existing_prefix(path) {
        Some(p) => can_create_dir(uid, &p),
        None => false,
    }
}

fn can_create_dir(uid: u32, path: &Path) -> bool {
    assert!(path.is_absolute());
    if path.is_dir() {
        return path.metadata().unwrap().uid() == uid;
    }
    if path.exists() {
        return false;
    }
    match path.parent() {
        Some(p) => can_create_dir(uid, p),
        None => false,
    }
}

fn get_user_id(user: &str) -> Result<u32> {
    let uid_bytes = Command::new("/usr/bin/id")
        .arg("-u")
        .arg(user)
        .output()?
        .stdout;
    String::from_utf8(uid_bytes)
        .or(Err(Error::UserNotFoundError(user.to_string())))?
        .trim()
        .parse::<u32>()
        .or(Err(Error::UserNotFoundError(user.to_string())))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use tempfile::{tempdir, TempDir};
    use testutil::tpm::SwTpm;

    use super::*;

    #[test]
    fn init_creates_all_necessary_and_files_with_correct_permissions() {
        let swtpm = SwTpm::new();
        let dir = tempdir().unwrap();
        let cfg_path = dir.path().join("totpm.conf");
        let config = Config::default(
            true,
            swtpm.tcti.clone(),
            Some(dir.path().join("system")),
            Some(dir.path().join("user")),
            None,
        );
        run(&cfg_path, config.clone(), &get_user_name(), false, dir.path()).unwrap();

        check_installed_exe(&dir);
        check_installed_config(&cfg_path);

        assert!(config.auth_value_path().is_file());
        assert_eq!(config.auth_value_path().metadata().unwrap().permissions().mode(), 0o100600);

        assert!(config.primary_key_handle_path().is_file());
        assert_eq!(config.primary_key_handle_path().metadata().unwrap().permissions().mode(), 0o100644);

        // init should NOT create the secrets database
        assert_eq!(config.secrets_db_path().exists(), false);
    }

    #[test]
    #[cfg(not(feature = "install"))]
    fn not_being_able_to_install_exe_is_fine_if_install_feature_is_disabled() {
        let swtpm = SwTpm::new();
        let dir = tempdir().unwrap();
        let cfg_path = dir.path().join("totpm.conf");
        let config = Config::default(
            true,
            swtpm.tcti.clone(),
            Some(dir.path().join("system")),
            Some(dir.path().join("user")),
            None,
        );
        run(&cfg_path, config.clone(), &get_user_name(), false, &PathBuf::from("/")).unwrap();

        assert!(config.auth_value_path().is_file());
        assert_eq!(config.auth_value_path().metadata().unwrap().permissions().mode(), 0o100600);

        assert!(config.primary_key_handle_path().is_file());
        assert_eq!(config.primary_key_handle_path().metadata().unwrap().permissions().mode(), 0o100644);

        // init should NOT create the secrets database
        assert_eq!(config.secrets_db_path().exists(), false);
    }

    #[test]
    #[cfg(feature = "install")]
    fn not_being_able_to_install_exe_is_an_error_if_install_feature_is_enabled() {
        let swtpm = SwTpm::new();
        let dir = tempdir().unwrap();
        let cfg_path = dir.path().join("totpm.conf");
        let config = Config::default(
            true,
            swtpm.tcti.clone(),
            Some(dir.path().join("system")),
            Some(dir.path().join("user")),
            None,
        );
        match run(&cfg_path, config, &get_user_name(), false, &PathBuf::from("/")).unwrap_err() {
            Error::RootRequired => {},
            err => panic!("wrong error: {:#?}", err),
        }
    }

    #[test]
    fn local_init_does_not_install_exe_but_creates_files_with_correct_permissions() {
        let swtpm = SwTpm::new();
        let dir = tempdir().unwrap();
        let cfg_path = dir.path().join("totpm.conf");
        let config = Config::default(
            true,
            swtpm.tcti.clone(),
            Some(dir.path().join("system")),
            Some(dir.path().join("user")),
            None,
        );
        run(&cfg_path, config.clone(), &get_user_name(), true, dir.path()).unwrap();

        let installed_exe_path = dir.path().join(EXE_NAME);
        assert_eq!(installed_exe_path.is_file(), false);

        assert!(config.auth_value_path().is_file());
        assert_eq!(config.auth_value_path().metadata().unwrap().permissions().mode(), 0o100600);

        assert!(config.primary_key_handle_path().is_file());
        assert_eq!(config.primary_key_handle_path().metadata().unwrap().permissions().mode(), 0o100644);

        // init should NOT create the secrets database
        assert_eq!(config.secrets_db_path().exists(), false);
    }

    #[cfg(feature = "install")]
    fn check_installed_exe(dir: &TempDir) {
        let installed_exe_path = dir.path().join(EXE_NAME);
        assert!(installed_exe_path.is_file());
        assert_eq!(installed_exe_path.metadata().unwrap().permissions().mode(), 0o104755);
    }

    #[cfg(not(feature = "install"))]
    fn check_installed_exe(dir: &TempDir) {
        let installed_exe_path = dir.path().join(EXE_NAME);
        assert!(!installed_exe_path.exists());
    }

    #[cfg(feature = "install")]
    fn check_installed_config(cfg_path: &Path) {
        assert!(cfg_path.is_file());
    }

    #[cfg(not(feature = "install"))]
    fn check_installed_config(cfg_path: &Path) {
        assert!(!cfg_path.exists());
    }

    fn get_user_name() -> String {
        std::env::var("USER").unwrap_or("root".to_string())
    }
}
