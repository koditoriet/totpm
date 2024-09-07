use std::{fs::{self, Permissions}, os::unix::fs::{MetadataExt, PermissionsExt}, path::{Path, PathBuf}, process::{exit, Command}};
use log::warn;
use crate::{config::Config, presence_verification::ConstPresenceVerifier, privileges::is_root, result::{Error, Result}, totp_store::TotpStore};

const EXE_NAME: &str = "totpm";

pub fn run(
    cfg_path: &Path,
    config: Config,
    user: &str,
    local: bool,
    exe_install_dir: &Path,
) -> Result<()> {
    if needs_root(cfg_path, &config, user, local, &exe_install_dir.join(EXE_NAME)) && !is_root() {
        eprintln!("must be root to initialize non-local TOTP store");
        exit(1)
    }

    if local {
        warn!(
            "{} {}",
            "Local installation is UNSAFE, as a local attacker with access to your account",
            "could generate an unlimited number of one-time codes. Proceed at your own risk!"
        )
    }

    log::info!("initializing secret store");

    log::info!("creating config parent directory at {}", cfg_path.parent().unwrap().to_str().unwrap());
    fs::create_dir_all(cfg_path.parent().unwrap())?;

    log::info!("writing config to {}", cfg_path.to_str().unwrap());
    fs::write(cfg_path, toml::to_string(&config)?)?;

    log::info!(
        "creating system data directory with permissions 0700 at {}",
        config.system_data_path.to_str().unwrap(),
    );
    let system_data_path = config.system_data_path.clone();
    let auth_value_path = config.auth_value_path();
    TotpStore::init(
        Box::new(ConstPresenceVerifier::new(true)),
        config,
    )?;

    if !local {
        log::info!("creating user '{}'", user);
        let useradd_result = Command::new("/usr/sbin/useradd")
            .arg("-r")
            .arg(user)
            .arg("-s")
            .arg("/usr/sbin/nologin")
            .output();
        match useradd_result {
            Ok(_) => {},
            Err(e) => { log::warn!("unable to create user '{}': {:#?}", user, e) },
        }
        let uid = get_user_id(user)?;

        log::info!("chowning system data directory to user {} (uid {})", user, uid);
        std::os::unix::fs::chown(&system_data_path, Some(uid), None)?;

        let executable_path = std::env::current_exe()?;
        let moved_executable_path = exe_install_dir.join(EXE_NAME);

        log::info!(
            "installing executable {} as {} with permissions 4755",
            executable_path.to_str().unwrap(),
            moved_executable_path.to_str().unwrap(),
        );
        std::fs::copy(&executable_path,&moved_executable_path)?;
        std::os::unix::fs::chown(&moved_executable_path, Some(uid), None)?;
        std::fs::set_permissions(&moved_executable_path, Permissions::from_mode(0o4755))?;
    }

    if !local {
        log::info!("chowning auth value file to {}", user);
        let uid = get_user_id(user)?;
        std::os::unix::fs::chown(auth_value_path, Some(uid), None)?;
    }

    Ok(())
}

fn needs_root(cfg_path: &Path, config: &Config, user: &str, local: bool, exe_install_path: &Path) -> bool {
    if local {
        return false;
    }
    let current_user = get_user_name();
    let current_user_id = get_user_id(&current_user).unwrap();
    if user != current_user {
        return true;
    }
    if !can_create_file(current_user_id, exe_install_path) {
        return true;
    }
    if !can_create_file(current_user_id, cfg_path) {
        return true;
    }
    if !can_create_dir(current_user_id, &config.system_data_path) {
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
        None => return false,
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
        .or(Err(Error::UserNotFoundError))?
        .trim()
        .parse::<u32>().or(Err(Error::UserNotFoundError))
}

fn get_user_name() -> String {
    std::env::var("USER").unwrap_or("root".to_string())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;
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
            Some(dir.path().join("user"))
        );
        run(&cfg_path, config.clone(), &get_user_name(), false, dir.path()).unwrap();

        let installed_exe_path = dir.path().join(EXE_NAME);
        assert!(installed_exe_path.is_file());
        assert_eq!(installed_exe_path.metadata().unwrap().permissions().mode(), 0o104755);

        assert!(config.auth_value_path().is_file());
        assert_eq!(config.auth_value_path().metadata().unwrap().permissions().mode(), 0o100600);

        assert!(config.primary_key_handle_path().is_file());
        assert_eq!(config.primary_key_handle_path().metadata().unwrap().permissions().mode(), 0o100644);

        // init should NOT create the secrets database
        assert_eq!(config.secrets_db_path().exists(), false);
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
            Some(dir.path().join("user"))
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
}
