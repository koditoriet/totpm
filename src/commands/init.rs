use std::{fs::{self, Permissions}, os::unix::fs::PermissionsExt, path::{Path, PathBuf}, process::{exit, Command}};

use log::warn;

use crate::{config::Config, presence_verification::ConstPresenceVerifier, privileges::is_root, result::{Error, Result}, totp_store::TotpStore};

pub fn run(
    cfg_path: &Path,
    config: Config,
    user: &str,
    local: bool,
) -> Result<()> {
    if !is_root() && !local {
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
    fs::create_dir_all(&config.system_data_path)?;
    std::fs::set_permissions(&config.system_data_path, Permissions::from_mode(0o700))?;

    if !local {
        log::info!("creating user {}", user);
        let _ = Command::new("/usr/sbin/useradd")
            .arg("-r")
            .arg(user)
            .arg("-s")
            .arg("/usr/sbin/nologin")
            .output()?;
        let uid = get_user_id(user)?;

        log::info!("chowning system data directory to user {} (uid {})", user, uid);
        std::os::unix::fs::chown(&config.system_data_path, Some(uid), None)?;

        let executable_path = std::env::current_exe()?;
        let moved_executable_path = PathBuf::from("/usr/local/bin").join(executable_path.file_name().unwrap());

        log::info!(
            "installing executable {} as {} with permissions 4755",
            executable_path.to_str().unwrap(),
            moved_executable_path.to_str().unwrap(),
        );
        std::fs::copy(&executable_path,&moved_executable_path)?;
        std::os::unix::fs::chown(&moved_executable_path, Some(uid), None)?;
        std::fs::set_permissions(&moved_executable_path, Permissions::from_mode(0o4755))?;
    }

    let auth_value_path = config.auth_value_path();
    TotpStore::init(
        Box::new(ConstPresenceVerifier::new(true)),
        config,
    )?;

    if !local {
        log::info!("chowning auth value file to {}", user);
        let uid = get_user_id(user)?;
        std::os::unix::fs::chown(auth_value_path, Some(uid), None)?;
    }

    Ok(())
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
