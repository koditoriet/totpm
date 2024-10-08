use std::{env, path::Path};
#[allow(deprecated)]
use std::{env::home_dir, path::PathBuf};

use serde_derive::{Deserialize, Serialize};

use crate::presence_verification::PresenceVerificationMethod;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Config {
    pub tpm: String,

    // Should always be absolute.
    pub system_data_path: PathBuf,

    // Must be interpreted relative to $HOME if relative.
    pub user_data_path: PathBuf,

    /// Max number of seconds to wait for presence verification.
    pub pv_timeout: u8,

    /// Method to use for presence verification.
    /// Valid values are:
    /// - fprintd: ask for the user's fingerprint by calling fprintd over dbus
    /// - none: don't verify user presence; only recommended for local installs
    pub pv_method: PresenceVerificationMethod,
}

impl Config {
    /// Returns a new config, with the default system data path if data path is not given.
    pub fn default(
        local: bool,
        tpm: String,
        system_data_path: Option<PathBuf>,
        user_data_path: Option<PathBuf>,
        presence_verification: Option<PresenceVerificationMethod>,
    ) -> Self {
        Config {
            tpm,
            system_data_path: system_data_path.as_deref().map(absolute_path).unwrap_or(
                if local {
                    local_path(&PathBuf::from(".local/state/totpm/system"))
                } else {
                    PathBuf::from("/var/lib/totpm")
                }
            ),
            user_data_path: user_data_path.unwrap_or(PathBuf::from(".local/state/totpm")),
            pv_timeout: 10,
            pv_method: presence_verification.unwrap_or(
                if local {
                    PresenceVerificationMethod::None
                } else {
                    PresenceVerificationMethod::Fprintd
                }                
            )
        }
    }

    pub fn auth_value_path(&self) -> PathBuf {
        self.system_data_path.join("auth_value")
    }

    pub fn primary_key_handle_path(&self) -> PathBuf {
        self.system_data_path.join("primary_key_handle")
    }

    pub fn secrets_db_path(&self) -> PathBuf {
        let secrets_db_file = "secrets.sqlite";
        if self.user_data_path.is_absolute() {       
            self.user_data_path.join(secrets_db_file)
        } else {
            #[allow(deprecated)]
            home_dir().unwrap().join(&self.user_data_path).join(secrets_db_file)
        }
    }
}

/// Makes the given path relative to the user's home directory.
pub fn local_path(file: &Path) -> PathBuf {
    assert!(file.is_relative());
    #[allow(deprecated)]
    env::home_dir().unwrap().join(file)
}

/// Makes the given path absolute without touching the file system.
/// Does not resolve symlinks or perform other magic.
pub fn absolute_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir().unwrap().join(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_default_config_uses_local_defaults() {
        #[allow(deprecated)]
        let home_dir = env::home_dir().unwrap();

        let cfg = Config::default(true, "device".to_string(), None, None, None);
        assert!(cfg.system_data_path.starts_with(&home_dir));
        assert!(cfg.user_data_path.is_relative());
        assert!(cfg.auth_value_path().starts_with(&home_dir));
        assert!(cfg.primary_key_handle_path().starts_with(&home_dir));
        assert!(cfg.secrets_db_path().starts_with(&home_dir));
        assert_eq!(cfg.pv_method, PresenceVerificationMethod::None);
    }

    #[test]
    fn global_default_config_uses_global_defaults() {
        #[allow(deprecated)]
        let home_dir = env::home_dir().unwrap();

        let cfg = Config::default(false, "device".to_string(), None, None, None);
        assert!(cfg.system_data_path.starts_with("/var/lib"));
        assert!(cfg.user_data_path.is_relative());
        assert!(cfg.auth_value_path().starts_with("/var/lib"));
        assert!(cfg.primary_key_handle_path().starts_with("/var/lib"));
        assert!(cfg.secrets_db_path().starts_with(&home_dir));
        assert_eq!(cfg.pv_method, PresenceVerificationMethod::Fprintd);
    }
}
