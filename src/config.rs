use std::{env,
    path::Path};
#[allow(deprecated)]
use std::{env::home_dir, path::PathBuf};

use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    pub tpm: String,

    // Should always be absolute.
    pub system_data_path: PathBuf,

    // Must be interpreted relative to $HOME if relative.
    pub user_data_path: PathBuf,

    /// Max number of seconds to wait for presence verification.
    pub pv_timeout: u8,
}

impl Config {
    /// Returns a new config, with the default system data path if data path is not given.
    pub fn default(
        local: bool,
        tpm: String,
        system_data_path: Option<PathBuf>,
        user_data_path: Option<PathBuf>
    ) -> Self {
        Config {
            tpm: tpm,
            system_data_path: system_data_path.as_deref().map(absolute_path).unwrap_or(
                if local {
                    local_path(&PathBuf::from(".local/state/totpm/system"))
                } else {
                    PathBuf::from("/var/lib/totpm")
                }
            ),
            user_data_path: user_data_path.unwrap_or(PathBuf::from(".local/state/totpm")),
            pv_timeout: 10,
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
