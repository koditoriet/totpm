#[allow(deprecated)]
use std::{env::home_dir, path::PathBuf};

use serde_derive::{Deserialize, Serialize};

#[derive(Serialize)]
#[derive(Deserialize)]
pub struct Config {
    pub tpm: String,

    // Should always be absolute.
    pub system_data_path: PathBuf,

    // Must be interpreted relative to $HOME if relative.
    pub user_data_path: PathBuf,
}

impl Config {
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