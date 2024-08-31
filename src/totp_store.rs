use std::{fs::Permissions, io::Write, os::unix::fs::PermissionsExt, time::{SystemTime, UNIX_EPOCH}};

use rand::RngCore;
use tss_esapi::{handles::KeyHandle, structures::Public, traits::{Marshall, UnMarshall}};

use crate::{config::Config, db::{self, model::Secret}, presence_verification::PresenceVerifier, privileges::{drop_privileges, with_uid_as_euid}, tpm::{self, HmacKey, TPM}};

#[derive(Debug)]
pub enum Error {
    NotInitialized,
    AlreadyInitialized,
    TpmError(tpm::Error),
    IOError(std::io::Error),
    DBError(db::Error),
    KeyHandleError,
    TpmLocked,
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<tss_esapi::Error> for Error {
    fn from(value: tss_esapi::Error) -> Self {
        Error::TpmError(tpm::Error::TpmError(value))
    }
}

impl From<tpm::Error> for Error {
    fn from(value: tpm::Error) -> Self {
        Error::TpmError(value)
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Error::IOError(value)
    }
}

impl From<db::Error> for Error {
    fn from(value: db::Error) -> Self {
        Error::DBError(value)
    }
}

// TODO: phantom type for with/without tpm
pub struct TotpStore {
    config: Config,
    tpm: Option<TPM>,
    primary_key: Option<KeyHandle>,
}

impl TotpStore {
    /// Creates a TOTP store client which does not access the TPM.
    /// Immediately drops privileges.
    pub fn without_tpm(config: Config) -> Self {
        drop_privileges();
        TotpStore {
            config: config,
            tpm: None,
            primary_key: None,
        }
    }

    /// Creates a TOTP store client which uses the TPM.
    /// Drops privileges immediately after reading the auth value.
    pub fn with_tpm(
        presence_verifier: Box<dyn PresenceVerifier>,
        config: Config,
    ) -> Result<Self> {
        log::info!("Creating TOTP store with the following settings:");
        log::info!("- auth value path: {}", config.auth_value_path().to_str().unwrap());
        log::info!("- primary key handle path: {}", config.primary_key_handle_path().to_str().unwrap());
        log::info!("- secrets db path: {}", config.secrets_db_path().to_str().unwrap());

        log::info!("reading auth value");
        let auth_value = read_auth_value(&config)?;

        log::info!("reading primary key persistent handle");
        let handle = read_primary_key_persistent_handle(&config)?;

        drop_privileges();

        let mut tpm = TPM::new(presence_verifier, &config.tpm)?;
        let primary_key = tpm.get_persistent_primary(handle, auth_value.try_into()?)?;
        Ok(TotpStore {
            config: config,
            tpm: Some(tpm),
            primary_key: Some(primary_key),
        })
    }

    /// Initializes a secret store.
    pub fn init(
        presence_verifier: Box<dyn PresenceVerifier>,
        config: Config,
    ) -> Result<()> {
        let mut tpm = TPM::new(presence_verifier, &config.tpm)?;

        log::info!(
            "creating auth value file with permissions 0600 at {}",
            config.auth_value_path().to_str().unwrap(),
        );
        let mut auth_value_file = std::fs::File::create(config.auth_value_path())?;
        auth_value_file.set_permissions(Permissions::from_mode(0o600))?;

        let mut auth_value = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut auth_value);
        auth_value_file.write_all(&auth_value)?;
        drop(auth_value_file);

        log::info!("creating primary key");
        let key_handle = tpm.create_persistent_primary(auth_value.try_into()?)?;
        let handle_u32: u32 = match key_handle {
            tss_esapi::interface_types::dynamic_handles::Persistent::Persistent(persistent_tpm_handle) => {
                persistent_tpm_handle.into()
            },
        };
        log::info!(
            "persisting primary key handle {} at {}",
            handle_u32,
            config.primary_key_handle_path().to_str().unwrap(),
        );
        std::fs::write(config.primary_key_handle_path(), handle_u32.to_string())?;
        Ok(())
    }

    /// Clears the secret store.
    /// If system is true, also removes all system data.
    pub fn clear(
        presence_verifier: Box<dyn PresenceVerifier>,
        config: Config,
        system: bool,
    ) -> Result<()> {
        if system {
            let mut tpm = TPM::new(presence_verifier, &config.tpm)?;

            if config.auth_value_path().is_file() && config.primary_key_handle_path().is_file() {
                let pk_handle = read_primary_key_persistent_handle(&config)?;
                let auth_value = read_auth_value(&config)?;

                log::info!("deleting persistent primary key from tpm");
                tpm.delete_persistent_primary(pk_handle, auth_value.try_into()?)?;
            } else {
                log::warn!("auth value or primary key handle missing; unable to remove key from tpm");
            }

            if config.auth_value_path().is_file() {
                log::info!("removing auth value at {}", config.auth_value_path().to_str().unwrap());
                std::fs::remove_file(config.auth_value_path())?;
            } else {
                log::info!("no auth value file to remove");
            }

            if config.primary_key_handle_path().is_file() {
                log::info!("removing primary key handle at {}", config.primary_key_handle_path().to_str().unwrap());
                std::fs::remove_file(config.primary_key_handle_path())?;
            } else {
                log::info!("no primary key handle file to remove");
            }
        }

        with_uid_as_euid(||{
            if config.secrets_db_path().is_file() {
                log::info!("removing secrets database at {}", config.secrets_db_path().to_str().unwrap());
                std::fs::remove_file(config.secrets_db_path())
            } else {
                log::info!("no secrets database to remove");
                Ok(())
            }
        })?;

        Ok(())
    }

    pub fn add(&mut self, service: &str, account: &str, digits: u8, interval: u32, secret: &Vec<u8>) -> Result<Secret> {
        let primary_key = *self.primary_key()?;

        log::info!("generating secret hmac key");
        let hmac_key = self.tpm()?.create_hmac_key(primary_key, secret)?;
        let secret = Secret::new(
            service.to_owned(),
            account.to_owned(),
            Some(digits),
            Some(interval),
            hmac_key.public.marshall()?,
            hmac_key.private.to_vec(),
        );

        log::info!("adding secret to database");
        let added_secret = self.with_db( |db| db.add_secret(secret))?;
        Ok(added_secret)
    }

    pub fn gen(&mut self, secret_id: i64, timestamp: SystemTime) -> Result<String> {
        log::info!("getting secret from secrets database");
        let secret = self.with_db(|db| {
            db.get_secret(secret_id)
        })?;

        log::info!("loading secret hmac key");
        let hmac_key = HmacKey::new(
            *self.primary_key()?,
            Public::unmarshall(&secret.public_data)?,
            secret.private_data.try_into()?
        );

        log::info!("generating one time code");
        let ts = timestamp.duration_since(UNIX_EPOCH).unwrap().as_secs() / secret.interval as u64;
        let hash = self.tpm()?.hmac(hmac_key, ts.to_be_bytes().to_vec().try_into()?)?;

        let offset = usize::from(hash[hash.len() - 1]) & 0xf;
        let mut code: u64 = (hash[offset] as u64 & 0x7f) * 0x1000000;
        code += hash[offset + 1] as u64 * 0x10000;
        code += hash[offset + 2] as u64 * 0x100;
        code += hash[offset + 3] as u64;
        code %= 10u64.pow(secret.digits as u32);
        Ok(format!("{:0>w$}", code, w = secret.digits as usize))
    }

    pub fn del(&mut self, secret_id: i64) -> Result<()> {
        let result = self.with_db(|db| {
            db.del_secret(secret_id)
        })?;
        Ok(result)
    }

    pub fn list(&mut self, service: Option<&str>, account: Option<&str>) -> Result<Vec<Secret>> {
        let result = self.with_db(|db| {
            db.list_secrets(service.unwrap_or(""), account.unwrap_or(""))
        })?;
        Ok(result)
    }

    fn with_db<T, F: FnOnce(&db::DB) -> db::Result<T>>(&mut self, f: F) -> db::Result<T> {
        Ok(db::with_db(self.config.secrets_db_path(), f)?)
    }

    fn tpm(&mut self) -> Result<&mut TPM> {
        match &mut self.tpm {
            Some(tpm) => Ok(tpm),
            None => Err(Error::TpmLocked),
        }
    }

    fn primary_key(&self) -> Result<&KeyHandle> {
        match &self.primary_key {
            Some(primary_key) => Ok(primary_key),
            None => Err(Error::TpmLocked),
        }
    }
}

fn read_primary_key_persistent_handle(config: &Config) -> Result<u32> {
    std::fs::read_to_string(config.primary_key_handle_path())?
        .trim()
        .parse().or(Err(Error::KeyHandleError))
}

fn read_auth_value(config: &Config) -> Result<Vec<u8>> {
    Ok(std::fs::read(config.auth_value_path())?)
}
