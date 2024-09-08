use std::{fs::Permissions, io::Write, marker::PhantomData, os::unix::fs::PermissionsExt, time::{SystemTime, UNIX_EPOCH}};

use rand::RngCore;
use tss_esapi::{handles::KeyHandle, structures::{Digest, Public}, traits::{Marshall, UnMarshall}};

use crate::{config::Config, db::{self, model::Secret}, presence_verification::{factory::create_presence_verifier, PresenceVerifier}, privileges::{drop_privileges, with_uid_as_euid}, tpm::{self, HmacKey, TPM}};

#[derive(Debug)]
pub enum Error {
    NotInitialized,
    AlreadyInitialized,
    TpmError(tpm::Error),
    IOError(std::io::Error),
    DBError(db::Error),
    KeyHandleError,
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

#[derive(Debug)]
pub struct TotpStore<T> {
    config: Config,
    tpm: Option<TPM>,
    primary_key: Option<KeyHandle>,
    phantom: PhantomData<T>,
}

#[derive(Debug)]
pub struct WithTPM;

#[derive(Debug)]
pub struct WithoutTPM;

impl <P> TotpStore<P> {
    pub fn del(&mut self, secret_id: i64) -> Result<()> {
        let result = self.with_db(|db| {
            db.del_secret(secret_id)
        })?;
        Ok(result)
    }

    pub fn list(&self, service: Option<&str>, account: Option<&str>) -> Result<Vec<Secret>> {
        let result = self.with_db(|db| {
            db.list_secrets(service.unwrap_or(""), account.unwrap_or(""))
        })?;
        Ok(result)
    }

    fn with_db<T, F: FnOnce(&db::DB) -> db::Result<T>>(&self, f: F) -> db::Result<T> {
        Ok(db::with_db(self.config.secrets_db_path(), f)?)
    }
}

impl TotpStore<WithoutTPM> {
    /// Creates a TOTP store client which does not access the TPM.
    /// Immediately drops privileges.
    pub fn without_tpm(config: Config) -> TotpStore<WithoutTPM> {
        drop_privileges();
        TotpStore {
            config: config,
            tpm: None,
            primary_key: None,
            phantom: PhantomData,
        }
    }

    /// Initializes a secret store.
    pub fn init(config: Config) -> Result<()> {
        if config.auth_value_path().is_file() || config.primary_key_handle_path().is_file() {
            return Err(Error::AlreadyInitialized);
        }
        let pv = create_presence_verifier(config.pv_method, config.pv_timeout);
        let mut tpm = TPM::new(pv, &config.tpm)?;

        log::info!(
            "creating system data directory with permissions 0700 at {}",
            config.system_data_path.to_str().unwrap(),
        );    
        std::fs::create_dir_all(&config.system_data_path)?;
        std::fs::set_permissions(&config.system_data_path, Permissions::from_mode(0o700))?;

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
    pub fn clear(config: Config, system: bool) -> Result<()> {
        if system {
            let pv = create_presence_verifier(config.pv_method, config.pv_timeout);
            let mut tpm = TPM::new(pv, &config.tpm)?;

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
}

impl TotpStore<WithTPM> {
    /// Creates a TOTP store client which uses the TPM.
    /// Drops privileges immediately after reading the auth value.
    pub fn with_tpm(config: Config) -> Result<Self> {
        let pv = create_presence_verifier(config.pv_method, config.pv_timeout);
        Self::with_tpm_ex(pv, config)
    }

    fn with_tpm_ex(pv: Box<dyn PresenceVerifier>, config: Config) -> Result<Self> {
        log::info!("Creating TOTP store with the following settings:");
        log::info!("- auth value path: {}", config.auth_value_path().to_str().unwrap());
        log::info!("- primary key handle path: {}", config.primary_key_handle_path().to_str().unwrap());
        log::info!("- secrets db path: {}", config.secrets_db_path().to_str().unwrap());

        log::info!("reading auth value");
        let auth_value = read_auth_value(&config).or(Err(Error::NotInitialized))?;

        log::info!("reading primary key persistent handle");
        let handle = read_primary_key_persistent_handle(&config).or(Err(Error::NotInitialized))?;

        drop_privileges();

        let mut tpm = TPM::new(pv, &config.tpm)?;
        let primary_key = tpm.get_persistent_primary(handle, auth_value.try_into()?)?;
        Ok(TotpStore {
            config: config,
            tpm: Some(tpm),
            primary_key: Some(primary_key),
            phantom: PhantomData,
        })
    }

    pub fn add(&mut self, service: &str, account: &str, digits: u8, interval: u32, secret: &[u8]) -> Result<Secret> {
        let primary_key = *self.primary_key();

        log::info!("generating secret hmac key");
        let hmac_key = self.tpm().create_hmac_key(primary_key, secret)?;
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
            *self.primary_key(),
            Public::unmarshall(&secret.public_data)?,
            secret.private_data.try_into()?
        );

        log::info!("generating one time code");
        let ts = timestamp.duration_since(UNIX_EPOCH).unwrap().as_secs() / secret.interval as u64;
        let hash = self.tpm().hmac(hmac_key, ts.to_be_bytes().to_vec().try_into()?)?;
        Ok(totp_code_to_string(&hash, secret.digits as u32))
    }

    fn tpm(&mut self) -> &mut TPM {
        match &mut self.tpm {
            Some(tpm) => tpm,
            None => unreachable!(),
        }
    }

    fn primary_key(&self) -> &KeyHandle {
        match &self.primary_key {
            Some(primary_key) => primary_key,
            None => unreachable!(),
        }
    }
}

fn totp_code_to_string(hash: &Digest, digits: u32) -> String {
    let offset = usize::from(hash[hash.len() - 1]) & 0xf;
    let mut code: u64 = (hash[offset] as u64 & 0x7f) * 0x1000000;
    code += hash[offset + 1] as u64 * 0x10000;
    code += hash[offset + 2] as u64 * 0x100;
    code += hash[offset + 3] as u64;
    code %= 10u64.pow(digits);
    format!("{:0>w$}", code, w = digits as usize)
}

fn read_primary_key_persistent_handle(config: &Config) -> Result<u32> {
    std::fs::read_to_string(config.primary_key_handle_path())?
        .trim()
        .parse().or(Err(Error::KeyHandleError))
}

fn read_auth_value(config: &Config) -> Result<Vec<u8>> {
    Ok(std::fs::read(config.auth_value_path())?)
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;
    use testutil::tpm::SwTpm;
    use tss_esapi::constants::response_code::{
        FormatOneResponseCode,
        FormatZeroResponseCode,
        Tss2ResponseCode::{FormatOne, FormatZero}
    };
    use tss_esapi::Error::Tss2Error;

    use crate::presence_verification;
    use crate::presence_verification::ConstPresenceVerifier;
    

    use super::*;

    #[test]
    fn with_tpm_fails_if_system_files_are_not_present() {
        let (config, _tepmdir, _swtpm) = setup();
        assert_eq!(config.auth_value_path().exists(), false);
        assert_eq!(config.primary_key_handle_path().exists(), false);
        match TotpStore::with_tpm(config.clone()) {
            Ok(_) => panic!("with_tpm did not fail even though system data directory was missing"),
            Err(Error::NotInitialized) => {},
            Err(e) => panic!("with_tpm failed with the wrong error: {:#?}", e),
        }
    }

    #[test]
    fn with_tpm_fails_if_presence_verification_fails() {
        let (config, _tepmdir, _swtpm) = setup();
        TotpStore::init(config.clone()).unwrap();
        match TotpStore::with_tpm_ex(Box::new(ConstPresenceVerifier::new(false)), config.clone()) {
            Ok(_) => panic!("with_tpm did not fail even though presence verification failed"),
            Err(Error::TpmError(tpm::Error::PresenceVerificationFailed)) => {},
            Err(e) => panic!("with_tpm failed with the wrong error: {:#?}", e),
        }
    }

    #[test]
    fn with_tpm_fails_if_presence_verification_errors() {
        let (config, _tepmdir, _swtpm) = setup();
        TotpStore::init(config.clone()).unwrap();
        match TotpStore::with_tpm_ex(Box::new(FailingPresenceVerifier), config.clone()) {
            Ok(_) => panic!("with_tpm did not fail even though presence verification failed"),
            Err(Error::TpmError(tpm::Error::PresenceVerificationError(_))) => {},
            Err(e) => panic!("with_tpm failed with the wrong error: {:#?}", e),
        }
    }

    #[test]
    fn with_tpm_succeeds_after_init() {
        let (config, _tepmdir, _swtpm) = setup();
        TotpStore::init(config.clone()).unwrap();
        TotpStore::with_tpm(config).unwrap();
    }

    #[test]
    fn init_fails_if_already_initialized() {
        let (config, _tepmdir, _swtpm) = setup();
        TotpStore::init(config.clone()).unwrap();
        let err = TotpStore::init(config).unwrap_err();
        match err {
            Error::AlreadyInitialized => {},
            e => panic!("wrong error: {:#?}", e),
        }
    }

    #[test]
    fn list_on_empty_store_returns_empty_list() {
        let (config, _tepmdir, _swtpm) = setup();
        TotpStore::init(config.clone()).unwrap();
        let secrets = TotpStore::without_tpm(config).list(None, None).unwrap();
        assert_eq!(secrets, vec![]);
    }

    #[test]
    fn list_after_add_lists_added_secrets() {
        let (config, _tepmdir, _swtpm) = setup();
        TotpStore::init(config.clone()).unwrap();
        let mut store = TotpStore::with_tpm(config).unwrap();
        let secret1 = store.add("firstsvc", "firstacc", 6, 30, "hello".as_bytes()).unwrap();
        let secret2 = store.add("secondsvc", "secondacc", 6, 30, "hello".as_bytes()).unwrap();
        let secrets = store.list(None, None).unwrap();
        assert_eq!(secrets, vec![secret1, secret2]);
    }

    #[test]
    fn list_properly_filters_secrets() {
        let (config, _tepmdir, _swtpm) = setup();
        TotpStore::init(config.clone()).unwrap();
        let mut store = TotpStore::with_tpm(config).unwrap();
        let secret1 = store.add("firstsvc", "firstacc", 6, 30, "hello".as_bytes()).unwrap();
        let secret2 = store.add("secondsvc", "secondacc", 6, 30, "hello".as_bytes()).unwrap();
        assert_eq!(store.list(Some("firstsvc"), None).unwrap(), vec![secret1.clone()]);
        assert_eq!(store.list(Some("first"), None).unwrap(), vec![secret1.clone()]);
        assert_eq!(store.list(Some("tsvc"), None).unwrap(), vec![secret1.clone()]);
        assert_eq!(store.list(None, Some("firstacc")).unwrap(), vec![secret1.clone()]);
        assert_eq!(store.list(None, Some("first")).unwrap(), vec![secret1.clone()]);
        assert_eq!(store.list(None, Some("tacc")).unwrap(), vec![secret1.clone()]);
        assert_eq!(store.list(Some("secondsvc"), None).unwrap(), vec![secret2.clone()]);
        assert_eq!(store.list(Some("second"), None).unwrap(), vec![secret2.clone()]);
        assert_eq!(store.list(Some("dsvc"), None).unwrap(), vec![secret2.clone()]);
        assert_eq!(store.list(None, Some("secondacc")).unwrap(), vec![secret2.clone()]);
        assert_eq!(store.list(None, Some("second")).unwrap(), vec![secret2.clone()]);
        assert_eq!(store.list(None, Some("dacc")).unwrap(), vec![secret2.clone()]);
        assert_eq!(store.list(Some("svc"), None).unwrap(), vec![secret1.clone(), secret2.clone()]);
        assert_eq!(store.list(None, Some("acc")).unwrap(), vec![secret1.clone(), secret2.clone()]);
    }

    #[test]
    fn del_deletes_secrets() {
        let (config, _tepmdir, _swtpm) = setup();
        TotpStore::init(config.clone()).unwrap();
        let mut store = TotpStore::with_tpm(config).unwrap();
        let secret1 = store.add("firstsvc", "firstacc", 6, 30, "hello".as_bytes()).unwrap();
        let secret2 = store.add("secondsvc", "secondacc", 6, 30, "hello".as_bytes()).unwrap();
        store.del(secret1.id).unwrap();
        let secrets = store.list(None, None).unwrap();
        assert_eq!(secrets, vec![secret2]);
    }

    #[test]
    fn del_on_nonexistent_id_errors() {
        let (config, _tepmdir, _swtpm) = setup();
        TotpStore::init(config.clone()).unwrap();
        let mut store = TotpStore::with_tpm(config).unwrap();
        let secret = store.add("firstsvc", "firstacc", 6, 30, "hello".as_bytes()).unwrap();
        match store.del(secret.id + 1).unwrap_err() {
            Error::DBError(db::Error::NoSuchElement) => {},
            err => panic!("wrong error: {:#?}", err),
        }
    }

    #[test]
    fn can_generate_codes_from_added_secret() {
        let (config, _tepmdir, _swtpm) = setup();
        TotpStore::init(config.clone()).unwrap();
        let mut store = TotpStore::with_tpm(config).unwrap();
        let secret = store.add("firstsvc", "firstacc", 6, 30, "hello".as_bytes()).unwrap();
        store.gen(secret.id, SystemTime::now()).unwrap();
    }

    #[test]
    fn gen_on_nonexistent_id_errors() {
        let (config, _tepmdir, _swtpm) = setup();
        TotpStore::init(config.clone()).unwrap();
        let mut store = TotpStore::with_tpm(config).unwrap();
        let secret = store.add("firstsvc", "firstacc", 6, 30, "hello".as_bytes()).unwrap();
        match store.gen(secret.id + 1, SystemTime::now()).unwrap_err() {
            Error::DBError(db::Error::NoSuchElement) => {},
            err => panic!("wrong error: {:#?}", err),
        }
    }

    #[test]
    fn with_tpm_errors_after_system_clear() {
        let (config, _tepmdir, _swtpm) = setup();
        TotpStore::init(config.clone()).unwrap();
        let mut store = TotpStore::with_tpm(config.clone()).unwrap();
        store.add("firstsvc", "firstacc", 6, 30, "hello".as_bytes()).unwrap();
        drop(store);

        TotpStore::clear(config.clone(), true).unwrap();
        match TotpStore::with_tpm(config.clone()).unwrap_err() {
            Error::NotInitialized => {},
            error => panic!("wrong error: {:#?}", error),
        }
    }

    #[test]
    fn primary_key_is_gone_from_tpm_after_system_clear() {
        let (config, _tepmdir, _swtpm) = setup();
        TotpStore::init(config.clone()).unwrap();
        let auth_value_backup = tempfile::NamedTempFile::new().unwrap();
        let primary_key_handle_backup = tempfile::NamedTempFile::new().unwrap();
        std::fs::copy(config.auth_value_path(), auth_value_backup.path()).unwrap();
        std::fs::copy(config.primary_key_handle_path(), primary_key_handle_backup.path()).unwrap();
        TotpStore::clear(config.clone(), true).unwrap();

        std::fs::copy(auth_value_backup.path(), config.auth_value_path()).unwrap();
        std::fs::copy(primary_key_handle_backup.path(), config.primary_key_handle_path()).unwrap();

        match TotpStore::with_tpm(config.clone()).unwrap_err() {
            Error::TpmError(tpm::Error::TpmError(Tss2Error(FormatOne(FormatOneResponseCode(395))))) => {},
            err => panic!("wrong error: {:#?}", err),
        }
    }

    #[test]
    fn new_primary_key_can_not_be_used_to_access_old_secrets() {
        let (config, _tepmdir, _swtpm) = setup();
        TotpStore::init(config.clone()).unwrap();
        let mut store = TotpStore::with_tpm(config.clone()).unwrap();
        let secret = store.add("firstsvc", "firstacc", 6, 30, "hello".as_bytes()).unwrap();
        drop(store);
        let secrets_db_backup = tempfile::NamedTempFile::new().unwrap();
        std::fs::copy(config.secrets_db_path(), secrets_db_backup.path()).unwrap();
        TotpStore::clear(config.clone(), true).unwrap();
        
        TotpStore::init(config.clone()).unwrap();
        std::fs::copy(secrets_db_backup.path(), config.secrets_db_path()).unwrap();
        let mut store = TotpStore::with_tpm(config.clone()).unwrap();
        match store.gen(secret.id, SystemTime::now()).unwrap_err() {
            Error::TpmError(tpm::Error::TpmError(Tss2Error(FormatZero(FormatZeroResponseCode(655370))))) => {},
            Error::TpmError(tpm::Error::TpmError(Tss2Error(FormatOne(FormatOneResponseCode(479))))) => {},
            err => panic!("wrong error: {:#?}", err),
        }
    }

    #[test]
    fn local_clear_removes_all_secrets_but_not_auth_file() {
        let (config, _tepmdir, _swtpm) = setup();
        TotpStore::init(config.clone()).unwrap();
        let mut store = TotpStore::with_tpm(config.clone()).unwrap();
        let old_secret = store.add("firstsvc", "firstacc", 6, 30, "hello".as_bytes()).unwrap();
        drop(store);

        TotpStore::clear(config.clone(), false).unwrap();
        let mut store = TotpStore::with_tpm(config.clone()).unwrap();
        assert_eq!(store.list(None, None).unwrap(), vec![]);
        match store.gen(old_secret.id, SystemTime::now()).unwrap_err() {
            Error::DBError(db::Error::NoSuchElement) => {},
            err => panic!("wrong error: {:#?}", err),
        }
    }

    fn setup() -> (Config, TempDir, SwTpm) {
        let tempdir = TempDir::new().unwrap();
        let sysdir = tempdir.path().join("sys");
        let userdir = tempdir.path().join("user");
        let swtpm = SwTpm::new();
        let pv = Some(presence_verification::PresenceVerificationMethod::None);
        let cfg = Config::default(true, swtpm.tcti.clone(), Some(sysdir), Some(userdir), pv);
        (cfg, tempdir, swtpm)
    }

    struct FailingPresenceVerifier;

    impl PresenceVerifier for FailingPresenceVerifier {
        fn owner_present(&mut self) -> std::result::Result<bool, presence_verification::Error> {
            Err(presence_verification::Error::ImplementationSpecificError("FailingPresenceVerifier".to_string()))
        }
    }
}