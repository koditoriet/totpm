use std::{collections::HashMap, path::Path};
use serde::Deserialize;
use crate::{base32, config::Config, result::Error, totp_store::TotpStore};

#[derive(Deserialize)]
struct ServiceInfo {
    pub account: String,
    pub secret: String,
    pub digits: Option<u8>,
    pub interval: Option<u32>,
}

pub fn run(config: Config, file: &Path) -> Result<(), Error> {
    let imports = import_json(file)?;
    let mut store = TotpStore::with_tpm(config)?;
    for (service, info) in imports {
        let secret_bytes = base32::decode(&info.secret).ok_or(Error::SecretFormatError)?;
        store.add(&service, &info.account, info.digits, info.interval, &secret_bytes)?;
    }
    Ok(())
}

fn import_json(file: &Path) -> Result<HashMap<String, ServiceInfo>, crate::result::Error> {
    let json_file = std::fs::File::open(file)?;
    serde_json::de::from_reader(json_file)
        .map_err(|_| crate::result::Error::ImportFormatError("not a json file or invalid schema".to_string()))
}    

#[cfg(test)]
mod tests {
    use std::time::SystemTime;
    use tempfile::{tempdir, NamedTempFile, TempDir};
    use testutil::tpm::SwTpm;
    use crate::{config::Config, presence_verification::PresenceVerificationMethod, totp_store::{TotpStore, WithTPM}};
    use super::run;

    #[test]
    fn import_succeeds_on_well_formed_json() {
        let (_tpm, _tmpdir, mut totp_store) = test_import("{
            \"foo\": {
                \"account\": \"bar\",
                \"secret\": \"MFRGGZDFMVTGO2DJNJVWY3LON5YHC4TT\",
                \"digits\": 5,
                \"interval\": 60
            }
        }").unwrap();
    
        let accounts = totp_store.list(Some("foo"), Some("bar")).unwrap();
        assert_eq!(accounts.len(), 1);
        let code = totp_store.gen(accounts[0].id, SystemTime::now()).unwrap();
        assert_ne!(code, "");
    }

    #[test]
    fn import_succeeds_on_minimal_single_secret_json() {
        let (_tpm, _tmpdir, mut totp_store) = test_import("{
            \"foo\": {
                \"account\": \"bar\",
                \"secret\": \"MFRGGZDFMVTGO2DJNJVWY3LON5YHC4TT\"
            }
        }").unwrap();

        let accounts = totp_store.list(Some("foo"), Some("bar")).unwrap();
        assert_eq!(accounts.len(), 1);
        let code = totp_store.gen(accounts[0].id, SystemTime::now()).unwrap();
        assert_ne!(code, "");
    }

    #[test]
    fn import_succeeds_on_empty_json() {
        let (_tpm, _tmpdir, totp_store) = test_import("{}").unwrap();
        let accounts = totp_store.list(None, None).unwrap();
        assert_eq!(accounts.len(), 0);
    }

    #[test]
    fn import_succeeds_on_mixed_format_json() {
        let (_tpm, _tmpdir, mut totp_store) = test_import("{
            \"interval_35\": {
                \"account\": \"foo\",
                \"secret\": \"MFRGGZDFMVTGO2DJNJVWY3LON5YHC4TT\",
                \"interval\": 35
            },
            \"digits_10\": {
                \"digits\": 10,
                \"account\": \"bar\",
                \"secret\": \"MFRGGZDFMVTGO2DJNJVWY3LON5YHC4RR\"
            },
            \"no_extra\": {
                \"account\": \"OVERWRITE ME\",
                \"secret\": \"GFRGGZDFMVTGO2DJNJVWY3LON5YHC4RR\"
            },
            \"no_extra\": {
                \"account\": \"baz\",
                \"secret\": \"GFRGGZDFMVTGO2DJNJVWY3LON5YHC4RR\"
            },
            \"all_extra\": {
                \"account\": \"quux\",
                \"interval\": 40,
                \"secret\": \"GFRGGZDFMVTGO2DJNJVWYWDON5YHC4RR\",
                \"digits\": 11
            }
        }").unwrap();
    
        let mut accounts = totp_store.list(None, None).unwrap();
        accounts.sort_by(|x, y| x.service.cmp(&y.service));
        assert_eq!(accounts.len(), 4);

        assert_eq!(accounts[0].service, "all_extra");
        assert_eq!(accounts[0].account, "quux");
        assert_eq!(accounts[0].digits, 11);
        assert_eq!(accounts[0].interval, 40);

        assert_eq!(accounts[1].service, "digits_10");
        assert_eq!(accounts[1].account, "bar");
        assert_eq!(accounts[1].digits, 10);
        assert_eq!(accounts[1].interval, 30);

        assert_eq!(accounts[2].service, "interval_35");
        assert_eq!(accounts[2].account, "foo");
        assert_eq!(accounts[2].digits, 6);
        assert_eq!(accounts[2].interval, 35);

        assert_eq!(accounts[3].service, "no_extra");
        assert_eq!(accounts[3].account, "baz");
        assert_eq!(accounts[3].digits, 6);
        assert_eq!(accounts[3].interval, 30);

        let code1 = totp_store.gen(accounts[0].id, SystemTime::now()).unwrap();
        let code2 = totp_store.gen(accounts[1].id, SystemTime::now()).unwrap();
        let code3 = totp_store.gen(accounts[2].id, SystemTime::now()).unwrap();
        let code4 = totp_store.gen(accounts[3].id, SystemTime::now()).unwrap();
        assert_ne!(code1, code2);
        assert_ne!(code1, code3);
        assert_ne!(code1, code4);
        assert_ne!(code2, code3);
        assert_ne!(code2, code4);
        assert_ne!(code3, code4);
    }

    #[test]
    fn import_fails_on_malformed_json() {
        expect_import_to_fail("{,}");
    }

    #[test]
    fn import_fails_on_json_array() {
        expect_import_to_fail("[]");
    }

    #[test]
    fn import_fails_on_missing_mandatory_field() {
        expect_import_to_fail("{
            \"some_service\": {
                \"account\": \"foo\",
                \"hemlis\": \"GFRGGZDFMVTGO2DJNJVWYWDON5YHC4RR\"
            }
        }");
    }

    #[test]
    fn import_fails_on_mixed_valid_and_invalid_entries() {
        expect_import_to_fail("{
            \"valid_service\": {
                \"account\": \"foo\",
                \"secret\": \"GFRGGZDFMVTGO2DJNJVWYWDON5YHC4RR\"
            },
            \"invalid_service\": {
                \"account\": \"bar\",
                \"hemlis\": \"GFRGGZDFMVTGO2DJNJVWYWDON5YHC4RR\"
            }
        }");
    }

    fn expect_import_to_fail(json: &str) {
        let (_tpm, _dir, cfg) = setup();
        let result = test_import_with_config(&cfg, json);
        match result {
            Ok(_) => panic!("import succeeded though it should have failed"),
            Err(crate::result::Error::ImportFormatError(_)) => {},
            Err(e) => panic!("import failed with wrong error: {:#?}", e),
        }

        let store = TotpStore::without_tpm(cfg);
        assert_eq!(0, store.list(None, None).unwrap().len());
    }

    fn test_import(json: &str) -> Result<(SwTpm, TempDir, TotpStore<WithTPM>), crate::result::Error> {
        let (tpm, dir, cfg) = setup();
        let store = test_import_with_config(&cfg, json)?;
        Ok((tpm, dir, store))
    }

    fn test_import_with_config(cfg: &Config, json: &str) -> Result<TotpStore<WithTPM>, crate::result::Error> {
        TotpStore::init(cfg.clone()).unwrap();
        let json_file = NamedTempFile::new().unwrap();
        std::fs::write(json_file.path(), json).unwrap();
        run(cfg.clone(), json_file.path())?;
        Ok(TotpStore::with_tpm(cfg.clone()).unwrap())
    }
    
    fn setup() -> (SwTpm, TempDir, Config) {
        let tpm = SwTpm::new();
        let dir = tempdir().unwrap();
        let cfg = Config::default(
            true,
            tpm.tcti.clone(),
            Some(dir.path().join("sys")),
            Some(dir.path().join("user")),
            Some(PresenceVerificationMethod::None)
        );
        (tpm, dir, cfg)
    }
}