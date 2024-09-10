use crate::{config::Config, result::{Error, Result}, term::pick_one, totp_store::TotpStore};

pub fn run(
    config: Config,
    service: &str,
    account: Option<&str>
) -> Result<()> {
    let alternatives = TotpStore::without_tpm(config.clone()).list(Some(service), account)?;
    
    if alternatives.is_empty() {
        return Err(Error::SecretNotFound);
    }

    if let Some(alt) = pick_one(
        &mut std::io::stdin().lock(),
        &mut std::io::stdout(),
        "found multiple matches for the given service/account combination",
        alternatives.iter()
    ) {
        let code = TotpStore::with_tpm(config)?.gen(alt.id, std::time::SystemTime::now())?;
        println!("{}", code);
        Ok(())
    } else {
        Err(Error::AmbiguousSecret)
    }
}

#[cfg(test)]
mod tests {
    use serial_test::serial;
    use tempfile::{tempdir, TempDir};
    use testutil::tpm::SwTpm;

    use crate::presence_verification::PresenceVerificationMethod;
    use crate::tpm::Error::PresenceVerificationFailed;
    use crate::totp_store::Error::TpmError;

    use super::*;

    #[test]
    fn gen_succeeds_on_unambiguous_secret() {
        let (_tpm, _dir, cfg) = setup();
        TotpStore::init(cfg.clone()).unwrap();
        let mut store = TotpStore::with_tpm(cfg.clone()).unwrap();
        store.add("foo", "bar", 6, 30, &[0,0,0,0,0,0,0,0,0,0]).unwrap();
        run(cfg, "foo", None).unwrap();
    }

    #[test]
    fn gen_fails_on_secret_not_found() {
        let (_tpm, _dir, cfg) = setup();
        TotpStore::init(cfg.clone()).unwrap();
        match run(cfg, "foo", None).unwrap_err() {
            crate::result::Error::SecretNotFound => {},
            err => panic!("wrong error: {:#?}", err),
        }
    }

    #[test]
    #[serial]
    fn presence_verification_happens_after_disambiguation() {
        let (_tpm, _dir, cfg) = setup();
        let mut failing_cfg = cfg.clone();
        failing_cfg.pv_method = PresenceVerificationMethod::AlwaysFail;
        TotpStore::init(cfg.clone()).unwrap();

        // If there are no matching accounts, we should quit before PV happens
        let error = run(failing_cfg.clone(), "foo", Some("bar")).unwrap_err();
        if let Error::SecretNotFound = error {} else {
            panic!("wrong error: {:#?}", error)
        }

        // If there is exactly one matching accounts, we should see PV happening and failing
        TotpStore::with_tpm(cfg.clone()).unwrap().add("foo", "bar", 6, 30, &[0,0,0,0,0,0,0,0,0,0]).unwrap();
        let error = run(failing_cfg.clone(), "foo", Some("bar")).unwrap_err();
        if let Error::TotpStoreError(TpmError(PresenceVerificationFailed)) = error {} else {
            panic!("wrong error: {:#?}", error)
        }
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
