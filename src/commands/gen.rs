use crate::{config::Config, presence_verification::fprintd::FprintdPresenceVerifier, result::Result, term::pick_one, totp_store::TotpStore};

pub fn run(
    config: Config,
    service: &str,
    account: Option<&str>
) -> Result<()> {
    let mut store = TotpStore::with_tpm(Box::new(FprintdPresenceVerifier::new(config.pv_timeout)), config)?;
    let alternatives = store.list(Some(service), account)?;
    
    if alternatives.is_empty() {
        println!("service/account combination not found");
        return Ok(())
    }

    if let Some(alt) = pick_one(
        &mut std::io::stdin().lock(),
        &mut std::io::stdout(),
        "found multiple matches for the given service/account combination",
        alternatives.iter()
    ) {
        let code = store.gen(alt.id, std::time::SystemTime::now())?;
        println!("{}", code);
    }

    Ok(())
}