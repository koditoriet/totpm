use crate::{config::Config, term::pick_one, totp_store::TotpStore};

pub fn run(config: Config, service: &str, account: &str) -> Result<(), crate::result::Error> {
    let mut store = TotpStore::without_tpm(config);
    let alternatives = store.list(Some(service), Some(account))?;
    
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
        store.del(alt.id)?;
    }
    Ok(())
}
