use crate::{config::Config, totp_store::TotpStore, result::Result};

pub fn run(config: Config, service: Option<&str>, account: Option<&str>) -> Result<()> {
    log::info!("listing secrets for {} @ {}", account.unwrap_or("(None)"), service.unwrap_or("(None)"));
    let mut store = TotpStore::without_tpm(config);
    for secret in store.list(service, account)? {
        println!("{} @ {}", secret.account, secret.service);
    }
    Ok(())
}
