use crate::{config::Config, totp_store::TotpStore, result::Result};

pub fn run(config: Config, service: Option<&str>, account: Option<&str>) -> Result<()> {
    log::info!("listing secrets for {} ({})", service.unwrap_or("(None)"), account.unwrap_or("None"));
    let store = TotpStore::without_tpm(config);
    for secret in store.list(service, account)? {
        println!("{} ({})", secret.service, secret.account);
    }
    Ok(())
}
