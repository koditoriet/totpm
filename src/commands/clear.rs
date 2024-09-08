use crate::{config::Config, result::Result, totp_store::TotpStore};

pub fn run(
    config: Config,
    system: bool,
    go_ahead: bool,
) -> Result<()> {
    if !go_ahead {
        eprintln!("verification flag not specified; aborting");
        return Ok(())
    }
    Ok(TotpStore::clear(config, system)?)
}