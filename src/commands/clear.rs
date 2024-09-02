use crate::{config::Config, presence_verification::fprintd::FprintdPresenceVerifier, result::Result, totp_store::TotpStore};

pub fn run(
    config: Config,
    system: bool,
    go_ahead: bool,
) -> Result<()> {
    if !go_ahead {
        eprintln!("verification flag not specified; aborting");
        return Ok(())
    }

    TotpStore::clear(Box::new(FprintdPresenceVerifier::new(config.pv_timeout)), config, system)?;

    Ok(())
}