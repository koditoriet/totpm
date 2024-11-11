use std::io::{self, Write};

use rpassword::read_password;

use crate::{base32, config::Config, result::{Error, Result}, totp_store::TotpStore};

pub fn run(
    config: Config,
    service: &str,
    account: &str,
    digits: Option<u8>,
    interval: Option<u32>,
    secret_on_stdin: bool,
) -> Result<()> {
    let secret = if secret_on_stdin {
        let mut buf = String::new();
        io::stdin().read_line(&mut buf)?;
        buf.trim().to_owned()
    } else {
        print!("Enter secret value for {} ({}): ", service, account);
        io::stdout().flush()?;
        read_password()?
    };

    log::info!("adding secret for {} ({})", service, account);
    let secret_bytes = base32::decode(&secret).ok_or(Error::SecretFormatError)?;
    let mut store = TotpStore::with_tpm(config)?;
    store.add(service, account, digits, interval, &secret_bytes)?;
    Ok(())
}
