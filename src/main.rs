use std::path::{Path, PathBuf};

use clap::Parser;
use serde::Deserialize;
use totpm::{args::Opts, config::{absolute_path, local_path, Config}, presence_verification::PresenceVerificationMethod, result::Result};

fn main() {
    let opts = Opts::parse();
    if opts.debug {
        stderrlog::new()
            .verbosity(log::Level::Trace)
            .init()
            .unwrap();
    }

    let config_path = resolve_config_path(false, opts.config.as_deref());
    run_command(opts, &config_path).unwrap();
}

fn run_command(opts: Opts, config_path: &Path) -> Result<()> {
    match opts.command {
        totpm::args::Command::Add { service, account, digits, interval, secret_on_stdin } => {
            totpm::commands::add::run(
                load_config(config_path)?,
                &service,
                &account,
                digits,
                interval,
                secret_on_stdin,
            )
        },
        totpm::args::Command::Del { service, account } => {
            totpm::commands::del::run(
                load_config(config_path)?,
                &service,
                &account,
            )
        },
        totpm::args::Command::Gen { service, account } => {
            totpm::commands::gen::run(
                load_config(config_path)?,
                &service,
                account.as_deref(),
            )
        },
        totpm::args::Command::List { service, account } => {
            totpm::commands::list::run(
                load_config(config_path)?,
                service.as_deref(),
                account.as_deref(),
            )
        },
        totpm::args::Command::Init { tpm, system_data_path, user_data_path, user, presence_verification, local } => {
            let config_path = resolve_config_path(local, opts.config.as_deref());
            let user_name = user.as_deref().unwrap_or("totpm");
            let pv = presence_verification.map(|x| PresenceVerificationMethod::from_str(&x)).transpose()?;
            let config = if cfg!(feature = "install") {
                Config::default(local, tpm, system_data_path, user_data_path, pv)
            } else {
                load_config(&config_path)?
            };
            totpm::commands::init::run(
                &config_path,
                config,
                user_name,
                local,
                &PathBuf::from("/usr/local/bin"),
            )
        },
        totpm::args::Command::Clear { yes_i_know_what_i_am_doing, system } => {
            totpm::commands::clear::run(
                load_config(config_path)?,
                system,
                yes_i_know_what_i_am_doing,
            )
        },
    }
}

/// Loads a config from the given path.
fn load_config(config_path: &Path) -> Result<Config> {
    let config_str = std::fs::read_to_string(config_path)?;
    Ok(Config::deserialize(toml::Deserializer::new(&config_str))?)
}

/// Returns the path to the totpm configuration file, according to the following rules:
/// - if config is not Some(p), then p is returned
/// - if force_local is true, then the path to the user-local config is returned
/// - if the user-local config exists, then its path is returned
/// - otherwise the path to the system-wide config is returned
fn resolve_config_path(force_local: bool, config: Option<&Path>) -> PathBuf {
    match config {
        Some(cfg) => absolute_path(cfg),
        None => {
          let local_config = local_path(Path::new(".config/totpm.conf"));
          if force_local || local_config.is_file() {
              local_config
          } else {
             "/etc/totpm.conf".into()
          }
        },
    }
}
