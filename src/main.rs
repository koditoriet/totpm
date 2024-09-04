use std::{env, path::{Path, PathBuf}};

use clap::Parser;
use serde::Deserialize;
use totpm::{args::Opts, config::{absolute_path, local_path, Config}, result::Result};

fn main() {
    let opts = Opts::parse();
    if opts.debug {
        stderrlog::new()
            .verbosity(log::Level::Trace)
            .init()
            .unwrap();
    }

    let config_path = resolve_config_path(false, opts.config.as_deref());
    match opts.command {
        totpm::args::Command::Add { service, account, digits, interval } => {
            totpm::commands::add::run(
                load_config(config_path).unwrap(),
                &service,
                &account,
                digits,
                interval,
            )
        },
        totpm::args::Command::Del { service, account } => {
            totpm::commands::del::run(
                load_config(config_path).unwrap(),
                &service,
                &account,
            )
        },
        totpm::args::Command::Gen { service, account } => {
            totpm::commands::gen::run(
                load_config(config_path).unwrap(),
                &service,
                account.as_deref(),
            )
        },
        totpm::args::Command::List { service, account } => {
            totpm::commands::list::run(
                load_config(config_path).unwrap(),
                service.as_deref(),
                account.as_deref(),
            )
        },
        totpm::args::Command::Init { tpm, system_data_path, user_data_path, user, local } => {
            let config_path = resolve_config_path(local, opts.config.as_deref());
            let user_name = user.as_deref().unwrap_or("totpm");
            totpm::commands::init::run(
                &config_path,
                Config::default(local, tpm, system_data_path, user_data_path),
                user_name,
                local,
                &PathBuf::from("/usr/local/bin"),
            )
        },
        totpm::args::Command::Clear { yes_i_know_what_i_am_doing, system } => {
            totpm::commands::clear::run(
                load_config(config_path).unwrap(),
                system,
                yes_i_know_what_i_am_doing,
            )
        },
    }.unwrap()
}

/// Loads a config from the given path.
fn load_config(config_path: PathBuf) -> Result<Config> {
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
