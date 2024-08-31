use std::path::PathBuf;

use clap::{command, Parser, Subcommand};

#[derive(Parser)]
#[derive(Debug)]
#[command(version, about, long_about = None)]
/// Manage TOTP (e.g. Google Authenticator, etc.) secrets.
pub struct Opts {
    #[command(subcommand)]
    pub command: Command,

    /// Path to global configuration file.
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Print debugging information and non-critical TPM.
    #[arg(short, long, default_value = "false")]
    pub debug: bool,
}

#[derive(Subcommand)]
#[derive(Debug)]
pub enum Command {
    /// Add a new TOTP secret.
    Add {
        /// Name of the service to add a secret for.
        service: String,

        /// Username associated with the secret.
        account: String,

        /// Number of security code digits.
        #[arg(short, long, default_value = "6")]
        digits: u8,

        /// How often to generate a new security code.
        #[arg(short, long, default_value = "30")]
        interval: u32,
    },

    /// Delete an existing TOTP secret.
    Del {
        /// Name of the service to delete secret for.
        service: String,

        /// Username associated with the secret to delete.
        account: String,
    },

    /// Generate a security code.
    Gen {
        /// Service to generate security code for.
        service: String,

        /// Username to generate security code for.
        account: Option<String>,
    },

    /// List all accounts matching the given partial service and account names.
    List {
        service: Option<String>,
        account: Option<String>,
    },

    Init {
        /// TPM configuration to use.
        /// May be either "device", "device:/path/to/tpm", or "swtpm:host=...,port=..."
        #[arg(short, long, default_value = "device")]
        tpm: String,

        /// Path to directory where totpm should store system-wide data.
        /// The directory is created if it does not exist.
        #[arg(short, long)]
        system_data_path: Option<PathBuf>,

        /// Path to directory where totpm should store user-specific data.
        /// If the path is not absolute, it is interpreted relative to
        /// each user's home directory.
        /// The directory is created if it does not exist.
        #[arg(short = 'p', long, default_value = ".local/state/totpm")]
        user_data_path: PathBuf,

        /// User which will own system-wide data files. Will be created if it does not exist.
        #[arg(short, long)]
        user: Option<String>,
    
        /// Allow user-local installation. A local installation will:
        /// - not create a user
        /// - create any files and directories as the current user
        /// - use user-local defaults for paths that are not explicitly specified
        #[arg(short, long, default_value = "false")]
        local: bool,
    },

    /// Remove all stored TOTP secrets, rendering them unusable.
    Clear {
        /// Are you REALLY sure?
        #[arg(long, default_value = "false")]
        yes_i_know_what_i_am_doing: bool,

        /// Also delete system-level data, rendering all secrets on this machine unusable.
        /// Requires root privileges.
        #[arg(short, long, default_value = "false")]
        system: bool,
    },
}
