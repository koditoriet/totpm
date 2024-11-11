use crate::totp_store;

#[derive(Debug)]
pub enum Error {
    IOError(std::io::Error),
    ConfigReadError(toml::de::Error),
    ConfigWriteError(toml::ser::Error),
    TotpStoreError(totp_store::Error),
    ImportFormatError(String),
    UserNotFoundError(String),
    SecretFormatError,
    InvalidPVMethod(String),
    RootRequired,
    SecretNotFound,
    AmbiguousSecret,
}

impl From<toml::ser::Error> for Error {
    fn from(value: toml::ser::Error) -> Self {
        Self::ConfigWriteError(value)
    }
}

impl From<toml::de::Error> for Error {
    fn from(value: toml::de::Error) -> Self {
        Self::ConfigReadError(value)
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::IOError(value)
    }
}

impl From<totp_store::Error> for Error {
    fn from(value: totp_store::Error) -> Self {
        Self::TotpStoreError(value)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
