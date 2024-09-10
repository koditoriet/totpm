use std::str::FromStr;

use serde::{de::IntoDeserializer, Deserialize, Serialize};

pub mod fprintd;
pub mod factory;

#[derive(Debug)]
#[derive(PartialEq)]
pub enum Error {
    ImplementationSpecificError(String)
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PresenceVerificationMethod {
    Fprintd,
    None,
    #[cfg(test)]
    AlwaysFail,
}

impl FromStr for PresenceVerificationMethod {
    fn from_str(s: &str) -> crate::result::Result<Self> {
        Self::deserialize(s.into_deserializer())
            .map_err(|_: serde::de::value::Error| crate::result::Error::InvalidPVMethod(s.to_string()))
    }
    
    type Err = crate::result::Error;
}

pub trait PresenceVerifier {
    fn owner_present(&mut self) -> Result<bool>;
}

pub struct ConstPresenceVerifier(bool);

impl ConstPresenceVerifier {
    pub fn new(const_result: bool) -> Self {
        ConstPresenceVerifier(const_result)
    }
}

impl PresenceVerifier for ConstPresenceVerifier {
    fn owner_present(&mut self) -> Result<bool> {
        Ok(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pv_method_deserializes_correctly() {
        assert_eq!(PresenceVerificationMethod::from_str("fprintd").unwrap(), PresenceVerificationMethod::Fprintd);
        assert_eq!(PresenceVerificationMethod::from_str("none").unwrap(), PresenceVerificationMethod::None);
        let invalid_values = vec!["FPRINTD", "", "fprintd ", " fprintd", " fprintd ", "no"];
        for v in invalid_values {
            match PresenceVerificationMethod::from_str(v) {
                Ok(x) => panic!("'{}' deserialized to '{:#?}'", v, x),
                Err(crate::result::Error::InvalidPVMethod(_)) => {},
                Err(e) => panic!("wrong error: {:#?}", e),
            }
        }
    }
}
