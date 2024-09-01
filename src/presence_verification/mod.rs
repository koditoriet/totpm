pub mod fprintd;

#[derive(Debug)]
#[derive(PartialEq)]
pub enum Error {
    ImplementationSpecificError(String)
}

type Result<T> = std::result::Result<T, Error>;

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
