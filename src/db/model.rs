use std::fmt::Display;

#[derive(Debug)]
#[derive(Clone)]
#[derive(PartialEq)]
pub struct Secret {
    pub id: i64,
    pub service: String,
    pub account: String,
    pub digits: u8,
    pub interval: u32,
    pub public_data: Vec<u8>,
    pub private_data: Vec<u8>,
}

impl Secret {
    pub fn new(
        service: String,
        account: String,
        digits: Option<u8>,
        interval: Option<u32>,
        public_data: Vec<u8>,
        private_data: Vec<u8>
    ) -> Self {
        Secret {
            id: 0,
            service: service,
            account: account,
            digits: digits.unwrap_or(6),
            interval: interval.unwrap_or(30),
            public_data: public_data,
            private_data: private_data
        }
    }
}

impl Display for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{} @ {}", self.account, self.service))
    }
}
