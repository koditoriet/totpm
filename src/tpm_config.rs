#[derive(Debug)]
pub struct TpmConfig {
    pub auth_value: Vec<u8>,
    pub primary_key_handle: u32,
    pub tpm_device: String,
}
