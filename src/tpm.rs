use std::str::FromStr;

use rand::RngCore;
use tss_esapi::{
    attributes::ObjectAttributes, constants::{
        response_code::FormatOneResponseCode, StartupType, Tss2ResponseCode
    }, handles::{
        KeyHandle, ObjectHandle, PersistentTpmHandle, TpmHandle
    }, interface_types::{
        algorithm::{
            HashingAlgorithm, PublicAlgorithm
        }, dynamic_handles::Persistent, resource_handles::{
            Hierarchy, Provision
        }
    }, structures::{
        Auth, Digest, HmacScheme, KeyedHashScheme, MaxBuffer, Private, Public,
        PublicKeyedHashParameters, SymmetricCipherParameters,
        SymmetricDefinitionObject
    }, Context, TctiNameConf
};

use crate::presence_verification::{self, PresenceVerifier};

pub struct TPM(Context);

impl TPM {
    pub fn new(mut pv: Box<dyn PresenceVerifier>, tcti: &str) -> Result<Self> {
        if !pv.owner_present()? {
            return Err(Error::PresenceVerificationFailed)
        }
        let tcti_cfg = TctiNameConf::from_str(tcti)?;
        let ctx = Context::new(tcti_cfg)?;
        let mut tpm = TPM(ctx);
        tpm.0.startup(StartupType::Clear)?;
        Ok(tpm)
    }
}

impl Drop for TPM {
    fn drop(&mut self) {
        self.0.shutdown(StartupType::State).unwrap();
    }
}

pub struct HmacKey {
    pub primary_key: KeyHandle,
    pub public: Public,
    pub private: Private,
}

impl HmacKey {
    pub fn new(primary_key: KeyHandle, public: Public, private: Private) -> Self {
        HmacKey {primary_key, public, private}
    }
}

#[derive(Debug)]
pub enum Error {
    TpmError(tss_esapi::Error),
    PresenceVerificationError(presence_verification::Error),
    PresenceVerificationFailed,
    EvictPrimaryKeyFailed,
    DropPrivilegesFailed,
}

type Result<T> = std::result::Result<T, Error>;

impl From<tss_esapi::Error> for Error {
    fn from(value: tss_esapi::Error) -> Self {
        Error::TpmError(value)
    }
}

impl From<presence_verification::Error> for Error {
    fn from(value: presence_verification::Error) -> Self {
        Error::PresenceVerificationError(value)
    }
}

impl TPM {
    pub fn create_persistent_primary(&mut self, auth_value: Auth) -> Result<Persistent> {
        let object_attributes = ObjectAttributes::builder()
            .with_user_with_auth(true)
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_decrypt(true)
            .with_restricted(true)
            .build()?;

        let public = Public::builder()
            .with_public_algorithm(PublicAlgorithm::SymCipher)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_symmetric_cipher_parameters(SymmetricCipherParameters::new(SymmetricDefinitionObject::AES_256_CFB))
            .with_symmetric_cipher_unique_identifier(Digest::default())
            .build()?;

        let mut initial = [0u8;32];
        rand::thread_rng().fill_bytes(&mut initial);

        return self.0.execute_with_nullauth_session(|ctx| {
            let cpkr = ctx.create_primary(
                Hierarchy::Owner,
                public,
                Some(auth_value.clone()),
                Some(initial.to_vec().try_into().unwrap()),
                None,
                None,
            )?;
            let persistent_handle = find_next_persistent_handle(ctx)?;
            ctx.evict_control(Provision::Owner, cpkr.key_handle.into(), persistent_handle)?;
            ctx.flush_context(cpkr.key_handle.into())?;
            return Ok(persistent_handle);
        });
    }

    pub fn get_persistent_primary(&mut self, handle: u32, auth_value: Auth) -> Result<KeyHandle> {
        self.0.execute_with_nullauth_session(|ctx| {
            let handle = ctx.tr_from_tpm_public(TpmHandle::Persistent(PersistentTpmHandle::new(handle)?))?;
            ctx.tr_set_auth(handle, auth_value)?;
            return Ok(handle.into());
        })
    }

    pub fn delete_persistent_primary(&mut self, handle: u32, auth_value: Auth) -> Result<()> {
        self.0.execute_with_nullauth_session(|ctx| {
            let persistent_handle = PersistentTpmHandle::new(handle)?;
            let object_handle = ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent_handle))?;
            ctx.tr_set_auth(object_handle, auth_value)?;
            let result = ctx.evict_control(Provision::Owner, object_handle, Persistent::Persistent(persistent_handle))?;
            if result == ObjectHandle::None {
                Ok(())
            } else {
                Err(Error::EvictPrimaryKeyFailed)
            }
        })
    }

    pub fn create_hmac_key(&mut self, primary_key: KeyHandle, key_material: &Vec<u8>) -> Result<HmacKey> {
        let hmac_key = self.0.execute_with_nullauth_session(|ctx| {
            ctx.create(
                primary_key,
                Public::KeyedHash {
                    object_attributes: ObjectAttributes::builder()
                        .with_sign_encrypt(true)
                        .with_user_with_auth(true)
                        .with_fixed_parent(true)
                        .with_fixed_tpm(true)
                        .with_sensitive_data_origin(false)
                        .build()
                        .unwrap(),
                    name_hashing_algorithm: HashingAlgorithm::Sha256,
                    auth_policy: Digest::default(),
                    parameters: PublicKeyedHashParameters::new(
                        KeyedHashScheme::Hmac { hmac_scheme: HmacScheme::new(HashingAlgorithm::Sha1) }
                    ),
                    unique: Digest::default(),
                },
                None,
                Some(key_material.clone().try_into()?),
                None,
                None
            )
        })?;
        return Ok(HmacKey::new(primary_key, hmac_key.out_public, hmac_key.out_private));
    }

    pub fn hmac(&mut self, hmac_key: HmacKey, buffer: MaxBuffer) -> tss_esapi::Result<Digest> {
        self.0.execute_with_nullauth_session(|ctx| {
            let key_handle = ctx.load(hmac_key.primary_key, hmac_key.private, hmac_key.public)?;
            let result = ctx.hmac(key_handle.into(), buffer, HashingAlgorithm::Sha1);
            ctx.flush_context(key_handle.into())?;
            return result
        })
    }
}

fn find_next_persistent_handle(ctx: &mut Context) -> tss_esapi::Result<Persistent> {
    let persistent_handle_start = 0x81000000u32;
    let persistent_handle_end = 0x8100FFFFu32;
    for h in persistent_handle_start .. persistent_handle_end {
        let handle = PersistentTpmHandle::new(h)?;
        let result = ctx.tr_from_tpm_public(TpmHandle::Persistent(handle));
        match result.err() {
            Some(tss_esapi::Error::Tss2Error(Tss2ResponseCode::FormatOne(FormatOneResponseCode(0x18b)))) => {
                // unused handle found!
                return Ok(Persistent::Persistent(handle));
            },
            Some(e) => {
                // something else went wrong
                return Err(e);
            },
            None => {
                // handle is in use, try next
            },
        }
    }
    panic!("unable to find a free persistent handle")
}
