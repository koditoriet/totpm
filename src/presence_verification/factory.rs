use super::{fprintd::FprintdPresenceVerifier, ConstPresenceVerifier, PresenceVerifier, PresenceVerificationMethod};

pub(crate) fn create_presence_verifier(
    method: PresenceVerificationMethod,
    timeout_secs: u8
) -> Box<dyn PresenceVerifier> {
    match method {
        PresenceVerificationMethod::Fprintd => Box::new(FprintdPresenceVerifier::new(timeout_secs)),
        PresenceVerificationMethod::None => Box::new(ConstPresenceVerifier::new(true)),
        #[cfg(test)]
        PresenceVerificationMethod::AlwaysFail => Box::new(ConstPresenceVerifier::new(false))
    }
}
