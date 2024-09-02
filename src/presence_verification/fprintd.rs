use std::{str::FromStr, sync::{Arc, Mutex}, time::{self, Duration}};

use dbus::{arg::ReadAll, blocking::{Connection, Proxy}, message::SignalArgs, Message, Path};

use crate::privileges::with_uid_as_euid;

use super::PresenceVerifier;

pub struct FprintdPresenceVerifier {
    use_system_bus: bool,
    timeout: Duration,
}

const FPRINTD_BUS_NAME: &str = "net.reactivated.Fprint";
const FPRINTD_MANAGER_PATH: &str = "/net/reactivated/Fprint/Manager";
const FPRINTD_MANAGER_IFACE: &str = "net.reactivated.Fprint.Manager";
const FPRINTD_DEVICE_IFACE: &str = "net.reactivated.Fprint.Device";

struct VerifyStatus {
    /// Status of the last verification attempt.
    status: Status,

    /// Is the attempt considered "done" (i.e. no need to call VerifyStop)?
    #[allow(dead_code)]
    done: bool,
}

/// All possible fprintd verification statuses.
#[derive(Clone, Copy, Debug)]
enum Status {
    Match,
    NoMatch,
    RetryScan,
    SwipeTooShort,
    FingerNotCentered,
    RemoveAndRetry,
    Disconnected,
    UnknownError,
}

impl FromStr for Status {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "verify-match" => Ok(Status::Match),
            "verify-no-match" => Ok(Status::NoMatch),
            "verify-retry-scan" => Ok(Status::RetryScan),
            "verify-swipe-too-short" => Ok(Status::SwipeTooShort),
            "verify-finger-not-entered" => Ok(Status::FingerNotCentered),
            "verify-remove-and-retry" => Ok(Status::RemoveAndRetry),
            "verify-disconnected" => Ok(Status::Disconnected),
            "verify-unknown-error" => Ok(Status::UnknownError),
            _ => Err(format!("unknown status: {}", s))
        }
    }
}

impl ToString for Status {
    fn to_string(&self) -> String {
        match self {
            Status::Match => "verify-match",
            Status::NoMatch => "verify-no-match",
            Status::RetryScan => "verify-retry-scan",
            Status::SwipeTooShort => "verify-swipe-too-short",
            Status::FingerNotCentered => "verify-finger-not-entered",
            Status::RemoveAndRetry => "verify-remove-and-retry",
            Status::Disconnected => "verify-disconnected",
            Status::UnknownError => "verify-unknown-error",
        }.to_string()
    }
}

impl ReadAll for VerifyStatus {
    fn read(i: &mut dbus::arg::Iter) -> Result<Self, dbus::arg::TypeMismatchError> {
        Ok(VerifyStatus {
            status: Status::from_str(i.read::<&str>()?).unwrap(),
            done: i.read()?,
        })
    }
}

impl SignalArgs for VerifyStatus {
    const NAME: &'static str = "VerifyStatus";
    const INTERFACE: &'static str = FPRINTD_DEVICE_IFACE;
}

/// Wrapper for a fprintd fingerprint scanner device DBus proxy, which releases the scanner when dropped.
struct FprintDevice<'a> {
    proxy: Proxy<'a, &'a Connection>,
    connection: &'a Connection,
}

impl <'a> Drop for FprintDevice<'a> {
    fn drop(&mut self) {
        // If release fails, there's not much we can do about it anyway
        match self.proxy.method_call(FPRINTD_DEVICE_IFACE, "Release", ()) {
            Ok(()) => (),
            Err(e) => log::warn!("failed to release fprintd device: {:#?}", e),
        }
    }
}

fn fail<T>(reason: &str) -> super::Result<T> {
    Err(super::Error::ImplementationSpecificError(reason.to_owned()))
}

impl <'a> FprintDevice<'a> {
    fn verify(&self, timeout: &Duration) -> super::Result<bool> {
        let scan_status = Arc::new(Mutex::new(None));
        let scan_status_clone = scan_status.clone();
        self.proxy.match_signal(move |status: VerifyStatus, _: &Connection, _: &Message| {
            *scan_status.lock().unwrap() = Some(status.status);
            true
        }).or(fail("fprintd: unable to listen for signal"))?;

        self.proxy.method_call(FPRINTD_DEVICE_IFACE, "VerifyStart", ("any",))
            .or(fail("fprintd: unable to start fingerprint verification"))?;

        eprintln!("place your finger on the fingerprint reader");
        let mut time_left = timeout.as_millis() as i64;
        while time_left > 0 {
            let t0 = time::Instant::now();
            self.connection.process(Duration::from_millis(time_left as u64))
                .or(fail("fprintd: unable to process incoming signals"))?;
            let t1 = time::Instant::now();
            time_left -= (t1 - t0).as_millis() as i64;

            match *scan_status_clone.lock().unwrap() {
                Some(status) => {
                    match status {
                        Status::Match => {
                            self.proxy.method_call(FPRINTD_DEVICE_IFACE, "VerifyStop", ())
                                .or(fail("fprintd: unable to stop fingerprint verification"))?;
                            return Ok(true)
                        },
                        Status::NoMatch => {
                            eprintln!("fingerprint not recognized, try again");
                            self.proxy.method_call(FPRINTD_DEVICE_IFACE, "VerifyStop", ())
                                .or(fail("fprintd: unable to stop fingerprint verification"))?;
                            self.proxy.method_call(FPRINTD_DEVICE_IFACE, "VerifyStart", ("any",))
                                .or(fail("fprintd: unable to restart fingerprint verification"))?;
                        },
                        Status::RetryScan | Status::SwipeTooShort | Status::FingerNotCentered | Status::RemoveAndRetry => {
                            eprintln!("fingerprint not recognized, try again")
                            // scan is still ongoing, keep waiting for status updates
                        },
                        Status::Disconnected => {
                            return fail("fprintd: fingerprint reader disconnected")
                        },
                        Status::UnknownError => {
                            self.proxy.method_call(FPRINTD_DEVICE_IFACE, "VerifyStop", ())
                                .or(fail("fprintd: unable to stop fingerprint verification"))?;
                            return fail("fprintd: fingerprint scan failed with unknown error")
                        },
                    }
                    
                },
                None => {},
            }
        }
        self.proxy.method_call(FPRINTD_DEVICE_IFACE, "VerifyStop", ())
            .or(fail("fprintd: unable to stop fingerprint verification"))?;
        Ok(false)
    }

    /// Finds the default fingerprint scanner, claims it, and returns a release-on-drop proxy object for it.
    fn claim_default_device(conn: &'a Connection) -> super::Result<Self> {
        let mgr_proxy = conn.with_proxy(
            FPRINTD_BUS_NAME,
            FPRINTD_MANAGER_PATH,
            Duration::from_secs(10),
        );
        let (device_path,): (Path,) = mgr_proxy.method_call(FPRINTD_MANAGER_IFACE, "GetDefaultDevice", ())
            .or(Err(super::Error::ImplementationSpecificError("fprintd: couldn't get default device".to_owned())))?;
        let proxy = conn.with_proxy(
            FPRINTD_BUS_NAME,
            device_path,
            Duration::from_secs(10),
        );
        proxy.method_call(FPRINTD_DEVICE_IFACE, "Claim", ("",))
            .or(Err(super::Error::ImplementationSpecificError("fprintd: unable to claim device".to_owned())))?;
        Ok(FprintDevice { proxy: proxy, connection: conn })
    }    
}

impl PresenceVerifier for FprintdPresenceVerifier {
    fn owner_present(&mut self) -> super::Result<bool> {
        with_uid_as_euid(|| {
            let conn = if self.use_system_bus {
                Connection::new_system()
            } else {
                Connection::new_session()
            }.or(Err(super::Error::ImplementationSpecificError("fprintd: couldn't connect to bus".to_owned())))?;
            let dev = FprintDevice::claim_default_device(&conn)?;
            dev.verify(&self.timeout)
        })
    }
}

impl FprintdPresenceVerifier {
    pub fn new(timeout_secs: u8) -> Self {
        FprintdPresenceVerifier { use_system_bus: true, timeout: Duration::from_secs(timeout_secs as u64) }
    }
}

#[cfg(test)]
mod tests {
    use dbus::MethodErr;
    use sequential_test::sequential;
    use testutil::fprintd::{FprintdMethod, FprintdMockBuilder, DEVICE_PATH};
    use crate::presence_verification;
    use super::*;

    fn new_session_verifier() -> FprintdPresenceVerifier {
        FprintdPresenceVerifier {
            use_system_bus: false,
            timeout: Duration::from_secs(1),
        }
    }

    #[test]
    #[sequential]
    fn failed_getdefaultdevice_fails_presence_verification() {
        let _mock = FprintdMockBuilder::<Status>::new()
            .expect_method(FprintdMethod::GetDefaultDevice(Err(MethodErr::no_arg())))
            .build();
        let mut pv = new_session_verifier();
        let error = pv.owner_present().unwrap_err();
        assert_eq!(error, presence_verification::Error::ImplementationSpecificError("fprintd: couldn't get default device".to_owned()))
    }

    #[test]
    #[sequential]
    fn failed_claim_fails_presence_verification() {
        let _mock = FprintdMockBuilder::<Status>::new()
            .expect_method(FprintdMethod::GetDefaultDevice(Ok(DEVICE_PATH.to_owned())))
            .expect_method(FprintdMethod::Claim("".to_owned(), Err(MethodErr::no_arg())))
            .build();
        let mut pv = new_session_verifier();
        let error = pv.owner_present().unwrap_err();
        assert_eq!(error, presence_verification::Error::ImplementationSpecificError("fprintd: unable to claim device".to_owned()))
    }

    #[test]
    #[sequential]
    fn failed_verifystart_fails_presence_verification() {
        let _mock = FprintdMockBuilder::<Status>::new()
            .expect_method(FprintdMethod::GetDefaultDevice(Ok(DEVICE_PATH.to_owned())))
            .expect_method(FprintdMethod::Claim("".to_owned(), Ok(())))
            .expect_method(FprintdMethod::VerifyStart("any".to_owned(), Err(MethodErr::no_arg())))
            .expect_method(FprintdMethod::Release(Ok(())))
            .build();
        let mut pv = new_session_verifier();
        let error = pv.owner_present().unwrap_err();
        assert_eq!(error, presence_verification::Error::ImplementationSpecificError("fprintd: unable to start fingerprint verification".to_owned()))
    }

    #[test]
    #[sequential]
    fn timeout_makes_presence_verification_succeed_with_result_false() {
        let _mock = FprintdMockBuilder::<Status>::new()
            .expect_method(FprintdMethod::GetDefaultDevice(Ok(DEVICE_PATH.to_owned())))
            .expect_method(FprintdMethod::Claim("".to_owned(), Ok(())))
            .expect_method(FprintdMethod::VerifyStart("any".to_owned(), Ok(())))
            .expect_method(FprintdMethod::VerifyStop(Ok(())))
            .expect_method(FprintdMethod::Release(Ok(())))
            .build();
        let mut pv = new_session_verifier();
        assert_eq!(pv.owner_present().unwrap(), false);
    }

    #[test]
    #[sequential]
    fn successful_scan_makes_presence_verification_succeed_with_result_true() {
        let _mock = FprintdMockBuilder::new()
            .expect_method(FprintdMethod::GetDefaultDevice(Ok(DEVICE_PATH.to_owned())))
            .expect_method(FprintdMethod::Claim("".to_owned(), Ok(())))
            .expect_method(FprintdMethod::VerifyStart("any".to_owned(), Ok(())))
            .wait(Duration::from_millis(100))
            .send_status(Status::Match, true)
            .expect_method(FprintdMethod::VerifyStop(Ok(())))
            .expect_method(FprintdMethod::Release(Ok(())))
            .build();
        let mut pv = new_session_verifier();
        assert_eq!(pv.owner_present().unwrap(), true);
    }

    #[test]
    #[sequential]
    fn no_match_followed_by_match_makes_presence_verification_succeed() {
        let _mock = FprintdMockBuilder::new()
            .expect_method(FprintdMethod::GetDefaultDevice(Ok(DEVICE_PATH.to_owned())))
            .expect_method(FprintdMethod::Claim("".to_owned(), Ok(())))
            .expect_method(FprintdMethod::VerifyStart("any".to_owned(), Ok(())))
            .wait(Duration::from_millis(100))
            .send_status(Status::NoMatch, true)
            .expect_method(FprintdMethod::VerifyStop(Ok(())))
            .expect_method(FprintdMethod::VerifyStart("any".to_owned(), Ok(())))
            .wait(Duration::from_millis(100))
            .send_status(Status::Match, true)
            .expect_method(FprintdMethod::VerifyStop(Ok(())))
            .expect_method(FprintdMethod::Release(Ok(())))
            .build();
        let mut pv = new_session_verifier();
        assert_eq!(pv.owner_present().unwrap(), true);
    }

    #[test]
    #[sequential]
    fn swipe_too_short_followed_by_match_makes_presence_verification_succeed() {
        let _mock = FprintdMockBuilder::new()
            .expect_method(FprintdMethod::GetDefaultDevice(Ok(DEVICE_PATH.to_owned())))
            .expect_method(FprintdMethod::Claim("".to_owned(), Ok(())))
            .expect_method(FprintdMethod::VerifyStart("any".to_owned(), Ok(())))
            .wait(Duration::from_millis(100))
            .send_status(Status::SwipeTooShort, false)
            .wait(Duration::from_millis(100))
            .send_status(Status::Match, true)
            .expect_method(FprintdMethod::VerifyStop(Ok(())))
            .expect_method(FprintdMethod::Release(Ok(())))
            .build();
        let mut pv = new_session_verifier();
        assert_eq!(pv.owner_present().unwrap(), true);
    }

    #[test]
    #[sequential]
    fn disconnected_makes_presence_verification_fail() {
        let _mock = FprintdMockBuilder::new()
            .expect_method(FprintdMethod::GetDefaultDevice(Ok(DEVICE_PATH.to_owned())))
            .expect_method(FprintdMethod::Claim("".to_owned(), Ok(())))
            .expect_method(FprintdMethod::VerifyStart("any".to_owned(), Ok(())))
            .wait(Duration::from_millis(100))
            .send_status(Status::Disconnected, false)
            .expect_method(FprintdMethod::Release(Ok(())))
            .build();
        let mut pv = new_session_verifier();
        assert_eq!(
            pv.owner_present().unwrap_err(),
            presence_verification::Error::ImplementationSpecificError("fprintd: fingerprint reader disconnected".to_owned())
        );
    }

    #[test]
    #[sequential]
    fn unknown_error_makes_presence_verification_fail() {
        let _mock = FprintdMockBuilder::new()
            .expect_method(FprintdMethod::GetDefaultDevice(Ok(DEVICE_PATH.to_owned())))
            .expect_method(FprintdMethod::Claim("".to_owned(), Ok(())))
            .expect_method(FprintdMethod::VerifyStart("any".to_owned(), Ok(())))
            .wait(Duration::from_millis(100))
            .send_status(Status::UnknownError, false)
            .expect_method(FprintdMethod::VerifyStop(Ok(())))
            .expect_method(FprintdMethod::Release(Ok(())))
            .build();
        let mut pv = new_session_verifier();
        assert_eq!(
            pv.owner_present().unwrap_err(),
            presence_verification::Error::ImplementationSpecificError("fprintd: fingerprint scan failed with unknown error".to_owned())
        );
    }
}
