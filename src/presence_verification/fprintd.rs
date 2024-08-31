use std::{str::FromStr, sync::{Arc, Mutex}, time::Duration};

use dbus::{arg::ReadAll, blocking::{Connection, Proxy}, message::SignalArgs, Message, Path};

use crate::privileges::with_uid_as_euid;

use super::PresenceVerifier;

pub struct FprintdPresenceVerifier;

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
#[derive(Clone, Copy)]
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
        let _: () = self.proxy.method_call(FPRINTD_DEVICE_IFACE, "Release", ()).unwrap();
    }
}

fn fail<T>(reason: &str) -> super::Result<T> {
    Err(super::Error::ImplementationSpecificError(reason.to_owned()))
}

impl <'a> FprintDevice<'a> {
    fn verify(&self) -> super::Result<bool> {
        let scan_status = Arc::new(Mutex::new(None));
        let scan_status_clone = scan_status.clone();
        self.proxy.match_signal(move |status: VerifyStatus, _: &Connection, _: &Message| {
            *scan_status.lock().unwrap() = Some(status.status);
            true
        }).or(fail("fprintd: unable to listen for signal"))?;

        self.proxy.method_call(FPRINTD_DEVICE_IFACE, "VerifyStart", ("any",))
            .or(fail("fprintd: unable to start fingerprint verification"))?;

        eprintln!("place your finger on the fingerprint reader");
        for _ in 1 .. 5 {
            self.connection.process(Duration::from_secs(10))
                .or(fail("fprintd: unable to process incoming signals"))?;

            match *scan_status_clone.lock().unwrap() {
                Some(status) => {
                    match status {
                        Status::Match => return Ok(true),
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
            let conn = Connection::new_system()
                .or(Err(super::Error::ImplementationSpecificError("fprintd: couldn't connect to system bus".to_owned())))?;
            let dev = FprintDevice::claim_default_device(&conn)?;
            dev.verify()
        })
    }
}

impl FprintdPresenceVerifier {
    pub fn new() -> Self {
        FprintdPresenceVerifier
    }
}
