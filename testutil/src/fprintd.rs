use std::{collections::VecDeque, sync::{Arc, Mutex}, thread::{self, JoinHandle}, time::Duration};

use dbus::{channel::{MatchingReceiver, Sender}, Message, MethodErr};

const FPRINTD_BUS_NAME: &str = "net.reactivated.Fprint";
const FPRINTD_MANAGER_PATH: &str = "/net/reactivated/Fprint/Manager";
const FPRINTD_MANAGER_IFACE: &str = "net.reactivated.Fprint.Manager";
const FPRINTD_DEVICE_IFACE: &str = "net.reactivated.Fprint.Device";

#[derive(Debug)]
pub enum FprintdMethod {
    GetDefaultDevice(Result<String, MethodErr>),
    Claim(String, Result<(), MethodErr>),
    Release(Result<(), MethodErr>),
    VerifyStart(String, Result<(), MethodErr>),
    VerifyStop(Result<(), MethodErr>),
}

#[derive(Debug)]
pub enum FprintdEvent<Status> {
    MethodCall(FprintdMethod),
    VerifyStatusSignal(Status, bool),
    Wait(Duration),
}

pub struct FprintdMockBuilder<Status> {
    event_sequence: VecDeque<FprintdEvent<Status>>
}

impl <Status: ToString + Send + std::fmt::Debug + 'static> FprintdMockBuilder<Status> {
    pub fn new() -> Self {
        FprintdMockBuilder { event_sequence: VecDeque::new() }
    }

    pub fn expect_method(mut self, method: FprintdMethod) -> Self {
        self.event_sequence.push_back(FprintdEvent::MethodCall(method));
        self
    }

    pub fn wait(mut self, duration: Duration) -> Self {
        self.event_sequence.push_back(FprintdEvent::Wait(duration));
        self
    }

    pub fn send_status(mut self, status: Status, done: bool) -> Self {
        self.event_sequence.push_back(FprintdEvent::VerifyStatusSignal(status, done));
        self
    }

    pub fn build(self) -> FprintdMock {
        FprintdMock::new(self.event_sequence)
    }
}

pub struct FprintdMock {
    join_handle: Option<JoinHandle<()>>,
    die_signal: Arc<Mutex<bool>>,
}

impl Drop for FprintdMock {
    fn drop(&mut self) {
        *self.die_signal.lock().unwrap() = true;
        if let Some(h) = self.join_handle.take() {
            h.join().unwrap_or(());
        }
    }
}

pub const DEVICE_PATH: &str = "/net/reactivated/Fprint/Device/0";

impl FprintdMock {
    fn new<Status: ToString + Send + std::fmt::Debug + 'static>(expected_sequence: VecDeque<FprintdEvent<Status>>) -> Self {
        let expected_sequence = Arc::new(Mutex::new(expected_sequence));
        let expected_sequence_getdefaultdevice = expected_sequence.clone();
        let expected_sequence_claim = expected_sequence.clone();
        let expected_sequence_release = expected_sequence.clone();
        let expected_sequence_verifystart = expected_sequence.clone();
        let expected_sequence_verifystop = expected_sequence.clone();

        let c = dbus::blocking::Connection::new_session().unwrap();
        c.request_name(FPRINTD_BUS_NAME, false, false, true).unwrap();
        let mut cr = dbus_crossroads::Crossroads::new();
        let mgr_iface = cr.register(FPRINTD_MANAGER_IFACE, |b| {
            b.method("GetDefaultDevice", (), ("device",), move |_, _, _: ()| {
                let evt = expected_sequence_getdefaultdevice.lock().unwrap().pop_front();
                if let Some(FprintdEvent::MethodCall(FprintdMethod::GetDefaultDevice(response))) = evt {
                    response.map(|p| (dbus::Path::new(p).unwrap(),))
                } else {
                    panic!("expected GetDefaultDevice but got {:#?}", evt);
                }
            });
        });
        let device_iface = cr.register(FPRINTD_DEVICE_IFACE, |b| {
            b.signal::<(String, bool), _>("VerifyStatus", ("status", "done"));
            b.method("Claim", ("username",), (), move |_, _, (username,): (String,)| {
                let evt = expected_sequence_claim.lock().unwrap().pop_front();
                if let Some(FprintdEvent::MethodCall(FprintdMethod::Claim(expected_username, response))) = evt {
                    assert_eq!(username, expected_username);
                    response
                } else {
                    panic!("expected Claim but got {:#?}", evt);
                }
            });
            b.method("Release", (), (), move |_, _, _: ()| {
                let evt: Option<FprintdEvent<Status>> = expected_sequence_release.lock().unwrap().pop_front();
                if let Some(FprintdEvent::MethodCall(FprintdMethod::Release(response))) = evt {
                    response
                } else {
                    panic!("expected Release but got {:#?}", evt);
                }
            });
            b.method("VerifyStart", ("finger",), (), move |_, _, (finger,): (String,)| {
                let evt = expected_sequence_verifystart.lock().unwrap().pop_front();
                if let Some(FprintdEvent::MethodCall(FprintdMethod::VerifyStart(expected_finger, response))) = evt {
                    assert_eq!(finger, expected_finger);
                    response
                } else {
                    panic!("expected VerifyStart but got {:#?}", evt);
                }
            });
            b.method("VerifyStop", (), (), move |_, _, _: ()| {
                let evt = expected_sequence_verifystop.lock().unwrap().pop_front();
                if let Some(FprintdEvent::MethodCall(FprintdMethod::VerifyStop(response))) = evt {
                    response
                } else {
                    panic!("expected VerifyStop but got {:#?}", evt);
                }
            });
        });

        cr.insert(FPRINTD_MANAGER_PATH, [&mgr_iface], ());
        cr.insert(DEVICE_PATH, [&device_iface], ());

        let die = Arc::new(Mutex::new(false));
        let die_signal = die.clone();
        let join_handle = std::thread::spawn(move || {
            c.start_receive(dbus::message::MatchRule::new_method_call(), Box::new(move |msg, conn| {
                cr.handle_message(msg, conn).unwrap();
                true
            }));
    
            while !*die.lock().unwrap() {
                c.process(std::time::Duration::from_millis(100)).unwrap();
                let mut seq = expected_sequence.lock().unwrap();
                let evt = seq.pop_front();
                match evt {
                    Some(FprintdEvent::Wait(duration)) => {
                        thread::sleep(duration);
                    },
                    Some(FprintdEvent::VerifyStatusSignal(status, done)) => {
                        let path = dbus::Path::new(DEVICE_PATH).unwrap();
                        let msg = Message::signal(
                            &path,
                            &FPRINTD_DEVICE_IFACE.into(),
                            &"VerifyStatus".to_string().into()
                        ).append2(status.to_string(), done);
                        c.send(msg).unwrap();
                    },
                    Some(e@FprintdEvent::MethodCall(_)) => {
                        seq.push_front(e);
                    },
                    None => {
                        // we still need to keep running or dbus shenanigans will happen
                    },
                }
            }
        });

        FprintdMock { join_handle: Some(join_handle), die_signal: die_signal }
    }
}