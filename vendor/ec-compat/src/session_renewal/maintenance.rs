use super::{IO_TIMEOUT, LegacyProbe, Observation, Reply};
use crate::modern::ModernSessionId;
use crate::{Error, Result};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Termination {
    ServerTimeout,
    SessionChanged,
    ValidityExpired,
    Unresponsive,
    ProtocolError,
}

#[derive(Default)]
struct Control {
    started: bool,
    stopped: bool,
    socket: Option<TcpStream>,
    termination: Option<Termination>,
    confirmations: u64,
}

#[derive(Default)]
struct Shared {
    control: Mutex<Control>,
    wake: Condvar,
}

/// Scoped to one authenticated session. Never reused across a fresh login.
#[derive(Clone, Default)]
pub(crate) struct MaintenanceStatus(Arc<Shared>);

impl MaintenanceStatus {
    pub(crate) fn confirmations(&self) -> u64 {
        self.0
            .control
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .confirmations
    }

    fn confirmed(&self) -> u64 {
        let mut state = self.0.control.lock().unwrap_or_else(|e| e.into_inner());
        if !state.stopped {
            state.confirmations = state.confirmations.saturating_add(1);
        }
        state.confirmations
    }
    pub(crate) fn termination(&self) -> Option<Termination> {
        self.0
            .control
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .termination
    }

    pub(crate) fn stop(&self) {
        let mut state = self.0.control.lock().unwrap_or_else(|e| e.into_inner());
        state.stopped = true;
        if let Some(socket) = state.socket.take() {
            let _ = socket.shutdown(Shutdown::Both);
        }
        self.0.wake.notify_all();
    }

    fn begin(&self) -> Result<()> {
        let mut state = self.0.control.lock().unwrap_or_else(|e| e.into_inner());
        if state.started || state.stopped {
            return Err(Error("session renewal already started or stopped".into()));
        }
        state.started = true;
        Ok(())
    }

    fn running(&self) -> bool {
        !self
            .0
            .control
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .stopped
    }

    fn register(&self, socket: &TcpStream) -> Result<()> {
        let mut state = self.0.control.lock().unwrap_or_else(|e| e.into_inner());
        if state.stopped {
            let _ = socket.shutdown(Shutdown::Both);
            return Err(Error("session renewal stopped".into()));
        }
        if let Some(previous) = state.socket.replace(socket.try_clone()?) {
            let _ = previous.shutdown(Shutdown::Both);
        }
        Ok(())
    }

    fn delay(&self, duration: Duration) -> bool {
        let state = self.0.control.lock().unwrap_or_else(|e| e.into_inner());
        let (state, _) = self
            .0
            .wake
            .wait_timeout_while(state, duration, |s| !s.stopped)
            .unwrap_or_else(|e| e.into_inner());
        !state.stopped
    }

    fn finish(&self, reason: Termination) -> bool {
        let mut state = self.0.control.lock().unwrap_or_else(|e| e.into_inner());
        // Manual disconnect wins over an in-flight reply or failed read.
        if state.stopped {
            return false;
        }
        state.termination = Some(reason);
        state.stopped = true;
        if let Some(socket) = state.socket.take() {
            let _ = socket.shutdown(Shutdown::Both);
        }
        self.0.wake.notify_all();
        true
    }
}

#[derive(Clone, Copy)]
struct Policy {
    initial_validity: Duration,
    interval: Duration,
    response_budget: Duration,
    retry_delay: Duration,
    io_timeout: Duration,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            initial_validity: Duration::from_secs(300),
            interval: Duration::from_secs(5),
            // Local liveness bound: the gateway may advertise a 30-day total
            // validity. It must not let a broken renewal channel look online.
            response_budget: Duration::from_secs(60),
            retry_delay: Duration::from_secs(3),
            io_timeout: IO_TIMEOUT,
        }
    }
}

struct Validity {
    deadline: Instant,
    last_response: Instant,
    confirmed: bool,
}

impl Validity {
    fn new(now: Instant, policy: Policy) -> Self {
        Self {
            deadline: now + policy.initial_validity,
            last_response: now,
            confirmed: false,
        }
    }

    fn limit(&self, policy: Policy) -> Instant {
        self.deadline
            .min(self.last_response + policy.response_budget)
    }

    fn expired(&self, now: Instant, policy: Policy) -> Option<Termination> {
        if now >= self.deadline {
            Some(Termination::ValidityExpired)
        } else if now >= self.last_response + policy.response_budget {
            Some(Termination::Unresponsive)
        } else {
            None
        }
    }

    fn observe(&mut self, reply: Reply, now: Instant) -> std::result::Result<(), Termination> {
        match reply {
            Reply::Renewed { seconds } => {
                self.deadline = now + Duration::from_secs(u64::from(seconds));
                self.last_response = now;
                self.confirmed = true;
            }
            Reply::Acknowledged => self.last_response = now,
            Reply::Connected | Reply::SessionUnchanged => {}
            Reply::TimedOut | Reply::InvalidValidity => return Err(Termination::ServerTimeout),
            Reply::SessionSwitch => return Err(Termination::SessionChanged),
            Reply::Unknown { .. } => return Err(Termination::ProtocolError),
        }
        Ok(())
    }
}

pub(crate) fn start(
    address: SocketAddr,
    session: &ModernSessionId,
    status: MaintenanceStatus,
    on_terminal: impl FnOnce() + Send + 'static,
) -> Result<JoinHandle<()>> {
    let session = ModernSessionId::from_bytes(session.as_bytes())?;
    status.begin()?;
    std::thread::Builder::new()
        .name("vpn-session-renewal".into())
        .spawn(move || {
            maintain(address, session, status, Policy::default(), on_terminal);
        })
        .map_err(Into::into)
}

fn maintain(
    address: SocketAddr,
    session: ModernSessionId,
    status: MaintenanceStatus,
    policy: Policy,
    on_terminal: impl FnOnce(),
) {
    let started = Instant::now();
    let mut validity = Validity::new(started, policy);
    let mut connection = None;
    let mut failures = 0_u32;
    eprintln!("VPN session renewal started (legacy TIMQ; session ID is not encrypted)");
    let reason = loop {
        if !status.running() {
            return;
        }
        if let Some(reason) = validity.expired(Instant::now(), policy) {
            break reason;
        }
        let deadline = validity
            .limit(policy)
            .min(Instant::now() + policy.io_timeout);
        let connecting = connection.is_none();
        let result = uptime_seconds().and_then(|uptime| match connection.as_mut() {
            Some(stream) => LegacyProbe::exchange_until(stream, 3, uptime, deadline),
            None => LegacyProbe::connect_observed(address, &session, uptime, deadline, |socket| {
                status.register(socket)
            })
            .map(|(stream, observation)| {
                connection = Some(stream);
                observation
            }),
        });
        if !status.running() {
            return;
        }
        // A late response cannot resurrect expired validity or a dead worker.
        if let Some(reason) = validity.expired(Instant::now(), policy) {
            break reason;
        }
        match result {
            Ok(Observation { reply, .. }) => {
                let was_confirmed = validity.confirmed;
                if let Err(reason) = validity.observe(reply, Instant::now()) {
                    eprintln!(
                        "VPN session renewal terminal reply: elapsed_ms={}, reply={reply:?}",
                        started.elapsed().as_millis()
                    );
                    break reason;
                }
                if let Reply::Renewed { seconds } = reply {
                    let count = status.confirmed();
                    if !was_confirmed || count.is_multiple_of(12) {
                        eprintln!(
                            "VPN session renewal confirmed: elapsed_ms={}, valid_seconds={seconds}, confirmations={count}",
                            started.elapsed().as_millis()
                        );
                    }
                }
                if matches!(reply, Reply::Renewed { .. } | Reply::Acknowledged) && failures > 0 {
                    eprintln!(
                        "VPN session renewal recovered: elapsed_ms={}, failed_attempts={failures}",
                        started.elapsed().as_millis()
                    );
                    failures = 0;
                }
                // After connection confirmation, send the first periodic query
                // immediately. Only completed periodic queries incur the wait.
                if connecting && reply == Reply::Connected {
                    continue;
                }
                if !status.delay(
                    policy.interval.min(
                        validity
                            .limit(policy)
                            .saturating_duration_since(Instant::now()),
                    ),
                ) {
                    return;
                }
            }
            Err(error) => {
                connection.take();
                failures = failures.saturating_add(1);
                let category = if error.0.starts_with("renewal reply")
                    || error.0.starts_with("renewal broadcast")
                    || error.0.starts_with("unexpected legacy")
                    || error.0.starts_with("modern session identifier")
                {
                    "protocol"
                } else {
                    "transport"
                };
                if failures == 1 || failures.is_multiple_of(5) {
                    eprintln!(
                        "VPN session renewal failed: elapsed_ms={}, category={category}, attempt={failures}",
                        started.elapsed().as_millis()
                    );
                }
                if category == "protocol" {
                    break Termination::ProtocolError;
                }
                if !status.delay(
                    policy.retry_delay.min(
                        validity
                            .limit(policy)
                            .saturating_duration_since(Instant::now()),
                    ),
                ) {
                    return;
                }
            }
        }
    };
    drop(connection);
    if status.finish(reason) {
        eprintln!(
            "VPN session renewal ended: elapsed_ms={}, reason={reason:?}, confirmations={}",
            started.elapsed().as_millis(),
            status.confirmations()
        );
        on_terminal();
    }
}

#[cfg(unix)]
fn uptime_seconds() -> Result<u32> {
    let mut time = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: writable timespec; read only on successful initialization.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, time.as_mut_ptr()) } != 0 {
        return Err(Error("renewal monotonic clock unavailable".into()));
    }
    // SAFETY: initialized by clock_gettime above.
    Ok(unsafe { time.assume_init() }.tv_sec as u32)
}

#[cfg(windows)]
fn uptime_seconds() -> Result<u32> {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetTickCount64() -> u64;
    }
    // SAFETY: GetTickCount64 takes no pointers and has no preconditions.
    Ok((unsafe { GetTickCount64() } / 1000) as u32)
}

#[cfg(not(any(unix, windows)))]
fn uptime_seconds() -> Result<u32> {
    Err(Error("renewal monotonic clock unsupported".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;

    fn policy() -> Policy {
        Policy {
            interval: Duration::from_millis(10),
            response_budget: Duration::from_millis(250),
            retry_delay: Duration::from_millis(10),
            io_timeout: Duration::from_millis(80),
            ..Policy::default()
        }
    }

    fn launch(
        address: SocketAddr,
        policy: Policy,
    ) -> (MaintenanceStatus, JoinHandle<()>, mpsc::Receiver<()>) {
        let status = MaintenanceStatus::default();
        status.begin().unwrap();
        let worker_state = status.clone();
        let (send, receive) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            maintain(
                address,
                ModernSessionId::from_bytes(b"0123456789abcdef").unwrap(),
                worker_state,
                policy,
                || {
                    let _ = send.send(());
                },
            );
        });
        (status, thread, receive)
    }

    fn accept(listener: &TcpListener) -> TcpStream {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match listener.accept() {
                Ok((socket, _)) => {
                    socket.set_nonblocking(false).unwrap();
                    socket
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    socket
                        .set_write_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    return socket;
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(error) => panic!("accept: {error}"),
            }
        }
    }

    fn request(socket: &mut TcpStream, kind: u32) {
        let mut bytes = [0; 28];
        socket.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes[..4], b"TIMQ");
        assert_eq!(&bytes[4..8], &kind.to_be_bytes());
        assert_eq!(&bytes[12..], b"0123456789abcdef");
    }

    fn reply(socket: &mut TcpStream, kind: u32, seconds: u32) {
        let mut bytes = [0; 60];
        bytes[..4].copy_from_slice(b"ACKQ");
        bytes[4..8].copy_from_slice(&kind.to_be_bytes());
        bytes[12..16].copy_from_slice(&seconds.to_be_bytes());
        bytes[16..32].copy_from_slice(b"fedcba9876543210");
        socket.write_all(&bytes).unwrap();
    }

    fn handshake(socket: &mut TcpStream) {
        let mut hello = [0; 82];
        socket.read_exact(&mut hello).unwrap();
        assert_eq!(&hello[44..60], b"0123456789abcdef");
        let mut flight = [0; 122];
        flight[..9].copy_from_slice(&[22, 3, 1, 0, 74, 2, 0, 0, 70]);
        flight[79..85].copy_from_slice(&[20, 3, 1, 0, 1, 1]);
        flight[85..90].copy_from_slice(&[22, 3, 1, 0, 32]);
        // Split the handshake to exercise complete reads, not a single recv.
        socket.write_all(&flight[..17]).unwrap();
        socket.write_all(&flight[17..]).unwrap();
        let mut confirm = [0; 43];
        socket.read_exact(&mut confirm).unwrap();
        assert_eq!(
            confirm.to_vec(),
            hex::decode(super::super::CONFIRM).unwrap()
        );
        request(socket, 4);
        reply(socket, 5, 0);
    }

    #[test]
    fn validity_and_network_budget_are_independent() {
        let now = Instant::now();
        let policy = Policy::default();
        let mut validity = Validity::new(now, policy);
        assert_eq!(validity.deadline, now + Duration::from_secs(300));
        validity
            .observe(Reply::Renewed { seconds: 2_592_000 }, now)
            .unwrap();
        let deadline = validity.deadline;
        validity
            .observe(Reply::Connected, now + Duration::from_secs(59))
            .unwrap();
        assert_eq!(
            validity.expired(now + Duration::from_secs(60), policy),
            Some(Termination::Unresponsive)
        );
        validity
            .observe(Reply::Acknowledged, now + Duration::from_secs(59))
            .unwrap();
        assert_eq!(validity.deadline, deadline);
        assert_eq!(
            validity.expired(now + Duration::from_secs(60), policy),
            None
        );
        validity
            .observe(Reply::Renewed { seconds: 1 }, now)
            .unwrap();
        assert_eq!(
            validity.expired(now + Duration::from_secs(1), policy),
            Some(Termination::ValidityExpired)
        );
    }

    #[test]
    fn recovery_uses_same_session_and_shutdown_closes_replacement_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (status, worker, terminal) = launch(listener.local_addr().unwrap(), policy());
        let mut first = accept(&listener);
        handshake(&mut first);
        request(&mut first, 3);
        reply(&mut first, 1, 2_592_000);
        // Consuming the next request proves the positive reply was processed.
        request(&mut first, 3);
        assert_eq!(status.confirmations(), 1);
        first.shutdown(Shutdown::Both).unwrap();
        let mut replacement = accept(&listener);
        handshake(&mut replacement);
        request(&mut replacement, 3);
        reply(&mut replacement, 1, 2_591_995);
        request(&mut replacement, 3);
        assert_eq!(status.confirmations(), 2);
        status.stop();
        let mut byte = [0];
        assert_eq!(replacement.read(&mut byte).unwrap(), 0);
        worker.join().unwrap();
        assert_eq!(status.termination(), None);
        assert!(terminal.try_recv().is_err());
    }

    #[test]
    fn server_timeout_switch_invalid_validity_and_unknown_stop_without_relogin() {
        for (kind, seconds, expected) in [
            (3, 0, Termination::ServerTimeout),
            (4, 0, Termination::SessionChanged),
            (1, 0, Termination::ServerTimeout),
            (1, 0xffff_ffff, Termination::ServerTimeout),
            (99, 0, Termination::ProtocolError),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let (status, worker, terminal) = launch(listener.local_addr().unwrap(), policy());
            let mut socket = accept(&listener);
            handshake(&mut socket);
            request(&mut socket, 3);
            reply(&mut socket, kind, seconds);
            terminal.recv_timeout(Duration::from_secs(2)).unwrap();
            worker.join().unwrap();
            assert_eq!(status.termination(), Some(expected));
            assert!(
                listener.accept().is_err(),
                "terminal session must not reconnect"
            );
        }
    }

    #[test]
    fn partial_handshake_cancellation_is_prompt_and_has_no_terminal_reason() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (status, worker, terminal) = launch(listener.local_addr().unwrap(), Policy::default());
        let mut socket = accept(&listener);
        let mut hello = [0; 82];
        socket.read_exact(&mut hello).unwrap();
        socket.write_all(&[22, 3]).unwrap();
        let start = Instant::now();
        status.stop();
        worker.join().unwrap();
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(status.termination(), None);
        assert!(terminal.try_recv().is_err());
    }

    #[test]
    fn dead_renewal_does_not_inherit_thirty_day_recovery_budget() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (status, worker, terminal) = launch(address, policy());
        let mut socket = accept(&listener);
        handshake(&mut socket);
        request(&mut socket, 3);
        reply(&mut socket, 1, 2_592_000);
        request(&mut socket, 3);
        socket.shutdown(Shutdown::Both).unwrap();
        drop(listener); // Recovery connections are refused.
        terminal.recv_timeout(Duration::from_secs(2)).unwrap();
        worker.join().unwrap();
        assert_eq!(status.termination(), Some(Termination::Unresponsive));
        assert_eq!(status.confirmations(), 1);
    }

    #[test]
    fn cancelled_generation_cannot_publish_a_late_terminal_state() {
        let old = MaintenanceStatus::default();
        let new = MaintenanceStatus::default();
        old.begin().unwrap();
        old.stop();
        new.begin().unwrap();
        assert!(!old.finish(Termination::SessionChanged));
        assert_eq!(new.termination(), None);
        assert!(new.running());
        assert!(old.begin().is_err());
        assert!(new.begin().is_err());
        new.stop();
    }

    #[test]
    fn stop_wakes_backoff_and_rejects_a_late_socket_registration() {
        let status = MaintenanceStatus::default();
        let waiting = status.clone();
        let thread = std::thread::spawn(move || waiting.delay(Duration::from_secs(30)));
        status.stop();
        assert!(!thread.join().unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let mut peer = accept(&listener);
        assert!(status.register(&socket).is_err());
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }
}
