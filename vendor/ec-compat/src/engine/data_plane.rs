use crate::engine::ip_packet::{push_and_extract_ipv4, validate_ipv4_packet};
use crate::modern::{
    ModernCommand, ModernControlRequest, ModernToken, ModernTokenAcquisition, parse_address_reply,
    validate_channel_reply,
};
use crate::special_tls11::SpecialTls11Stream;
use crate::{Error, Result};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

// svpnservice 7.6.7: command idle >30 seconds then every 5 seconds;
// data ICMP heartbeat after >30 seconds without a send. See docs/connection-maintenance.md.
const COMMAND_IDLE: Duration = Duration::from_secs(35);
const SEND_IDLE: Duration = Duration::from_secs(31);
// These are local recovery budgets, not claimed official constants.
const ACK_TIMEOUT: Duration = Duration::from_secs(10);
const DATA_ACK_TIMEOUT: Duration = Duration::from_secs(95);
const RETRY_DELAYS: [Duration; 3] = [
    Duration::from_secs(3),
    Duration::from_secs(5),
    Duration::from_secs(10),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Control = 0,
    Send = 1,
    Receive = 2,
}

/// Transport abstraction also allows scripted fault/recovery tests without a VPN login.
trait Records: Send {
    fn write(&mut self, bytes: &[u8]) -> Result<()>;
    fn read(&mut self, maximum: usize) -> Result<Zeroizing<Vec<u8>>>;
    fn wait(&self, timeout: Duration) -> Result<bool>;
}
impl Records for SpecialTls11Stream {
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.write_application_data(bytes)
    }
    fn read(&mut self, maximum: usize) -> Result<Zeroizing<Vec<u8>>> {
        self.read_application_data(maximum)
    }
    fn wait(&self, timeout: Duration) -> Result<bool> {
        self.wait_readable(timeout)
    }
}

type Dial = dyn Fn(Kind, &Shared) -> Result<Box<dyn Records>> + Send + Sync;

#[derive(Default)]
struct ReceiveLiveness {
    heartbeat_supported: bool,
    pending: Option<Instant>,
}
impl ReceiveLiveness {
    fn heartbeat_sent(&mut self, now: Instant) {
        // Learn support from a valid reply before using it as a timeout signal.
        // Some gateways do not echo these probes; silence alone cannot prove
        // that a receive channel which never acknowledged them has failed.
        if self.heartbeat_supported && self.pending.is_none() {
            self.pending = Some(now + DATA_ACK_TIMEOUT);
        }
    }
    fn observe(&mut self, heartbeat_reply: bool) {
        self.heartbeat_supported |= heartbeat_reply;
        // Any authenticated IPv4 traffic proves the receive path is alive.
        self.pending = None;
    }
    fn expired(&mut self, now: Instant) -> bool {
        if self.pending.is_some_and(|deadline| now >= deadline) {
            self.pending = None;
            true
        } else {
            false
        }
    }
}

struct Shared {
    stopped: AtomicBool,
    sockets: Mutex<[Option<TcpStream>; 3]>,
    wake: Condvar,
    activity: Mutex<Instant>,
    receive_liveness: Mutex<ReceiveLiveness>,
    events: tokio::sync::mpsc::Sender<()>,
    token: ModernToken,
    address: Ipv4Addr,
    peer: SocketAddr,
    dial: Arc<Dial>,
    retry_delays: Vec<Duration>,
}
impl Shared {
    fn running(&self) -> bool {
        !self.stopped.load(Ordering::Acquire)
    }
    fn register(&self, kind: Kind, socket: &TcpStream) -> Result<()> {
        let mut sockets = self
            .sockets
            .lock()
            .map_err(|_| Error("VPN socket lock poisoned".into()))?;
        if !self.running() {
            let _ = socket.shutdown(Shutdown::Both);
            return Err(Error("VPN transport stopped".into()));
        }
        if let Some(old) = sockets[kind as usize].replace(socket.try_clone()?) {
            let _ = old.shutdown(Shutdown::Both);
        }
        if kind == Kind::Receive {
            self.receive_liveness
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .pending = None;
        }
        Ok(())
    }
    fn shutdown(&self) {
        // Serialize the flag with the condition variable predicate to prevent a
        // lost wake while a retry/idle worker is entering wait_timeout.
        let _activity = self.activity.lock().unwrap_or_else(|e| e.into_inner());
        self.stopped.store(true, Ordering::Release);
        self.wake.notify_all();
        let sockets = self.sockets.lock().unwrap_or_else(|e| e.into_inner());
        for socket in sockets.iter().flatten() {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }
    fn fault(&self, kind: Kind) {
        if self.running() {
            let _ = self.events.try_send(()); // Coalesce simultaneous channel faults.
            eprintln!("VPN {kind:?} channel interrupted; recovering existing session");
        }
    }
    fn delay(&self, duration: Duration) -> bool {
        let lock = self.activity.lock().unwrap_or_else(|e| e.into_inner());
        let _ = self
            .wake
            .wait_timeout_while(lock, duration, |_| self.running());
        self.running()
    }
    fn invalidate_data(&self) {
        let sockets = self.sockets.lock().unwrap_or_else(|e| e.into_inner());
        for socket in sockets[1..].iter().flatten() {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }
}

struct Channel {
    stream: Box<dyn Records>,
    kind: Kind,
    shared: Arc<Shared>,
}
impl Channel {
    fn recover(&mut self) -> Result<()> {
        self.shared.fault(self.kind);
        for (attempt, delay) in self.shared.retry_delays.iter().enumerate() {
            if !self.shared.delay(*delay) {
                return Err(Error("VPN transport stopped".into()));
            }
            match (self.shared.dial)(self.kind, &self.shared) {
                Ok(stream) if self.shared.running() => {
                    self.stream = stream;
                    if self.kind == Kind::Control {
                        self.shared.invalidate_data();
                    }
                    eprintln!("VPN {:?} channel recovered", self.kind);
                    return Ok(());
                }
                Err(error) if self.shared.running() => {
                    eprintln!(
                        "VPN {:?} channel recovery attempt {} failed: {error}",
                        self.kind,
                        attempt + 1
                    );
                }
                _ => {}
            }
        }
        self.shared.shutdown();
        Err(Error(format!(
            "VPN {:?} channel recovery exhausted",
            self.kind
        )))
    }
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        if !self.shared.running() {
            return Err(Error("VPN transport stopped".into()));
        }
        if let Err(error) = self.stream.write(bytes) {
            if self.shared.running() {
                eprintln!("VPN {:?} channel write failed: {error}", self.kind);
            }
            self.recover()?;
            // Packet retransmission is bounded. TCP/UDP payload may have been
            // partially delivered before failure; higher protocols handle it.
            if let Err(error) = self.stream.write(bytes) {
                self.shared.fault(self.kind);
                self.shared.shutdown();
                return Err(error);
            }
        }
        Ok(())
    }
}

pub struct EasyConnectDataPlane {
    lease: AddressLease,
    sender: PacketSender,
    receiver: PacketReceiver,
    health_events: Option<tokio::sync::mpsc::Receiver<()>>,
}

impl EasyConnectDataPlane {
    pub fn connect(
        host: &str,
        acquisition: &ModernTokenAcquisition,
        timeout: Duration,
        pin: Option<&[u8; 32]>,
    ) -> Result<Self> {
        let peer = acquisition.peer_address();
        let leaf = *acquisition.verified_leaf_sha256();
        let token = acquisition.token().clone();
        let mut control = SpecialTls11Stream::connect(peer, host, timeout, &leaf, pin)?;
        control.write_application_data(
            ModernControlRequest::new(ModernCommand::RequestAddress, &token, None)?.as_bytes(),
        )?;
        let address = parse_address_reply(&control.read_application_data(128)?)?;
        if address.is_unspecified() {
            return Err(Error(
                "gateway returned an unspecified virtual address".into(),
            ));
        }
        control.set_read_timeout(Some(timeout.min(Duration::from_secs(5))))?;
        let host = host.to_owned();
        let pin = pin.copied();
        let setup_timeout = timeout.min(Duration::from_secs(5));
        let dial: Arc<Dial> = Arc::new(move |kind, shared| {
            let mut stream = SpecialTls11Stream::connect_observed(
                peer,
                &host,
                setup_timeout,
                &leaf,
                pin.as_ref(),
                |socket| shared.register(kind, socket),
            )?;
            let command = match kind {
                Kind::Control => ModernCommand::Reconnect,
                Kind::Send => ModernCommand::Send,
                Kind::Receive => ModernCommand::Receive,
            };
            if !negotiate(&mut stream, kind, command, &shared.token, shared.address)? {
                // Official MakeCmdTunnel falls back to NEWCONNECT after reset.
                // Keep the same authenticated token; never submit credentials.
                stream = SpecialTls11Stream::connect_observed(
                    peer,
                    &host,
                    setup_timeout,
                    &leaf,
                    pin.as_ref(),
                    |socket| shared.register(kind, socket),
                )?;
                if !negotiate(
                    &mut stream,
                    kind,
                    ModernCommand::RequestAddress,
                    &shared.token,
                    shared.address,
                )? {
                    return Err(Error("gateway rejected command recovery".into()));
                }
            }
            if kind == Kind::Receive {
                stream.set_read_timeout(None)?;
            }
            Ok(Box::new(stream))
        });
        let (events, health_events) = tokio::sync::mpsc::channel(1);
        let shared = Arc::new(Shared {
            stopped: AtomicBool::new(false),
            sockets: Mutex::new([None, None, None]),
            wake: Condvar::new(),
            activity: Mutex::new(Instant::now()),
            receive_liveness: Mutex::new(ReceiveLiveness::default()),
            events,
            token,
            address,
            peer,
            dial,
            retry_delays: RETRY_DELAYS.to_vec(),
        });
        shared.register(Kind::Control, &control.shutdown_handle()?)?;
        // The lease guard cancels all sockets on partial setup failures, too.
        let mut lease = AddressLease {
            shared: shared.clone(),
            control: Some(Channel {
                stream: Box::new(control),
                kind: Kind::Control,
                shared: shared.clone(),
            }),
            workers: Vec::new(),
        };
        let send = (shared.dial)(Kind::Send, &shared)?;
        let receive = (shared.dial)(Kind::Receive, &shared)?;
        let sender = PacketSender {
            channel: Arc::new(Mutex::new(Channel {
                stream: send,
                kind: Kind::Send,
                shared: shared.clone(),
            })),
            shared: shared.clone(),
        };
        let receiver = PacketReceiver {
            channel: Channel {
                stream: receive,
                kind: Kind::Receive,
                shared: shared.clone(),
            },
            buffered: Zeroizing::new(Vec::new()),
        };
        // Start only after every transport is ready. Both workers are joined by
        // the lease guard; shutdown interrupts timer waits, reads and handshakes.
        let control = lease.control.take().expect("control channel exists");
        lease
            .workers
            .push(std::thread::spawn(move || maintain_control(control)));
        let send = sender.channel.clone();
        let heartbeat_state = shared.clone();
        lease.workers.push(std::thread::spawn(move || {
            maintain_sender(send, heartbeat_state)
        }));
        Ok(Self {
            lease,
            sender,
            receiver,
            health_events: Some(health_events),
        })
    }
    pub fn assigned_address(&self) -> Ipv4Addr {
        self.lease.shared.address
    }
    pub fn peer_address(&self) -> std::io::Result<SocketAddr> {
        Ok(self.lease.shared.peer)
    }
    /// Includes sockets created by recovery, not just the original three fds.
    pub fn shutdown_handle(&self) -> PlaneShutdown {
        PlaneShutdown(self.lease.shared.clone())
    }
    pub fn take_health_events(&mut self) -> tokio::sync::mpsc::Receiver<()> {
        self.health_events
            .take()
            .expect("health events already taken")
    }
    pub fn split(self) -> (AddressLease, PacketSender, PacketReceiver) {
        (self.lease, self.sender, self.receiver)
    }
}

pub struct PlaneShutdown(Arc<Shared>);
impl PlaneShutdown {
    pub fn shutdown(&self) {
        self.0.shutdown();
    }
}
impl Drop for PlaneShutdown {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub struct AddressLease {
    shared: Arc<Shared>,
    control: Option<Channel>,
    workers: Vec<JoinHandle<()>>,
}
impl AddressLease {
    pub fn assigned_address(&self) -> Ipv4Addr {
        self.shared.address
    }
    pub fn transport_is_open(&self) -> bool {
        self.shared.running()
    }
}
impl Drop for AddressLease {
    fn drop(&mut self) {
        self.shared.shutdown();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

pub struct PacketSender {
    channel: Arc<Mutex<Channel>>,
    shared: Arc<Shared>,
}
impl PacketSender {
    pub fn send_ipv4(&mut self, packet: &[u8]) -> Result<()> {
        validate_ipv4_packet(packet, Some(self.shared.address))?;
        let mut channel = self
            .channel
            .lock()
            .map_err(|_| Error("VPN send lock poisoned".into()))?;
        channel.write(packet)?;
        *self
            .shared
            .activity
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Instant::now();
        self.shared.wake.notify_all();
        Ok(())
    }
}

pub struct PacketReceiver {
    channel: Channel,
    buffered: Zeroizing<Vec<u8>>,
}
impl PacketReceiver {
    pub fn receive_ipv4(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        loop {
            if let Some(packet) = push_and_extract_ipv4(&mut self.buffered, &[])? {
                self.observe_receive(&packet);
                return Ok(packet);
            }
            // A new transport must never inherit an incomplete IPv4 frame from
            // its predecessor. Read here rather than across Channel::read retries.
            let chunk = match self.channel.stream.read(16 * 1024) {
                Ok(chunk) => chunk,
                Err(error) => {
                    if self.channel.shared.running() {
                        eprintln!("VPN Receive channel read failed: {error}");
                    }
                    self.buffered.clear();
                    self.channel.recover()?;
                    continue;
                }
            };
            if let Some(packet) = push_and_extract_ipv4(&mut self.buffered, &chunk)? {
                self.observe_receive(&packet);
                return Ok(packet);
            }
        }
    }
    fn observe_receive(&self, packet: &[u8]) {
        let state = &self.channel.shared;
        let reply = is_data_heartbeat_reply(packet, state.address, &state.token);
        let mut live = state
            .receive_liveness
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if reply && !live.heartbeat_supported {
            eprintln!("VPN data heartbeat confirmed");
        }
        live.observe(reply);
        state.wake.notify_all();
    }
}

/// False is the observed SERVER_RESET response to a command reconnect.
fn negotiate(
    stream: &mut dyn Records,
    kind: Kind,
    command: ModernCommand,
    token: &ModernToken,
    address: Ipv4Addr,
) -> Result<bool> {
    stream.write(
        ModernControlRequest::new(command, token, (kind != Kind::Control).then_some(address))?
            .as_bytes(),
    )?;
    let reply = stream.read(1500)?;
    if kind == Kind::Control {
        if reply.len() >= 4 && reply[..4] == 3_u32.to_le_bytes() {
            return Ok(false);
        }
        if parse_address_reply(&reply)? != address {
            return Err(Error(
                "gateway changed the VPN address during recovery".into(),
            ));
        }
    } else {
        validate_channel_reply(&reply, command)?;
    }
    Ok(true)
}

fn maintain_control(channel: Channel) {
    maintain_control_with_timing(channel, COMMAND_IDLE, ACK_TIMEOUT);
}

fn maintain_control_with_timing(mut channel: Channel, idle: Duration, ack_timeout: Duration) {
    let mut idle_deadline = Instant::now() + idle;
    let mut pending_ack = None;
    let mut confirmed = false;
    let mut buffered = Zeroizing::new(Vec::new());
    while channel.shared.running() {
        let deadline = pending_ack.unwrap_or(idle_deadline);
        let result = (|| -> Result<()> {
            if channel
                .stream
                .wait(deadline.saturating_duration_since(Instant::now()))?
            {
                buffered.extend_from_slice(&channel.stream.read(4096)?);
                // Official server command structure is 40 bytes including its
                // 4-byte marker. Our TLS payload contains the 36-byte body.
                while buffered.len() >= 36 {
                    let command = u32::from_le_bytes(buffered[..4].try_into().unwrap());
                    if command != 15 {
                        return Err(Error(
                            "VPN control event requires session confirmation".into(),
                        ));
                    }
                    buffered.drain(..36);
                    if !confirmed {
                        eprintln!("VPN command heartbeat confirmed");
                        confirmed = true;
                    }
                    pending_ack = None;
                    idle_deadline = Instant::now() + idle;
                }
                if buffered.len() > 4096 {
                    return Err(Error("VPN control reply exceeds limit".into()));
                }
                if pending_ack.is_some_and(|ack| Instant::now() >= ack) {
                    return Err(Error(
                        "VPN command heartbeat acknowledgement timed out".into(),
                    ));
                }
            } else if pending_ack.is_some() {
                return Err(Error(
                    "VPN command heartbeat acknowledgement timed out".into(),
                ));
            } else {
                channel.stream.write(
                    ModernControlRequest::new(
                        ModernCommand::Heartbeat,
                        &channel.shared.token,
                        None,
                    )?
                    .as_bytes(),
                )?;
                pending_ack = Some(Instant::now() + ack_timeout);
            }
            Ok(())
        })();
        if let Err(error) = result {
            if channel.shared.running() {
                eprintln!("VPN Control channel failed: {error}");
            }
            buffered.clear();
            if channel.recover().is_err() {
                break;
            }
            pending_ack = None;
            idle_deadline = Instant::now() + idle;
        }
    }
}

fn maintain_sender(channel: Arc<Mutex<Channel>>, shared: Arc<Shared>) {
    while shared.running() {
        let mut live = shared
            .receive_liveness
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let expired = live.expired(now);
        let probe_due = live
            .pending
            .map(|deadline| deadline.saturating_duration_since(now));
        drop(live);
        if expired {
            shared.fault(Kind::Receive);
            eprintln!("VPN data heartbeat acknowledgement timed out; reopening receive channel");
            let sockets = shared.sockets.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(socket) = &sockets[Kind::Receive as usize] {
                let _ = socket.shutdown(Shutdown::Both);
            }
        }
        let activity = shared.activity.lock().unwrap_or_else(|e| e.into_inner());
        let send_due = SEND_IDLE.saturating_sub(activity.elapsed());
        let due = probe_due.map_or(send_due, |probe| probe.min(send_due));
        if !due.is_zero() {
            let _ = shared.wake.wait_timeout(activity, due);
            continue;
        }
        drop(activity);
        let mut channel = match channel.lock() {
            Ok(channel) => channel,
            Err(_) => {
                shared.shutdown();
                break;
            }
        };
        // A real send could have won the lock while we were waiting for it.
        if shared
            .activity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .elapsed()
            < SEND_IDLE
        {
            continue;
        }
        let peer = match shared.peer.ip() {
            std::net::IpAddr::V4(ip) => ip,
            _ => {
                shared.shutdown();
                break;
            }
        };
        let packet = data_heartbeat(shared.address, peer, &shared.token);
        if channel.write(&packet).is_err() {
            break;
        }
        let now = Instant::now();
        *shared.activity.lock().unwrap_or_else(|e| e.into_inner()) = now;
        shared
            .receive_liveness
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .heartbeat_sent(now);
    }
}

fn is_data_heartbeat_reply(packet: &[u8], address: Ipv4Addr, token: &ModernToken) -> bool {
    packet.len() == 76
        && packet[0] == 0x45
        && packet[9] == 1
        && packet[20] == 0
        && packet[21] == 0
        && packet[16..20] == address.octets()
        && packet[24..28] == [0x55, 0x55, 0x44, 0x33]
        && packet[28..46] == *b"SANGFORSCSIPCLIENT"
        && packet[46..62] == token.as_bytes()[32..48]
        && checksum(&packet[..20]) == 0
        && checksum(&packet[20..]) == 0
}

/// Reconstruct the official 76-byte ICMP echo body (without IPCP/local wrapper).
/// svpnservice MakeHeartBeat at 0x100111f10; session identifier stays zeroizing.
fn data_heartbeat(source: Ipv4Addr, gateway: Ipv4Addr, token: &ModernToken) -> Zeroizing<Vec<u8>> {
    let mut packet = Zeroizing::new(vec![0_u8; 76]);
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&76_u16.to_be_bytes());
    packet[4..6].copy_from_slice(&[0xbb, 0xaa]);
    packet[8] = 64;
    packet[9] = 1;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&gateway.octets());
    packet[20] = 8;
    packet[24..26].copy_from_slice(&[0x55, 0x55]);
    packet[26..28].copy_from_slice(&[0x44, 0x33]);
    packet[28..46].copy_from_slice(b"SANGFORSCSIPCLIENT");
    packet[46..62].copy_from_slice(&token.as_bytes()[32..48]);
    packet[62..75].copy_from_slice(b"L3VPNABCDEFGH");
    let icmp = checksum(&packet[20..]);
    packet[22..24].copy_from_slice(&icmp.to_be_bytes());
    let ip = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip.to_be_bytes());
    packet
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|p| u32::from(p[0]) * 256 + u32::from(*p.get(1).unwrap_or(&0)))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modern::ModernSessionId;
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicUsize;

    fn token() -> ModernToken {
        ModernToken::derive(
            &[7; 16],
            &ModernSessionId::from_bytes(b"0123456789ABCDEF").unwrap(),
        )
        .unwrap()
    }
    fn shared(
        dial: Arc<Dial>,
        delays: Vec<Duration>,
    ) -> (Arc<Shared>, tokio::sync::mpsc::Receiver<()>) {
        let (events, receiver) = tokio::sync::mpsc::channel(1);
        (
            Arc::new(Shared {
                stopped: AtomicBool::new(false),
                sockets: Mutex::new([None, None, None]),
                wake: Condvar::new(),
                activity: Mutex::new(Instant::now()),
                receive_liveness: Mutex::new(ReceiveLiveness::default()),
                events,
                token: token(),
                address: "192.0.2.8".parse().unwrap(),
                peer: "198.51.100.9:4430".parse().unwrap(),
                dial,
                retry_delays: delays,
            }),
            receiver,
        )
    }
    struct Script {
        writes: Arc<Mutex<Vec<Vec<u8>>>>,
        fail_write: bool,
        reads: VecDeque<Result<Zeroizing<Vec<u8>>>>,
    }
    impl Records for Script {
        fn write(&mut self, bytes: &[u8]) -> Result<()> {
            if self.fail_write {
                return Err(Error("synthetic broken pipe".into()));
            }
            self.writes.lock().unwrap().push(bytes.to_vec());
            Ok(())
        }
        fn read(&mut self, _: usize) -> Result<Zeroizing<Vec<u8>>> {
            self.reads
                .pop_front()
                .unwrap_or_else(|| Err(Error("synthetic EOF".into())))
        }
        fn wait(&self, _: Duration) -> Result<bool> {
            Ok(true)
        }
    }
    fn script(writes: Arc<Mutex<Vec<Vec<u8>>>>) -> Script {
        Script {
            writes,
            fail_write: false,
            reads: VecDeque::new(),
        }
    }

    #[test]
    fn heartbeat_matches_official_icmp_fields_and_checksums() {
        let source = "192.0.2.8".parse().unwrap();
        let gateway = "198.51.100.9".parse().unwrap();
        let packet = data_heartbeat(source, gateway, &token());
        validate_ipv4_packet(&packet, Some(source)).unwrap();
        assert_eq!(&packet[16..20], &gateway.octets());
        assert_eq!(&packet[24..28], &[0x55, 0x55, 0x44, 0x33]);
        assert_eq!(
            &packet[28..],
            b"SANGFORSCSIPCLIENT0123456789ABCDEFL3VPNABCDEFGH\0"
        );
        assert_eq!(checksum(&packet[..20]), 0);
        assert_eq!(checksum(&packet[20..]), 0);
    }

    #[test]
    fn send_failure_recovers_same_channel_without_reauthenticating() {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let recovered = writes.clone();
        let attempts = Arc::new(AtomicUsize::new(0));
        let count = attempts.clone();
        let (state, mut events) = shared(
            Arc::new(move |kind, state| {
                assert_eq!(kind, Kind::Send);
                assert_eq!(state.address, "192.0.2.8".parse::<Ipv4Addr>().unwrap());
                assert_eq!(&state.token.as_bytes()[32..], b"0123456789ABCDEF");
                if count.fetch_add(1, Ordering::SeqCst) == 0 {
                    return Err(Error("synthetic setup failure".into()));
                }
                Ok(Box::new(script(recovered.clone())))
            }),
            vec![Duration::ZERO; 3],
        );
        let mut initial = script(writes.clone());
        initial.fail_write = true;
        let mut channel = Channel {
            kind: Kind::Send,
            stream: Box::new(initial),
            shared: state.clone(),
        };
        channel.write(b"retained packet").unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(*writes.lock().unwrap(), vec![b"retained packet".to_vec()]);
        assert!(events.try_recv().is_ok());
        assert!(events.try_recv().is_err());
        assert!(state.running());
    }

    #[test]
    fn recovery_exhaustion_stops_all_workers() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let count = attempts.clone();
        let (state, _) = shared(
            Arc::new(move |_, _| {
                count.fetch_add(1, Ordering::SeqCst);
                Err(Error("unavailable".into()))
            }),
            vec![Duration::ZERO; 3],
        );
        let mut channel = Channel {
            stream: Box::new(script(Default::default())),
            kind: Kind::Receive,
            shared: state.clone(),
        };
        assert!(channel.recover().is_err());
        assert!(!state.running());
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn cancellation_interrupts_backoff_and_never_dials() {
        let (state, _) = shared(
            Arc::new(|_, _| panic!("shutdown must not dial")),
            vec![Duration::from_secs(3600)],
        );
        let worker_state = state.clone();
        let (ready, wait) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut channel = Channel {
                stream: Box::new(script(Default::default())),
                kind: Kind::Send,
                shared: worker_state,
            };
            ready.send(()).unwrap();
            channel.recover()
        });
        wait.recv().unwrap();
        state.shutdown();
        assert!(worker.join().unwrap().is_err());
    }

    #[test]
    fn shutdown_interrupts_replacement_socket_and_rejects_later_registration() {
        use std::io::Read;
        let (state, _) = shared(Arc::new(|_, _| panic!("not used")), vec![]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let original = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        original
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let (_peer, _) = listener.accept().unwrap();
        state.register(Kind::Receive, &original).unwrap();
        let mut replacement = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        replacement
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let (_peer2, _) = listener.accept().unwrap();
        state.register(Kind::Receive, &replacement).unwrap();
        state.shutdown();
        let mut original = original;
        for socket in [&mut original, &mut replacement] {
            // Platforms may report EOF or an I/O error after local shutdown.
            // A timeout would mean shutdown failed to interrupt the read.
            match socket.read(&mut [0]) {
                Ok(bytes) => assert_eq!(bytes, 0),
                Err(error) => assert!(!matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                )),
            }
        }
        assert!(state.register(Kind::Receive, &replacement).is_err());
    }

    #[test]
    fn reconnect_drops_partial_packet_from_previous_transport() {
        let packet = data_heartbeat(
            "192.0.2.8".parse().unwrap(),
            "198.51.100.9".parse().unwrap(),
            &token(),
        );
        let recovered_packet = packet.clone();
        let (state, _) = shared(
            Arc::new(move |kind, _| {
                assert_eq!(kind, Kind::Receive);
                Ok(Box::new(Script {
                    writes: Default::default(),
                    fail_write: false,
                    reads: VecDeque::from([Ok(recovered_packet.clone())]),
                }))
            }),
            vec![Duration::ZERO],
        );
        let mut receiver = PacketReceiver {
            channel: Channel {
                shared: state,
                kind: Kind::Receive,
                stream: Box::new(Script {
                    writes: Default::default(),
                    fail_write: false,
                    reads: VecDeque::from([
                        Ok(Zeroizing::new(packet[..7].to_vec())),
                        Err(Error("EOF midway through IPv4".into())),
                    ]),
                }),
            },
            buffered: Zeroizing::new(Vec::new()),
        };
        assert_eq!(receiver.receive_ipv4().unwrap(), packet);
    }
    struct ControlScript {
        reads: VecDeque<Zeroizing<Vec<u8>>>,
        ready: Mutex<VecDeque<bool>>,
        writes: Arc<Mutex<Vec<Vec<u8>>>>,
    }
    impl Records for ControlScript {
        fn write(&mut self, bytes: &[u8]) -> Result<()> {
            self.writes.lock().unwrap().push(bytes.to_vec());
            Ok(())
        }
        fn read(&mut self, _: usize) -> Result<Zeroizing<Vec<u8>>> {
            Ok(self.reads.pop_front().expect("only read when ready"))
        }
        fn wait(&self, _: Duration) -> Result<bool> {
            Ok(self.ready.lock().unwrap().pop_front().unwrap_or(false))
        }
    }

    #[test]
    fn command_heartbeat_accepts_fragmented_ack_and_missing_ack_triggers_recovery() {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let attempts = Arc::new(AtomicUsize::new(0));
        let count = attempts.clone();
        let (state, mut events) = shared(
            Arc::new(move |kind, _| {
                assert_eq!(kind, Kind::Control);
                count.fetch_add(1, Ordering::SeqCst);
                Err(Error("recovery intentionally unavailable".into()))
            }),
            vec![Duration::ZERO],
        );
        let expected =
            ModernControlRequest::new(ModernCommand::Heartbeat, &state.token, None).unwrap();
        let mut ack = vec![0_u8; 36];
        ack[..4].copy_from_slice(&15_u32.to_le_bytes());
        let fragments = [&ack[..1], &ack[1..3], &ack[3..8], &ack[8..]];
        let stream = ControlScript {
            reads: fragments
                .into_iter()
                .map(|x| Zeroizing::new(x.to_vec()))
                .collect(),
            ready: Mutex::new(VecDeque::from([
                false, true, true, true, true, false, false,
            ])),
            writes: writes.clone(),
        };
        maintain_control_with_timing(
            Channel {
                stream: Box::new(stream),
                kind: Kind::Control,
                shared: state.clone(),
            },
            Duration::ZERO,
            Duration::from_secs(1),
        );
        assert_eq!(
            *writes.lock().unwrap(),
            vec![expected.as_bytes().to_vec(); 2]
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert!(events.try_recv().is_ok());
        assert!(!state.running());
    }

    #[test]
    fn server_reset_notifies_session_monitor_before_recovery() {
        let (state, mut events) =
            shared(Arc::new(|_, _| Err(Error("server reset".into()))), vec![]);
        let mut reset = vec![0_u8; 36];
        reset[..4].copy_from_slice(&3_u32.to_le_bytes());
        let stream = ControlScript {
            reads: VecDeque::from([Zeroizing::new(reset)]),
            ready: Mutex::new(VecDeque::from([true])),
            writes: Default::default(),
        };
        maintain_control_with_timing(
            Channel {
                stream: Box::new(stream),
                kind: Kind::Control,
                shared: state.clone(),
            },
            Duration::ZERO,
            Duration::from_secs(1),
        );
        assert!(events.try_recv().is_ok());
        assert!(!state.running());
    }
    #[test]
    fn reconnect_handshake_preserves_authentication_and_rejects_address_changes() {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let token = token();
        let address = "192.0.2.8".parse().unwrap();
        let mut reply = vec![0_u8; 36];
        reply[4..8].copy_from_slice(&Ipv4Addr::new(192, 0, 2, 8).octets());
        let mut reset = vec![0_u8; 36];
        reset[..4].copy_from_slice(&3_u32.to_le_bytes());
        let mut wrong = reply.clone();
        wrong[7] = 9;
        let mut stream = Script {
            writes: writes.clone(),
            fail_write: false,
            reads: VecDeque::from([
                Ok(Zeroizing::new(reset)),
                Ok(Zeroizing::new(reply)),
                Ok(Zeroizing::new(wrong)),
            ]),
        };
        assert!(
            !negotiate(
                &mut stream,
                Kind::Control,
                ModernCommand::Reconnect,
                &token,
                address
            )
            .unwrap()
        );
        assert!(
            negotiate(
                &mut stream,
                Kind::Control,
                ModernCommand::RequestAddress,
                &token,
                address
            )
            .unwrap()
        );
        assert!(
            negotiate(
                &mut stream,
                Kind::Control,
                ModernCommand::Reconnect,
                &token,
                address
            )
            .is_err()
        );
        let writes = writes.lock().unwrap();
        assert_eq!(&writes[0][..4], &1_u32.to_le_bytes());
        assert_eq!(&writes[1][..4], &0_u32.to_le_bytes());
        for bytes in writes.iter() {
            assert_eq!(&bytes[4..52], token.as_bytes());
            assert_eq!(&bytes[60..64], &[0xff; 4]);
        }
    }
    #[test]
    fn data_probe_timeout_requires_confirmed_support_and_clears_on_any_receive() {
        let now = Instant::now();
        let mut live = ReceiveLiveness::default();
        live.heartbeat_sent(now);
        assert!(!live.expired(now + DATA_ACK_TIMEOUT));
        live.observe(true);
        live.heartbeat_sent(now);
        // A subsequent send must not extend the original outstanding deadline.
        live.heartbeat_sent(now + Duration::from_secs(31));
        assert!(!live.expired(now + Duration::from_secs(94)));
        assert!(live.expired(now + DATA_ACK_TIMEOUT));
        assert!(!live.expired(now + DATA_ACK_TIMEOUT));
        live.heartbeat_sent(now);
        live.observe(false);
        assert!(!live.expired(now + DATA_ACK_TIMEOUT));
    }

    #[test]
    fn data_ack_requires_correct_session_and_valid_checksums() {
        let address = "192.0.2.8".parse().unwrap();
        let peer = "198.51.100.9".parse().unwrap();
        let token = token();
        let mut ack = data_heartbeat(peer, address, &token);
        ack[20] = 0;
        ack[22..24].fill(0);
        let sum = checksum(&ack[20..]);
        ack[22..24].copy_from_slice(&sum.to_be_bytes());
        assert!(is_data_heartbeat_reply(&ack, address, &token));
        ack[46] ^= 1;
        assert!(!is_data_heartbeat_reply(&ack, address, &token));
    }
}
