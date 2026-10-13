//! macOS 7.6.7 TimeQry session renewal, independent of the TLS data plane.
//!
//! This legacy transport is NOT TLS: it exposes TWFID and has no server
//! authentication. See docs/connection-maintenance.md for this protocol boundary.
//! Evidence: CSClient SHA-256 947042c981763a8c5104f5f1ccf95829dc15bf3cc4fe687dcba99de8e52358e4,
//! HandShakeServer 0x100051be0, UpDateReqMsg 0x100052a70,
//! RecvServerMsg 0x100052b70, ProcessServerMsg 0x100052cf0.
use crate::modern::{ModernSessionId, connect_gateway_tcp};
use crate::{Error, Result};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

mod maintenance;
pub(crate) use maintenance::{MaintenanceStatus, Termination, start};

const HEADER_LEN: usize = 60;
// Local allocation/time policy, not an official protocol constant.
const MAX_BROADCAST: usize = 64 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(3);
const HELLO: &str = "160301004d01000049030146837424014316291f953ec963b9fcb61600aa2015eb750759408b8d0ce160332030303030303030303030303030303030409a8a0fcd81d82edb7b8ff71bc180c6000200390100";
const CONFIRM: &str =
    "14030100010116030100202bd1df0ee24cda7a360ede2481b97932678ff2888cefa37e501c096b099c5a0d";

/// Safe metadata only: no server text, session IDs, or traffic counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reply {
    Renewed { seconds: u32 },
    InvalidValidity,
    Acknowledged,
    TimedOut,
    SessionSwitch,
    SessionUnchanged,
    Connected,
    Unknown { message_type: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Observation {
    pub reply: Reply,
    pub body_length: usize,
}

fn request(
    message_type: u32,
    uptime_seconds: u32,
    session: &ModernSessionId,
) -> Zeroizing<[u8; 28]> {
    let mut bytes = Zeroizing::new([0; 28]);
    bytes[..4].copy_from_slice(b"TIMQ");
    bytes[4..8].copy_from_slice(&message_type.to_be_bytes());
    bytes[8..12].copy_from_slice(&uptime_seconds.to_be_bytes());
    bytes[12..].copy_from_slice(session.as_bytes());
    bytes
}

fn field(header: &[u8; HEADER_LEN], offset: usize) -> u32 {
    u32::from_be_bytes(
        header[offset..offset + 4]
            .try_into()
            .expect("fixed header field"),
    )
}

fn parse_header(header: &[u8; HEADER_LEN], session: &ModernSessionId) -> Result<Observation> {
    if !header[..4].eq_ignore_ascii_case(b"ACKQ") {
        return Err(Error("renewal reply has invalid magic".into()));
    }
    let body_length = field(header, 56) as usize;
    if body_length > MAX_BROADCAST {
        return Err(Error("renewal broadcast exceeds local size limit".into()));
    }
    let reply = match field(header, 4) {
        1 => {
            let seconds = field(header, 12);
            // Native code compares the swapped value as a signed int32.
            if seconds == 0 || seconds > i32::MAX as u32 {
                Reply::InvalidValidity
            } else {
                Reply::Renewed { seconds }
            }
        }
        2 => Reply::Acknowledged,
        3 => Reply::TimedOut,
        4 => {
            let candidate = ModernSessionId::from_bytes(&header[16..32])?;
            if candidate.as_bytes() == session.as_bytes() {
                Reply::SessionUnchanged
            } else {
                Reply::SessionSwitch
            }
        }
        5 => Reply::Connected,
        message_type => Reply::Unknown { message_type },
    };
    Ok(Observation { reply, body_length })
}

fn read_reply(
    mut read_exact: impl FnMut(&mut [u8]) -> Result<()>,
    session: &ModernSessionId,
) -> Result<Observation> {
    let mut header = Zeroizing::new([0; HEADER_LEN]);
    read_exact(header.as_mut())?;
    let observation = parse_header(&header, session)?;
    // Consume the entire bounded broadcast before reading another ACKQ. Never
    // log or interpret its text. Invalid headers terminate the connection.
    let mut remaining = observation.body_length;
    let mut scratch = Zeroizing::new([0; 1024]);
    while remaining != 0 {
        let count = remaining.min(scratch.len());
        read_exact(&mut scratch[..count])?;
        remaining -= count;
    }
    Ok(observation)
}

fn read_until(stream: &mut TcpStream, mut bytes: &mut [u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|value| !value.is_zero())
            .ok_or_else(|| Error("renewal read deadline exceeded".into()))?;
        stream.set_read_timeout(Some(remaining))?;
        match stream.read(bytes) {
            Ok(0) => return Err(Error("renewal connection closed".into())),
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// One unauthenticated legacy transport. Any I/O or framing failure permanently
/// closes this instance. Maintenance always reconnects with a fresh instance.
pub struct LegacyProbe {
    stream: Option<TcpStream>,
    session: ModernSessionId,
}

impl LegacyProbe {
    pub fn connect_without_server_authentication(
        address: SocketAddr,
        session: &ModernSessionId,
        uptime_seconds: u32,
    ) -> Result<(Self, Observation)> {
        Self::connect_observed(
            address,
            session,
            uptime_seconds,
            Instant::now() + IO_TIMEOUT,
            |_| Ok(()),
        )
    }

    fn connect_observed(
        address: SocketAddr,
        session: &ModernSessionId,
        uptime_seconds: u32,
        deadline: Instant,
        observe: impl FnOnce(&TcpStream) -> Result<()>,
    ) -> Result<(Self, Observation)> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|value| !value.is_zero())
            .ok_or_else(|| Error("renewal connection deadline exceeded".into()))?;
        let stream = connect_gateway_tcp(address, remaining.min(IO_TIMEOUT))?;
        let mut probe = Self {
            stream: Some(stream),
            session: ModernSessionId::from_bytes(session.as_bytes())?,
        };
        let stream = probe.stream.as_mut().expect("new transport");
        observe(stream)?;
        let mut hello = Zeroizing::new(hex::decode(HELLO).expect("static hello hex"));
        hello[44..60].copy_from_slice(session.as_bytes());
        write_until(stream, &hello, deadline)?;
        let mut response = Zeroizing::new([0; 122]);
        read_until(stream, response.as_mut(), deadline)?;
        // These structural checks reject ordinary TLS flights. They provide
        // no cryptographic identity check, even when every byte matches.
        if response[..9] != [22, 3, 1, 0, 74, 2, 0, 0, 70]
            || response[79..85] != [20, 3, 1, 0, 1, 1]
            || response[85..90] != [22, 3, 1, 0, 32]
        {
            return Err(Error("unexpected legacy renewal handshake layout".into()));
        }
        write_until(
            stream,
            &hex::decode(CONFIRM).expect("static confirmation hex"),
            deadline,
        )?;
        let observation = probe.exchange_until(4, uptime_seconds, deadline)?;
        Ok((probe, observation))
    }

    /// macOS sends type 3; type 1 from other client versions is not substituted.
    pub fn poll(&mut self, uptime_seconds: u32) -> Result<Observation> {
        self.exchange(3, uptime_seconds)
    }

    pub fn shutdown_handle(&self) -> Result<TcpStream> {
        self.stream
            .as_ref()
            .ok_or_else(|| Error("renewal probe is closed".into()))?
            .try_clone()
            .map_err(Into::into)
    }

    fn exchange(&mut self, message_type: u32, uptime_seconds: u32) -> Result<Observation> {
        self.exchange_until(message_type, uptime_seconds, Instant::now() + IO_TIMEOUT)
    }

    fn exchange_until(
        &mut self,
        message_type: u32,
        uptime_seconds: u32,
        deadline: Instant,
    ) -> Result<Observation> {
        // Ownership ensures partial reads cannot be retried on a desynchronized
        // socket. A later call fails closed instead of restarting the header.
        let mut stream = self
            .stream
            .take()
            .ok_or_else(|| Error("renewal probe is closed".into()))?;
        let result = (|| {
            write_until(
                &mut stream,
                request(message_type, uptime_seconds, &self.session).as_ref(),
                deadline,
            )?;
            read_reply(
                |bytes| read_until(&mut stream, bytes, deadline),
                &self.session,
            )
        })();
        let observation = match result {
            Ok(observation) => observation,
            Err(error) => {
                // A cancellation handle may own a cloned fd. Dropping only
                // this fd would leave that TCP connection alive.
                let _ = stream.shutdown(Shutdown::Both);
                return Err(error);
            }
        };
        if matches!(
            observation.reply,
            Reply::TimedOut | Reply::InvalidValidity | Reply::SessionSwitch | Reply::Unknown { .. }
        ) {
            let _ = stream.shutdown(Shutdown::Both);
        } else {
            self.stream = Some(stream);
        }
        Ok(observation)
    }
}

fn write_until(stream: &mut TcpStream, mut bytes: &[u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|value| !value.is_zero())
            .ok_or_else(|| Error("renewal write deadline exceeded".into()))?;
        stream.set_write_timeout(Some(remaining))?;
        match stream.write(bytes) {
            Ok(0) => return Err(Error("renewal connection closed".into())),
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

impl Drop for LegacyProbe {
    fn drop(&mut self) {
        if let Some(stream) = &self.stream {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn session() -> ModernSessionId {
        ModernSessionId::from_bytes(b"0123456789abcdef").unwrap()
    }

    fn header(kind: u32, seconds: u32, length: u32) -> [u8; HEADER_LEN] {
        let mut bytes = [0; HEADER_LEN];
        bytes[..4].copy_from_slice(b"ACKQ");
        bytes[4..8].copy_from_slice(&kind.to_be_bytes());
        bytes[12..16].copy_from_slice(&seconds.to_be_bytes());
        bytes[56..].copy_from_slice(&length.to_be_bytes());
        bytes
    }

    #[test]
    fn native_request_offsets_and_mac_periodic_type() {
        let golden =
            hex::decode("54494d51000000031122334430313233343536373839616263646566").unwrap();
        assert_eq!(request(3, 0x11223344, &session()).as_slice(), golden);
        assert_eq!(&request(4, 1, &session())[4..8], &[0, 0, 0, 4]);
        assert_eq!(hex::decode(HELLO).unwrap().len(), 82);
        assert_eq!(hex::decode(CONFIRM).unwrap().len(), 43);
    }

    #[test]
    fn native_types_and_signed_validity() {
        assert_eq!(
            parse_header(&header(1, 300, 0), &session()).unwrap().reply,
            Reply::Renewed { seconds: 300 }
        );
        for seconds in [0, 0x80000000, 0xffffffff] {
            assert_eq!(
                parse_header(&header(1, seconds, 0), &session())
                    .unwrap()
                    .reply,
                Reply::InvalidValidity
            );
        }
        for (kind, reply) in [
            (2, Reply::Acknowledged),
            (3, Reply::TimedOut),
            (5, Reply::Connected),
            (99, Reply::Unknown { message_type: 99 }),
        ] {
            assert_eq!(
                parse_header(&header(kind, 0, 0), &session()).unwrap().reply,
                reply
            );
        }
    }

    #[test]
    fn switch_is_classified_without_exposing_or_adopting_id() {
        let mut bytes = header(4, 0, 0);
        assert!(parse_header(&bytes, &session()).is_err());
        bytes[16..32].copy_from_slice(b"0123456789abcdef");
        assert_eq!(
            parse_header(&bytes, &session()).unwrap().reply,
            Reply::SessionUnchanged
        );
        bytes[16..32].copy_from_slice(b"fedcba9876543210");
        let result = parse_header(&bytes, &session()).unwrap();
        assert_eq!(result.reply, Reply::SessionSwitch);
        assert!(!format!("{result:?}").contains("fedcba"));
    }

    #[test]
    fn broadcast_boundary_preserves_coalesced_next_header() {
        let mut data = header(2, 0, 1025).to_vec();
        data.extend_from_slice(&[42; 1025]);
        data.extend_from_slice(&header(1, 300, 0));
        let mut cursor = Cursor::new(data);
        let first = read_reply(
            |bytes| cursor.read_exact(bytes).map_err(Into::into),
            &session(),
        )
        .unwrap();
        assert_eq!(first.body_length, 1025);
        let second = read_reply(
            |bytes| cursor.read_exact(bytes).map_err(Into::into),
            &session(),
        )
        .unwrap();
        assert_eq!(second.reply, Reply::Renewed { seconds: 300 });
        assert_eq!(cursor.position(), 1145);
    }

    #[test]
    fn invalid_magic_oversize_and_truncated_body_are_errors() {
        let mut bytes = header(2, 0, 0);
        bytes[..4].copy_from_slice(b"ackq");
        assert!(parse_header(&bytes, &session()).is_ok());
        bytes[0] = 0;
        assert!(parse_header(&bytes, &session()).is_err());
        assert!(parse_header(&header(2, 0, MAX_BROADCAST as u32 + 1), &session()).is_err());
        let mut cursor = Cursor::new(header(2, 0, 1));
        assert!(
            read_reply(
                |bytes| cursor.read_exact(bytes).map_err(Into::into),
                &session()
            )
            .is_err()
        );
    }

    #[test]
    fn fragmented_header_and_eof_poison_the_probe() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let writer = std::thread::spawn(move || {
            let mut request = [0; 28];
            server.read_exact(&mut request).unwrap();
            for part in header(1, 300, 0).chunks(7) {
                server.write_all(part).unwrap();
            }
            server.read_exact(&mut request).unwrap();
            server.write_all(b"ACKQ").unwrap();
        });
        let mut probe = LegacyProbe {
            stream: Some(socket),
            session: session(),
        };
        assert_eq!(
            probe.poll(1).unwrap().reply,
            Reply::Renewed { seconds: 300 }
        );
        assert!(probe.poll(2).is_err());
        assert!(probe.stream.is_none());
        assert_eq!(probe.poll(3).unwrap_err().0, "renewal probe is closed");
        writer.join().unwrap();
    }

    #[test]
    fn shutdown_interrupts_a_partial_header() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let mut probe = LegacyProbe {
            stream: Some(socket),
            session: session(),
        };
        let cancel = probe.shutdown_handle().unwrap();
        let worker = std::thread::spawn(move || probe.poll(1));
        let mut request = [0; 28];
        server.read_exact(&mut request).unwrap();
        server.write_all(b"ACK").unwrap();
        cancel.shutdown(Shutdown::Both).unwrap();
        assert!(worker.join().unwrap().is_err());
    }

    #[test]
    fn read_deadline_bounds_a_stalled_partial_header() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        server.write_all(b"ACK").unwrap();
        let mut bytes = [0; HEADER_LEN];
        let start = Instant::now();
        assert!(read_until(&mut socket, &mut bytes, start + Duration::from_millis(30)).is_err());
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_eq!(&bytes[..3], b"ACK");
        assert!(read_until(&mut socket, &mut [0], Instant::now()).is_err());
    }
}
