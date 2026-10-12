use ec_compat::engine::dns::DirectDnsResolver;
use ec_compat::engine::proxy::{NameResolver, validate_domain};
use ec_compat::{Error, Result};
use socket2::SockRef;
use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::Semaphore;

#[path = "ec_fallback/campus.rs"]
mod campus;

const SOCKS_VERSION: u8 = 5;
const NO_AUTH: u8 = 0;
const CONNECT: u8 = 1;
const IPV4: u8 = 1;
const DOMAIN: u8 = 3;
const MAX_METHODS: usize = 32;
const MAX_DOMAIN: usize = 253;
const MAX_CONNECTIONS: usize = 256;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
// The campus engine may spend up to ten seconds establishing a tunnel-side TCP
// connection. The relay must not fail a healthy request before that deadline.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(12);
const DIRECT_TIMEOUT: Duration = Duration::from_secs(8);
const CAMPUS_DOMAIN_SUFFIXES: &[&str] = &["hkust-gz.edu.cn", "hkust.edu.hk"];

#[derive(Clone, Debug)]
struct Target {
    encoded: Vec<u8>,
    host: String,
    literal: Option<Ipv4Addr>,
    port: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TargetClass {
    CampusDomain,
    PrivateLiteral,
    General,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("ec-fallback: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let listen = argument(&args, "--listen")?
        .parse::<SocketAddr>()
        .map_err(|_| Error("--listen must be a socket address".into()))?;
    let upstream = argument(&args, "--upstream")?
        .parse::<SocketAddr>()
        .map_err(|_| Error("--upstream must be a socket address".into()))?;
    let general_upstream = optional_argument(&args, "--general-upstream")?
        .map(str::parse::<SocketAddr>)
        .transpose()
        .map_err(|_| Error("--general-upstream must be a socket address".into()))?;
    let direct_interface_name = argument(&args, "--direct-interface")?;
    let direct_interface = interface_index(direct_interface_name)?;
    let campus = campus::CampusRouting::load()?;
    if let Some(campus) = &campus {
        tokio::spawn(Arc::clone(campus).run());
    }
    if !listen.ip().is_loopback()
        || !upstream.ip().is_loopback()
        || general_upstream.is_some_and(|address| !address.ip().is_loopback())
    {
        return Err(Error(
            "fallback listeners and upstreams must be loopback-only".into(),
        ));
    }
    let resolver: Arc<dyn NameResolver> = Arc::new(DirectDnsResolver::new(
        vec![Ipv4Addr::new(223, 5, 5, 5), Ipv4Addr::new(119, 29, 29, 29)],
        Duration::from_secs(3),
    )?);
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|_| Error("cannot bind fallback SOCKS listener".into()))?;
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    println!(
        "Fallback SOCKS5 listening on {listen}; campus upstream {upstream}; general upstream {}; direct interface {direct_interface_name}",
        general_upstream
            .map(|address| address.to_string())
            .unwrap_or_else(|| "disabled".to_owned())
    );
    loop {
        let (client, peer) = listener.accept().await?;
        if !peer.ip().is_loopback() {
            continue;
        }
        let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
            continue;
        };
        let resolver = Arc::clone(&resolver);
        let campus = campus.clone();
        tokio::spawn(async move {
            let _slot = slot;
            if let Err(error) = handle(
                client,
                upstream,
                general_upstream,
                direct_interface,
                resolver.as_ref(),
                campus.as_deref(),
            )
            .await
            {
                eprintln!("fallback request failed: {error}");
            }
        });
    }
}

fn interface_index(name: &str) -> Result<NonZeroU32> {
    let name = CString::new(name)
        .map_err(|_| Error("--direct-interface contains an invalid NUL byte".into()))?;
    // SAFETY: CString guarantees a valid NUL-terminated pointer for the duration
    // of this call. if_nametoindex does not retain the pointer.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    NonZeroU32::new(index)
        .ok_or_else(|| Error("--direct-interface does not name a local interface".into()))
}

fn argument<'a>(args: &'a [String], name: &str) -> Result<&'a str> {
    args.iter()
        .position(|arg| arg == name)
        .and_then(|index| args.get(index + 1))
        .map(String::as_str)
        .ok_or_else(|| Error(format!("missing required argument: {name}")))
}

fn optional_argument<'a>(args: &'a [String], name: &str) -> Result<Option<&'a str>> {
    let Some(index) = args.iter().position(|arg| arg == name) else {
        return Ok(None);
    };
    args.get(index + 1)
        .filter(|value| !value.starts_with("--"))
        .map(String::as_str)
        .map(Some)
        .ok_or_else(|| Error(format!("missing value for argument: {name}")))
}

async fn handle(
    mut client: TcpStream,
    upstream: SocketAddr,
    general_upstream: Option<SocketAddr>,
    direct_interface: NonZeroU32,
    resolver: &dyn NameResolver,
    campus: Option<&campus::CampusRouting>,
) -> Result<()> {
    let target = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_request(&mut client))
        .await
        .map_err(|_| Error("fallback SOCKS handshake timed out".into()))??;
    let routed = route_target(
        &target,
        upstream,
        general_upstream,
        direct_interface,
        resolver,
        campus,
    )
    .await;
    let mut remote = match routed {
        Ok(stream) => stream,
        Err(error) => {
            let _ = reply(&mut client, 4).await;
            return Err(error);
        }
    };
    reply(&mut client, 0).await?;
    match tokio::io::copy_bidirectional(&mut client, &mut remote).await {
        Ok(_) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::UnexpectedEof
            ) =>
        {
            Ok(())
        }
        Err(_) => Err(Error("fallback stream forwarding failed".into())),
    }
}

async fn route_target(
    target: &Target,
    upstream: SocketAddr,
    general_upstream: Option<SocketAddr>,
    mut direct_interface: NonZeroU32,
    resolver: &dyn NameResolver,
    campus: Option<&campus::CampusRouting>,
) -> Result<TcpStream> {
    if let Some(campus) = campus {
        let allowed = match target.literal {
            Some(ip) => campus.policy.allows_ipv4(ip),
            None => campus.policy.allows_domain(&target.host),
        };
        if target.literal.is_some_and(is_private_destination) && !allowed {
            return Err(Error(
                "private destination is outside the local campus policy".into(),
            ));
        }
        if let Some(network) = campus.network().await {
            direct_interface = network.interface;
            if allowed && network.on_campus {
                let address = match target.literal {
                    Some(ip) => Ok(ip),
                    None => network.resolver.resolve_ipv4(&target.host).await,
                };
                if let Ok(ip) = address {
                    if !ip.is_loopback()
                        && !ip.is_link_local()
                        && !ip.is_unspecified()
                        && !ip.is_multicast()
                        && !ip.is_broadcast()
                        && !ec_compat::engine::proxy::is_synthetic_fake_ipv4(ip)
                    {
                        if let Ok(stream) = campus::connect_bound(
                            ip,
                            target.port,
                            network.interface,
                            Duration::from_secs(3),
                        )
                        .await
                        {
                            return Ok(stream);
                        }
                    }
                }
            }
        }
    }
    match classify_target(target) {
        TargetClass::CampusDomain => {
            match tokio::time::timeout(UPSTREAM_TIMEOUT, via_upstream(upstream, target)).await {
                Ok(Ok(stream)) => Ok(stream),
                _ => via_direct(target, direct_interface, resolver).await,
            }
        }
        TargetClass::PrivateLiteral => {
            tokio::time::timeout(UPSTREAM_TIMEOUT, via_upstream(upstream, target))
                .await
                .map_err(|_| Error("campus SOCKS connection timed out".into()))?
        }
        TargetClass::General => match general_upstream {
            Some(address) => tokio::time::timeout(DIRECT_TIMEOUT, via_upstream(address, target))
                .await
                .map_err(|_| Error("general SOCKS connection timed out".into()))?,
            None => Err(Error(
                "non-campus destination requires --general-upstream".into(),
            )),
        },
    }
}

fn is_campus_domain(host: &str) -> bool {
    CAMPUS_DOMAIN_SUFFIXES.iter().any(|suffix| {
        host == *suffix
            || host
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

fn classify_target(target: &Target) -> TargetClass {
    match target.literal {
        Some(address) if is_private_destination(address) => TargetClass::PrivateLiteral,
        Some(_) => TargetClass::General,
        None if is_campus_domain(&target.host) => TargetClass::CampusDomain,
        None => TargetClass::General,
    }
}

async fn read_request(client: &mut TcpStream) -> Result<Target> {
    let mut greeting = [0_u8; 2];
    client.read_exact(&mut greeting).await?;
    if greeting[0] != SOCKS_VERSION || greeting[1] == 0 || greeting[1] as usize > MAX_METHODS {
        return Err(Error("invalid fallback SOCKS greeting".into()));
    }
    let mut methods = vec![0_u8; greeting[1] as usize];
    client.read_exact(&mut methods).await?;
    if !methods.contains(&NO_AUTH) {
        client.write_all(&[SOCKS_VERSION, 0xff]).await?;
        return Err(Error(
            "fallback SOCKS client requires authentication".into(),
        ));
    }
    client.write_all(&[SOCKS_VERSION, NO_AUTH]).await?;

    let mut header = [0_u8; 4];
    client.read_exact(&mut header).await?;
    if header[..3] != [SOCKS_VERSION, CONNECT, 0] {
        return Err(Error("fallback supports only SOCKS5 CONNECT".into()));
    }
    let mut encoded = vec![header[3]];
    let (host, literal) = match header[3] {
        IPV4 => {
            let mut bytes = [0_u8; 4];
            client.read_exact(&mut bytes).await?;
            encoded.extend_from_slice(&bytes);
            let address = Ipv4Addr::from(bytes);
            (address.to_string(), Some(address))
        }
        DOMAIN => {
            let length = client.read_u8().await? as usize;
            if length == 0 || length > MAX_DOMAIN {
                return Err(Error("fallback SOCKS domain length is invalid".into()));
            }
            let mut bytes = vec![0_u8; length];
            client.read_exact(&mut bytes).await?;
            let host = std::str::from_utf8(&bytes)
                .map_err(|_| Error("fallback SOCKS domain is not UTF-8".into()))?
                .to_ascii_lowercase();
            validate_domain(&host)?;
            encoded.push(length as u8);
            encoded.extend_from_slice(&bytes);
            (host, None)
        }
        _ => return Err(Error("fallback SOCKS address type is unsupported".into())),
    };
    let port = client.read_u16().await?;
    if port == 0 {
        return Err(Error("fallback SOCKS destination port is invalid".into()));
    }
    encoded.extend_from_slice(&port.to_be_bytes());
    Ok(Target {
        encoded,
        host,
        literal,
        port,
    })
}

async fn via_upstream(upstream: SocketAddr, target: &Target) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(upstream).await?;
    stream.write_all(&[SOCKS_VERSION, 1, NO_AUTH]).await?;
    let mut greeting = [0_u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting != [SOCKS_VERSION, NO_AUTH] {
        return Err(Error("upstream SOCKS rejected authentication".into()));
    }
    let mut request = vec![SOCKS_VERSION, CONNECT, 0];
    request.extend_from_slice(&target.encoded);
    stream.write_all(&request).await?;
    consume_reply(&mut stream).await?;
    Ok(stream)
}

async fn consume_reply(stream: &mut TcpStream) -> Result<()> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != SOCKS_VERSION || header[1] != 0 {
        return Err(Error("upstream SOCKS could not reach destination".into()));
    }
    match header[3] {
        IPV4 => {
            let mut ignored = [0_u8; 6];
            stream.read_exact(&mut ignored).await?;
        }
        DOMAIN => {
            let length = stream.read_u8().await? as usize;
            let mut ignored = vec![0_u8; length + 2];
            stream.read_exact(&mut ignored).await?;
        }
        4 => {
            let mut ignored = [0_u8; 18];
            stream.read_exact(&mut ignored).await?;
        }
        _ => {
            return Err(Error(
                "upstream SOCKS returned an invalid address type".into(),
            ));
        }
    }
    Ok(())
}

async fn via_direct(
    target: &Target,
    direct_interface: NonZeroU32,
    resolver: &dyn NameResolver,
) -> Result<TcpStream> {
    let address = match target.literal {
        Some(address) => address,
        None => resolver.resolve_ipv4(&target.host).await?,
    };
    if is_private_destination(address) {
        return Err(Error(
            "private campus destination is unavailable without the tunnel".into(),
        ));
    }
    let socket = TcpSocket::new_v4()?;
    SockRef::from(&socket)
        .bind_device_by_index_v4(Some(direct_interface))
        .map_err(|_| Error("cannot bind direct fallback socket to physical interface".into()))?;
    tokio::time::timeout(
        DIRECT_TIMEOUT,
        socket.connect(SocketAddr::new(IpAddr::V4(address), target.port)),
    )
    .await
    .map_err(|_| Error("direct fallback connection timed out".into()))?
    .map_err(Error::from)
}

async fn reply(client: &mut TcpStream, code: u8) -> Result<()> {
    client
        .write_all(&[SOCKS_VERSION, code, 0, IPV4, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

fn is_private_destination(address: Ipv4Addr) -> bool {
    address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_unspecified()
        || address.is_multicast()
        || address.is_broadcast()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(host: &str, literal: Option<Ipv4Addr>) -> Target {
        Target {
            encoded: Vec::new(),
            host: host.to_owned(),
            literal,
            port: 443,
        }
    }

    #[test]
    fn private_and_non_routable_destinations_are_fail_closed() {
        assert!(is_private_destination(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(is_private_destination(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private_destination(Ipv4Addr::LOCALHOST));
        assert!(is_private_destination(Ipv4Addr::new(169, 254, 1, 1)));
        assert!(!is_private_destination(Ipv4Addr::new(192, 0, 2, 1)));
    }

    #[test]
    fn only_exact_campus_suffixes_use_the_campus_domain_route() {
        for host in [
            "hkust-gz.edu.cn",
            "library.hkust-gz.edu.cn",
            "hkust.edu.hk",
            "www.hkust.edu.hk",
        ] {
            assert_eq!(
                classify_target(&target(host, None)),
                TargetClass::CampusDomain
            );
        }
        for host in [
            "chatgpt.com",
            "not-hkust-gz.edu.cn",
            "hkust-gz.edu.cn.example",
        ] {
            assert_eq!(classify_target(&target(host, None)), TargetClass::General);
        }
    }

    #[test]
    fn literal_addresses_never_use_public_domain_fallback() {
        assert_eq!(
            classify_target(&target("private.invalid", Some(Ipv4Addr::new(10, 0, 0, 8)),)),
            TargetClass::PrivateLiteral
        );
        assert_eq!(
            classify_target(&target("203.0.113.8", Some(Ipv4Addr::new(203, 0, 113, 8)),)),
            TargetClass::General
        );
    }

    #[test]
    fn campus_upstream_deadline_covers_the_engine_connect_budget() {
        assert!(UPSTREAM_TIMEOUT > Duration::from_secs(10));
        assert!(UPSTREAM_TIMEOUT <= Duration::from_secs(15));
    }
}
