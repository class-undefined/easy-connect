use ec_compat::engine::proxy::validate_domain;
use ec_compat::{Error, Result};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, lookup_host};

const SOCKS_VERSION: u8 = 5;
const NO_AUTH: u8 = 0;
const CONNECT: u8 = 1;
const DOMAIN: u8 = 3;
const DIRECT_DEADLINE: Duration = Duration::from_millis(1500);
const PROXY_DEADLINE: Duration = Duration::from_secs(12);
const CAMPUS_DOMAIN_SUFFIXES: &[&str] = &["hkust-gz.edu.cn", "hkust.edu.hk"];

#[derive(Debug, Eq, PartialEq)]
struct Options {
    proxy: SocketAddr,
    host: String,
    port: u16,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("ec-ssh-route: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let options = parse_options(&args)?;
    let stream = match connect_direct(&options.host, options.port, DIRECT_DEADLINE).await {
        Ok(stream) => stream,
        Err(_) => connect_via_proxy(options.proxy, &options.host, options.port).await?,
    };
    relay(stream).await
}

fn parse_options(args: &[String]) -> Result<Options> {
    if args.len() != 4 || args[0] != "--proxy" {
        return Err(Error(
            "usage: ec-ssh-route --proxy 127.0.0.1:PORT HOST PORT".into(),
        ));
    }
    let proxy = args[1]
        .parse::<SocketAddr>()
        .map_err(|_| Error("--proxy must be a socket address".into()))?;
    if !proxy.ip().is_loopback() {
        return Err(Error("--proxy must be loopback-only".into()));
    }
    let host = args[2].trim_end_matches('.').to_ascii_lowercase();
    validate_domain(&host)?;
    if !is_campus_domain(&host) {
        return Err(Error("SSH route is limited to campus domains".into()));
    }
    let port = args[3]
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| Error("SSH destination port is invalid".into()))?;
    Ok(Options { proxy, host, port })
}

fn is_campus_domain(host: &str) -> bool {
    CAMPUS_DOMAIN_SUFFIXES.iter().any(|suffix| {
        host == *suffix
            || host
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

async fn connect_direct(host: &str, port: u16, deadline: Duration) -> Result<TcpStream> {
    tokio::time::timeout(deadline, connect_direct_inner(host, port))
        .await
        .map_err(|_| Error("direct campus connection timed out".into()))?
}

async fn connect_direct_inner(host: &str, port: u16) -> Result<TcpStream> {
    let addresses = lookup_host((host, port))
        .await
        .map_err(|_| Error("direct campus DNS lookup failed".into()))?;
    for address in addresses.filter(|address| matches!(address.ip(), IpAddr::V4(_))) {
        if let Ok(stream) = TcpStream::connect(address).await {
            return Ok(stream);
        }
    }
    Err(Error("direct campus SSH connection is unavailable".into()))
}

async fn connect_via_proxy(proxy: SocketAddr, host: &str, port: u16) -> Result<TcpStream> {
    tokio::time::timeout(PROXY_DEADLINE, connect_via_proxy_inner(proxy, host, port))
        .await
        .map_err(|_| Error("campus SOCKS connection timed out".into()))?
}

async fn connect_via_proxy_inner(proxy: SocketAddr, host: &str, port: u16) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy).await.map_err(|_| {
        Error("campus SOCKS listener is unavailable; connect the campus app".into())
    })?;
    stream.write_all(&[SOCKS_VERSION, 1, NO_AUTH]).await?;
    let mut greeting = [0_u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting != [SOCKS_VERSION, NO_AUTH] {
        return Err(Error("campus SOCKS rejected authentication".into()));
    }
    stream.write_all(&socks_request(host, port)?).await?;
    consume_socks_reply(&mut stream).await?;
    Ok(stream)
}

fn socks_request(host: &str, port: u16) -> Result<Vec<u8>> {
    let encoded = host.as_bytes();
    let length = u8::try_from(encoded.len())
        .map_err(|_| Error("SSH destination hostname is too long".into()))?;
    let mut request = Vec::with_capacity(encoded.len() + 7);
    request.extend_from_slice(&[SOCKS_VERSION, CONNECT, 0, DOMAIN, length]);
    request.extend_from_slice(encoded);
    request.extend_from_slice(&port.to_be_bytes());
    Ok(request)
}

async fn consume_socks_reply(stream: &mut TcpStream) -> Result<()> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != SOCKS_VERSION || header[1] != 0 {
        return Err(Error(
            "campus SOCKS could not reach the SSH destination".into(),
        ));
    }
    let remaining = match header[3] {
        1 => 6,
        3 => usize::from(stream.read_u8().await?) + 2,
        4 => 18,
        _ => return Err(Error("campus SOCKS returned an invalid address".into())),
    };
    let mut ignored = vec![0_u8; remaining];
    stream.read_exact(&mut ignored).await?;
    Ok(())
}

async fn relay(mut remote: TcpStream) -> Result<()> {
    let (mut remote_read, mut remote_write) = remote.split();
    let mut input = tokio::io::stdin();
    let mut output = tokio::io::stdout();
    let upload = async {
        tokio::io::copy(&mut input, &mut remote_write).await?;
        remote_write.shutdown().await
    };
    let download = async {
        tokio::io::copy(&mut remote_read, &mut output).await?;
        output.flush().await
    };
    tokio::pin!(upload, download);
    tokio::select! {
        result = &mut download => result?,
        result = &mut upload => {
            result?;
            download.await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn accepts_only_campus_domain_boundaries() {
        assert!(is_campus_domain("hpc2login.hpc.hkust-gz.edu.cn"));
        assert!(is_campus_domain("hkust.edu.hk"));
        assert!(!is_campus_domain("not-hkust-gz.edu.cn"));
        assert!(!is_campus_domain("hkust-gz.edu.cn.example"));
    }

    #[test]
    fn parses_a_loopback_proxy_and_campus_target() {
        let options = parse_options(&[
            "--proxy".into(),
            "127.0.0.1:1080".into(),
            "HPC.HKUST-GZ.EDU.CN.".into(),
            "22".into(),
        ])
        .unwrap();
        assert_eq!(options.proxy, "127.0.0.1:1080".parse().unwrap());
        assert_eq!(options.host, "hpc.hkust-gz.edu.cn");
        assert_eq!(options.port, 22);
        assert!(
            parse_options(&[
                "--proxy".into(),
                "192.0.2.1:1080".into(),
                "hpc.hkust-gz.edu.cn".into(),
                "22".into(),
            ])
            .is_err()
        );
    }

    #[test]
    fn socks_request_preserves_the_unresolved_hostname() {
        let request = socks_request("hpc.hkust-gz.edu.cn", 22).unwrap();
        assert_eq!(&request[..5], &[5, 1, 0, 3, 19]);
        assert_eq!(&request[5..24], b"hpc.hkust-gz.edu.cn");
        assert_eq!(&request[24..], &22_u16.to_be_bytes());
    }

    #[tokio::test]
    async fn direct_route_reuses_the_successful_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = tokio::spawn(async move { listener.accept().await.unwrap() });
        let stream = connect_direct("127.0.0.1", port, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(stream.peer_addr().unwrap().port(), port);
        accepted.await.unwrap();
    }

    #[tokio::test]
    async fn proxy_route_sends_a_domain_request() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&[5, 0]).await.unwrap();
            let mut request = vec![0_u8; 5 + 19 + 2];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(request, socks_request("hpc.hkust-gz.edu.cn", 22).unwrap());
            stream
                .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        connect_via_proxy(address, "hpc.hkust-gz.edu.cn", 22)
            .await
            .unwrap();
        server.await.unwrap();
    }
}
