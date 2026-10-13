//! Uncredentialed P0 experiments. Never accepts a real session identifier.
use anyhow::{Result, bail};
use ec_compat::modern::{ModernSessionId, parse_sha256_pin, request_modern_token_with_pin};
use ec_compat::session_renewal::LegacyProbe;
use ec_compat::special_tls11::SpecialTls11Stream;
use std::time::{Duration, Instant};

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 || !matches!(args[3].as_str(), "legacy-dummy" | "tls-timq" | "tls-text") {
        bail!(
            "usage: session-renewal-transport HTTPS_ORIGIN CERT_SHA256 legacy-dummy|tls-timq|tls-text"
        );
    }
    let url = url::Url::parse(&args[1])?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("gateway must be an HTTPS origin without credentials");
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("missing host"))?;
    let pin = parse_sha256_pin(&args[2])?;
    let timeout = Duration::from_secs(3);
    let dummy = ModernSessionId::from_bytes(b"0000000000000000")?;
    let verified = request_modern_token_with_pin(&args[1], &dummy, timeout, Some(pin))?;
    let start = Instant::now();
    if args[3] == "legacy-dummy" {
        let (_probe, observation) =
            LegacyProbe::connect_without_server_authentication(verified.peer_address(), &dummy, 0)?;
        println!(
            "credentials_submitted=false server_authenticated=false elapsed_ms={} reply={:?} body_bytes={}",
            start.elapsed().as_millis(),
            observation.reply,
            observation.body_length
        );
        return Ok(());
    }
    let mut stream = SpecialTls11Stream::connect_tcp_proxy(
        verified.peer_address(),
        host,
        timeout,
        verified.verified_leaf_sha256(),
        None,
    )?;
    println!("independent TCPP TLS handshake verified; credentials_submitted=false");
    if args[3] == "tls-timq" {
        let mut request = [0; 28];
        request[..4].copy_from_slice(b"TIMQ");
        request[4..8].copy_from_slice(&4_u32.to_be_bytes());
        request[12..].copy_from_slice(b"0000000000000000");
        stream.write_application_data(&request)?;
        let response = stream.read_application_data(65596).inspect_err(|_| {
            eprintln!(
                "stage=TLS_TIMQ_read elapsed_ms={} renewal_verified=false",
                start.elapsed().as_millis()
            );
        })?;
        println!(
            "response_bytes={} ackq={} renewal_verified=false",
            response.len(),
            response.len() >= 4 && response[..4].eq_ignore_ascii_case(b"ACKQ")
        );
    } else {
        // libecbase Curl_vpn_connect, 0x7d4b9..0x7d569. These are resource
        // proxy commands, not evidence of a session-renewal transport.
        for (stage, request) in [
            ("C01", b"C01 HELLO\r\nCLIENT: MOBILE/1.0\r\n\r\n".as_slice()),
            (
                "C02",
                b"C02 AUTH SESSION\r\nID: 0000000000000000\r\n\r\n".as_slice(),
            ),
        ] {
            stream.write_application_data(request)?;
            let response = stream.read_application_data(1024)?;
            println!(
                "stage={} response_bytes={} expected_prefix={} elapsed_ms={} session_authenticated=false renewal_verified=false",
                stage,
                response.len(),
                response.starts_with(stage.as_bytes()),
                start.elapsed().as_millis()
            );
        }
    }
    Ok(())
}
