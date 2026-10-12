use crate::{
    resources::{PublishedResources, ResourceResolver},
    tun,
};
use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use ec_compat::engine::dns::VpnDnsResolver;
use ec_compat::engine::netstack::VirtualNetstack;
use ec_compat::engine::policy::RoutePolicy;
use ec_compat::engine::proxy::{NameResolver, RejectDomainResolver};
use ec_compat::engine::session::AuthenticatedEngineSession;
use ec_compat::engine::socks::SocksServer;
use ec_compat::modern::{parse_sha256_pin, probe_special_tls_contract};
use ec_compat::probe::{GatewaySession, read_credentials};
use ec_compat::xml::{first_descendant_text, parse_xml};
use serde_json::{Value, json};
use std::{
    io::{self, Write},
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use url::Url;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(version, about = "Independent EasyConnect-compatible Rust CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum ConnectMode {
    Tun,
    Socks,
}

#[derive(Args)]
struct GatewayArgs {
    #[arg(long, conflicts_with = "gateway", required_unless_present = "gateway")]
    config: Option<PathBuf>,
    /// Gateway HTTPS URL; configuration is generated in memory.
    #[arg(long, conflicts_with = "config", required_unless_present = "config")]
    gateway: Option<String>,
    /// Explicit certificate SHA-256 pin for a private/self-signed gateway.
    #[arg(long, requires = "gateway", conflicts_with = "config")]
    cert_sha256: Option<String>,
}

impl GatewayArgs {
    fn resolve(&self, require_routes: bool) -> Result<Value> {
        match (&self.config, &self.gateway) {
            (Some(path), None) => load_profile(path, require_routes),
            (None, Some(url)) => profile(url, self.cert_sha256.as_deref()),
            _ => bail!("provide exactly one of --gateway or --config"),
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Install the per-user privileged background broker (run elevated once).
    InstallService {
        #[arg(long)]
        owner: String,
    },
    /// Internal launchd/SCM entry point.
    #[command(hide = true)]
    Service {
        #[arg(long)]
        owner: String,
    },
    /// Check macOS utun and ICMP forwarding locally, without a VPN login.
    TunSelfTest,
    /// Generate a profile. No connection or credential storage.
    Init {
        #[arg(long)]
        gateway: String,
        #[arg(long)]
        cert_sha256: Option<String>,
        #[arg(long, default_value = "config/local.json")]
        output: PathBuf,
    },
    /// Check public login metadata without submitting credentials.
    Discover {
        #[command(flatten)]
        target: GatewayArgs,
        /// Inspect only the uncredentialed TLS tunnel handshake, not an address lease.
        #[arg(long)]
        tunnel_handshake: bool,
    },
    /// Validate the local profile without network access.
    CheckConfig {
        #[arg(long)]
        config: PathBuf,
    },
    /// Authenticate, list published gateway resources, and log out.
    Resources {
        #[command(flatten)]
        target: GatewayArgs,
        #[arg(long)]
        username: Option<String>,
        #[arg(long, conflicts_with = "username")]
        credentials_stdin: bool,
    },
    /// Connect using macOS TUN (default) or loopback SOCKS5.
    Connect {
        #[command(flatten)]
        target: GatewayArgs,
        #[arg(long)]
        username: Option<String>,
        /// Read exactly two lines (username/password) from stdin until EOF.
        #[arg(long, conflicts_with = "username")]
        credentials_stdin: bool,
        #[arg(long, requires = "credentials_stdin", hide = true)]
        shutdown_stdin: bool,
        #[arg(long, value_enum, default_value = "tun")]
        mode: ConnectMode,
        #[arg(long, default_value = "127.0.0.1:1080")]
        listen: SocketAddr,
    },
}

fn profile(gateway: &str, pin: Option<&str>) -> Result<Value> {
    validate_gateway(gateway)?;
    let url = Url::parse(gateway)?;
    let pin = pin.or_else(|| {
        if url.host_str() == Some("166.111.77.32") && url.port_or_known_default() == Some(4430) {
            Some("012fa1b92104a5d514b903a7691e791e890452a499c6980cb590f89016464bb3")
        } else {
            None
        }
    });
    if let Some(pin) = pin {
        parse_sha256_pin(pin)?;
    }
    Ok(json!({
        "base_url": gateway.trim_end_matches('/'),
        "timeout_seconds": 15,
        "user_agent": "EasyConnect_mac",
        "endpoints": {
            "discovery": "/por/login_auth.csp?apiversion=1",
            "password_config": "/public/psw_config?apiversion=1",
            "password_login": "/por/login_psw.csp?anti_replay=1&encrypt=1&apiversion=1",
            "session_config": "/por/conf.csp?apiversion=1",
            "resource_list": "/por/rclist.csp?apiversion=1",
            "logout": "/por/logout.csp?apiversion=1"
        },
        "tls": {"leaf_sha256": pin},
        "proxy": {"auto_resources": true, "route_domains": [], "route_ipv4_cidrs": [], "vpn_dns_servers": []},
        "tunnel": {"mtu": 1400}
    }))
}

pub(crate) fn validate_gateway(gateway: &str) -> Result<()> {
    let url = Url::parse(gateway).context("invalid gateway URL")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        bail!("gateway must be an HTTPS origin without credentials, path, query or fragment");
    }
    Ok(())
}

fn load_profile(path: &PathBuf, require_routes: bool) -> Result<Value> {
    let bytes = std::fs::read(path).context("cannot read profile")?;
    if bytes.len() > 64 * 1024 {
        bail!("profile exceeds 64 KiB");
    }
    let config: Value = serde_json::from_slice(&bytes).context("invalid profile JSON")?;
    validate_gateway(config["base_url"].as_str().context("missing base_url")?)?;
    if let Some(pin) = config["tls"]["leaf_sha256"].as_str() {
        parse_sha256_pin(pin)?;
    }
    for key in [
        "discovery",
        "password_config",
        "password_login",
        "session_config",
        "resource_list",
        "logout",
    ] {
        let endpoint = config["endpoints"][key]
            .as_str()
            .context("missing endpoint")?;
        if !endpoint.starts_with('/') || endpoint.starts_with("//") {
            bail!("endpoint {key} must be a same-origin path");
        }
    }
    let timeout = config["timeout_seconds"]
        .as_u64()
        .context("invalid timeout_seconds")?;
    if !(1..=60).contains(&timeout) {
        bail!("timeout_seconds must be within 1..60");
    }
    let mtu = config["tunnel"]["mtu"].as_u64().context("invalid mtu")?;
    if !(576..=1500).contains(&mtu) {
        bail!("mtu must be within 576..1500");
    }
    configured_dns(&config)?;
    let domains = config["proxy"]["route_domains"]
        .as_array()
        .context("route_domains must be an array")?;
    let cidrs = config["proxy"]["route_ipv4_cidrs"]
        .as_array()
        .context("route_ipv4_cidrs must be an array")?;
    let auto = config["proxy"]["auto_resources"].as_bool().unwrap_or(true);
    if require_routes && (!auto || !domains.is_empty() || !cidrs.is_empty()) {
        RoutePolicy::from_config(&config)
            .context("add the intranet domains or IPv4 CIDRs to proxy routes")?;
    }
    Ok(config)
}

fn configured_dns(config: &Value) -> Result<Vec<Ipv4Addr>> {
    let values = config["proxy"]["vpn_dns_servers"]
        .as_array()
        .context("vpn_dns_servers must be an array")?;
    if values.len() > 4 {
        bail!("at most four VPN DNS servers are supported");
    }
    values
        .iter()
        .map(|v| {
            let ip: Ipv4Addr = v.as_str().context("DNS must be an IPv4 string")?.parse()?;
            if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
                bail!("invalid VPN DNS address");
            }
            Ok(ip)
        })
        .collect()
}

fn credentials(
    username: Option<String>,
    stdin: bool,
    controlled: bool,
) -> Result<(Zeroizing<String>, Zeroizing<String>)> {
    if controlled {
        use std::io::{BufRead, Read};
        let mut input = std::io::stdin().lock();
        let mut lines = Vec::new();
        for _ in 0..2 {
            let mut bytes = Zeroizing::new(Vec::new());
            input.by_ref().take(8193).read_until(b'\n', &mut bytes)?;
            if bytes.len() > 8192 || bytes.last() != Some(&b'\n') {
                bail!("invalid controlled credential input");
            }
            bytes.pop();
            lines.push(Zeroizing::new(String::from_utf8(bytes.to_vec())?));
        }
        let password = lines.pop().context("missing password")?;
        let username = lines.pop().context("missing username")?;
        drop(input);
        std::thread::spawn(|| {
            let mut line = String::new();
            let _ = std::io::stdin().read_line(&mut line);
            crate::service::STOP.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        return Ok((username, password));
    }
    if stdin {
        return Ok(read_credentials(io::stdin().lock())?);
    }
    let username = match username {
        Some(name) => name,
        None => {
            eprint!("VPN username: ");
            io::stderr().flush()?;
            let mut line = String::new();
            io::stdin().read_line(&mut line)?;
            line.trim_end_matches(['\r', '\n']).to_owned()
        }
    };
    let password = Zeroizing::new(rpassword::prompt_password("VPN password: ")?);
    if username.trim().is_empty() || password.is_empty() {
        bail!("username and password must be non-empty");
    }
    Ok((Zeroizing::new(username), password))
}

fn discover(config: Value, tunnel_handshake: bool) -> Result<()> {
    let pin = config["tls"]["leaf_sha256"]
        .as_str()
        .map(parse_sha256_pin)
        .transpose()?;
    let session = GatewaySession::new_with_pin(
        config["base_url"]
            .as_str()
            .context("missing gateway")?
            .to_owned(),
        "EasyConnect_mac".into(),
        config["timeout_seconds"].as_u64().unwrap_or(15),
        pin,
    )?;
    let path = config["endpoints"]["discovery"]
        .as_str()
        .context("missing discovery")?;
    let (body, _, status) = session.request("discovery", path, ec_compat_http_get(), None)?;
    let body = Zeroizing::new(body);
    let doc = parse_xml(&body, "discovery")?;
    let root = doc.root_element();
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "http_status": status,
            "gateway_version": first_descendant_text(root, "VPNVERSION"),
            "start_auth": first_descendant_text(root, "StartAuth"),
            "captcha": first_descendant_text(root, "RndImg"),
            "error_code": first_descendant_text(root, "ErrorCode"),
            "mid_attack_check": first_descendant_text(root, "MID_ATK_CHECK"),
            "credentials_submitted": false,
            "tunnel_verified": false
        }))?
    );
    if tunnel_handshake {
        let pin = pin.context("tunnel handshake probe requires an explicit certificate pin")?;
        let contract = probe_special_tls_contract(
            config["base_url"].as_str().context("missing gateway")?,
            Duration::from_secs(10),
            &pin,
            None,
        )?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "tunnel_handshake": "modern",
                "tls_version": contract.protocol_version,
                "cipher_suite": contract.cipher_suite,
                "certificate_verified": contract.certificate_verified,
                "certificate_verification": contract.certificate_verification,
                "tunnel_verified": false
            }))?
        );
        if !contract.certificate_verified {
            bail!("tunnel certificate differs from configured HTTPS certificate pin");
        }
    }
    Ok(())
}

fn ec_compat_http_get() -> reqwest::Method {
    reqwest::Method::GET
}

fn list_resources(
    config: Value,
    username: Zeroizing<String>,
    password: Zeroizing<String>,
) -> Result<()> {
    let session = AuthenticatedEngineSession::authenticate(&config, &username, &password)?;
    let result = session
        .resource_xml()
        .map_err(anyhow::Error::from)
        .and_then(|xml| {
            let resources = PublishedResources::parse(&xml)?;
            println!("{}", serde_json::to_string_pretty(&resources.summary())?);
            Ok(())
        });
    let logout = session.logout();
    result?;
    logout.context("resource listing succeeded but logout did not complete")?;
    Ok(())
}

async fn connect(
    config: Value,
    username: Zeroizing<String>,
    password: Zeroizing<String>,
    bind: SocketAddr,
    mode: ConnectMode,
) -> Result<()> {
    if mode == ConnectMode::Socks && (!bind.ip().is_loopback() || bind.port() == 0) {
        bail!("SOCKS listener must use a loopback address and a nonzero port");
    }
    let configured_dns = configured_dns(&config)?;
    let mtu = config["tunnel"]["mtu"].as_u64().context("missing mtu")? as usize;
    let service_config = config.clone();
    // reqwest's blocking client must be created, used, and dropped outside Tokio workers.
    let (session, published, policy) = tokio::task::spawn_blocking(move || -> Result<_> {
        let session = AuthenticatedEngineSession::authenticate(&config, &username, &password)?;
        let result = (|| -> Result<_> {
            let xml = session.resource_xml()?;
            let published = PublishedResources::parse(&xml)?;
            let policy = published.route_policy(&config)?;
            Ok((published, Arc::new(policy)))
        })();
        match result {
            Ok((published, policy)) => Ok((session, published, policy)),
            Err(error) => {
                let _ = session.logout();
                Err(error)
            }
        }
    })
    .await??;
    println!(
        "Loaded {} published resources, {} groups; default resource: {}",
        published.entries.len(),
        published.groups.len(),
        published.default_resource
    );
    if published.skipped_hosts > 0 {
        eprintln!(
            "{} resource hosts had unsupported formats and were omitted from automatic routes",
            published.skipped_hosts
        );
    }
    let mut dns = session.dns_servers();
    if dns.is_empty() {
        dns = published.dns_servers.iter().copied().collect();
    }
    if dns.is_empty() {
        dns = configured_dns;
    }
    let (session, plane) =
        tokio::task::spawn_blocking(move || match session.establish_data_plane() {
            Ok(plane) => Ok((session, plane)),
            Err(error) => {
                if session.logout().is_err() {
                    eprintln!("logout after tunnel failure did not complete");
                }
                Err(error)
            }
        })
        .await??;
    let service_result = if mode == ConnectMode::Tun {
        tun::run(plane, published, policy, service_config, dns, mtu).await
    } else {
        async {
        let stack = Arc::new(VirtualNetstack::start(plane, mtu)?);
        let fallback: Arc<dyn NameResolver> = if dns.is_empty() {
            eprintln!("No VPN DNS supplied. Gateway static DNS records and IP targets work; configure proxy.vpn_dns_servers for other domain targets.");
            Arc::new(RejectDomainResolver)
        } else { Arc::new(VpnDnsResolver::new(Arc::clone(&stack), dns, Duration::from_secs(5))?) };
        let resolver: Arc<dyn NameResolver> = Arc::new(ResourceResolver { hosts: published.hosts, fallback });
        let server = SocksServer::new(bind, Arc::clone(&stack), resolver, policy)?.bind().await?;
        println!("Tunnel established; SOCKS5 listening on {bind}");
        let unhealthy = async {
            while stack.is_healthy() { tokio::time::sleep(Duration::from_secs(1)).await; }
        };
        tokio::select! {
            result = server.serve() => { result?; bail!("SOCKS service stopped"); },
            signal = shutdown_signal() => { signal?; Ok(()) },
            _ = unhealthy => { bail!("VPN data channel disconnected; reconnect by rerunning connect"); }
        }
    }.await
    };
    let logout = tokio::task::spawn_blocking(move || session.logout()).await?;
    if logout.is_err() {
        eprintln!("logout did not complete; the gateway may retain the session until timeout");
    }
    service_result
}

pub(crate) async fn shutdown_signal() -> Result<()> {
    let stopped = async {
        while !crate::service::STOP.load(std::sync::atomic::Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! { result = tokio::signal::ctrl_c() => result?, _ = term.recv() => {}, _=stopped=>{} }
    }
    #[cfg(not(unix))]
    tokio::select! {result=tokio::signal::ctrl_c()=>result?,_=stopped=>{}}
    Ok(())
}

#[tokio::main]
pub async fn run() -> Result<()> {
    match Cli::parse().command {
        Command::InstallService { owner } => crate::service::install(&owner),
        Command::Service { owner } => {
            #[cfg(target_os = "windows")]
            {
                crate::service::run_windows(owner)
            }
            #[cfg(not(target_os = "windows"))]
            {
                let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                let flag = stop.clone();
                tokio::spawn(async move {
                    let _ = shutdown_signal().await;
                    flag.store(true, std::sync::atomic::Ordering::Relaxed);
                });
                tokio::task::spawn_blocking(move || crate::service::run(&owner, stop)).await?
            }
        }
        Command::TunSelfTest => {
            tun::preflight()?;
            tun::self_test().await
        }
        Command::Init {
            gateway,
            cert_sha256,
            output,
        } => {
            let config = profile(&gateway, cert_sha256.as_deref())?;
            if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)?;
            }
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output)
                .context("profile exists or cannot be created")?;
            writeln!(file, "{}", serde_json::to_string_pretty(&config)?)?;
            println!(
                "Created {}. Routes default to authenticated gateway resources.",
                output.display()
            );
            Ok(())
        }
        Command::Discover {
            target,
            tunnel_handshake,
        } => {
            let config = target.resolve(false)?;
            tokio::task::spawn_blocking(move || discover(config, tunnel_handshake)).await?
        }
        Command::CheckConfig { config } => {
            load_profile(&config, true)?;
            println!("Profile valid");
            Ok(())
        }
        Command::Resources {
            target,
            username,
            credentials_stdin,
        } => {
            let config = target.resolve(false)?;
            tokio::task::spawn_blocking(move || {
                let (username, password) = credentials(username, credentials_stdin, false)?;
                list_resources(config, username, password)
            })
            .await?
        }
        Command::Connect {
            target,
            username,
            credentials_stdin,
            shutdown_stdin,
            listen,
            mode,
        } => {
            let config = target.resolve(true)?;
            let brokered = mode == ConnectMode::Tun
                && tun::preflight().is_err()
                && crate::service::installed();
            if mode == ConnectMode::Tun && !brokered {
                tun::preflight()?;
            }
            if mode == ConnectMode::Socks && (!listen.ip().is_loopback() || listen.port() == 0) {
                bail!("SOCKS must listen on loopback with nonzero port");
            }
            let (username, password) = tokio::task::spawn_blocking(move || {
                credentials(username, credentials_stdin, shutdown_stdin)
            })
            .await??;
            if brokered {
                return connect_brokered(config, username, password).await;
            }
            connect(config, username, password, listen, mode).await
        }
    }
}

async fn connect_brokered(
    config: Value,
    username: Zeroizing<String>,
    password: Zeroizing<String>,
) -> Result<()> {
    if !config["proxy"]["auto_resources"].as_bool().unwrap_or(true)
        || config["proxy"]["route_domains"]
            .as_array()
            .is_some_and(|v| !v.is_empty())
        || config["proxy"]["route_ipv4_cidrs"]
            .as_array()
            .is_some_and(|v| !v.is_empty())
    {
        bail!(
            "brokered CLI connections use gateway defaults; custom routing still requires direct elevation"
        );
    }
    let request = crate::service::Request::Connect {
        gateway: config["base_url"]
            .as_str()
            .context("missing gateway")?
            .to_owned(),
        username: username.to_string(),
        password: password.to_string(),
        cert_sha256: config["tls"]["leaf_sha256"].as_str().map(str::to_owned),
    };
    tokio::task::spawn_blocking(move || crate::service::request(request)).await??;
    let watch = async {
        let mut seen = 0;
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let status = tokio::task::spawn_blocking(|| {
                crate::service::request(crate::service::Request::Status)
            })
            .await??;
            for line in status.logs.iter().skip(seen) {
                println!("{line}");
            }
            seen = status.logs.len();
            if matches!(
                status.phase,
                crate::service::Phase::Disconnected | crate::service::Phase::Failed
            ) {
                bail!("background connection ended");
            }
        }
    };
    let result = tokio::select! {result=watch=>result,result=shutdown_signal()=>result};
    tokio::task::spawn_blocking(|| crate::service::request(crate::service::Request::Disconnect))
        .await??;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn url_only_uses_defaults_and_binds_known_pin_to_exact_gateway() {
        let known = profile("https://166.111.77.32:4430/", None).unwrap();
        assert!(known["tls"]["leaf_sha256"].is_string());
        assert_eq!(known["proxy"]["auto_resources"], true);
        for url in ["https://166.111.77.32:443", "https://example.com:4430"] {
            assert!(profile(url, None).unwrap()["tls"]["leaf_sha256"].is_null());
        }
        let override_pin = "00".repeat(32);
        assert_eq!(
            profile("https://166.111.77.32:4430", Some(&override_pin)).unwrap()["tls"]["leaf_sha256"],
            override_pin
        );
    }
    #[test]
    fn cli_requires_one_gateway_source() {
        assert!(
            Cli::try_parse_from([
                "easy-connect",
                "connect",
                "--gateway",
                "https://example.com"
            ])
            .is_ok()
        );
        assert!(Cli::try_parse_from(["easy-connect", "connect", "--config", "test.json"]).is_ok());
        assert!(Cli::try_parse_from(["easy-connect", "connect"]).is_err());
        assert!(
            Cli::try_parse_from([
                "easy-connect",
                "connect",
                "--config",
                "test.json",
                "--gateway",
                "https://example.com"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "easy-connect",
                "connect",
                "--config",
                "test.json",
                "--cert-sha256",
                "00"
            ])
            .is_err()
        );
    }
    #[test]
    fn gateway_is_an_https_origin_without_credentials() {
        for url in [
            "http://example.com",
            "https://u:p@example.com",
            "https://example.com/x",
            "https://example.com/?secret=x",
            "https://example.com/#x",
        ] {
            assert!(validate_gateway(url).is_err());
        }
        assert!(validate_gateway("https://166.111.77.32:4430/").is_ok());
    }
    #[test]
    fn profile_requires_explicit_routes() {
        let mut config = profile("https://example.com", None).unwrap();
        assert!(RoutePolicy::from_config(&config).is_err());
        config["proxy"]["route_ipv4_cidrs"] = json!(["10.0.0.0/8"]);
        assert!(
            RoutePolicy::from_config(&config)
                .unwrap()
                .allows_ipv4("10.1.2.3".parse().unwrap())
        );
    }
    #[test]
    fn dns_rejects_invalid_addresses() {
        let mut config = profile("https://example.com", None).unwrap();
        for address in ["0.0.0.0", "224.0.0.1", "255.255.255.255", "example.com"] {
            config["proxy"]["vpn_dns_servers"] = json!([address]);
            assert!(configured_dns(&config).is_err());
        }
    }
}
