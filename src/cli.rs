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
use ec_compat::session_status::{SessionEndReason, SessionStatus};
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
    /// Check local TUN and ICMP forwarding without a VPN login.
    TunSelfTest {
        /// Also test a Linux network namespace through source NAT.
        #[cfg(target_os = "linux")]
        #[arg(long)]
        forwarding: bool,
    },
    /// Withdraw VPN subnet advertisements left by an interrupted Linux worker.
    #[cfg(target_os = "linux")]
    LinuxCleanup,
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
    /// Change the VPN account password interactively, without starting a tunnel.
    ChangePassword {
        #[command(flatten)]
        target: GatewayArgs,
        #[arg(long)]
        username: Option<String>,
    },
    /// Connect using TUN (default) or loopback SOCKS5.
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

pub(crate) fn profile(gateway: &str, pin: Option<&str>) -> Result<Value> {
    validate_gateway(gateway)?;
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
    if !config["tunnel"]["share_with_tailscale"].is_null()
        && !config["tunnel"]["share_with_tailscale"].is_boolean()
    {
        bail!("tunnel.share_with_tailscale must be a boolean");
    }
    #[cfg(not(target_os = "linux"))]
    if config["tunnel"]["share_with_tailscale"].as_bool() == Some(true) {
        bail!("Tailscale sharing currently supports Linux only");
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
        crate::service::CONTROLLED.store(true, std::sync::atomic::Ordering::Relaxed);
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
    let prepared = tokio::task::spawn_blocking(move || -> Result<_> {
        if connection_cancelled() {
            return Ok(None);
        }
        let session = match AuthenticatedEngineSession::authenticate(&config, &username, &password)
        {
            Ok(session) => session,
            Err(_) if connection_cancelled() => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if connection_cancelled() {
            let _ = session.logout();
            return Ok(None);
        }
        if let Some(policy) = session.password_policy() {
            eprintln!("{} {}", policy.message(), policy.marker());
        }
        let result = (|| -> Result<_> {
            let xml = session.resource_xml()?;
            let published = PublishedResources::parse(&xml)?;
            let policy = published.route_policy(&config)?;
            Ok((published, Arc::new(policy)))
        })();
        match result {
            Ok((published, policy)) => Ok(Some((session, published, policy))),
            Err(error) => {
                let _ = session.logout();
                if connection_cancelled() {
                    Ok(None)
                } else {
                    Err(error)
                }
            }
        }
    })
    .await??;
    let Some((session, published, policy)) = prepared else {
        return Ok(());
    };
    println!(
        "Loaded {} published resources, {} groups; default resource: {}",
        published.entries.len(),
        published.groups.len(),
        published.default_resource
    );
    if crate::service::CONTROLLED.load(std::sync::atomic::Ordering::Relaxed)
        && let Err(error) = crate::resources::ResourceCatalog::from_published(&published)
            .write_events(std::io::stdout().lock())
    {
        let _ = tokio::task::spawn_blocking(move || session.logout()).await;
        return Err(error.into());
    }
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
    let established = tokio::task::spawn_blocking(move || {
        if connection_cancelled() {
            let _ = session.logout();
            return Ok(None);
        }
        match session.establish_data_plane() {
            Ok(plane) if connection_cancelled() => {
                drop(plane);
                let _ = session.logout();
                Ok(None)
            }
            Ok(plane) => Ok(Some((session, plane))),
            Err(error) => {
                if connection_cancelled() {
                    let _ = session.logout();
                    return Ok(None);
                }
                if session.logout().is_err() {
                    eprintln!("logout after tunnel failure did not complete");
                }
                Err(error)
            }
        }
    })
    .await??;
    let Some((session, mut plane)) = established else {
        return Ok(());
    };
    let health_events = plane.take_health_events();
    let service = async {
        if mode == ConnectMode::Tun {
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
        }
    };
    let (finish, finished) = tokio::sync::oneshot::channel();
    let monitor = monitor_session(
        session,
        |session: AuthenticatedEngineSession| async move {
            tokio::task::spawn_blocking(move || {
                let status = session.session_status();
                (session, status)
            })
            .await
            .map_err(anyhow::Error::from)
        },
        finished,
        health_events,
    );
    tokio::pin!(service, monitor);
    let (service_result, session, reason) = tokio::select! {
        // Manual cancellation wins if the service and monitor finish together.
        biased;
        result = &mut service => {
            let cancelled = result.is_ok() || connection_cancelled();
            if !cancelled && let Err(error) = &result {
                eprintln!("VPN data service stopped: {error:#}");
            }
            let _ = finish.send(!cancelled);
            let (session, reason) = monitor.await?;
            let cancelled = cancelled || connection_cancelled();
            (if cancelled { Ok(()) } else { result }, session, if cancelled { None } else { reason })
        },
        monitored = &mut monitor => {
            let cancelled = connection_cancelled();
            // Do not drop tun::run: allow DNS/routes and all packet workers to
            // clean up through its existing cooperative shutdown path.
            crate::service::STOP.store(true, std::sync::atomic::Ordering::Relaxed);
            let result = service.await;
            let (session, reason) = monitored?;
            (if cancelled { Ok(()) } else { result }, session, if cancelled { None } else { reason })
        },
    };
    if let Some(reason) = reason {
        eprintln!("{}", reason.marker());
    }
    // A confirmed remote logout needs no second logout request. In particular,
    // don't interfere with the replacement session after a private kick.
    let logout = tokio::task::spawn_blocking(move || {
        if reason.is_some_and(|reason| reason != SessionEndReason::ConnectionLost) {
            drop(session);
            Ok(())
        } else {
            session.logout()
        }
    })
    .await?;
    if logout.is_err() {
        eprintln!("logout did not complete; the gateway may retain the session until timeout");
    }
    if let Some(reason) = reason {
        return Err(SessionEnded(reason).into());
    }
    service_result
}

#[derive(Debug)]
pub struct SessionEnded(pub SessionEndReason);
impl std::fmt::Display for SessionEnded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.message())
    }
}
impl std::error::Error for SessionEnded {}

fn connection_cancelled() -> bool {
    crate::service::STOP.load(std::sync::atomic::Ordering::Relaxed)
}

/// Errors are strings, and XML parser details may contain gateway response
/// content. Log only reviewed fixed messages and bounded numeric HTTP statuses.
fn session_status_error_summary(error: &ec_compat::Error) -> &str {
    let message = error.0.as_str();
    match message {
        "gateway session status request failed (timeout)"
        | "gateway session status request failed (connect_or_tls)"
        | "gateway session status request failed (protocol_or_io)"
        | "gateway session status request failed (response_body)"
        | "gateway session status request failed (transport)"
        | "gateway session status response read failed"
        | "gateway session status response exceeds the size limit"
        | "gateway session status attempted a non-HTTPS response"
        | "gateway session status has an unexpected root"
        | "gateway session status has no error code"
        | "gateway returned an unsupported session status"
        | "gateway requested an unsupported session switch"
        | "session status: DTD/entity declarations are not accepted"
        | "cookie state unavailable"
        | "网关证书已变化，连接已停止；请联系管理员核实" => message,
        _ if message.starts_with("session status: invalid XML:") => {
            "session status: invalid XML (details redacted)"
        }
        _ if message.starts_with("session status: invalid UTF-8:") => {
            "session status: invalid UTF-8 (details redacted)"
        }
        _ => {
            if let Some(status) = message.strip_prefix("gateway session status returned HTTP ")
                && status.len() == 3
                && status.bytes().all(|byte| byte.is_ascii_digit())
                && status
                    .parse::<u16>()
                    .is_ok_and(|code| (100..=599).contains(&code))
            {
                return message;
            }
            "unclassified session status error (details redacted)"
        }
    }
}

/// The state stays on a blocking worker during each HTTPS request. We always
/// await that worker (including on cancellation) so reqwest is never dropped
/// on an async runtime thread and no authenticated session is abandoned. Healthy
/// transports never query the portal: only transport faults or the final service
/// failure trigger a query to distinguish connectivity loss from remote logout.
async fn monitor_session<S, F, Fut>(
    mut session: S,
    mut query: F,
    mut finished: tokio::sync::oneshot::Receiver<bool>,
    mut health_events: tokio::sync::mpsc::Receiver<()>,
) -> Result<(S, Option<SessionEndReason>)>
where
    F: FnMut(S) -> Fut,
    Fut: std::future::Future<Output = Result<(S, ec_compat::Result<SessionStatus>)>>,
{
    let mut failures = 0_u32;
    let mut health_events_open = true;
    loop {
        let mut final_query = tokio::select! {
            biased;
            command = &mut finished => {
                if command != Ok(true) { return Ok((session, None)); }
                true
            },
            event = health_events.recv(), if health_events_open => {
                if event.is_none() {
                    // Closing the transport notification stream does not itself
                    // prove a failure; the data service owns the final outcome.
                    health_events_open = false;
                    continue;
                }
                false
            },
        };
        let (returned, status) = query(session).await?;
        session = returned;
        if !final_query {
            match finished.try_recv() {
                Ok(false) | Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                    return Ok((session, None));
                }
                Ok(true) => final_query = true,
                Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
            }
        }
        match status {
            Ok(SessionStatus::Ended(reason)) => return Ok((session, Some(reason))),
            Ok(SessionStatus::Online) if !final_query => {
                if failures > 0 {
                    eprintln!("VPN session status query recovered");
                }
                failures = 0;
            }
            Err(error) if !final_query => {
                // The portal and packet transport are independent connections.
                // An unavailable/unsupported status endpoint does not prove
                // that the data channel failed. Its owner monitors actual I/O.
                failures = failures.saturating_add(1_u32);
                if failures == 1 || failures.is_multiple_of(6) {
                    eprintln!(
                        "VPN session status query failed ({failures} consecutive transport events): {}; allowing data channel recovery",
                        session_status_error_summary(&error)
                    );
                }
            }
            Err(error) => {
                eprintln!(
                    "VPN final session status query failed: {}",
                    session_status_error_summary(&error)
                );
                return Ok((session, Some(SessionEndReason::ConnectionLost)));
            }
            // A broken data channel with an online/unknown control session is
            // a connectivity failure, never evidence of a private kick.
            _ => return Ok((session, Some(SessionEndReason::ConnectionLost))),
        }
    }
}

pub(crate) async fn shutdown_signal() -> Result<()> {
    let stopped = async {
        while !crate::service::STOP.load(std::sync::atomic::Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    if crate::service::CONTROLLED.load(std::sync::atomic::Ordering::Relaxed) {
        stopped.await;
        return Ok(());
    }
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
        #[cfg(target_os = "linux")]
        Command::LinuxCleanup => tun::linux::cleanup(),
        Command::TunSelfTest {
            #[cfg(target_os = "linux")]
            forwarding,
        } => {
            tun::preflight()?;
            #[cfg(target_os = "linux")]
            if forwarding {
                return tun::linux::self_test_forwarding().await;
            }
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
        Command::ChangePassword { target, username } => {
            let config = target.resolve(false)?;
            tokio::task::spawn_blocking(move || -> Result<()> {
                let (username, old) = credentials(username, false, false)?;
                let new = Zeroizing::new(rpassword::prompt_password("New VPN password: ")?);
                let confirm = Zeroizing::new(rpassword::prompt_password("Confirm new password: ")?);
                if new.as_str() != confirm.as_str() {
                    bail!("两次输入的新密码不一致");
                }
                ec_compat::password::change_password(&config, &username, &old, &new)?;
                println!("密码已更新，请使用新密码重新连接。");
                Ok(())
            })
            .await?
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
    fn session_status_error_logs_preserve_only_reviewed_diagnostics() {
        for message in [
            "gateway session status request failed (timeout)",
            "gateway session status request failed (connect_or_tls)",
            "gateway session status returned HTTP 401",
            "gateway returned an unsupported session status",
            "gateway requested an unsupported session switch",
        ] {
            assert_eq!(
                session_status_error_summary(&ec_compat::Error(message.into())),
                message
            );
        }
        for (message, expected) in [
            (
                "session status: invalid XML: unknown entity 'private-token'",
                "session status: invalid XML (details redacted)",
            ),
            (
                "session status: invalid UTF-8: private-token",
                "session status: invalid UTF-8 (details redacted)",
            ),
            (
                "gateway session status returned HTTP 401 private-token",
                "unclassified session status error (details redacted)",
            ),
            (
                "gateway session status request failed (timeout) private-token",
                "unclassified session status error (details redacted)",
            ),
            (
                "request failed: https://vpn.example/?exdata=private-token",
                "unclassified session status error (details redacted)",
            ),
            (
                "gateway requested an unsupported session switch: private-token",
                "unclassified session status error (details redacted)",
            ),
        ] {
            assert_eq!(
                session_status_error_summary(&ec_compat::Error(message.into())),
                expected
            );
        }
    }

    fn queued_health_events(count: usize) -> tokio::sync::mpsc::Receiver<()> {
        let (events, receiver) = tokio::sync::mpsc::channel(count.max(1));
        for _ in 0..count {
            events.try_send(()).unwrap();
        }
        receiver
    }

    #[tokio::test]
    async fn session_monitor_cancellation_never_queries_or_reports_a_failure() {
        let (finish, finished) = tokio::sync::oneshot::channel();
        finish.send(false).unwrap();
        let (_, reason) = monitor_session(
            (),
            |_| async {
                panic!("manual cancellation must win over a queued transport fault");
                #[allow(unreachable_code)]
                Ok(((), Ok(SessionStatus::Online)))
            },
            finished,
            queued_health_events(1),
        )
        .await
        .unwrap();
        assert_eq!(reason, None);
    }

    #[tokio::test]
    async fn healthy_session_never_queries_the_gateway() {
        let (finish, finished) = tokio::sync::oneshot::channel();
        let (_events, health_events) = tokio::sync::mpsc::channel(1);
        let monitor = monitor_session(
            (),
            |_| async {
                panic!("healthy transports must not query the gateway");
                #[allow(unreachable_code)]
                Ok(((), Ok(SessionStatus::Online)))
            },
            finished,
            health_events,
        );
        tokio::pin!(monitor);
        assert!(
            tokio::time::timeout(Duration::from_millis(30), &mut monitor)
                .await
                .is_err()
        );
        finish.send(false).unwrap();
        assert_eq!(monitor.await.unwrap().1, None);
    }

    #[tokio::test]
    async fn closed_health_stream_waits_for_service_and_does_not_query() {
        let (finish, finished) = tokio::sync::oneshot::channel();
        let monitor = monitor_session(
            (),
            |_| async {
                panic!("closed health stream alone is not a failed service");
                #[allow(unreachable_code)]
                Ok(((), Ok(SessionStatus::Online)))
            },
            finished,
            queued_health_events(0),
        );
        tokio::pin!(monitor);
        // This also catches a recv(None) loop: such a loop starves the timer.
        assert!(
            tokio::time::timeout(Duration::from_millis(30), &mut monitor)
                .await
                .is_err()
        );
        finish.send(false).unwrap();
        assert_eq!(monitor.await.unwrap().1, None);
    }

    #[tokio::test]
    async fn session_monitor_manual_cancel_during_query_suppresses_kick() {
        let (finish, finished) = tokio::sync::oneshot::channel();
        let mut finish = Some(finish);
        let (_, reason) = monitor_session(
            (),
            |_| {
                finish.take().unwrap().send(false).unwrap();
                async { Ok(((), Ok(SessionStatus::Ended(SessionEndReason::PrivateKick)))) }
            },
            finished,
            queued_health_events(1),
        )
        .await
        .unwrap();
        assert_eq!(reason, None);
    }

    #[tokio::test]
    async fn service_failure_during_query_reuses_its_result() {
        let (finish, finished) = tokio::sync::oneshot::channel();
        let mut finish = Some(finish);
        let (calls, reason) = monitor_session(
            0,
            |calls| {
                finish
                    .take()
                    .expect("one query is sufficient")
                    .send(true)
                    .unwrap();
                async move { Ok((calls + 1, Ok(SessionStatus::Online))) }
            },
            finished,
            queued_health_events(1),
        )
        .await
        .unwrap();
        assert_eq!(calls, 1);
        assert_eq!(reason, Some(SessionEndReason::ConnectionLost));
    }

    #[tokio::test]
    async fn broken_channel_checks_reason_and_never_assumes_private_kick() {
        for (status, expected) in [
            (Ok(SessionStatus::Online), SessionEndReason::ConnectionLost),
            (
                Ok(SessionStatus::Ended(SessionEndReason::PrivateKick)),
                SessionEndReason::PrivateKick,
            ),
            (
                Ok(SessionStatus::Ended(SessionEndReason::Unknown)),
                SessionEndReason::Unknown,
            ),
            (
                Err(ec_compat::Error("network".into())),
                SessionEndReason::ConnectionLost,
            ),
        ] {
            let (finish, finished) = tokio::sync::oneshot::channel();
            finish.send(true).unwrap();
            let mut status = Some(status);
            let (calls, reason) = monitor_session(
                0,
                |calls| {
                    let status = status.take().expect("only one final query");
                    async move { Ok((calls + 1, status)) }
                },
                finished,
                queued_health_events(1),
            )
            .await
            .unwrap();
            assert_eq!(calls, 1);
            assert_eq!(reason, Some(expected));
        }
    }

    #[tokio::test]
    async fn monitor_tolerates_transient_events_until_remote_logout_is_confirmed() {
        let (_finish, finished) = tokio::sync::oneshot::channel();
        let responses = [
            Err(ec_compat::Error("network".into())),
            Ok(SessionStatus::Online),
            Err(ec_compat::Error("network".into())),
            Err(ec_compat::Error("network".into())),
            Ok(SessionStatus::Ended(SessionEndReason::AdminKick)),
        ];
        let mut responses = responses.into_iter();
        let (calls, reason) = monitor_session(
            0,
            |calls| {
                let response = responses.next().expect("monitor should stop once ended");
                async move { Ok((calls + 1, response)) }
            },
            finished,
            queued_health_events(5),
        )
        .await
        .unwrap();
        assert_eq!(calls, 5);
        assert_eq!(reason, Some(SessionEndReason::AdminKick));
    }

    #[tokio::test]
    async fn repeated_status_errors_do_not_interrupt_transport_recovery() {
        let (_finish, finished) = tokio::sync::oneshot::channel();
        let (calls, reason) = monitor_session(
            0,
            |calls| async move {
                let status = if calls < 8 {
                    Err(ec_compat::Error("network".into()))
                } else {
                    Ok(SessionStatus::Ended(SessionEndReason::AdminKick))
                };
                Ok((calls + 1, status))
            },
            finished,
            queued_health_events(9),
        )
        .await
        .unwrap();
        assert_eq!(calls, 9);
        assert_eq!(reason, Some(SessionEndReason::AdminKick));
    }

    #[tokio::test]
    async fn status_error_waits_for_a_new_transport_event() {
        let (finish, finished) = tokio::sync::oneshot::channel();
        let (events, health_events) = tokio::sync::mpsc::channel(1);
        events.try_send(()).unwrap();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let monitor = monitor_session(
            (),
            move |_| {
                observed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                async { Ok(((), Err(ec_compat::Error("network".into())))) }
            },
            finished,
            health_events,
        );
        tokio::pin!(monitor);
        assert!(
            tokio::time::timeout(Duration::from_millis(30), &mut monitor)
                .await
                .is_err()
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
        finish.send(false).unwrap();
        assert_eq!(monitor.await.unwrap().1, None);
    }

    #[test]
    fn generated_profiles_use_only_explicit_certificate_pins() {
        let generated = profile("https://vpn.example.com:4430/", None).unwrap();
        assert!(generated["tls"]["leaf_sha256"].is_null());
        assert_eq!(generated["proxy"]["auto_resources"], true);
        let pin = "ab".repeat(32);
        assert_eq!(
            profile("https://vpn.example.com:4430", Some(&pin)).unwrap()["tls"]["leaf_sha256"],
            pin
        );
        assert!(profile("https://vpn.example.com", Some("invalid")).is_err());
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
        assert!(validate_gateway("https://vpn.example.com:4430/").is_ok());
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
