use ec_compat::engine::dns::{DirectDnsResolver, VpnDnsResolver};
use ec_compat::engine::ip_packet::stack_mtu;
use ec_compat::engine::netstack::VirtualNetstack;
use ec_compat::engine::policy::RoutePolicy;
use ec_compat::engine::proxy::{NameResolver, RejectDomainResolver, SystemDnsResolver};
use ec_compat::engine::session::AuthenticatedEngineSession;
use ec_compat::engine::socks::SocksServer;
use ec_compat::probe::read_credentials;
use ec_compat::watch::load_json;
use ec_compat::{Error, Result};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const MAX_FALLBACK_DNS_SERVERS: usize = 4;
const MAX_VPN_DNS_SERVERS: usize = 4;
const MIN_KEEPALIVE_INTERVAL_SECONDS: u64 = 10;
const MAX_KEEPALIVE_INTERVAL_SECONDS: u64 = 300;
const MAX_KEEPALIVE_FAILURE_THRESHOLD: u64 = 10;
const RECONNECT_INITIAL_DELAY: Duration = Duration::from_secs(2);
const RECONNECT_MAX_DELAY: Duration = Duration::from_secs(60);
const PARENT_CHECK_INTERVAL: Duration = Duration::from_millis(250);
const PARENT_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

struct ParentLifetime {
    shutdown: tokio::sync::watch::Receiver<bool>,
    finished: Arc<AtomicBool>,
}

impl ParentLifetime {
    fn start(parent_pid: u32) -> Result<Self> {
        if current_parent_pid()? != parent_pid {
            return Err(Error(
                "--parent-pid must identify the engine's actual parent".into(),
            ));
        }
        let (sender, shutdown) = tokio::sync::watch::channel(false);
        let finished = Arc::new(AtomicBool::new(false));
        let watchdog_finished = Arc::clone(&finished);
        std::thread::Builder::new()
            .name("desktop-parent-watchdog".into())
            .spawn(move || {
                while !watchdog_finished.load(Ordering::Acquire) {
                    // Unix reparents an orphaned child. Checking our own parent
                    // avoids mistaking a reused PID for the desktop process.
                    if current_parent_pid().ok() != Some(parent_pid) {
                        eprintln!("ec-engine: desktop parent exited; stopping app-owned engine");
                        let _ = sender.send(true);
                        let deadline = Instant::now() + PARENT_SHUTDOWN_GRACE;
                        while !watchdog_finished.load(Ordering::Acquire) {
                            if Instant::now() >= deadline {
                                // Authentication, stdin and logout use blocking
                                // APIs. An independent thread also bounds exit
                                // when they cannot reach the graceful path.
                                std::process::exit(0);
                            }
                            std::thread::sleep(PARENT_CHECK_INTERVAL);
                        }
                        return;
                    }
                    std::thread::sleep(PARENT_CHECK_INTERVAL);
                }
            })
            .map_err(|_| Error("cannot monitor the desktop parent process".into()))?;
        Ok(Self { shutdown, finished })
    }

    async fn wait(&self) {
        let mut shutdown = self.shutdown.clone();
        while !*shutdown.borrow_and_update() {
            if shutdown.changed().await.is_err() {
                return;
            }
        }
    }
}

impl Drop for ParentLifetime {
    fn drop(&mut self) {
        self.finished.store(true, Ordering::Release);
    }
}

#[cfg(unix)]
fn current_parent_pid() -> Result<u32> {
    // getppid has no failure mode and does not dereference pointers.
    Ok(unsafe { libc::getppid() } as u32)
}

#[cfg(not(unix))]
fn current_parent_pid() -> Result<u32> {
    Err(Error(
        "--parent-pid is supported only on Unix platforms".into(),
    ))
}

fn parse_parent_pid(value: &str) -> Result<u32> {
    value
        .parse::<u32>()
        .ok()
        .filter(|pid| *pid > 0 && *pid <= i32::MAX as u32)
        .filter(|_| value.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or_else(|| Error("--parent-pid requires a positive process ID".into()))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KeepaliveConfig {
    domain: String,
    interval: Duration,
    failure_threshold: u32,
}

enum SessionOutcome {
    Shutdown(Result<()>),
    Disconnected(Error),
}

fn argument_value<'a>(args: &'a [String], name: &str) -> Result<&'a str> {
    args.iter()
        .position(|argument| argument == name)
        .and_then(|index| args.get(index + 1))
        .map(String::as_str)
        .ok_or_else(|| Error(format!("missing required argument: {name}")))
}

fn optional_argument_value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|argument| argument == name)
        .and_then(|index| args.get(index + 1))
        .map(String::as_str)
}

fn validate_arguments(args: &[String]) -> Result<()> {
    let mut config_seen = false;
    let mut credentials_seen = false;
    let mut socks_seen = false;
    let mut local_policy_seen = false;
    let mut parent_pid_seen = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--credentials-stdin" if !credentials_seen => {
                credentials_seen = true;
                index += 1;
            }
            "--config" if !config_seen => {
                config_seen = true;
                if args
                    .get(index + 1)
                    .is_none_or(|value| value.starts_with("--"))
                {
                    return Err(Error("--config requires one value".into()));
                }
                index += 2;
            }
            "--socks-bind" if !socks_seen => {
                socks_seen = true;
                if args
                    .get(index + 1)
                    .is_none_or(|value| value.starts_with("--"))
                {
                    return Err(Error("--socks-bind requires one value".into()));
                }
                index += 2;
            }
            "--local-policy" if !local_policy_seen => {
                local_policy_seen = true;
                if args
                    .get(index + 1)
                    .is_none_or(|value| value.starts_with("--"))
                {
                    return Err(Error("--local-policy requires one value".into()));
                }
                index += 2;
            }
            "--parent-pid" if !parent_pid_seen => {
                parent_pid_seen = true;
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| Error("--parent-pid requires one value".into()))?;
                parse_parent_pid(value)?;
                index += 2;
            }
            argument => {
                return Err(Error(format!(
                    "unsupported or duplicate engine argument: {argument}"
                )));
            }
        }
    }
    Ok(())
}

fn apply_local_policy(config: &mut serde_json::Value, policy: serde_json::Value) -> Result<()> {
    let object = policy
        .as_object()
        .ok_or_else(|| Error("local policy must be a JSON object".into()))?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "version" | "vpn_dns_servers" | "route_ipv4_cidrs"
        ) {
            return Err(Error(format!("unsupported local policy key: {key}")));
        }
    }
    if object.get("version").and_then(serde_json::Value::as_u64) != Some(1) {
        return Err(Error("local policy version must be 1".into()));
    }
    let vpn_dns_servers = object
        .get("vpn_dns_servers")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));
    let route_ipv4_cidrs = object
        .get("route_ipv4_cidrs")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));
    let proxy = config
        .get_mut("proxy")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| Error("engine profile proxy configuration is missing".into()))?;
    proxy.insert("vpn_dns_servers".into(), vpn_dns_servers);
    proxy.insert("route_ipv4_cidrs".into(), route_ipv4_cidrs);
    Ok(())
}

fn configured_fallback_dns_servers(config: &serde_json::Value) -> Result<Vec<Ipv4Addr>> {
    let value = &config["proxy"]["fallback_dns_servers"];
    if value.is_null() {
        return Ok(Vec::new());
    }
    let values = value
        .as_array()
        .filter(|values| values.len() <= MAX_FALLBACK_DNS_SERVERS)
        .ok_or_else(|| Error("proxy fallback DNS servers must be a bounded array".into()))?;
    let mut servers = Vec::new();
    for value in values {
        let server = value
            .as_str()
            .and_then(|value| value.parse::<Ipv4Addr>().ok())
            .filter(|server| {
                !server.is_unspecified() && !server.is_broadcast() && !server.is_multicast()
            })
            .ok_or_else(|| Error("proxy fallback DNS server is invalid".into()))?;
        if !servers.contains(&server) {
            servers.push(server);
        }
    }
    Ok(servers)
}

fn configured_vpn_dns_servers(config: &serde_json::Value) -> Result<Vec<Ipv4Addr>> {
    let value = &config["proxy"]["vpn_dns_servers"];
    if value.is_null() {
        return Ok(Vec::new());
    }
    let values = value
        .as_array()
        .filter(|values| values.len() <= MAX_VPN_DNS_SERVERS)
        .ok_or_else(|| Error("proxy VPN DNS servers must be a bounded array".into()))?;
    let mut servers = Vec::new();
    for value in values {
        let server = value
            .as_str()
            .and_then(|value| value.parse::<Ipv4Addr>().ok())
            .filter(|server| {
                !server.is_unspecified() && !server.is_broadcast() && !server.is_multicast()
            })
            .ok_or_else(|| Error("proxy VPN DNS server is invalid".into()))?;
        if !servers.contains(&server) {
            servers.push(server);
        }
    }
    Ok(servers)
}

fn configured_keepalive(
    config: &serde_json::Value,
    policy: &RoutePolicy,
) -> Result<Option<KeepaliveConfig>> {
    let domain_value = &config["tunnel"]["keepalive_domain"];
    let interval_value = &config["tunnel"]["keepalive_interval_seconds"];
    let failures_value = &config["tunnel"]["keepalive_failure_threshold"];
    if domain_value.is_null() && interval_value.is_null() && failures_value.is_null() {
        return Ok(None);
    }
    let domain = domain_value
        .as_str()
        .map(str::trim)
        .filter(|domain| !domain.is_empty())
        .ok_or_else(|| Error("tunnel keepalive domain must be a non-empty string".into()))?
        .to_ascii_lowercase();
    if !policy.allows_domain(&domain) {
        return Err(Error(
            "tunnel keepalive domain must be allowed by the campus route policy".into(),
        ));
    }
    let interval_seconds = interval_value
        .as_u64()
        .filter(|seconds| {
            (MIN_KEEPALIVE_INTERVAL_SECONDS..=MAX_KEEPALIVE_INTERVAL_SECONDS).contains(seconds)
        })
        .ok_or_else(|| {
            Error(format!(
                "tunnel keepalive interval must be within {MIN_KEEPALIVE_INTERVAL_SECONDS}..{MAX_KEEPALIVE_INTERVAL_SECONDS} seconds"
            ))
        })?;
    let failure_threshold = failures_value
        .as_u64()
        .filter(|failures| (1..=MAX_KEEPALIVE_FAILURE_THRESHOLD).contains(failures))
        .ok_or_else(|| {
            Error(format!(
                "tunnel keepalive failure threshold must be within 1..{MAX_KEEPALIVE_FAILURE_THRESHOLD}"
            ))
        })? as u32;
    Ok(Some(KeepaliveConfig {
        domain,
        interval: Duration::from_secs(interval_seconds),
        failure_threshold,
    }))
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("ec-engine: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    validate_arguments(&args)?;
    let parent = optional_argument_value(&args, "--parent-pid")
        .map(|value| ParentLifetime::start(parse_parent_pid(value)?))
        .transpose()?;
    if !args
        .iter()
        .any(|argument| argument == "--credentials-stdin")
    {
        return Err(Error(
            "--credentials-stdin is required; credential flags do not exist".into(),
        ));
    }
    let mut config = load_json(Path::new(argument_value(&args, "--config")?))?;
    if let Some(policy_path) = optional_argument_value(&args, "--local-policy") {
        let policy = load_json(Path::new(policy_path))?;
        apply_local_policy(&mut config, policy)?;
    }
    let bind = argument_value(&args, "--socks-bind")?
        .parse::<SocketAddr>()
        .map_err(|_| Error("--socks-bind is not a valid socket address".into()))?;
    let policy = Arc::new(RoutePolicy::from_config(&config)?);
    let keepalive = configured_keepalive(&config, &policy)?;
    let (username, password) = read_credentials(std::io::stdin().lock())?;

    let mut previously_connected = false;
    let mut reconnect_delay = RECONNECT_INITIAL_DELAY;
    loop {
        let delay = match run_connected_session(
            &config,
            bind,
            Arc::clone(&policy),
            &username,
            &password,
            keepalive.as_ref(),
            parent.as_ref(),
        )
        .await
        {
            Ok(SessionOutcome::Shutdown(logout)) => return logout,
            Ok(SessionOutcome::Disconnected(error)) => {
                previously_connected = true;
                reconnect_delay = RECONNECT_INITIAL_DELAY;
                eprintln!(
                    "ec-engine: {error}; reconnecting in {} seconds",
                    reconnect_delay.as_secs()
                );
                reconnect_delay
            }
            Err(error) if !previously_connected => return Err(error),
            Err(error) => {
                let delay = reconnect_delay;
                eprintln!(
                    "ec-engine: reconnect attempt failed: {error}; retrying in {} seconds",
                    delay.as_secs()
                );
                reconnect_delay = (reconnect_delay * 2).min(RECONNECT_MAX_DELAY);
                delay
            }
        };
        if shutdown_before_reconnect(delay, parent.as_ref()).await? {
            return Ok(());
        }
    }
}

async fn run_connected_session(
    config: &serde_json::Value,
    bind: SocketAddr,
    policy: Arc<RoutePolicy>,
    username: &Zeroizing<String>,
    password: &Zeroizing<String>,
    keepalive: Option<&KeepaliveConfig>,
    parent: Option<&ParentLifetime>,
) -> Result<SessionOutcome> {
    let session = AuthenticatedEngineSession::authenticate(config, username, password)?;
    let gateway_dns_servers = session.dns_servers();
    let data_plane = session.establish_data_plane()?;
    // Lowering this makes campus servers use smaller segments, which is what
    // reaches destinations whose path cannot carry a full-size packet.
    let mtu = stack_mtu(config["tunnel"]["mtu"].as_u64());
    let netstack = Arc::new(VirtualNetstack::start(data_plane, mtu)?);
    let health = Arc::clone(&netstack);
    let allow_system_dns_fallback = config["proxy"]["allow_system_dns_fallback"]
        .as_bool()
        .unwrap_or(false);
    let configured_vpn_dns_servers = configured_vpn_dns_servers(config)?;
    let fallback_dns_servers = configured_fallback_dns_servers(config)?;
    let vpn_dns_servers = if gateway_dns_servers.is_empty() {
        configured_vpn_dns_servers
    } else {
        gateway_dns_servers
    };
    let (resolver, vpn_resolver, dns_mode): (
        Arc<dyn NameResolver>,
        Option<Arc<VpnDnsResolver>>,
        &str,
    ) = if !vpn_dns_servers.is_empty() {
        let vpn_resolver = Arc::new(VpnDnsResolver::new(
            Arc::clone(&netstack),
            vpn_dns_servers,
            Duration::from_secs(5),
        )?);
        (vpn_resolver.clone(), Some(vpn_resolver), "VPN")
    } else if !fallback_dns_servers.is_empty() {
        eprintln!(
            "WARNING: gateway DNS is unavailable; allowed campus names use configured fallback DNS"
        );
        (
            Arc::new(DirectDnsResolver::new(
                fallback_dns_servers,
                Duration::from_secs(5),
            )?),
            None,
            "configured fallback",
        )
    } else if allow_system_dns_fallback {
        eprintln!("WARNING: gateway DNS is unavailable; allowed campus names use system DNS");
        (Arc::new(SystemDnsResolver), None, "system fallback")
    } else {
        (Arc::new(RejectDomainResolver), None, "disabled")
    };
    let server = SocksServer::new(bind, Arc::clone(&netstack), Arc::clone(&resolver), policy)?
        .bind()
        .await?;
    println!("Client IP assigned");
    println!("Proxy DNS mode: {dns_mode}");
    println!("Campus-only route policy: enforced");
    println!("Tunnel MTU: {mtu}");
    match (keepalive, vpn_resolver.as_ref()) {
        (Some(settings), Some(_)) => println!(
            "Tunnel keepalive: {} every {} seconds (reconnect after {} failures)",
            settings.domain,
            settings.interval.as_secs(),
            settings.failure_threshold
        ),
        (Some(_), None) => eprintln!(
            "WARNING: VPN DNS is unavailable; end-to-end keepalive is disabled (TCP keepalive remains active)"
        ),
        (None, _) => println!("Tunnel keepalive: TCP only"),
    }
    println!("SOCKS5 server listening on {bind} (TCP CONNECT + UDP ASSOCIATE)");
    let mut services = tokio::task::JoinSet::new();
    services.spawn(async move {
        server
            .serve()
            .await
            .map_err(|error| Error(format!("SOCKS5 service failed: {error}")))
    });
    if let (Some(settings), Some(vpn_resolver)) = (keepalive.cloned(), vpn_resolver) {
        services.spawn(async move { run_keepalive(vpn_resolver, settings).await });
    }
    let shutdown_reason = {
        let service_exit = async {
            match services.join_next().await {
                Some(Ok(Ok(()))) => Error("local proxy service stopped unexpectedly".into()),
                Some(Ok(Err(error))) => error,
                Some(Err(_)) => Error("local proxy service task failed".into()),
                None => Error("all local proxy services stopped unexpectedly".into()),
            }
        };
        tokio::pin!(service_exit);
        tokio::select! {
            signal = shutdown_signal(parent) => {
                signal?;
                None
            }
            error = &mut service_exit => Some(error),
            _ = wait_for_unhealthy(health) => {
                Some(Error("VPN data plane disconnected".into()))
            }
        }
    };
    services.abort_all();
    if let Some(error) = shutdown_reason {
        if let Err(logout_error) = session.logout() {
            eprintln!("ec-engine: stale-session logout failed: {logout_error}");
        }
        return Ok(SessionOutcome::Disconnected(error));
    }
    Ok(SessionOutcome::Shutdown(session.logout()))
}

async fn run_keepalive(resolver: Arc<VpnDnsResolver>, settings: KeepaliveConfig) -> Result<()> {
    let mut ticker = tokio::time::interval(settings.interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Tokio's first interval tick is immediate. A newly established session has
    // already exchanged several packets, so wait one full interval before the
    // first liveness query.
    ticker.tick().await;
    let mut consecutive_failures = 0_u32;
    let mut confirmed = false;
    loop {
        ticker.tick().await;
        match resolver.probe_ipv4(&settings.domain).await {
            Ok(_) => {
                if consecutive_failures > 0 {
                    eprintln!("ec-engine: tunnel keepalive recovered");
                }
                consecutive_failures = 0;
                if !confirmed {
                    println!("Tunnel keepalive confirmed through VPN DNS");
                    confirmed = true;
                }
            }
            Err(error) => {
                consecutive_failures += 1;
                eprintln!(
                    "ec-engine: tunnel keepalive failed ({consecutive_failures}/{}): {error}",
                    settings.failure_threshold
                );
                if consecutive_failures >= settings.failure_threshold {
                    return Err(Error(format!(
                        "tunnel keepalive failed {} consecutive times",
                        settings.failure_threshold
                    )));
                }
            }
        }
    }
}

async fn shutdown_before_reconnect(
    delay: Duration,
    parent: Option<&ParentLifetime>,
) -> Result<bool> {
    tokio::select! {
        signal = shutdown_signal(parent) => {
            signal?;
            Ok(true)
        }
        _ = tokio::time::sleep(delay) => Ok(false),
    }
}

async fn shutdown_signal(parent: Option<&ParentLifetime>) -> Result<()> {
    let parent_exit = async {
        match parent {
            Some(parent) => parent.wait().await,
            None => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        signal = external_shutdown_signal() => signal,
        _ = parent_exit => Ok(()),
    }
}

#[cfg(unix)]
async fn external_shutdown_signal() -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate())
        .map_err(|_| Error("cannot install termination signal handler".into()))?;
    tokio::select! {
        signal = tokio::signal::ctrl_c() => {
            signal.map_err(|_| Error("cannot install interrupt signal handler".into()))
        }
        _ = terminate.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
async fn external_shutdown_signal() -> Result<()> {
    tokio::signal::ctrl_c()
        .await
        .map_err(|_| Error("cannot install interrupt signal handler".into()))
}

async fn wait_for_unhealthy(netstack: Arc<VirtualNetstack>) {
    while netstack.is_healthy() {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_accepts_only_the_single_socks_listener_contract() {
        let valid = [
            "--config",
            "profile.json",
            "--credentials-stdin",
            "--socks-bind",
            "127.0.0.1:1080",
        ]
        .map(str::to_owned);
        assert!(validate_arguments(&valid).is_ok());

        let valid_with_policy = [
            "--config",
            "profile.json",
            "--local-policy",
            "policy.json",
            "--credentials-stdin",
            "--socks-bind",
            "127.0.0.1:1080",
        ]
        .map(str::to_owned);
        assert!(validate_arguments(&valid_with_policy).is_ok());

        let extra_listener = [
            "--config",
            "profile.json",
            "--credentials-stdin",
            "--socks-bind",
            "127.0.0.1:1080",
            "--http-bind",
            "127.0.0.1:1081",
        ]
        .map(str::to_owned);
        assert!(validate_arguments(&extra_listener).is_err());
    }

    #[test]
    fn parent_pid_requires_a_single_positive_process_id() {
        assert_eq!(parse_parent_pid("1234").unwrap(), 1234);
        for value in ["", "0", "-1", "+1", "1.5", "abc", "2147483648"] {
            assert!(parse_parent_pid(value).is_err(), "accepted {value:?}");
            let args = ["--parent-pid", value].map(str::to_owned);
            assert!(validate_arguments(&args).is_err());
        }
        assert!(validate_arguments(&["--parent-pid".into()]).is_err());
        let duplicate = ["--parent-pid", "123", "--parent-pid", "123"].map(str::to_owned);
        assert!(validate_arguments(&duplicate).is_err());
        assert!(validate_arguments(&["--parent-pid".into(), "1234".into()]).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn parent_pid_cannot_claim_an_unrelated_process() {
        let actual_parent = current_parent_pid().unwrap();
        let unrelated = if actual_parent == 1 { 2 } else { 1 };
        assert!(ParentLifetime::start(unrelated).is_err());
        assert!(ParentLifetime::start(actual_parent).is_ok());
    }

    #[cfg(unix)]
    fn run_parent_watchdog_fixture(mode: &str) -> (std::process::Output, Duration) {
        let directory = std::env::temp_dir().join(format!(
            "ec-engine-parent-test-{}-{}-{mode}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let started = Instant::now();
        // The intermediary inherits this pipe into its child, so output waits
        // for the orphaned engine fixture to close it as well.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::parent_watchdog_fixture",
                "--ignored",
                "--nocapture",
            ])
            .env("EC_ENGINE_PARENT_WATCHDOG_MODE", format!("parent-{mode}"))
            .env("EC_ENGINE_PARENT_WATCHDOG_READY", directory.join("ready"))
            .output()
            .unwrap();
        let elapsed = started.elapsed();
        std::fs::remove_dir_all(directory).unwrap();
        (output, elapsed)
    }

    #[cfg(unix)]
    #[test]
    fn parent_monitor_observes_a_real_parent_exit() {
        let (output, elapsed) = run_parent_watchdog_fixture("graceful");
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("desktop parent exited"));
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("parent shutdown requested"), "{stdout}");
        assert!(
            elapsed < Duration::from_secs(5),
            "shutdown took {elapsed:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn parent_watchdog_bounds_exit_during_a_blocking_operation() {
        let (output, elapsed) = run_parent_watchdog_fixture("blocked");
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("desktop parent exited"));
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("blocking operation started"), "{stdout}");
        assert!(!stdout.contains("blocking operation returned"), "{stdout}");
        assert!(
            elapsed < Duration::from_secs(10),
            "shutdown took {elapsed:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "subprocess helper for parent watchdog integration tests"]
    fn parent_watchdog_fixture() {
        let Ok(mode) = std::env::var("EC_ENGINE_PARENT_WATCHDOG_MODE") else {
            return;
        };
        let ready = std::env::var_os("EC_ENGINE_PARENT_WATCHDOG_READY").unwrap();
        if let Some(child_mode) = mode.strip_prefix("parent-") {
            let _child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tests::parent_watchdog_fixture",
                    "--ignored",
                    "--nocapture",
                ])
                .env("EC_ENGINE_PARENT_WATCHDOG_MODE", child_mode)
                .env(
                    "EC_ENGINE_PARENT_WATCHDOG_EXPECTED_PID",
                    std::process::id().to_string(),
                )
                .stdin(std::process::Stdio::null())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            while !Path::new(&ready).exists() {
                assert!(Instant::now() < deadline, "child watchdog did not start");
                std::thread::sleep(Duration::from_millis(20));
            }
            // Exiting without waiting simulates Force Quit of the GUI parent.
            std::process::exit(0);
        }
        let expected_parent = std::env::var("EC_ENGINE_PARENT_WATCHDOG_EXPECTED_PID")
            .unwrap()
            .parse()
            .unwrap();
        let parent = ParentLifetime::start(expected_parent).unwrap();
        if mode == "blocked" {
            println!("blocking operation started");
            std::fs::write(&ready, b"ready").unwrap();
            std::thread::sleep(Duration::from_secs(15));
            println!("blocking operation returned");
        } else {
            std::fs::write(&ready, b"ready").unwrap();
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(parent.wait());
            println!("parent shutdown requested");
        }
    }

    #[test]
    fn fallback_dns_configuration_is_bounded_and_deduplicated() {
        let config = serde_json::json!({
            "proxy": {
                "fallback_dns_servers": ["223.5.5.5", "119.29.29.29", "223.5.5.5"]
            }
        });
        assert_eq!(
            configured_fallback_dns_servers(&config).unwrap(),
            [
                "223.5.5.5".parse::<Ipv4Addr>().unwrap(),
                "119.29.29.29".parse::<Ipv4Addr>().unwrap()
            ]
        );
        for invalid in [
            serde_json::json!(["0.0.0.0"]),
            serde_json::json!(["224.0.0.1"]),
            serde_json::json!(["not-an-address"]),
            serde_json::json!(["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"]),
        ] {
            let config = serde_json::json!({"proxy": {"fallback_dns_servers": invalid}});
            assert!(configured_fallback_dns_servers(&config).is_err());
        }
    }

    #[test]
    fn vpn_dns_configuration_is_bounded_and_deduplicated() {
        let config = serde_json::json!({
            "proxy": {
                "vpn_dns_servers": ["192.0.2.53", "192.0.2.53"]
            }
        });
        assert_eq!(
            configured_vpn_dns_servers(&config).unwrap(),
            ["192.0.2.53".parse::<Ipv4Addr>().unwrap()]
        );
        for invalid in [
            serde_json::json!(["0.0.0.0"]),
            serde_json::json!(["224.0.0.1"]),
            serde_json::json!(["not-an-address"]),
            serde_json::json!(["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"]),
        ] {
            let config = serde_json::json!({"proxy": {"vpn_dns_servers": invalid}});
            assert!(configured_vpn_dns_servers(&config).is_err());
        }
    }

    #[test]
    fn keepalive_must_be_bounded_and_inside_the_route_policy() {
        let config = serde_json::json!({
            "proxy": {
                "route_domains": ["hkust-gz.edu.cn"],
                "route_ipv4_cidrs": ["198.51.100.0/24"]
            },
            "tunnel": {
                "keepalive_domain": "ssfas.hkust-gz.edu.cn",
                "keepalive_interval_seconds": 30,
                "keepalive_failure_threshold": 2
            }
        });
        let policy = RoutePolicy::from_config(&config).unwrap();
        assert_eq!(
            configured_keepalive(&config, &policy).unwrap(),
            Some(KeepaliveConfig {
                domain: "ssfas.hkust-gz.edu.cn".into(),
                interval: Duration::from_secs(30),
                failure_threshold: 2,
            })
        );

        for tunnel in [
            serde_json::json!({
                "keepalive_domain": "example.com",
                "keepalive_interval_seconds": 30,
                "keepalive_failure_threshold": 2
            }),
            serde_json::json!({
                "keepalive_domain": "ssfas.hkust-gz.edu.cn",
                "keepalive_interval_seconds": 9,
                "keepalive_failure_threshold": 2
            }),
            serde_json::json!({
                "keepalive_domain": "ssfas.hkust-gz.edu.cn",
                "keepalive_interval_seconds": 30,
                "keepalive_failure_threshold": 0
            }),
        ] {
            let invalid = serde_json::json!({
                "proxy": {
                    "route_domains": ["hkust-gz.edu.cn"],
                    "route_ipv4_cidrs": ["198.51.100.0/24"]
                },
                "tunnel": tunnel
            });
            let policy = RoutePolicy::from_config(&invalid).unwrap();
            assert!(configured_keepalive(&invalid, &policy).is_err());
        }
    }

    #[test]
    fn local_policy_can_only_replace_private_network_fields() {
        let mut config = serde_json::json!({
            "base_url": "https://remote.hkust-gz.edu.cn",
            "proxy": {
                "vpn_dns_servers": [],
                "route_domains": ["hkust-gz.edu.cn"],
                "route_ipv4_cidrs": []
            }
        });
        apply_local_policy(
            &mut config,
            serde_json::json!({
                "version": 1,
                "vpn_dns_servers": ["192.0.2.53"],
                "route_ipv4_cidrs": ["198.51.100.0/24"]
            }),
        )
        .unwrap();
        assert_eq!(config["base_url"], "https://remote.hkust-gz.edu.cn");
        assert_eq!(config["proxy"]["route_domains"][0], "hkust-gz.edu.cn");
        assert_eq!(config["proxy"]["vpn_dns_servers"][0], "192.0.2.53");
        assert_eq!(config["proxy"]["route_ipv4_cidrs"][0], "198.51.100.0/24");

        let rejected = serde_json::json!({
            "version": 1,
            "base_url": "https://example.com",
            "vpn_dns_servers": [],
            "route_ipv4_cidrs": []
        });
        assert!(apply_local_policy(&mut config, rejected).is_err());
    }
}
