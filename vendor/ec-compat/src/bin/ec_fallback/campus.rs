//! Opt-in, local campus detection. No routes, proxies or system DNS are changed.
use super::*;
use ec_compat::engine::policy::RoutePolicy;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;
use tokio::sync::RwLock;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    policy_file: PathBuf,
    app_path: PathBuf,
    probe_host: String,
    probe_port: u16,
    gateway_address: Ipv4Addr,
    #[serde(default)]
    auto_launch: bool,
}

#[derive(Clone)]
pub struct Network {
    pub interface: NonZeroU32,
    pub resolver: Arc<DirectDnsResolver>,
    pub on_campus: bool,
    checked: Instant,
    fingerprint: String,
}

pub struct CampusRouting {
    config: Config,
    pub policy: RoutePolicy,
    dns: Vec<Ipv4Addr>,
    current: RwLock<Option<Network>>,
    directory: PathBuf,
}

#[derive(Default)]
struct Lifecycle {
    fingerprint: String,
    campus_votes: u8,
    outside_votes: u8,
    attempted_launch: bool,
}

impl Lifecycle {
    fn observe(&mut self, fingerprint: &str, campus: bool) {
        if self.fingerprint != fingerprint {
            *self = Self {
                fingerprint: fingerprint.to_owned(),
                ..Self::default()
            };
        }
        if campus {
            self.campus_votes = self.campus_votes.saturating_add(1);
            self.outside_votes = 0;
        } else {
            self.outside_votes = self.outside_votes.saturating_add(1);
            self.campus_votes = 0;
        }
    }

    fn should_launch(&self, running: bool, state: &LaunchState) -> bool {
        self.outside_votes >= 3 && !running && state.permits_launch() && !self.attempted_launch
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct AppSession {
    version: u32,
    session_id: String,
    pid: u32,
    status: SessionStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum SessionStatus {
    Running,
    ManualStopped,
    CampusStopped,
}

enum LaunchState {
    FirstLaunch,
    Session(AppSession),
    Inhibited,
}

impl LaunchState {
    fn permits_launch(&self) -> bool {
        matches!(
            self,
            Self::FirstLaunch
                | Self::Session(AppSession {
                    status: SessionStatus::CampusStopped,
                    ..
                })
        )
    }

    fn manual_stop(&self, pids: &[u32]) -> bool {
        match self {
            Self::Inhibited => true,
            Self::Session(session) => match session.status {
                SessionStatus::ManualStopped => true,
                SessionStatus::Running => !pids.contains(&session.pid),
                SessionStatus::CampusStopped => false,
            },
            Self::FirstLaunch => false,
        }
    }

    fn running_session(&self, pids: &[u32]) -> Option<&AppSession> {
        match self {
            Self::Session(session)
                if session.status == SessionStatus::Running && pids.contains(&session.pid) =>
            {
                Some(session)
            }
            _ => None,
        }
    }
}

fn valid_session_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn launch_state(directory: &Path) -> LaunchState {
    let path = directory.join("app-session.json");
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => LaunchState::FirstLaunch,
        Err(_) => LaunchState::Inhibited,
        Ok(_) => {
            let session = read_private_json(&path)
                .ok()
                .and_then(|value| serde_json::from_value::<AppSession>(value).ok());
            match session {
                Some(session)
                    if session.version == 1
                        && valid_session_id(&session.session_id)
                        && session.pid > 0
                        && session.pid <= i32::MAX as u32 =>
                {
                    LaunchState::Session(session)
                }
                _ => LaunchState::Inhibited,
            }
        }
    }
}

fn automation_paused(directory: &Path) -> bool {
    // A malformed marker or an unreadable directory must not resume automation.
    !matches!(
        std::fs::symlink_metadata(directory.join("auto-paused")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    )
}

fn automatic_launch_allowed(directory: &Path) -> bool {
    !automation_paused(directory) && launch_state(directory).permits_launch()
}

fn ensure_campus_platform() -> Result<()> {
    if cfg!(target_os = "macos") {
        Ok(())
    } else {
        Err(Error("campus auto-routing requires macOS".into()))
    }
}

fn shutdown_request(session: &AppSession) -> serde_json::Value {
    serde_json::json!({
        "version": 1,
        "session_id": session.session_id,
        "pid": session.pid,
    })
}

fn cancel_campus_shutdown(directory: &Path, session: &AppSession) {
    let path = directory.join("campus-shutdown.json");
    if read_private_json(&path).ok() == Some(shutdown_request(session)) {
        let _ = std::fs::remove_file(path);
    }
}

fn request_campus_shutdown(directory: &Path, pids: &[u32]) -> std::io::Result<Option<AppSession>> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if automation_paused(directory) {
        return Ok(None);
    }
    let state = launch_state(directory);
    let Some(session) = state.running_session(pids) else {
        return Ok(None);
    };
    let temporary = directory.join(format!(
        ".campus-shutdown.{}.{:016x}.tmp",
        std::process::id(),
        rand::random::<u64>()
    ));
    let request = shutdown_request(session);
    let result = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(request.to_string().as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&temporary, directory.join("campus-shutdown.json"))
    })();
    if let Err(error) = result {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    // The GUI may have stopped or reopened while the request was written. Only
    // a request for the same running session can classify the next SIGUSR2 as
    // an automatic campus stop; the relay never updates app-session.json.
    if automation_paused(directory)
        || launch_state(directory).running_session(pids) != Some(session)
    {
        cancel_campus_shutdown(directory, session);
        return Ok(None);
    }
    Ok(Some(session.clone()))
}

fn read_private_json(path: &Path) -> Result<serde_json::Value> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::getuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(Error(
            "campus configuration must be an owner-only regular file".into(),
        ));
    }
    serde_json::from_slice(&std::fs::read(path)?)
        .map_err(|_| Error("invalid campus configuration".into()))
}

impl CampusRouting {
    pub fn load() -> Result<Option<Arc<Self>>> {
        let directory = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".config")))
            .ok_or_else(|| Error("home directory is unavailable".into()))?
            .join("hkustgz-connect");
        let file = directory.join("relay.json");
        if !file.exists() {
            return Ok(None);
        }
        // Keep the original relay available without campus configuration on
        // other platforms; never try macOS discovery or app lifecycle commands.
        ensure_campus_platform()?;
        let config: Config = serde_json::from_value(read_private_json(&file)?)
            .map_err(|_| Error("invalid campus relay settings".into()))?;
        if !config.app_path.is_absolute()
            || !config.policy_file.is_absolute()
            || !is_campus_domain(&config.probe_host)
            || config.probe_port == 0
            || is_private_destination(config.gateway_address)
        {
            return Err(Error("invalid campus relay scope".into()));
        }
        let local = read_private_json(&config.policy_file)?;
        let policy = RoutePolicy::from_config(&serde_json::json!({"proxy": {
            "route_domains": CAMPUS_DOMAIN_SUFFIXES,
            "route_ipv4_cidrs": local["route_ipv4_cidrs"],
        }}))?;
        let dns: Vec<Ipv4Addr> = serde_json::from_value(local["vpn_dns_servers"].clone())
            .map_err(|_| Error("invalid campus DNS list".into()))?;
        if dns.is_empty() || dns.len() > 8 || dns.iter().any(|ip| !ip.is_private()) {
            return Err(Error(
                "campus detection requires explicit private campus DNS servers".into(),
            ));
        }
        Ok(Some(Arc::new(Self {
            config,
            policy,
            dns,
            current: RwLock::new(None),
            directory,
        })))
    }

    pub async fn network(&self) -> Option<Network> {
        self.current
            .read()
            .await
            .clone()
            .filter(|n| n.checked.elapsed() < Duration::from_secs(25))
    }

    pub async fn run(self: Arc<Self>) {
        let mut lifecycle = Lifecycle::default();
        let mut last_mode = String::new();
        loop {
            let physical = tokio::task::spawn_blocking(physical_network)
                .await
                .ok()
                .flatten();
            if let Some((name, address, dns)) = physical {
                if let Ok(interface) = interface_index(&name) {
                    let resolver = Arc::new(
                        DirectDnsResolver::new(self.dns.clone(), Duration::from_secs(2))
                            .expect("validated DNS")
                            .with_interface(interface),
                    );
                    // DHCP/scoped DNS must identify the campus before private campus probes.
                    // The probe itself is physically bound and reads an SSH banner, so a
                    // proxy TUN's successful TCP accept cannot masquerade as campus access.
                    let campus_dns = dns.iter().any(|ip| self.dns.contains(ip));
                    let campus =
                        campus_dns && self.probe_campus(interface, resolver.as_ref()).await;
                    let fingerprint = format!("{name}/{address}/{dns:?}");
                    let app = self.config.app_path.clone();
                    let pids = tokio::task::spawn_blocking(move || app_pids(&app))
                        .await
                        .unwrap_or_default();
                    lifecycle.observe(&fingerprint, campus);
                    let previous = self.network().await;
                    let campus_route = campus
                        || (lifecycle.outside_votes < 3
                            && previous
                                .is_some_and(|n| n.on_campus && n.fingerprint == fingerprint));
                    *self.current.write().await = Some(Network {
                        interface,
                        resolver,
                        on_campus: campus_route,
                        checked: Instant::now(),
                        fingerprint: fingerprint.clone(),
                    });
                    if lifecycle.campus_votes >= 2 {
                        lifecycle.attempted_launch = false;
                    }
                    let mode = if campus_route {
                        "campus"
                    } else {
                        "outside-or-unavailable"
                    };
                    if mode != last_mode {
                        println!("Campus route state: {mode} ({name})");
                        last_mode = mode.into();
                    }
                    let state = launch_state(&self.directory);
                    self.write_status(mode, &name, state.manual_stop(&pids));
                    if self.config.auto_launch && !automation_paused(&self.directory) {
                        if lifecycle.campus_votes >= 2 && !pids.is_empty() {
                            if let Ok(Some(session)) =
                                request_campus_shutdown(&self.directory, &pids)
                            {
                                // Only exact executable paths belonging to the configured app.
                                // Recheck after writing the request, before sending its signal.
                                if app_pids(&self.config.app_path).contains(&session.pid)
                                    && !automation_paused(&self.directory)
                                    && launch_state(&self.directory).running_session(&[session.pid])
                                        == Some(&session)
                                {
                                    if Command::new("/bin/kill")
                                        .args(["-USR2", &session.pid.to_string()])
                                        .status()
                                        .is_ok_and(|status| status.success())
                                    {
                                        println!("Campus confirmed; requested Connect shutdown");
                                    } else {
                                        cancel_campus_shutdown(&self.directory, &session);
                                    }
                                } else {
                                    cancel_campus_shutdown(&self.directory, &session);
                                }
                            }
                        } else if lifecycle.should_launch(!pids.is_empty(), &state)
                            && gateway_reachable(&dns, interface, self.config.gateway_address).await
                        {
                            // A manual stop can happen during the gateway probe. Its durable
                            // session state takes precedence over this network observation.
                            if automatic_launch_allowed(&self.directory)
                                && app_pids(&self.config.app_path).is_empty()
                            {
                                lifecycle.attempted_launch = true;
                                let _ = Command::new("/usr/bin/open")
                                    .arg("-g")
                                    .arg("-a")
                                    .arg(&self.config.app_path)
                                    .args(["--args", "--campus-auto"])
                                    .status();
                                println!("Off-campus gateway reachable; launched Connect");
                            }
                        }
                    }
                }
            } else {
                *self.current.write().await = None;
                // Network vote resets never change the durable user stop decision.
                lifecycle.campus_votes = 0;
                lifecycle.outside_votes = 0;
                self.write_status(
                    "offline",
                    "",
                    launch_state(&self.directory).manual_stop(&[]),
                );
            }
            tokio::time::sleep(Duration::from_secs(8)).await;
        }
    }

    async fn probe_campus(&self, interface: NonZeroU32, resolver: &DirectDnsResolver) -> bool {
        let operation = async {
            let ip = resolver.resolve_ipv4(&self.config.probe_host).await?;
            if !ip.is_private() {
                return Err(Error("campus probe must resolve privately".into()));
            }
            let mut stream = connect_bound(
                ip,
                self.config.probe_port,
                interface,
                Duration::from_secs(2),
            )
            .await?;
            let mut banner = [0; 4];
            stream.read_exact(&mut banner).await?;
            Ok::<_, Error>(&banner == b"SSH-")
        };
        matches!(
            tokio::time::timeout(Duration::from_secs(3), operation).await,
            Ok(Ok(true))
        )
    }

    fn write_status(&self, mode: &str, interface: &str, suppressed: bool) {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let path = self
            .directory
            .join(format!(".relay-state.{}.tmp", std::process::id()));
        let result = (|| -> std::io::Result<()> {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
            file.write_all(serde_json::json!({"mode":mode,"interface":interface,"manual_stop":suppressed,
                "updated_at":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()}).to_string().as_bytes())?;
            std::fs::rename(&path, self.directory.join("relay-state.json"))
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn output(command: &str, args: &[&str]) -> String {
    Command::new(command)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

fn physical_network() -> Option<(String, String, Vec<Ipv4Addr>)> {
    let routes = output("/sbin/route", &["-n", "get", "default"]);
    let mut name = routes
        .lines()
        .find_map(|l| l.trim().strip_prefix("interface:").map(str::trim))
        .filter(|n| physical_name(n))
        .map(str::to_owned);
    if name.is_none() {
        let nwi = output("/usr/sbin/scutil", &["--nwi"]);
        name = nwi
            .lines()
            .filter_map(|l| l.split_whitespace().next())
            .find(|n| physical_name(n))
            .map(str::to_owned);
    }
    let name = name?;
    let address = output("/usr/sbin/ipconfig", &["getifaddr", &name])
        .trim()
        .to_owned();
    address.parse::<Ipv4Addr>().ok()?;
    let dns = output(
        "/usr/sbin/ipconfig",
        &["getoption", &name, "domain_name_server"],
    )
    .split_whitespace()
    .filter_map(|s| s.parse().ok())
    .collect();
    Some((name, address, dns))
}

fn physical_name(name: &str) -> bool {
    name.strip_prefix("en")
        .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
}

fn app_pids(app: &Path) -> Vec<u32> {
    let executable = app.join("Contents/MacOS/HKUST(GZ) Connect");
    let executable = executable.to_string_lossy();
    output("/bin/ps", &["-axo", "pid=,comm="])
        .lines()
        .filter_map(|line| {
            let (pid, command) = line.trim().split_once(char::is_whitespace)?;
            (command.trim() == executable)
                .then(|| pid.parse().ok())
                .flatten()
        })
        .collect()
}

async fn gateway_reachable(dns: &[Ipv4Addr], interface: NonZeroU32, cached: Ipv4Addr) -> bool {
    // Bootstrap the public gateway using the current physical network's DNS.
    // The last verified gateway address is only a bounded fallback, not a
    // permanent hostname override or a system-wide resolver setting.
    let mut address = cached;
    if let Ok(resolver) = DirectDnsResolver::new(dns.to_vec(), Duration::from_secs(2)) {
        if let Ok(ip) = resolver
            .with_interface(interface)
            .resolve_ipv4("remote.hkust-gz.edu.cn")
            .await
        {
            if !is_private_destination(ip) {
                address = ip;
            }
        }
    }
    connect_bound(address, 443, interface, Duration::from_secs(2))
        .await
        .is_ok()
}

#[cfg(target_os = "macos")]
pub async fn connect_bound(
    ip: Ipv4Addr,
    port: u16,
    interface: NonZeroU32,
    timeout: Duration,
) -> Result<TcpStream> {
    let socket = TcpSocket::new_v4()?;
    SockRef::from(&socket).bind_device_by_index_v4(Some(interface))?;
    tokio::time::timeout(
        timeout,
        socket.connect(SocketAddr::new(IpAddr::V4(ip), port)),
    )
    .await
    .map_err(|_| Error("physical campus connection timed out".into()))?
    .map_err(Error::from)
}

#[cfg(not(target_os = "macos"))]
pub async fn connect_bound(
    _ip: Ipv4Addr,
    _port: u16,
    _interface: NonZeroU32,
    _timeout: Duration,
) -> Result<TcpStream> {
    Err(Error("physical campus connection requires macOS".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};

    const SESSION_ID: &str = "43b616e8-09dc-4c09-81eb-9b2fd8cba2cd";

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "connect-campus-test-{}-{:016x}",
                std::process::id(),
                rand::random::<u64>()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn write_session(&self, status: &str) {
            self.write_json(serde_json::json!({
                "version": 1,
                "session_id": SESSION_ID,
                "pid": 12345,
                "status": status,
            }));
        }

        fn write_json(&self, value: serde_json::Value) {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(self.0.join("app-session.json"))
                .unwrap();
            file.write_all(value.to_string().as_bytes()).unwrap();
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn transient_failures_do_not_launch() {
        let mut s = Lifecycle::default();
        s.observe("wifi-a", false);
        s.observe("wifi-a", false);
        assert!(!s.should_launch(false, &LaunchState::FirstLaunch));
        s.observe("wifi-a", false);
        assert!(s.should_launch(false, &LaunchState::FirstLaunch));
        assert!(!s.should_launch(true, &LaunchState::FirstLaunch));
    }

    #[test]
    fn manual_quit_and_force_quit_stay_stopped_after_network_changes_and_relay_restart() {
        for status in ["manual-stopped", "running"] {
            let directory = TestDirectory::new();
            directory.write_session(status);
            let mut s = Lifecycle::default();
            // A stale running session survives SIGKILL, when a quit handler cannot run.
            assert!(launch_state(&directory.0).manual_stop(&[]));
            for fingerprint in ["wifi-a", "campus", "wifi-b"] {
                for _ in 0..3 {
                    s.observe(fingerprint, fingerprint == "campus");
                }
                assert!(!s.should_launch(false, &launch_state(&directory.0)));
                assert!(!automatic_launch_allowed(&directory.0));
            }
            // A fresh relay still reads the same durable decision.
            let mut restarted = Lifecycle::default();
            for _ in 0..3 {
                restarted.observe("wifi-c", false);
            }
            assert!(!restarted.should_launch(false, &launch_state(&directory.0)));
        }
    }

    #[test]
    fn only_first_launch_and_completed_campus_stop_permit_automatic_launch() {
        let directory = TestDirectory::new();
        assert!(automatic_launch_allowed(&directory.0));
        directory.write_session("campus-stopped");
        assert!(automatic_launch_allowed(&directory.0));
        directory.write_session("running");
        assert!(!automatic_launch_allowed(&directory.0));
        assert!(!launch_state(&directory.0).manual_stop(&[12345]));
        directory.write_session("manual-stopped");
        assert!(!automatic_launch_allowed(&directory.0));
    }

    #[test]
    fn stop_during_gateway_probe_inhibits_final_launch_check() {
        let directory = TestDirectory::new();
        directory.write_session("campus-stopped");
        assert!(automatic_launch_allowed(&directory.0));
        // The GUI can be opened and force-quit while the relay awaits its probe.
        directory.write_session("running");
        assert!(!automatic_launch_allowed(&directory.0));
    }

    #[test]
    fn invalid_or_non_private_session_state_inhibits_automatic_launch() {
        let directory = TestDirectory::new();
        let valid = serde_json::json!({
            "version": 1,
            "session_id": SESSION_ID,
            "pid": 12345,
            "status": "campus-stopped",
        });
        for (field, value) in [
            ("version", serde_json::json!(2)),
            ("session_id", serde_json::json!("invalid-session")),
            ("pid", serde_json::json!(0)),
            ("pid", serde_json::json!(u32::MAX)),
            ("status", serde_json::json!("unknown")),
            ("unexpected", serde_json::json!(true)),
        ] {
            let mut invalid = valid.clone();
            invalid[field] = value;
            directory.write_json(invalid);
            assert!(!automatic_launch_allowed(&directory.0), "field {field}");
        }
        let path = directory.0.join("app-session.json");
        std::fs::write(&path, b"not json").unwrap();
        assert!(!automatic_launch_allowed(&directory.0));
        directory.write_json(valid);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!automatic_launch_allowed(&directory.0));
        std::fs::remove_file(&path).unwrap();
        symlink(directory.0.join("missing"), &path).unwrap();
        assert!(!automatic_launch_allowed(&directory.0));
    }

    #[test]
    fn campus_shutdown_request_matches_only_the_running_session_main_pid() {
        let directory = TestDirectory::new();
        directory.write_session("running");
        assert!(
            request_campus_shutdown(&directory.0, &[54321])
                .unwrap()
                .is_none()
        );
        assert!(!directory.0.join("campus-shutdown.json").exists());
        let session = request_campus_shutdown(&directory.0, &[12345, 54321])
            .unwrap()
            .unwrap();
        assert_eq!(session.pid, 12345);
        assert_eq!(session.session_id, SESSION_ID);
        let path = directory.0.join("campus-shutdown.json");
        assert_eq!(
            read_private_json(&path).unwrap(),
            shutdown_request(&session)
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // Issuing a request alone must never permit relaunch after a force quit.
        assert!(!automatic_launch_allowed(&directory.0));
        cancel_campus_shutdown(&directory.0, &session);
        assert!(!path.exists());
        for status in ["manual-stopped", "campus-stopped"] {
            directory.write_session(status);
            assert!(
                request_campus_shutdown(&directory.0, &[12345])
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn pause_marker_blocks_both_launch_and_campus_shutdown() {
        let directory = TestDirectory::new();
        directory.write_session("campus-stopped");
        let marker = directory.0.join("auto-paused");
        std::fs::write(&marker, b"").unwrap();
        assert!(!automatic_launch_allowed(&directory.0));
        directory.write_session("running");
        assert!(
            request_campus_shutdown(&directory.0, &[12345])
                .unwrap()
                .is_none()
        );
        assert!(!directory.0.join("campus-shutdown.json").exists());
        // Even a broken marker symlink represents a pause, not an absent marker.
        std::fs::remove_file(&marker).unwrap();
        symlink(directory.0.join("missing"), &marker).unwrap();
        assert!(automation_paused(&directory.0));
    }

    #[test]
    fn campus_success_resets_off_campus_votes() {
        let mut s = Lifecycle::default();
        s.observe("wifi", false);
        s.observe("wifi", false);
        s.observe("wifi", true);
        assert_eq!(s.outside_votes, 0);
        s.observe("wifi", false);
        assert!(!s.should_launch(false, &LaunchState::FirstLaunch));
    }
    #[test]
    fn only_physical_interfaces_are_accepted() {
        assert!(physical_name("en0"));
        assert!(physical_name("en12"));
        for n in ["utun7", "lo0", "en", "en0;bad"] {
            assert!(!physical_name(n));
        }
    }

    #[test]
    fn campus_automation_requires_macos() {
        assert_eq!(ensure_campus_platform().is_ok(), cfg!(target_os = "macos"));
    }

    #[cfg(not(target_os = "macos"))]
    #[tokio::test]
    async fn unsupported_physical_campus_connections_fail_closed() {
        let error = connect_bound(
            Ipv4Addr::LOCALHOST,
            443,
            NonZeroU32::new(1).unwrap(),
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "physical campus connection requires macOS"
        );
    }
}
