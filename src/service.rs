//! Loopback broker. A per-user capability authenticates fixed VPN operations.
use anyhow::{Context, Result, bail};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use zeroize::{Zeroize, Zeroizing};
const PORT: u16 = 40571;
const LIMIT: u64 = 16384;
#[cfg(target_os = "windows")]
const NAME: &str = "EasyConnect";
pub(crate) static STOP: AtomicBool = AtomicBool::new(false);

#[derive(Serialize, Deserialize)]
pub enum Request {
    Status,
    Disconnect,
    Connect {
        gateway: String,
        username: String,
        password: String,
        cert_sha256: Option<String>,
    },
}
impl Drop for Request {
    fn drop(&mut self) {
        if let Self::Connect { password, .. } = self {
            password.zeroize();
        }
    }
}
#[derive(Serialize, Deserialize)]
struct Envelope {
    token: String,
    request: Request,
}
impl Drop for Envelope {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Disconnected,
    Connecting,
    Connected,
    Stopping,
    Failed,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Status {
    pub phase: Phase,
    pub interface: Option<String>,
    pub address: Option<String>,
    pub routes: usize,
    pub resources: usize,
    pub groups: usize,
    pub logs: VecDeque<String>,
    pub version: String,
}
impl Default for Status {
    fn default() -> Self {
        Self {
            phase: Phase::Disconnected,
            interface: None,
            address: None,
            routes: 0,
            resources: 0,
            groups: 0,
            logs: VecDeque::new(),
            version: env!("CARGO_PKG_VERSION").into(),
        }
    }
}
#[derive(Serialize, Deserialize)]
struct Response {
    status: Option<Status>,
    error: Option<String>,
}

pub fn current_owner() -> Result<String> {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: geteuid takes no pointers.
        Ok(unsafe { libc::geteuid() }.to_string())
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let out = Command::new("whoami.exe")
            .creation_flags(0x08000000)
            .args(["/user", "/fo", "csv", "/nh"])
            .output()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let owner = text
            .split('"')
            .find(|s| s.starts_with("S-1-"))
            .context("user SID unavailable")?
            .to_owned();
        validate_owner(&owner)?;
        Ok(owner)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    bail!("unsupported platform")
}
fn validate_owner(owner: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    if owner.parse::<u32>().unwrap_or(0) == 0 || !owner.bytes().all(|b| b.is_ascii_digit()) {
        bail!("owner must be a regular user UID");
    }
    #[cfg(target_os = "windows")]
    if !owner.starts_with("S-1-")
        || !owner
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'S' | b'-'))
    {
        bail!("invalid SID");
    }
    Ok(())
}
pub fn token_path(owner: &str) -> Result<PathBuf> {
    validate_owner(owner)?;
    #[cfg(target_os = "macos")]
    let base = PathBuf::from("/Library/Application Support/EasyConnect");
    #[cfg(target_os = "windows")]
    let base = PathBuf::from(std::env::var_os("ProgramData").context("ProgramData unavailable")?)
        .join("EasyConnect");
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let base = PathBuf::from("/unsupported");
    Ok(base.join(format!("rpc-{owner}.token")))
}
fn token(owner: &str) -> Result<Zeroizing<String>> {
    let value = Zeroizing::new(
        std::fs::read_to_string(token_path(owner)?)
            .context("background service is not installed for this user")?,
    );
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("invalid service capability");
    }
    Ok(value)
}
pub fn installed() -> bool {
    current_owner().and_then(|o| token(&o)).is_ok()
}
pub fn request(request: Request) -> Result<Status> {
    let capability = token(&current_owner()?)?;
    let mut socket =
        TcpStream::connect_timeout(&([127, 0, 0, 1], PORT).into(), Duration::from_secs(2))
            .context("background service is not running")?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    let envelope = Envelope {
        token: capability.to_string(),
        request,
    };
    let mut body = Zeroizing::new(serde_json::to_vec(&envelope)?);
    body.push(b'\n');
    if body.len() as u64 > LIMIT {
        bail!("request too large");
    }
    socket.write_all(&body)?;
    let mut output = String::new();
    BufReader::new(socket)
        .take(262144)
        .read_to_string(&mut output)?;
    let response: Response = serde_json::from_str(&output)?;
    if let Some(error) = response.error {
        bail!("{error}");
    }
    response.status.context("missing service status")
}
fn authorized(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0_u8, |v, (a, b)| v | (a ^ b)) == 0
}
fn validate_credentials(
    gateway: &str,
    user: &str,
    password: &str,
    pin: Option<&str>,
) -> Result<()> {
    crate::cli::validate_gateway(gateway)?;
    if user.is_empty()
        || user.len() > 256
        || password.is_empty()
        || password.len() > 4096
        || user.contains(['\n', '\r', '\0'])
        || password.contains(['\n', '\r', '\0'])
    {
        bail!("invalid credentials");
    }
    if let Some(pin) = pin {
        ec_compat::modern::parse_sha256_pin(pin)?;
    }
    Ok(())
}
struct Worker {
    child: Option<Child>,
    input: Option<ChildStdin>,
    status: Arc<Mutex<Status>>,
}
impl Worker {
    fn refresh(&mut self) -> Result<()> {
        if let Some(child) = &mut self.child
            && let Some(exit) = child.try_wait()?
        {
            #[cfg(target_os = "windows")]
            crate::tun::cleanup_worker_dns(child.id());
            self.child = None;
            self.input = None;
            let mut s = self
                .status
                .lock()
                .map_err(|_| anyhow::anyhow!("state lock poisoned"))?;
            s.phase = if exit.success() {
                Phase::Disconnected
            } else {
                Phase::Failed
            };
            s.interface = None;
            s.address = None;
            s.routes = 0;
        }
        Ok(())
    }
    fn handle(&mut self, request: &Request) -> Result<Status> {
        self.refresh()?;
        match request {
            Request::Status => {}
            Request::Disconnect => {
                if let Some(input) = &mut self.input {
                    input.write_all(b"stop\n")?;
                    input.flush()?;
                    self.status
                        .lock()
                        .map_err(|_| anyhow::anyhow!("state lock poisoned"))?
                        .phase = Phase::Stopping;
                }
            }
            Request::Connect {
                gateway,
                username,
                password,
                cert_sha256,
            } => {
                if self.child.is_some() {
                    bail!("disconnect the active connection first");
                }
                validate_credentials(gateway, username, password, cert_sha256.as_deref())?;
                let mut command = Command::new(std::env::current_exe()?);
                command
                    .args([
                        "connect",
                        "--gateway",
                        gateway,
                        "--mode",
                        "tun",
                        "--credentials-stdin",
                        "--shutdown-stdin",
                    ])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                if let Some(pin) = cert_sha256 {
                    command.args(["--cert-sha256", pin]);
                }
                #[cfg(target_os = "windows")]
                {
                    use std::os::windows::process::CommandExt;
                    command.creation_flags(0x08000000);
                }
                let mut child = command.spawn()?;
                let mut input = child.stdin.take().context("worker input missing")?;
                let bytes = Zeroizing::new(format!("{username}\n{password}\n"));
                if let Err(error) = input.write_all(bytes.as_bytes()) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(error.into());
                }
                input.flush()?;
                *self
                    .status
                    .lock()
                    .map_err(|_| anyhow::anyhow!("state lock poisoned"))? = Status {
                    phase: Phase::Connecting,
                    ..Default::default()
                };
                if let Some(out) = child.stdout.take() {
                    logs(out, self.status.clone());
                }
                if let Some(out) = child.stderr.take() {
                    logs(out, self.status.clone());
                }
                self.child = Some(child);
                self.input = Some(input);
            }
        }
        Ok(self
            .status
            .lock()
            .map_err(|_| anyhow::anyhow!("state lock poisoned"))?
            .clone())
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.handle(&Request::Disconnect);
        for _ in 0..100 {
            let _ = self.refresh();
            if self.child.is_none() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if let Some(c) = &mut self.child {
            let _ = c.kill();
            let _ = c.wait();
            #[cfg(target_os = "windows")]
            crate::tun::cleanup_worker_dns(c.id());
        }
    }
}
fn logs(reader: impl Read + Send + 'static, state: Arc<Mutex<Status>>) {
    std::thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        loop {
            let mut bytes = Vec::new();
            match reader.by_ref().take(8192).read_until(b'\n', &mut bytes) {
                Ok(0) | Err(_) => break,
                _ => {}
            }
            let line = String::from_utf8_lossy(&bytes).trim().to_owned();
            let Ok(mut state) = state.lock() else {
                break;
            };
            let words: Vec<_> = line.split_whitespace().collect();
            if line.starts_with("TUN ready:") {
                state.phase = Phase::Connected;
                state.interface = words.get(2).map(|s| s.trim_end_matches(',').into());
                state.address = words.get(4).map(|s| s.trim_end_matches(',').into());
                state.routes = words.get(7).and_then(|s| s.parse().ok()).unwrap_or(0);
            }
            if line.starts_with("Loaded ") {
                state.resources = words.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                state.groups = words.get(4).and_then(|s| s.parse().ok()).unwrap_or(0);
            }
            state.logs.push_back(line);
            while state.logs.len() > 100 {
                state.logs.pop_front();
            }
        }
    });
}
pub fn run(owner: &str, stop: Arc<AtomicBool>) -> Result<()> {
    crate::tun::preflight()?;
    let capability = token(owner)?;
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, PORT))?;
    listener.set_nonblocking(true)?;
    let mut worker = Worker {
        child: None,
        input: None,
        status: Arc::new(Mutex::new(Status::default())),
    };
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut socket, peer)) => {
                if !peer.ip().is_loopback() {
                    continue;
                }
                socket.set_read_timeout(Some(Duration::from_secs(2)))?;
                socket.set_write_timeout(Some(Duration::from_secs(2)))?;
                let result = (|| -> Result<Status> {
                    let mut bytes = Zeroizing::new(Vec::new());
                    BufReader::new(&mut socket)
                        .take(LIMIT + 1)
                        .read_until(b'\n', &mut bytes)?;
                    if bytes.len() as u64 > LIMIT || bytes.last() != Some(&b'\n') {
                        bail!("invalid request");
                    }
                    let envelope: Envelope = serde_json::from_slice(&bytes)?;
                    if !authorized(envelope.token.as_bytes(), capability.as_bytes()) {
                        bail!("unauthorized");
                    }
                    worker.handle(&envelope.request)
                })();
                let response = match result {
                    Ok(status) => Response {
                        status: Some(status),
                        error: None,
                    },
                    Err(error) => Response {
                        status: None,
                        error: Some(error.to_string()),
                    },
                };
                let _ = serde_json::to_writer(&mut socket, &response);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(25))
            }
            Err(error) => return Err(error.into()),
        }
        worker.refresh()?;
    }
    Ok(())
}
pub fn install(owner: &str) -> Result<()> {
    validate_owner(owner)?;
    crate::tun::preflight()?;
    let file = token_path(owner)?;
    let dir = file.parent().context("service directory missing")?;
    std::fs::create_dir_all(dir)?;
    if std::fs::symlink_metadata(dir)?.file_type().is_symlink() {
        bail!("service directory may not be a symlink");
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
    }
    if !file.exists() {
        let mut random = [0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let value = Zeroizing::new(hex::encode(random));
        random.zeroize();
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(&file)?.write_all(value.as_bytes())?;
    } else if std::fs::symlink_metadata(&file)?.file_type().is_symlink() {
        bail!("capability may not be a symlink");
    }
    #[cfg(target_os = "macos")]
    install_macos(owner, &file)?;
    #[cfg(target_os = "windows")]
    install_windows(owner, &file)?;
    println!("Background service installed; subsequent connections need no elevation");
    Ok(())
}
#[cfg(target_os = "macos")]
fn install_macos(owner: &str, token: &std::path::Path) -> Result<()> {
    use std::{
        ffi::CString,
        os::unix::{ffi::OsStrExt, fs::PermissionsExt},
    };
    let path = CString::new(token.as_os_str().as_bytes())?;
    // SAFETY: a validated UID and live NUL-terminated path are passed to chown.
    if unsafe { libc::chown(path.as_ptr(), owner.parse()?, u32::MAX) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    std::fs::set_permissions(token, std::fs::Permissions::from_mode(0o600))?;
    let label = "com.easy-connect.service";
    let destination = PathBuf::from("/Library/PrivilegedHelperTools/easy-connect");
    std::fs::create_dir_all(destination.parent().context("destination missing")?)?;
    let _ = Command::new("/bin/launchctl")
        .args(["bootout", &format!("system/{label}")])
        .status();
    let temp = destination.with_extension("new");
    std::fs::copy(std::env::current_exe()?, &temp)?;
    std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o755))?;
    std::fs::rename(temp, &destination)?;
    let plist = PathBuf::from(format!("/Library/LaunchDaemons/{label}.plist"));
    let xml = format!(
        r#"<?xml version="1.0"?><plist version="1.0"><dict><key>Label</key><string>{label}</string><key>ProgramArguments</key><array><string>{}</string><string>service</string><string>--owner</string><string>{owner}</string></array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ProcessType</key><string>Background</string></dict></plist>"#,
        destination.display()
    );
    std::fs::write(&plist, xml)?;
    std::fs::set_permissions(&plist, std::fs::Permissions::from_mode(0o644))?;
    if !Command::new("/bin/launchctl")
        .args(["bootstrap", "system"])
        .arg(plist)
        .status()?
        .success()
    {
        bail!("launchd could not start service");
    }
    Ok(())
}
#[cfg(target_os = "windows")]
fn install_windows(owner: &str, token: &std::path::Path) -> Result<()> {
    let source = std::env::current_exe()?;
    let dir = PathBuf::from(std::env::var_os("ProgramFiles").context("ProgramFiles missing")?)
        .join("EasyConnect");
    std::fs::create_dir_all(&dir)?;
    let _ = Command::new("sc.exe").args(["stop", NAME]).status();
    std::thread::sleep(Duration::from_secs(2));
    let binary = dir.join("easy-connect.exe");
    std::fs::copy(&source, &binary)?;
    std::fs::copy(source.with_file_name("wintun.dll"), dir.join("wintun.dll"))?;
    if !Command::new("icacls.exe")
        .arg(token)
        .args([
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:F",
            "*S-1-5-32-544:F",
            &format!("*{owner}:R"),
        ])
        .status()?
        .success()
    {
        bail!("cannot protect service capability");
    }
    let exists = Command::new("sc.exe")
        .args(["query", NAME])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?
        .success();
    let bin = format!("\"{}\" service --owner {owner}", binary.display());
    if !Command::new("sc.exe")
        .args([
            if exists { "config" } else { "create" },
            NAME,
            "binPath=",
            &bin,
            "start=",
            "auto",
        ])
        .status()?
        .success()
    {
        bail!("cannot install Windows service");
    }
    if !Command::new("sc.exe")
        .args(["start", NAME])
        .status()?
        .success()
    {
        bail!("cannot start Windows service");
    }
    Ok(())
}
#[cfg(target_os = "windows")]
pub fn run_windows(owner: String) -> Result<()> {
    static OWNER: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    windows_service::define_windows_service!(entry, service_main);
    fn service_main(_: Vec<std::ffi::OsString>) {
        use windows_service::{
            service::{
                ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
                ServiceType,
            },
            service_control_handler::{self, ServiceControlHandlerResult},
        };
        let stopped = Arc::new(AtomicBool::new(false));
        let flag = stopped.clone();
        let Ok(handler) = service_control_handler::register(NAME, move |event| match event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                flag.store(true, Ordering::Relaxed);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }) else {
            return;
        };
        let status = |state| ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        };
        let _ = handler.set_service_status(status(ServiceState::Running));
        if let Some(owner) = OWNER.get() {
            let _ = run(owner, stopped);
        }
        let _ = handler.set_service_status(status(ServiceState::Stopped));
    }
    let _ = OWNER.set(owner);
    windows_service::service_dispatcher::start(NAME, entry)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credentials_cannot_inject_worker_control() {
        for password in ["a\nb", "a\rb", "a\0b", ""] {
            assert!(validate_credentials("https://example.com", "u", password, None).is_err());
        }
        assert!(validate_credentials("https://example.com", "u", "p", None).is_ok());
    }
    #[test]
    fn capabilities_match_exactly() {
        assert!(authorized(b"abc", b"abc"));
        assert!(!authorized(b"abc", b"abd"));
        assert!(!authorized(b"abc", b"ab"));
    }
}
