//! Loopback broker. A per-user capability authenticates fixed VPN operations.
use anyhow::{Context, Result, bail};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
#[cfg(target_os = "windows")]
use std::net::{TcpListener, TcpStream};
#[cfg(target_os = "macos")]
use std::os::unix::net::{UnixListener as TcpListener, UnixStream as TcpStream};
use std::{
    collections::VecDeque,
    io::{BufRead, BufReader, Read, Write},
    path::PathBuf,
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use zeroize::{Zeroize, Zeroizing};
#[cfg(target_os = "windows")]
const PORT: u16 = 40571;
const LIMIT: u64 = 16384;
#[cfg(target_os = "windows")]
const NAME: &str = "EasyConnectRust";
pub(crate) static STOP: AtomicBool = AtomicBool::new(false);
pub(crate) static CONTROLLED: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "windows")]
fn known_folder(id: &windows_sys::core::GUID) -> Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    let mut path = std::ptr::null_mut();
    // SAFETY: valid GUID and output pointer. Windows allocates a NUL-terminated path.
    let result = unsafe {
        windows_sys::Win32::UI::Shell::SHGetKnownFolderPath(id, 0, std::ptr::null_mut(), &mut path)
    };
    if result < 0 || path.is_null() {
        bail!("Windows known folder unavailable");
    }
    // SAFETY: SHGetKnownFolderPath guarantees a NUL-terminated allocation until freed.
    let owned = unsafe {
        let mut len = 0;
        while *path.add(len) != 0 {
            len += 1;
        }
        let value = std::ffi::OsString::from_wide(std::slice::from_raw_parts(path, len));
        windows_sys::Win32::System::Com::CoTaskMemFree(path as _);
        value
    };
    Ok(PathBuf::from(owned))
}

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
struct Challenge {
    nonce: String,
}
#[derive(Serialize, Deserialize)]
struct ServerProof {
    nonce: String,
    proof: String,
}
#[derive(Serialize, Deserialize)]
struct Frame {
    payload: String,
    proof: String,
}
impl Drop for Frame {
    fn drop(&mut self) {
        self.payload.zeroize();
    }
}
fn nonce() -> String {
    let mut bytes = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}
fn valid_nonce(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
fn mac(key: &[u8], role: &str, client: &str, server: &str, payload: &str) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts every key length");
    for value in ["easy-connect-rpc-v1", role, client, server, payload] {
        mac.update(value.as_bytes());
        mac.update(&[0]);
    }
    mac
}
fn proof(key: &[u8], role: &str, client: &str, server: &str, payload: &str) -> String {
    hex::encode(
        mac(key, role, client, server, payload)
            .finalize()
            .into_bytes(),
    )
}
fn verify(
    key: &[u8],
    role: &str,
    client: &str,
    server: &str,
    payload: &str,
    signature: &str,
) -> Result<()> {
    let bytes = hex::decode(signature).context("invalid broker proof")?;
    mac(key, role, client, server, payload)
        .verify_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("background service authentication failed"))
}
fn send_frame(socket: &mut TcpStream, value: &impl Serialize) -> Result<()> {
    serde_json::to_writer(&mut *socket, value)?;
    socket.write_all(b"\n")?;
    socket.flush()?;
    Ok(())
}
fn receive<T: serde::de::DeserializeOwned>(socket: &mut TcpStream, limit: u64) -> Result<T> {
    let mut bytes = Zeroizing::new(Vec::new());
    BufReader::new(socket)
        .take(limit + 1)
        .read_until(b'\n', &mut bytes)?;
    if bytes.len() as u64 > limit || bytes.last() != Some(&b'\n') {
        bail!("invalid broker frame");
    }
    Ok(serde_json::from_slice(&bytes)?)
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
    #[serde(default)]
    pub password_policy: Option<ec_compat::password::PasswordPolicy>,
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
            password_policy: None,
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
    let base = known_folder(&windows_sys::Win32::UI::Shell::FOLDERID_ProgramData)?
        .join("EasyConnect Rust");
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
#[cfg(target_os = "macos")]
fn socket_path(owner: &str) -> Result<PathBuf> {
    validate_owner(owner)?;
    Ok(PathBuf::from(format!("/var/run/easy-connect-{owner}.sock")))
}
#[cfg(target_os = "macos")]
fn connect_broker(owner: &str) -> Result<TcpStream> {
    use std::os::fd::AsRawFd;
    let socket =
        TcpStream::connect(socket_path(owner)?).context("background service is not running")?;
    let mut uid = 0;
    let mut gid = 0;
    // SAFETY: live descriptor and valid integer output pointers.
    if unsafe { libc::getpeereid(socket.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if uid != 0 {
        bail!("broker endpoint is not root-owned");
    }
    Ok(socket)
}
#[cfg(target_os = "windows")]
fn connect_broker(_: &str) -> Result<TcpStream> {
    use std::os::windows::process::CommandExt;
    let socket = TcpStream::connect_timeout(&([127, 0, 0, 1], PORT).into(), Duration::from_secs(2))
        .context("background service is not running")?;
    let status = Command::new("sc.exe")
        .creation_flags(0x08000000)
        .args(["queryex", NAME])
        .output()?;
    let text = String::from_utf8_lossy(&status.stdout);
    let pid = text
        .lines()
        .find_map(|s| {
            s.trim()
                .strip_prefix("PID")
                .and_then(|s| s.trim().strip_prefix(':'))
                .and_then(|s| s.trim().parse::<u32>().ok())
        })
        .filter(|p| *p != 0)
        .context("broker SCM identity unavailable")?;
    let table = Command::new("netstat.exe")
        .creation_flags(0x08000000)
        .args(["-ano", "-p", "tcp"])
        .output()?;
    let endpoint = format!("127.0.0.1:{PORT}");
    let text = String::from_utf8_lossy(&table.stdout);
    if !text.lines().any(|line| {
        let p: Vec<_> = line.split_whitespace().collect();
        p.get(1) == Some(&endpoint.as_str())
            && p.last().and_then(|v| v.parse::<u32>().ok()) == Some(pid)
    }) {
        bail!("broker endpoint does not belong to the installed SCM service");
    }
    Ok(socket)
}
#[cfg(target_os = "macos")]
struct SocketGuard(PathBuf);
#[cfg(target_os = "macos")]
impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
pub fn request(request: Request) -> Result<Status> {
    let owner = current_owner()?;
    let capability = token(&owner)?;
    let mut socket = connect_broker(&owner)?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    let client = nonce();
    send_frame(
        &mut socket,
        &Challenge {
            nonce: client.clone(),
        },
    )?;
    let server: ServerProof = receive(&mut socket, LIMIT)?;
    if !valid_nonce(&server.nonce) {
        bail!("invalid broker nonce");
    }
    // Authenticate the server before serializing or transmitting a VPN password.
    verify(
        capability.as_bytes(),
        "server",
        &client,
        &server.nonce,
        "",
        &server.proof,
    )?;
    let payload = Zeroizing::new(serde_json::to_string(&request)?);
    if payload.len() as u64 > LIMIT / 2 {
        bail!("request too large");
    }
    let frame = Frame {
        proof: proof(
            capability.as_bytes(),
            "request",
            &client,
            &server.nonce,
            &payload,
        ),
        payload: payload.to_string(),
    };
    send_frame(&mut socket, &frame)?;
    let frame: Frame = receive(&mut socket, 2 * 1024 * 1024)?;
    verify(
        capability.as_bytes(),
        "response",
        &client,
        &server.nonce,
        &frame.payload,
        &frame.proof,
    )?;
    let response: Response = serde_json::from_str(&frame.payload)?;
    if let Some(error) = response.error {
        bail!("{error}");
    }
    response.status.context("missing service status")
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
            if let Some(policy) = ec_compat::password::PasswordPolicy::from_log(&line) {
                state.password_policy = Some(policy);
            }
            let words: Vec<_> = line.split_whitespace().collect();
            if line.starts_with("TUN ready:") && state.phase == Phase::Connecting {
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
    #[cfg(target_os = "windows")]
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, PORT))?;
    #[cfg(target_os = "macos")]
    let (listener, _socket_guard) = {
        use std::{
            ffi::CString,
            os::unix::{
                ffi::OsStrExt,
                fs::{FileTypeExt, PermissionsExt},
            },
        };
        let path = socket_path(owner)?;
        if let Ok(metadata) = std::fs::symlink_metadata(&path) {
            if !metadata.file_type().is_socket() {
                bail!("broker path is not a socket");
            }
            if TcpStream::connect(&path).is_ok() {
                bail!("another broker instance is active");
            }
            std::fs::remove_file(&path)?;
        }
        let listener = TcpListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let file = CString::new(path.as_os_str().as_bytes())?;
        // SAFETY: live NUL-terminated socket path and validated owner UID.
        if unsafe { libc::chown(file.as_ptr(), owner.parse()?, u32::MAX) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        (listener, SocketGuard(path))
    };
    listener.set_nonblocking(true)?;
    let mut worker = Worker {
        child: None,
        input: None,
        status: Arc::new(Mutex::new(Status::default())),
    };
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut socket, peer)) => {
                #[cfg(target_os = "windows")]
                if !peer.ip().is_loopback() {
                    continue;
                }
                #[cfg(target_os = "macos")]
                let _ = peer;
                socket.set_read_timeout(Some(Duration::from_secs(2)))?;
                socket.set_write_timeout(Some(Duration::from_secs(2)))?;
                let exchange = (|| -> Result<(String, String, Request)> {
                    let client: Challenge = receive(&mut socket, LIMIT)?;
                    if !valid_nonce(&client.nonce) {
                        bail!("invalid client nonce");
                    }
                    let server = nonce();
                    send_frame(
                        &mut socket,
                        &ServerProof {
                            proof: proof(
                                capability.as_bytes(),
                                "server",
                                &client.nonce,
                                &server,
                                "",
                            ),
                            nonce: server.clone(),
                        },
                    )?;
                    let frame: Frame = receive(&mut socket, LIMIT)?;
                    verify(
                        capability.as_bytes(),
                        "request",
                        &client.nonce,
                        &server,
                        &frame.payload,
                        &frame.proof,
                    )?;
                    let request: Request = serde_json::from_str(&frame.payload)?;
                    Ok((client.nonce, server, request))
                })();
                let Ok((client, server, request)) = exchange else {
                    continue;
                };
                let result = worker.handle(&request);
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
                let payload = serde_json::to_string(&response)?;
                let frame = Frame {
                    proof: proof(
                        capability.as_bytes(),
                        "response",
                        &client,
                        &server,
                        &payload,
                    ),
                    payload,
                };
                let _ = send_frame(&mut socket, &frame);
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
        use std::{
            ffi::CString,
            os::unix::{ffi::OsStrExt, fs::PermissionsExt},
        };
        let path = CString::new(dir.as_os_str().as_bytes())?;
        // SAFETY: the checked directory path is NUL-terminated; root owns the shared directory.
        if unsafe { libc::chown(path.as_ptr(), 0, 0) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
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
fn stop_windows_service() -> Result<()> {
    use windows_service::{
        service::{ServiceAccess, ServiceState},
        service_manager::{ServiceManager, ServiceManagerAccess},
    };
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = match manager
        .open_service(NAME, ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)
    {
        Ok(service) => service,
        Err(windows_service::Error::Winapi(error))
            if error.raw_os_error()
                == Some(windows_sys::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST as i32) =>
        {
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    let status = service.query_status()?;
    if status.current_state == ServiceState::Stopped {
        return Ok(());
    }
    // Retain the process handle before stopping, so SCM's Stopped notification
    // cannot race copying the executable while its process is still exiting.
    use windows_sys::Win32::{
        Foundation::{CloseHandle, WAIT_OBJECT_0},
        System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject},
    };
    let pid = status
        .process_id
        .context("service process ID unavailable")?;
    // SAFETY: a PID from SCM and SYNCHRONIZE-only access are passed to OpenProcess.
    let process = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    if process.is_null() {
        return Err(std::io::Error::last_os_error()).context("cannot wait for service shutdown");
    }
    let result = (|| -> Result<()> {
        if status.current_state != ServiceState::StopPending {
            service.stop()?;
        }
        // SAFETY: process is a live owned handle, closed below on all paths.
        if unsafe { WaitForSingleObject(process, 30_000) } != WAIT_OBJECT_0 {
            bail!("background service did not stop; update was not applied");
        }
        Ok(())
    })();
    // SAFETY: close our OpenProcess handle exactly once, including on stop errors.
    unsafe {
        CloseHandle(process);
    }
    result
}

#[cfg(target_os = "windows")]
fn install_windows(owner: &str, token: &std::path::Path) -> Result<()> {
    let source = std::env::current_exe()?;
    let dir = known_folder(&windows_sys::Win32::UI::Shell::FOLDERID_ProgramFiles)?
        .join("EasyConnect Rust");
    std::fs::create_dir_all(&dir)?;
    stop_windows_service()?;
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
    fn broker_proofs_bind_role_nonces_and_payload() {
        let signature = proof(b"key", "request", "client", "server", "data");
        assert!(verify(b"key", "request", "client", "server", "data", &signature).is_ok());
        assert!(verify(b"other", "request", "client", "server", "data", &signature).is_err());
        assert!(verify(b"key", "response", "client", "server", "data", &signature).is_err());
        assert!(verify(b"key", "request", "different", "server", "data", &signature).is_err());
        assert!(
            verify(
                b"key", "request", "client", "server", "tampered", &signature
            )
            .is_err()
        );
    }
}
