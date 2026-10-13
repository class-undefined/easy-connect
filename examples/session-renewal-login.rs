//! Bounded diagnostic exercising the same renewal lifecycle as `connect`.
use anyhow::{Context, Result, bail};
use clap::Parser;
use ec_compat::engine::session::AuthenticatedEngineSession;
use ec_compat::session_status::SessionStatus;
use std::sync::mpsc;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    gateway: String,
    #[arg(long)]
    cert_sha256: Option<String>,
    /// Consent to exposing TWFID on the legacy unauthenticated TCP channel.
    #[arg(long)]
    allow_plaintext_session_id: bool,
    #[arg(long, default_value = "20", value_parser = clap::value_parser!(u64).range(1..=1800))]
    seconds: u64,
}

fn run(
    args: Args,
    username: Zeroizing<String>,
    password: Zeroizing<String>,
    stopped: mpsc::Receiver<()>,
) -> Result<()> {
    if stopped.try_recv().is_ok() {
        return Ok(());
    }
    let mut config: serde_json::Value =
        serde_json::from_str(include_str!("../config/gateway.example.json"))?;
    config["base_url"] = args.gateway.into();
    config["tls"]["leaf_sha256"] = args.cert_sha256.into();
    config["timeout_seconds"] = 5.into();
    let session = AuthenticatedEngineSession::authenticate(&config, &username, &password)
        .map_err(|_| anyhow::anyhow!("HTTPS authentication/setup failed (details redacted)"))?;
    drop(password);
    drop(username);
    let mut remote_ended = false;
    let result = (|| -> Result<()> {
        if stopped.try_recv().is_ok() {
            return Ok(());
        }
        // Establish the current real TLS data plane alongside the legacy query
        // connection. No TUN/routes/DNS are installed by this diagnostic.
        let plane = session.establish_data_plane()?;
        let plane_stop = plane.shutdown_handle();
        let (lease, _sender, _receiver) = plane.split();
        let start = Instant::now();
        loop {
            if !lease.transport_is_open() {
                bail!("production renewal or data transport stopped");
            }
            if start.elapsed() >= Duration::from_secs(args.seconds) {
                break;
            }
            let wait = Duration::from_millis(100)
                .min(Duration::from_secs(args.seconds).saturating_sub(start.elapsed()));
            match stopped.recv_timeout(wait) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
        let renewals = session.renewal_confirmations();
        println!(
            "probe_finished elapsed_ms={} positive_renewals={} data_transport_open={} internal_access_tested=false production_lifecycle=true",
            start.elapsed().as_millis(),
            renewals,
            lease.transport_is_open()
        );
        if renewals == 0 {
            bail!("no positive renewal was confirmed");
        }
        plane_stop.shutdown();
        Ok(())
    })();
    // Never log out a replacement session. A failed status query provides no
    // evidence of a kick; only the current authenticated cookies are cleaned up.
    if !remote_ended && result.is_err() {
        remote_ended = matches!(session.session_status(), Ok(SessionStatus::Ended(_)));
    }
    if !remote_ended && session.logout().is_err() {
        eprintln!("probe logout failed; session cleanup is unconfirmed");
    }
    result
}

fn main() -> Result<()> {
    let args = Args::parse();
    if !args.allow_plaintext_session_id {
        bail!(
            "legacy renewal exposes the session ID and has no server authentication; explicit --allow-plaintext-session-id consent is required"
        );
    }
    let url = url::Url::parse(&args.gateway)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("gateway must be an HTTPS origin without credentials");
    }
    if let Some(pin) = &args.cert_sha256 {
        ec_compat::modern::parse_sha256_pin(pin)?;
    }
    println!(
        "诊断会在独立 TCP 连接中明文发送会话 ID，无法认证该连接的服务器。密码仍经已验证的 HTTPS 提交。请先退出其他客户端；Ctrl-C 结束诊断并清理本次会话。"
    );
    // Prompt before installing async signal handlers: Ctrl-C during input must
    // terminate immediately, while no authenticated session exists yet.
    let username = Zeroizing::new(rpassword::prompt_password("账号（隐藏输入）: ")?);
    let password = Zeroizing::new(rpassword::prompt_password("密码: ")?);
    tokio::runtime::Runtime::new()?.block_on(async move {
        let (stop, stopped) = mpsc::channel();
        let mut worker =
            tokio::task::spawn_blocking(move || run(args, username, password, stopped));
        tokio::select! {
            result = &mut worker => result.context("probe worker failed")?,
            signal = tokio::signal::ctrl_c() => {
                signal?;
                let _ = stop.send(());
                worker.await.context("probe worker failed")?
            }
        }
    })
}
