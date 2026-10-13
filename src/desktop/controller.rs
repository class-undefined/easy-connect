use super::*;
use std::sync::mpsc::{self, RecvTimeoutError, Sender};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Readiness {
    #[default]
    Preparing,
    Updating,
    Ready,
    Failed,
}
impl Readiness {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Preparing => "正在准备连接环境…",
            Self::Updating => "正在更新连接环境…",
            Self::Ready => "连接环境已就绪",
            Self::Failed => "连接环境未就绪",
        }
    }
}

#[derive(Default)]
pub(super) struct Live {
    pub status: Option<Status>,
    pub notice: Option<String>,
    pub readiness: Readiness,
    pub busy: bool,
    pub quitting: bool,
    pub quit_ready: bool,
    pub replacement_password: Option<Zeroizing<String>>,
    pending: Option<Phase>,
}
impl Live {
    fn observe_status(&mut self, result: Result<Status>) {
        match result {
            Ok(status) if current_version(&status) => {
                self.status = Some(status);
                if self.readiness == Readiness::Failed {
                    self.notice = None;
                }
                self.readiness = Readiness::Ready;
            }
            result => {
                self.status = None;
                if self.readiness == Readiness::Ready {
                    self.readiness = Readiness::Failed;
                    self.notice = Some(match result {
                        Ok(status) => format!(
                            "后台版本已变更（{}），请点击重试检查连接环境",
                            status.version
                        ),
                        Err(error) => {
                            format!("无法连接后台服务：{error:#}；请点击重试检查连接环境")
                        }
                    });
                }
            }
        }
    }
    pub(super) fn phase(&self) -> Option<Phase> {
        self.pending
            .or_else(|| self.status.as_ref().map(|s| s.phase))
    }
    pub(super) fn can_connect(&self) -> bool {
        self.readiness == Readiness::Ready
            && !self.busy
            && !self.quitting
            && matches!(self.phase(), Some(Phase::Disconnected | Phase::Failed))
    }
    pub(super) fn can_disconnect(&self) -> bool {
        self.readiness == Readiness::Ready
            && !self.quitting
            && matches!(self.phase(), Some(Phase::Connecting | Phase::Connected))
            && (!self.busy || self.phase() == Some(Phase::Connecting))
    }
    pub(super) fn connect_label(&self) -> &'static str {
        if self.quitting {
            return "正在退出…";
        }
        match self.readiness {
            Readiness::Preparing => "正在准备…",
            Readiness::Updating => "正在更新…",
            Readiness::Failed => "暂不可连接",
            Readiness::Ready => match self.phase() {
                Some(Phase::Connecting) => "取消连接",
                Some(Phase::Connected) => "断开连接",
                Some(Phase::Stopping) => "正在断开…",
                _ if self.busy => "处理中…",
                _ => "连接",
            },
        }
    }
    pub(super) fn loading(&self) -> bool {
        self.busy
            || self.quitting
            || matches!(self.readiness, Readiness::Preparing | Readiness::Updating)
            || matches!(self.phase(), Some(Phase::Connecting | Phase::Stopping))
    }

    fn finish_action(
        &mut self,
        pending: Option<Phase>,
        result: Result<()>,
        status: Option<Status>,
    ) {
        self.status = status;
        // A cancel can be queued while the connect request is still in flight.
        // Only the last queued action may release its UI state or set a notice.
        if self.pending == pending {
            self.pending = None;
            self.busy = false;
            self.notice = result.err().map(|e| format!("{e:#}"));
        }
    }
}

type Work = Box<dyn FnOnce() -> Result<()> + Send>;
enum Command {
    Action { pending: Option<Phase>, work: Work },
    Prepare,
    Quit(Option<Work>),
}
pub(super) struct Controller {
    pub live: Arc<Mutex<Live>>,
    commands: Sender<Command>,
}

const POLL: Duration = Duration::from_millis(750);
const RETRY: Duration = Duration::from_millis(250);
const WAIT_ATTEMPTS: usize = 120;

fn inactive(status: &Status) -> bool {
    matches!(status.phase, Phase::Disconnected | Phase::Failed)
}

// Keep polling and mutations on one worker: an older status response must never
// overwrite the result of a newer connect/disconnect request.
impl Controller {
    pub(super) fn new() -> Self {
        Self::configured(true)
    }
    pub(super) fn for_tailscale() -> Self {
        Self::configured(false)
    }
    fn configured(native: bool) -> Self {
        let live = Arc::new(Mutex::new(if native {
            Live::default()
        } else {
            Live {
                readiness: Readiness::Ready,
                status: Some(Status::default()),
                ..Default::default()
            }
        }));
        let (commands, receiver) = mpsc::channel();
        let state = live.clone();
        std::thread::spawn(move || {
            if native {
                prepare(&state);
            }
            loop {
                match receiver.recv_timeout(POLL) {
                    Ok(Command::Action { pending, work }) => {
                        let result = work();
                        let status = if native {
                            service::request(Request::Status).ok()
                        } else {
                            Some(Status::default())
                        };
                        if let Ok(mut live) = state.lock() {
                            live.finish_action(pending, result, status);
                        }
                    }
                    Ok(Command::Prepare) => {
                        if native {
                            prepare(&state);
                        }
                    }
                    Ok(Command::Quit(install)) => {
                        let updating = install.is_some();
                        let result = if native {
                            finish_exit(
                                &mut service::request,
                                &mut || std::thread::sleep(RETRY),
                                install,
                                service::installed(),
                            )
                        } else {
                            install.map_or(Ok(()), |work| work())
                        };
                        if let Ok(mut live) = state.lock() {
                            live.quit_ready = result.is_ok();
                            live.quitting = result.is_ok();
                            live.notice = result.err().map(|e| {
                                format!(
                                    "{}：{e:#}",
                                    if updating {
                                        "更新安装失败"
                                    } else {
                                        "退出失败"
                                    }
                                )
                            });
                        }
                        if state.lock().is_ok_and(|s| s.quit_ready) {
                            break;
                        }
                    }
                    Err(RecvTimeoutError::Timeout) if !native => {}
                    Err(RecvTimeoutError::Timeout) => {
                        let status = service::request(Request::Status);
                        if let Ok(mut live) = state.lock() {
                            // Polling may recover readiness, but must never
                            // launch an installer or repeat an elevation prompt.
                            live.observe_status(status);
                        }
                    }
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }
        });
        Self { live, commands }
    }

    pub(super) fn action(&self, work: impl FnOnce() -> Result<()> + Send + 'static) -> bool {
        self.submit(None, work)
    }
    pub(super) fn connect(&self, work: impl FnOnce() -> Result<()> + Send + 'static) -> bool {
        self.submit(Some(Phase::Connecting), work)
    }
    fn submit(
        &self,
        pending: Option<Phase>,
        work: impl FnOnce() -> Result<()> + Send + 'static,
    ) -> bool {
        let Ok(mut live) = self.live.lock() else {
            return false;
        };
        let queue_cancel =
            pending == Some(Phase::Stopping) && live.phase() == Some(Phase::Connecting);
        if (live.busy && !queue_cancel)
            || live.quitting
            || (pending == Some(Phase::Connecting) && !live.can_connect())
            || (pending == Some(Phase::Stopping) && !live.can_disconnect())
        {
            return false;
        }
        live.busy = true;
        live.pending = pending;
        live.notice = None;
        if self
            .commands
            .send(Command::Action {
                pending,
                work: Box::new(work),
            })
            .is_err()
        {
            live.busy = false;
            live.pending = None;
            live.notice = Some("后台任务已停止，请重新打开应用".into());
            return false;
        }
        true
    }
    pub(super) fn disconnect(&self) {
        self.submit(Some(Phase::Stopping), || {
            service::request(Request::Disconnect)?;
            Ok(())
        });
    }
    pub(super) fn retry(&self) {
        if let Ok(mut live) = self.live.lock()
            && live.readiness == Readiness::Failed
            && !live.busy
            && !live.quitting
        {
            live.readiness = Readiness::Preparing;
            live.notice = None;
            let _ = self.commands.send(Command::Prepare);
        }
    }
    pub(super) fn quit(&self) {
        self.request_quit(None);
    }
    pub(super) fn quit_with_install(
        &self,
        install: impl FnOnce() -> Result<()> + Send + 'static,
    ) -> bool {
        self.request_quit(Some(Box::new(install)))
    }
    fn request_quit(&self, install: Option<Work>) -> bool {
        if let Ok(mut live) = self.live.lock()
            && !live.quitting
        {
            live.quitting = true;
            if self.commands.send(Command::Quit(install)).is_ok() {
                return true;
            }
            live.quitting = false;
            live.notice = Some("后台任务已停止，请重新打开应用".into());
        }
        false
    }
}
fn current_version(status: &Status) -> bool {
    status.version == env!("CARGO_PKG_VERSION")
}
fn finish_exit(
    request: &mut impl FnMut(Request) -> Result<Status>,
    sleep: &mut impl FnMut(),
    install: Option<Work>,
    installed: bool,
) -> Result<()> {
    match request(Request::Status) {
        Ok(status) if !inactive(&status) => disconnect_and_wait(request, sleep)?,
        Err(error) if install.is_some() && installed => {
            return Err(error).context("无法确认 VPN 已断开，暂不安装更新");
        }
        _ => {}
    }
    install.map_or(Ok(()), |work| work())
}
fn prepare(live: &Arc<Mutex<Live>>) {
    if let Ok(mut state) = live.lock() {
        state.readiness = Readiness::Preparing;
        state.status = None;
        state.notice = None;
    }
    let result = ensure_service(
        &mut service::request,
        install_service,
        &mut || std::thread::sleep(RETRY),
        |readiness| {
            if let Ok(mut state) = live.lock() {
                state.readiness = readiness;
            }
        },
    );
    if let Ok(mut state) = live.lock() {
        match result {
            Ok(status) => {
                state.status = Some(status);
                state.readiness = Readiness::Ready;
            }
            Err(error) => {
                state.status = None;
                state.readiness = Readiness::Failed;
                state.notice = Some(format!("连接环境准备失败：{error:#}"));
            }
        }
    }
}
fn disconnect_and_wait(
    request: &mut impl FnMut(Request) -> Result<Status>,
    sleep: &mut impl FnMut(),
) -> Result<()> {
    let mut status = request(Request::Disconnect)?;
    for _ in 0..WAIT_ATTEMPTS {
        if inactive(&status) {
            return Ok(());
        }
        sleep();
        status = request(Request::Status).context("无法确认旧连接已断开")?;
    }
    bail!("旧连接尚未完全断开，请稍后重试");
}
fn ensure_service(
    request: &mut impl FnMut(Request) -> Result<Status>,
    install: impl FnOnce() -> Result<()>,
    sleep: &mut impl FnMut(),
    progress: impl Fn(Readiness),
) -> Result<Status> {
    // Give launchd/SCM a short grace period to recover before requesting elevation.
    let mut status = request(Request::Status).ok();
    for _ in 0..8 {
        if status.is_some() {
            break;
        }
        sleep();
        status = request(Request::Status).ok();
    }
    if let Some(status) = status {
        if current_version(&status) {
            return Ok(status);
        }
        if semver::Version::parse(&status.version)?
            > semver::Version::parse(env!("CARGO_PKG_VERSION"))?
        {
            bail!("后台已由较新版本管理，请打开最新版应用");
        }
        progress(Readiness::Updating);
        if !inactive(&status) {
            disconnect_and_wait(request, sleep)?;
        }
    }
    install()?;
    let mut last_error = anyhow::anyhow!("后台未返回状态");
    for _ in 0..WAIT_ATTEMPTS {
        match request(Request::Status) {
            Ok(status) if current_version(&status) => return Ok(status),
            Ok(status) => {
                last_error = anyhow::anyhow!("后台版本不匹配：{}", status.version);
            }
            Err(error) => last_error = error,
        }
        sleep();
    }
    Err(last_error).context("后台启动超时，请重试；若问题持续，请重新打开应用")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn client_mode_runs_actions_and_exits_without_preparing_native_service() {
        let controller = Controller::for_tailscale();
        assert_eq!(controller.live.lock().unwrap().readiness, Readiness::Ready);
        let (sent, received) = std::sync::mpsc::channel();
        assert!(controller.action(move || {
            sent.send(()).unwrap();
            Ok(())
        }));
        received.recv_timeout(Duration::from_secs(1)).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while controller.live.lock().unwrap().busy && std::time::Instant::now() < deadline {
            std::thread::yield_now();
        }
        controller.quit();
        while !controller.live.lock().unwrap().quit_ready && std::time::Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert!(controller.live.lock().unwrap().quit_ready);
    }
    #[test]
    fn update_installer_waits_for_disconnect_and_aborts_on_cleanup_failure() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let launched = Arc::new(AtomicBool::new(false));
        let marker = launched.clone();
        let mut calls = 0;
        finish_exit(
            &mut |_| {
                calls += 1;
                assert!(!launched.load(Ordering::Relaxed));
                Ok(status(
                    if calls < 3 {
                        Phase::Stopping
                    } else {
                        Phase::Disconnected
                    },
                    env!("CARGO_PKG_VERSION"),
                ))
            },
            &mut || {},
            Some(Box::new(move || {
                marker.store(true, Ordering::Relaxed);
                Ok(())
            })),
            true,
        )
        .unwrap();
        assert_eq!(calls, 3);
        assert!(launched.load(Ordering::Relaxed));
        assert!(
            finish_exit(
                &mut |_| Ok(status(Phase::Stopping, env!("CARGO_PKG_VERSION"))),
                &mut || {},
                Some(Box::new(|| panic!("installer ran before cleanup"))),
                true
            )
            .is_err()
        );
        assert!(
            finish_exit(
                &mut |_| bail!("offline"),
                &mut || {},
                Some(Box::new(|| panic!("installer ran without status"))),
                true
            )
            .is_err()
        );
    }
    fn status(phase: Phase, version: &str) -> Status {
        Status {
            phase,
            version: version.into(),
            ..Default::default()
        }
    }
    #[test]
    fn polling_outages_never_restart_preparation() {
        let mut live = Live {
            readiness: Readiness::Ready,
            status: Some(Status::default()),
            ..Default::default()
        };
        for _ in 0..3 {
            live.observe_status(Err(anyhow::anyhow!("broken pipe")));
            assert_eq!(live.readiness, Readiness::Failed);
            assert!(!live.can_connect());
            assert!(!live.loading());
            assert!(live.notice.as_ref().unwrap().contains("broken pipe"));
            live.observe_status(Err(anyhow::anyhow!("offline")));
            assert_eq!(live.readiness, Readiness::Failed);
            assert!(live.notice.as_ref().unwrap().contains("broken pipe"));
            live.observe_status(Ok(Status::default()));
            assert_eq!(live.readiness, Readiness::Ready);
            assert!(live.can_connect());
            assert!(live.notice.is_none());
        }
    }
    #[test]
    fn polling_version_change_requires_manual_retry() {
        let mut live = Live {
            readiness: Readiness::Ready,
            ..Default::default()
        };
        live.observe_status(Ok(status(Phase::Disconnected, "0.0.1")));
        assert_eq!(live.readiness, Readiness::Failed);
        assert!(live.notice.as_ref().unwrap().contains("0.0.1"));
        assert!(!live.can_connect());
    }
    #[test]
    fn polling_preserves_authorization_failure_until_manual_retry() {
        let (commands, receiver) = mpsc::channel();
        let controller = Controller {
            live: Arc::new(Mutex::new(Live {
                readiness: Readiness::Failed,
                notice: Some("管理员授权被取消".into()),
                ..Default::default()
            })),
            commands,
        };
        {
            let mut live = controller.live.lock().unwrap();
            live.observe_status(Err(anyhow::anyhow!("offline")));
            assert_eq!(live.readiness, Readiness::Failed);
            assert_eq!(live.notice.as_deref(), Some("管理员授权被取消"));
            assert!(receiver.try_recv().is_err());
        }
        controller.retry();
        controller.retry();
        assert!(matches!(receiver.try_recv(), Ok(Command::Prepare)));
        assert!(receiver.try_recv().is_err());
        assert_eq!(
            controller.live.lock().unwrap().readiness,
            Readiness::Preparing
        );
    }
    #[test]
    fn startup_timeout_retains_the_broker_error_and_installs_only_once() {
        use std::cell::Cell;
        let installs = Cell::new(0);
        let error = ensure_service(
            &mut |_| Err(anyhow::anyhow!("broken pipe").context("status handshake failed")),
            || {
                installs.set(installs.get() + 1);
                Ok(())
            },
            &mut || {},
            |_| {},
        )
        .unwrap_err();
        assert_eq!(installs.get(), 1);
        let message = format!("{error:#}");
        assert!(message.contains("后台启动超时"));
        assert!(message.contains("status handshake failed"));
        assert!(message.contains("broken pipe"));
    }
    #[test]
    fn connection_controls_follow_worker_phase_after_request_finishes() {
        let mut live = Live {
            readiness: Readiness::Ready,
            status: Some(Status::default()),
            ..Default::default()
        };
        assert!(live.can_connect());
        live.pending = Some(Phase::Connecting);
        live.busy = true;
        assert!(live.loading());
        assert!(!live.can_connect());
        assert!(live.can_disconnect());
        assert_eq!(live.connect_label(), "取消连接");
        live.pending = None;
        live.busy = false;
        for phase in [Phase::Connecting, Phase::Connected, Phase::Stopping] {
            live.status.as_mut().unwrap().phase = phase;
            assert!(!live.can_connect());
            assert_eq!(live.loading(), phase != Phase::Connected);
            assert_eq!(live.can_disconnect(), phase != Phase::Stopping);
        }
        live.status.as_mut().unwrap().phase = Phase::Failed;
        assert!(live.can_connect());
        live.readiness = Readiness::Preparing;
        assert!(!live.can_connect());
        live.readiness = Readiness::Ready;
        live.status = None;
        assert!(!live.can_connect());
    }
    #[test]
    fn repeated_connect_commands_are_rejected_before_worker_acknowledges() {
        let (commands, receiver) = mpsc::channel();
        let controller = Controller {
            live: Arc::new(Mutex::new(Live {
                readiness: Readiness::Ready,
                status: Some(Status::default()),
                ..Default::default()
            })),
            commands,
        };
        assert!(controller.connect(|| Ok(())));
        assert!(!controller.connect(|| panic!("duplicate connection")));
        assert_eq!(
            controller.live.lock().unwrap().phase(),
            Some(Phase::Connecting)
        );
        assert!(matches!(receiver.try_recv(), Ok(Command::Action { .. })));
        assert!(receiver.try_recv().is_err());
        let mut live = controller.live.lock().unwrap();
        live.pending = None;
        live.busy = false;
        live.status.as_mut().unwrap().phase = Phase::Connected;
        drop(live);
        assert!(!controller.connect(|| panic!("already connected")));
    }
    #[test]
    fn cancel_queues_while_connect_is_pending_and_survives_its_completion() {
        let (commands, receiver) = mpsc::channel();
        let controller = Controller {
            live: Arc::new(Mutex::new(Live {
                readiness: Readiness::Ready,
                status: Some(Status::default()),
                ..Default::default()
            })),
            commands,
        };
        assert!(controller.connect(|| Ok(())));
        controller.disconnect();
        controller.disconnect();
        assert!(matches!(
            receiver.try_recv(),
            Ok(Command::Action {
                pending: Some(Phase::Connecting),
                ..
            })
        ));
        assert!(matches!(
            receiver.try_recv(),
            Ok(Command::Action {
                pending: Some(Phase::Stopping),
                ..
            })
        ));
        assert!(receiver.try_recv().is_err());
        let mut live = controller.live.lock().unwrap();
        live.finish_action(
            Some(Phase::Connecting),
            Err(anyhow::anyhow!("connection cancelled")),
            Some(status(Phase::Connecting, env!("CARGO_PKG_VERSION"))),
        );
        assert_eq!(live.phase(), Some(Phase::Stopping));
        assert!(live.busy);
        assert!(!live.can_connect());
        assert!(!live.can_disconnect());
        assert!(live.notice.is_none());
        live.finish_action(Some(Phase::Stopping), Ok(()), Some(Status::default()));
        assert_eq!(live.phase(), Some(Phase::Disconnected));
        assert!(!live.busy);
        assert!(live.can_connect());
    }
    #[test]
    fn installer_success_is_not_readiness_until_matching_service_responds() {
        use std::cell::Cell;
        let installed = Cell::new(false);
        assert!(
            ensure_service(
                &mut |_| Ok(status(Phase::Disconnected, "0.0.1")),
                || {
                    installed.set(true);
                    Ok(())
                },
                &mut || {},
                |_| {},
            )
            .is_err()
        );
        assert!(installed.get());
    }
    #[test]
    fn compatible_service_keeps_existing_connection() {
        let ready = status(Phase::Connected, env!("CARGO_PKG_VERSION"));
        let result = ensure_service(
            &mut |_| Ok(ready.clone()),
            || panic!("must not reinstall"),
            &mut || {},
            |_| {},
        )
        .unwrap();
        assert_eq!(result.phase, Phase::Connected);
    }
    #[test]
    fn upgrade_waits_for_disconnect_before_installing_and_for_new_service() {
        use std::cell::Cell;
        let calls = Cell::new(0);
        let installed = Cell::new(false);
        let progress = Cell::new(Readiness::Preparing);
        let result = ensure_service(
            &mut |request| {
                let n = calls.get();
                calls.set(n + 1);
                match n {
                    0 => Ok(status(Phase::Connected, "0.0.1")),
                    1 => {
                        assert!(matches!(request, Request::Disconnect));
                        Ok(status(Phase::Stopping, "0.0.1"))
                    }
                    2 => {
                        assert!(!installed.get());
                        Ok(status(Phase::Stopping, "0.0.1"))
                    }
                    3 => {
                        assert!(!installed.get());
                        Ok(status(Phase::Disconnected, "0.0.1"))
                    }
                    4 => {
                        assert!(installed.get());
                        bail!("restarting")
                    }
                    5 => Ok(Status::default()),
                    _ => panic!("unexpected request"),
                }
            },
            || {
                assert_eq!(calls.get(), 4);
                installed.set(true);
                Ok(())
            },
            &mut || {},
            |s| progress.set(s),
        )
        .unwrap();
        assert!(current_version(&result));
        assert_eq!(progress.get(), Readiness::Updating);
    }
    #[test]
    fn unavailable_service_is_installed_and_authorization_failure_is_returned() {
        use std::cell::Cell;
        let installed = Cell::new(false);
        let result = ensure_service(
            &mut |_| {
                if installed.get() {
                    Ok(Status::default())
                } else {
                    bail!("offline")
                }
            },
            || {
                installed.set(true);
                Ok(())
            },
            &mut || {},
            |_| {},
        )
        .unwrap();
        assert!(current_version(&result));
        let error = ensure_service(
            &mut |_| bail!("offline"),
            || bail!("授权取消"),
            &mut || {},
            |_| {},
        )
        .unwrap_err();
        assert!(error.to_string().contains("授权取消"));
    }
    #[test]
    fn stalled_disconnect_never_replaces_service() {
        assert!(
            ensure_service(
                &mut |_| Ok(status(Phase::Stopping, "0.0.1")),
                || panic!("must not replace active worker"),
                &mut || {},
                |_| {}
            )
            .is_err()
        );
    }
    #[test]
    fn old_app_never_downgrades_newer_service() {
        assert!(
            ensure_service(
                &mut |_| Ok(status(Phase::Connected, "99.0.0")),
                || panic!("must not downgrade"),
                &mut || {},
                |_| {}
            )
            .is_err()
        );
    }
}
