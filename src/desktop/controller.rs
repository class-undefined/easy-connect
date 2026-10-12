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
            && !self.busy
            && !self.quitting
            && matches!(self.phase(), Some(Phase::Connecting | Phase::Connected))
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
                Some(Phase::Connecting) => "连接中…",
                Some(Phase::Connected) => "已连接",
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
}

type Work = Box<dyn FnOnce() -> Result<()> + Send>;
enum Command {
    Action(Work),
    Prepare,
    Quit,
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
        let live = Arc::new(Mutex::new(Live::default()));
        let (commands, receiver) = mpsc::channel();
        let state = live.clone();
        std::thread::spawn(move || {
            prepare(&state);
            loop {
                match receiver.recv_timeout(POLL) {
                    Ok(Command::Action(work)) => {
                        let result = work();
                        let status = service::request(Request::Status).ok();
                        if let Ok(mut live) = state.lock() {
                            live.status = status;
                            live.pending = None;
                            live.busy = false;
                            live.notice = result.err().map(|e| format!("{e:#}"));
                        }
                    }
                    Ok(Command::Prepare) => prepare(&state),
                    Ok(Command::Quit) => {
                        let result = match service::request(Request::Status) {
                            Ok(status) if !inactive(&status) => {
                                disconnect_and_wait(&mut service::request, &mut || {
                                    std::thread::sleep(RETRY)
                                })
                            }
                            _ => Ok(()),
                        };
                        if let Ok(mut live) = state.lock() {
                            live.quit_ready = result.is_ok();
                            live.quitting = result.is_ok();
                            live.notice = result.err().map(|e| format!("退出失败：{e:#}"));
                        }
                        if state.lock().is_ok_and(|s| s.quit_ready) {
                            break;
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        let status = service::request(Request::Status).ok();
                        let compatible = status.as_ref().is_some_and(current_version);
                        let repair = if let Ok(mut live) = state.lock() {
                            let repair = !compatible && live.readiness == Readiness::Ready;
                            live.status = status;
                            if compatible {
                                if live.readiness == Readiness::Failed {
                                    live.notice = None;
                                }
                                live.readiness = Readiness::Ready;
                            } else if repair {
                                live.readiness = Readiness::Preparing;
                            }
                            repair
                        } else {
                            false
                        };
                        if repair {
                            prepare(&state);
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
        if live.busy
            || live.quitting
            || (pending == Some(Phase::Connecting) && !live.can_connect())
            || (pending == Some(Phase::Stopping) && !live.can_disconnect())
        {
            return false;
        }
        live.busy = true;
        live.pending = pending;
        live.notice = None;
        if self.commands.send(Command::Action(Box::new(work))).is_err() {
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
        if let Ok(mut live) = self.live.lock()
            && !live.quitting
        {
            live.quitting = true;
            let _ = self.commands.send(Command::Quit);
        }
    }
}
fn current_version(status: &Status) -> bool {
    status.version == env!("CARGO_PKG_VERSION")
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
    for _ in 0..WAIT_ATTEMPTS {
        if let Ok(status) = request(Request::Status)
            && current_version(&status)
        {
            return Ok(status);
        }
        sleep();
    }
    bail!("后台启动超时，请重试；若问题持续，请重新打开应用");
}

#[cfg(test)]
mod tests {
    use super::*;
    fn status(phase: Phase, version: &str) -> Status {
        Status {
            phase,
            version: version.into(),
            ..Default::default()
        }
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
        assert!(matches!(receiver.try_recv(), Ok(Command::Action(_))));
        assert!(receiver.try_recv().is_err());
        let mut live = controller.live.lock().unwrap();
        live.pending = None;
        live.busy = false;
        live.status.as_mut().unwrap().phase = Phase::Connected;
        drop(live);
        assert!(!controller.connect(|| panic!("already connected")));
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
