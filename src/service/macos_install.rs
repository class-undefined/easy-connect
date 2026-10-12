//! Replace a launchd job only after its registration and old process disappear.
use anyhow::{Context, Result, bail};
use std::{
    fs::{File, OpenOptions, Permissions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

const LABEL: &str = "com.easy-connect.service";
const TARGET: &str = "system/com.easy-connect.service";
const HELPER: &str = "/Library/PrivilegedHelperTools/easy-connect";
const PLIST: &str = "/Library/LaunchDaemons/com.easy-connect.service.plist";
const STOP_POLLS: usize = 120;
const BOOTSTRAP_ATTEMPTS: usize = 3;
const POLL_INTERVAL: Duration = Duration::from_millis(250);

struct CommandOutput {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl CommandOutput {
    fn success(&self) -> bool {
        self.code == Some(0)
    }

    fn diagnostic(&self) -> String {
        format!(
            "exit {}: {} {}",
            self.code
                .map_or_else(|| "signal".into(), |code| code.to_string()),
            self.stderr.trim(),
            self.stdout.trim()
        )
        .trim()
        .to_owned()
    }
}

trait Launchd {
    fn command(&mut self, args: &[&str]) -> Result<CommandOutput>;
    fn process_running(&mut self, pid: i32) -> Result<bool>;
    fn sleep(&mut self, duration: Duration);
}

struct SystemLaunchd;

impl Launchd for SystemLaunchd {
    fn command(&mut self, args: &[&str]) -> Result<CommandOutput> {
        let output = Command::new("/bin/launchctl")
            .args(args)
            .output()
            .with_context(|| format!("cannot execute launchctl {}", args.join(" ")))?;
        Ok(CommandOutput {
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    fn process_running(&mut self, pid: i32) -> Result<bool> {
        // SAFETY: the positive PID came from launchd; signal 0 only queries it.
        if unsafe { libc::kill(pid, 0) } == 0 {
            return Ok(true);
        }
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ESRCH) => Ok(false),
            Some(libc::EPERM) => Ok(true),
            _ => Err(error).context("cannot check old background process"),
        }
    }

    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

fn job(runner: &mut impl Launchd) -> Result<Option<String>> {
    let output = runner.command(&["print", TARGET])?;
    if output.success() {
        Ok(Some(output.stdout))
    } else if output.code == Some(113) {
        // launchctl's BOOTSTRAP_UNKNOWN_SERVICE. Permission/IPC errors are not absence.
        Ok(None)
    } else {
        bail!("cannot inspect background service: {}", output.diagnostic())
    }
}

fn job_pid(state: &str) -> Option<i32> {
    state.lines().find_map(|line| {
        line.trim()
            .strip_prefix("pid = ")?
            .parse::<i32>()
            .ok()
            .filter(|pid| *pid > 0)
    })
}

fn stop_existing(runner: &mut impl Launchd) -> Result<()> {
    let Some(initial) = job(runner)? else {
        return Ok(());
    };
    let mut pids = job_pid(&initial).into_iter().collect::<Vec<_>>();
    let stopped = runner.command(&["bootout", TARGET])?;
    let mut state = job(runner)?;
    if !stopped.success() && state.is_some() {
        bail!("cannot unload background service: {}", stopped.diagnostic());
    }
    // bootout requests removal; it does not provide a process-exit barrier.
    // Keep both barriers: launchd may remove the registration before the PID exits.
    for poll in 0..=STOP_POLLS {
        if let Some(pid) = state.as_deref().and_then(job_pid)
            && !pids.contains(&pid)
        {
            pids.push(pid);
        }
        let mut running = false;
        for &pid in &pids {
            running |= runner.process_running(pid)?;
        }
        if state.is_none() && !running {
            return Ok(());
        }
        if poll < STOP_POLLS {
            runner.sleep(POLL_INTERVAL);
            state = job(runner)?;
        }
    }
    bail!(
        "background service did not stop within 30 seconds; update was not applied; launchd: {}",
        state
            .as_deref()
            .unwrap_or("job removed; old process still exiting")
    )
}

fn replace_job(runner: &mut impl Launchd, publish: impl FnOnce() -> Result<()>) -> Result<()> {
    stop_existing(runner)?;
    publish()?;
    let enabled = runner.command(&["enable", TARGET])?;
    if !enabled.success() {
        bail!("cannot enable background service: {}", enabled.diagnostic());
    }
    for attempt in 1..=BOOTSTRAP_ATTEMPTS {
        let output = runner.command(&["bootstrap", "system", PLIST])?;
        if output.success() {
            return Ok(());
        }
        let state = job(runner).context(output.diagnostic())?;
        // launchd can briefly retain teardown state after the public job disappears.
        // Retry only EIO/EBUSY, only while absent, and within this one authorization.
        if attempt == BOOTSTRAP_ATTEMPTS
            || !matches!(output.code, Some(libc::EIO | libc::EBUSY))
            || state.is_some()
        {
            bail!(
                "launchctl bootstrap failed after {attempt} attempt(s): {}; launchd: {}",
                output.diagnostic(),
                state.as_deref().unwrap_or("service not registered")
            );
        }
        runner.sleep(Duration::from_millis(500 * attempt as u64));
    }
    unreachable!("bootstrap attempts are nonzero")
}

/// Stage files in the protected destination directory, without copying ownership
/// or extended attributes from the user's app. rename then publishes a whole file.
struct StagedFile(PathBuf);

impl StagedFile {
    fn create(destination: &Path, mut contents: impl Read, mode: u32) -> Result<Self> {
        let directory = destination.parent().context("destination missing")?;
        std::fs::create_dir_all(directory)?;
        let metadata = std::fs::symlink_metadata(directory)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            bail!("service destination must be a root-owned protected directory");
        }
        let path = directory.join(format!(".easy-connect-{}.new", super::nonce()));
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)?;
        let staged = Self(path);
        std::io::copy(&mut contents, &mut output)?;
        set_owner(&output, 0, 0)?;
        output.set_permissions(Permissions::from_mode(mode))?;
        output.flush()?;
        output.sync_all()?;
        Ok(staged)
    }

    fn publish(&self, destination: &Path) -> Result<()> {
        std::fs::rename(&self.0, destination).context("cannot publish background service file")
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn set_owner(file: &File, uid: u32, gid: u32) -> Result<()> {
    // SAFETY: the descriptor belongs to a live File; fchown does not consume it.
    if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
        return Err(std::io::Error::last_os_error()).context("cannot set service file ownership");
    }
    Ok(())
}

pub(super) fn install(owner: &str, token: &Path) -> Result<()> {
    let capability = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(token)?;
    set_owner(&capability, owner.parse()?, u32::MAX)?;
    capability.set_permissions(Permissions::from_mode(0o600))?;

    let executable = File::open(std::env::current_exe()?)?;
    let helper = StagedFile::create(Path::new(HELPER), executable, 0o755)?;
    let xml = format!(
        r#"<?xml version="1.0"?><plist version="1.0"><dict><key>Label</key><string>{LABEL}</string><key>ProgramArguments</key><array><string>{HELPER}</string><string>service</string><string>--owner</string><string>{owner}</string></array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ProcessType</key><string>Background</string></dict></plist>"#
    );
    let plist = StagedFile::create(Path::new(PLIST), xml.as_bytes(), 0o644)?;
    replace_job(&mut SystemLaunchd, || {
        helper.publish(Path::new(HELPER))?;
        plist.publish(Path::new(PLIST))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::VecDeque, rc::Rc};

    enum Step {
        Command(Vec<&'static str>, CommandOutput),
        Process(i32, bool),
        Sleep,
    }

    struct ScriptedLaunchd {
        steps: VecDeque<Step>,
        events: Rc<RefCell<Vec<String>>>,
    }

    impl ScriptedLaunchd {
        fn new(steps: impl IntoIterator<Item = Step>) -> Self {
            Self {
                steps: steps.into_iter().collect(),
                events: Rc::default(),
            }
        }
    }

    impl Launchd for ScriptedLaunchd {
        fn command(&mut self, args: &[&str]) -> Result<CommandOutput> {
            let Some(Step::Command(expected, output)) = self.steps.pop_front() else {
                panic!("unexpected command: {args:?}");
            };
            assert_eq!(args, expected);
            self.events.borrow_mut().push(args[0].to_string());
            Ok(output)
        }

        fn process_running(&mut self, pid: i32) -> Result<bool> {
            let Some(Step::Process(expected, running)) = self.steps.pop_front() else {
                panic!("unexpected process check: {pid}");
            };
            assert_eq!(pid, expected);
            self.events
                .borrow_mut()
                .push(format!("pid {pid}: {running}"));
            Ok(running)
        }

        fn sleep(&mut self, _duration: Duration) {
            assert!(matches!(self.steps.pop_front(), Some(Step::Sleep)));
            self.events.borrow_mut().push("sleep".into());
        }
    }

    fn command(args: &[&'static str], code: i32, stdout: &str, stderr: &str) -> Step {
        Step::Command(
            args.to_vec(),
            CommandOutput {
                code: Some(code),
                stdout: stdout.into(),
                stderr: stderr.into(),
            },
        )
    }

    fn absent() -> Step {
        command(&["print", TARGET], 113, "", "Could not find service")
    }

    fn present(pid: i32) -> Step {
        command(
            &["print", TARGET],
            0,
            &format!("state = running\n\tpid = {pid}\n"),
            "",
        )
    }

    fn bootout() -> Step {
        command(&["bootout", TARGET], 0, "", "")
    }

    fn enable() -> Step {
        command(&["enable", TARGET], 0, "", "")
    }

    fn bootstrap(code: i32) -> Step {
        command(
            &["bootstrap", "system", PLIST],
            code,
            "",
            if code == 0 {
                ""
            } else {
                "Bootstrap failed: Input/output error"
            },
        )
    }

    #[test]
    fn first_install_does_not_require_an_existing_job() -> Result<()> {
        let mut runner = ScriptedLaunchd::new([absent(), enable(), bootstrap(0)]);
        let events = runner.events.clone();
        replace_job(&mut runner, || {
            events.borrow_mut().push("publish".into());
            Ok(())
        })?;
        assert_eq!(
            &*events.borrow(),
            &["print", "publish", "enable", "bootstrap"]
        );
        assert!(runner.steps.is_empty());
        Ok(())
    }

    #[test]
    fn upgrade_waits_for_registration_and_process_exit_before_publishing() -> Result<()> {
        let mut runner = ScriptedLaunchd::new([
            present(42),
            bootout(),
            present(42),
            Step::Process(42, true),
            Step::Sleep,
            absent(),
            Step::Process(42, true),
            Step::Sleep,
            absent(),
            Step::Process(42, false),
            enable(),
            bootstrap(0),
        ]);
        let events = runner.events.clone();
        replace_job(&mut runner, || {
            events.borrow_mut().push("publish".into());
            Ok(())
        })?;
        let events = events.borrow();
        let publish = events.iter().position(|event| event == "publish").unwrap();
        assert_eq!(events[publish - 1], "pid 42: false");
        assert_eq!(events.iter().filter(|event| *event == "sleep").count(), 2);
        assert!(runner.steps.is_empty());
        Ok(())
    }

    #[test]
    fn unloading_error_is_preserved_and_never_replaces_files() {
        let mut runner = ScriptedLaunchd::new([
            present(42),
            command(&["bootout", TARGET], 1, "", "Operation not permitted"),
            present(42),
        ]);
        let error = replace_job(&mut runner, || panic!("must not publish"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("cannot unload"));
        assert!(error.contains("Operation not permitted"));
        assert!(runner.steps.is_empty());
    }

    #[test]
    fn process_that_outlives_registration_prevents_replacement_after_timeout() {
        let mut steps = vec![present(42), bootout(), absent()];
        for poll in 0..=STOP_POLLS {
            steps.push(Step::Process(42, true));
            if poll < STOP_POLLS {
                steps.extend([Step::Sleep, absent()]);
            }
        }
        let mut runner = ScriptedLaunchd::new(steps);
        let error = replace_job(&mut runner, || panic!("must not publish"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("update was not applied"));
        assert!(error.contains("old process still exiting"));
        assert!(runner.steps.is_empty());
    }

    #[test]
    fn unknown_query_failures_are_not_misread_as_missing_service() {
        let mut runner = ScriptedLaunchd::new([command(
            &["print", TARGET],
            1,
            "",
            "Operation not permitted",
        )]);
        let error = replace_job(&mut runner, || panic!("must not publish"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("cannot inspect"));
        assert!(error.contains("Operation not permitted"));
    }

    #[test]
    fn transient_bootstrap_error_retries_inside_one_install() -> Result<()> {
        let mut runner = ScriptedLaunchd::new([
            absent(),
            enable(),
            bootstrap(5),
            absent(),
            Step::Sleep,
            bootstrap(0),
        ]);
        let mut publications = 0;
        replace_job(&mut runner, || {
            publications += 1;
            Ok(())
        })?;
        assert_eq!(publications, 1);
        assert!(runner.steps.is_empty());
        Ok(())
    }

    #[test]
    fn persistent_bootstrap_error_has_a_retry_limit_and_diagnostics() {
        let mut steps = vec![absent(), enable()];
        for attempt in 1..=BOOTSTRAP_ATTEMPTS {
            steps.extend([bootstrap(5), absent()]);
            if attempt < BOOTSTRAP_ATTEMPTS {
                steps.push(Step::Sleep);
            }
        }
        let mut runner = ScriptedLaunchd::new(steps);
        let error = replace_job(&mut runner, || Ok(())).unwrap_err().to_string();
        assert!(error.contains("3 attempt(s)"));
        assert!(error.contains("exit 5"));
        assert!(error.contains("Input/output error"));
        assert!(runner.steps.is_empty());
    }

    #[test]
    fn bootstrap_does_not_retry_permission_errors_or_registered_jobs() {
        for (code, state) in [(1, absent()), (5, present(100))] {
            let mut runner = ScriptedLaunchd::new([absent(), enable(), bootstrap(code), state]);
            let error = replace_job(&mut runner, || Ok(())).unwrap_err().to_string();
            assert!(error.contains("1 attempt(s)"));
            assert!(runner.steps.is_empty());
        }
    }

    #[test]
    fn publish_failure_never_bootstraps_partial_files() {
        let mut runner = ScriptedLaunchd::new([absent()]);
        let error = replace_job(&mut runner, || bail!("disk full"))
            .unwrap_err()
            .to_string();
        assert_eq!(error, "disk full");
        assert!(runner.steps.is_empty());
    }
}
