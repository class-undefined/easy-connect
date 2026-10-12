use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::{
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[derive(Clone)]
pub(in crate::desktop) struct PreparedUpdate {
    pub job: PathBuf,
}

pub(super) fn cache() -> Result<PathBuf> {
    Ok(dirs::cache_dir()
        .context("无法找到更新缓存目录")?
        .join("easy-connect")
        .join("updates"))
}

pub(super) fn new_job() -> Result<PathBuf> {
    let root = cache()?;
    fs::create_dir_all(&root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    }
    let job = root.join(format!("update-{:016x}", rand::random::<u64>()));
    fs::create_dir(&job)?;
    Ok(job)
}

pub(super) fn previous_failure() -> Option<String> {
    #[derive(Deserialize)]
    struct Receipt {
        success: bool,
        version: String,
    }
    let receipt = cache().ok()?.join("last-update.json");
    let data = fs::read_to_string(&receipt).ok()?;
    let _ = fs::remove_file(receipt);
    let result: Receipt = serde_json::from_str(data.trim_start_matches('\u{feff}')).ok()?;
    (!result.success).then(|| format!("v{} 未能完成安装，已重新打开应用。请重试；若取消了管理员授权，请在下次更新时允许安装。", result.version))
}

fn run(command: &mut Command, context: &str) -> Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let output = command.output().with_context(|| context.to_owned())?;
    if !output.status.success() {
        bail!(
            "{context}：{}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn app_path(executable: &Path) -> Result<PathBuf> {
    let macos = executable.parent().context("应用路径无效")?;
    let contents = macos.parent().context("应用路径无效")?;
    let app = contents.parent().context("应用路径无效")?;
    if macos.file_name().is_none_or(|n| n != "MacOS")
        || contents.file_name().is_none_or(|n| n != "Contents")
        || app.extension().is_none_or(|n| n != "app")
    {
        bail!("请从安装后的 .app 中使用一键更新");
    }
    Ok(app.to_owned())
}

#[cfg(target_os = "macos")]
fn plist_value(app: &Path, key: &str) -> Result<String> {
    let output = Command::new("/usr/bin/plutil")
        .args(["-extract", key, "raw", "-o", "-"])
        .arg(app.join("Contents/Info.plist"))
        .output()?;
    if !output.status.success() {
        bail!("更新包缺少有效的 {key}");
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

#[cfg(target_os = "macos")]
fn validate_app(app: &Path, version: &str) -> Result<()> {
    if !fs::symlink_metadata(app)?.file_type().is_dir()
        || plist_value(app, "CFBundleIdentifier")? != "com.easy-connect.desktop"
        || plist_value(app, "CFBundleShortVersionString")? != version
        || plist_value(app, "CFBundleVersion")? != version
        || plist_value(app, "CFBundleExecutable")? != "easy-connect-gui"
    {
        bail!("更新包的应用标识或版本不匹配");
    }
    for name in ["easy-connect", "easy-connect-gui"] {
        if !fs::symlink_metadata(app.join("Contents/MacOS").join(name))?
            .file_type()
            .is_file()
        {
            bail!("更新包缺少可执行文件 {name}");
        }
    }
    run(
        Command::new("/usr/bin/codesign")
            .args(["--verify", "--deep", "--strict"])
            .arg(app),
        "更新包签名校验失败",
    )
}

#[cfg(target_os = "macos")]
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(target_os = "macos")]
pub(super) fn prepare(archive: &Path, job: PathBuf, version: &str) -> Result<PreparedUpdate> {
    let current = app_path(&std::env::current_exe()?)?;
    prepare_macos(archive, job, version, current)
}

#[cfg(target_os = "macos")]
pub(super) fn prepare_macos(
    archive: &Path,
    job: PathBuf,
    version: &str,
    current: PathBuf,
) -> Result<PreparedUpdate> {
    let destination = if current.starts_with("/Volumes")
        || current.to_string_lossy().contains("/AppTranslocation/")
    {
        PathBuf::from("/Applications/EasyConnect Rust.app")
    } else {
        current.clone()
    };
    let mount = job.join("mount");
    fs::create_dir(&mount)?;
    run(
        Command::new("/usr/bin/hdiutil")
            .args(["attach", "-readonly", "-nobrowse", "-mountpoint"])
            .arg(&mount)
            .arg(archive),
        "无法挂载更新包",
    )?;
    let staged = job.join("EasyConnect Rust.app");
    let result = (|| {
        let app = mount.join("EasyConnect Rust.app");
        validate_app(&app, version)?;
        run(
            Command::new("/usr/bin/ditto").arg(app).arg(&staged),
            "无法准备新版应用",
        )?;
        validate_app(&staged, version)
    })();
    let detached = run(
        Command::new("/usr/bin/hdiutil").arg("detach").arg(&mount),
        "无法卸载更新磁盘",
    );
    result?;
    detached?;
    let parent = destination.parent().context("安装目录无效")?;
    let unique = job.file_name().context("更新目录无效")?.to_string_lossy();
    let incoming = parent.join(format!(".easy-connect-{unique}.app"));
    let backup = parent.join(format!(".easy-connect-{unique}-previous.app"));
    let mut plan = format!(
        "parent_pid={}\nversion={}\n",
        std::process::id(),
        shell_quote(version)
    );
    for (key, value) in [
        ("staged", staged),
        ("destination", destination),
        ("incoming", incoming),
        ("backup", backup),
        ("fallback", current),
        ("receipt", cache()?.join("last-update.json")),
    ] {
        plan.push_str(&format!(
            "{key}={}\n",
            shell_quote(value.to_str().context("安装路径不是有效的 Unicode")?)
        ));
    }
    fs::write(job.join("plan.sh"), plan)?;
    fs::write(job.join("apply.sh"), include_str!("macos-apply.sh"))?;
    fs::write(job.join("launch.sh"), include_str!("macos-launch.sh"))?;
    fs::write(
        job.join("elevate.applescript"),
        "on run argv\nset commandText to \"/bin/sh\"\nrepeat with value in argv\nset commandText to commandText & \" \" & quoted form of (value as text)\nend repeat\ndo shell script commandText with administrator privileges\nend run\n",
    )?;
    Ok(PreparedUpdate { job })
}

#[cfg(windows)]
fn powershell() -> Result<PathBuf> {
    Ok(
        PathBuf::from(std::env::var_os("SystemRoot").context("无法找到 Windows 系统目录")?)
            .join("System32/WindowsPowerShell/v1.0/powershell.exe"),
    )
}

#[cfg(windows)]
pub(super) fn prepare(archive: &Path, job: PathBuf, version: &str) -> Result<PreparedUpdate> {
    let executable = std::env::current_exe()?;
    let destination = executable.parent().context("安装目录无效")?;
    if executable
        .file_name()
        .is_none_or(|n| n != "easy-connect-gui.exe")
    {
        bail!("请从安装后的 easy-connect-gui.exe 中使用一键更新");
    }
    let staged = job.join("package");
    fs::create_dir(&staged)?;
    let unpack = job.join("unpack.ps1");
    fs::write(&unpack, include_str!("windows-unpack.ps1"))?;
    run(
        Command::new(powershell()?)
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(unpack)
            .arg("-Archive")
            .arg(archive)
            .arg("-Destination")
            .arg(&staged),
        "无法解压更新包",
    )?;
    for name in ["easy-connect.exe", "easy-connect-gui.exe", "wintun.dll"] {
        let binary = staged.join(name);
        if !fs::symlink_metadata(&binary)?.file_type().is_file() {
            bail!("更新包缺少 {name}");
        }
        let mut file = std::fs::File::open(binary)?;
        use std::io::{Read, Seek, SeekFrom};
        let mut header = [0u8; 64];
        file.read_exact(&mut header)?;
        if &header[..2] != b"MZ" {
            bail!("更新包包含无效的 {name}");
        }
        file.seek(SeekFrom::Start(
            u32::from_le_bytes(header[60..64].try_into()?) as u64,
        ))?;
        let mut pe = [0u8; 6];
        file.read_exact(&mut pe)?;
        let machine = if cfg!(target_arch = "aarch64") {
            0xaa64u16
        } else {
            0x8664u16
        };
        if &pe[..4] != b"PE\0\0" || u16::from_le_bytes([pe[4], pe[5]]) != machine {
            bail!("更新包架构不匹配");
        }
    }
    let unique = job.file_name().context("更新目录无效")?.to_string_lossy();
    let plan = serde_json::json!({
        "parent_pid": std::process::id(), "version": version, "staged": staged, "destination": destination,
        "incoming": destination.join(format!(".easy-connect-{unique}")),
        "backup": destination.join(format!(".easy-connect-{unique}-previous")),
        "receipt": cache()?.join("last-update.json"), "ready": job.join("ready"),
        "files": ["easy-connect.exe", "easy-connect-gui.exe", "wintun.dll", "LICENSE", "THIRD_PARTY_NOTICES.md", "README.md", "DEPENDENCY-LICENSES.txt", "UPSTREAM-NOTICE.md", "UPSTREAM-PROVENANCE.md", "SOURCE.txt", "WINTUN-LICENSE.txt", "LICENSES"],
    });
    fs::write(job.join("plan.json"), serde_json::to_vec(&plan)?)?;
    fs::write(job.join("install.ps1"), include_str!("windows-install.ps1"))?;
    Ok(PreparedUpdate { job })
}

pub(super) fn launch(prepared: &PreparedUpdate) -> Result<()> {
    let log = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(cache()?.join("last-update.log"))?;
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut c = Command::new("/bin/sh");
        c.arg(prepared.job.join("launch.sh")).arg(&prepared.job);
        c
    };
    #[cfg(windows)]
    let mut command = {
        use std::os::windows::process::CommandExt;
        let mut c = Command::new(powershell()?);
        c.args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(prepared.job.join("install.ps1"))
        .arg("-Plan")
        .arg(prepared.job.join("plan.json"))
        .creation_flags(0x08000000);
        c
    };
    let mut child = command
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .spawn()
        .context("无法启动更新安装程序")?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if child.try_wait()?.is_some() {
            bail!("更新安装程序未能启动，请重试");
        }
        if prepared.job.join("ready").is_file() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("更新安装程序启动超时");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDirectory(PathBuf);
    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir()
                .join(format!("ec-update 测试 '-{:016x}", rand::random::<u64>()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn only_bundle_executables_are_eligible_for_in_place_update() {
        assert_eq!(
            app_path(Path::new(
                "/Applications/EasyConnect Rust.app/Contents/MacOS/easy-connect-gui"
            ))
            .unwrap(),
            PathBuf::from("/Applications/EasyConnect Rust.app")
        );
        assert!(app_path(Path::new("/tmp/easy-connect-gui")).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn shell_arguments_preserve_spaces_quotes_and_substitution_syntax() {
        let value = "a space' and $(not-a-command); \"quoted\"";
        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("printf '%s' {}", shell_quote(value)))
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(String::from_utf8(output.stdout).unwrap(), value);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn invalid_macos_package_leaves_the_previous_app_untouched() -> Result<()> {
        let fixture = TestDirectory::new();
        let source = fixture.0.join("new.app");
        let target = fixture.0.join("installed.app");
        let incoming = fixture.0.join("incoming.app");
        let backup = fixture.0.join("backup.app");
        fs::create_dir(&source)?;
        fs::create_dir(&target)?;
        fs::write(source.join("invalid"), b"invalid package")?;
        fs::write(target.join("old"), b"previous version")?;
        let script = fixture.0.join("apply.sh");
        fs::write(&script, include_str!("macos-apply.sh"))?;
        let output = Command::new("/bin/sh")
            .arg(&script)
            .arg(source)
            .arg(&target)
            .arg(&incoming)
            .arg(&backup)
            .output()?;
        assert!(!output.status.success());
        assert_eq!(fs::read(target.join("old"))?, b"previous version");
        assert!(!incoming.exists());
        assert!(!backup.exists());
        Ok(())
    }

    #[cfg(windows)]
    fn windows_fixture() -> Result<(TestDirectory, PathBuf, PathBuf)> {
        let fixture = TestDirectory::new();
        let source = fixture.0.join("new");
        let target = fixture.0.join("installed");
        fs::create_dir(&source)?;
        fs::create_dir(&target)?;
        for name in ["easy-connect.exe", "easy-connect-gui.exe"] {
            fs::write(source.join(name), b"new")?;
            fs::write(target.join(name), b"old")?;
        }
        fs::write(target.join("personal.txt"), b"do not replace")?;
        let plan = fixture.0.join("plan.json");
        fs::write(
            &plan,
            serde_json::to_vec(&serde_json::json!({
                "staged": source, "destination": target,
                "incoming": fixture.0.join("incoming"), "backup": fixture.0.join("backup"),
                "files": ["easy-connect.exe", "easy-connect-gui.exe"],
            }))?,
        )?;
        fs::write(
            fixture.0.join("install.ps1"),
            include_str!("windows-install.ps1"),
        )?;
        Ok((fixture, plan, target))
    }

    #[cfg(windows)]
    fn apply_windows_fixture(root: &Path, plan: &Path) -> Result<()> {
        run(
            Command::new(powershell()?)
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                ])
                .arg(root.join("install.ps1"))
                .arg("-Plan")
                .arg(plan)
                .arg("-ApplyOnly"),
            "fixture installer",
        )
    }

    #[cfg(windows)]
    #[test]
    fn windows_update_preserves_unrelated_files_and_backs_up_binaries() -> Result<()> {
        let (fixture, plan, target) = windows_fixture()?;
        apply_windows_fixture(&fixture.0, &plan)?;
        assert_eq!(fs::read(target.join("easy-connect-gui.exe"))?, b"new");
        assert_eq!(
            fs::read(fixture.0.join("backup/easy-connect-gui.exe"))?,
            b"old"
        );
        assert_eq!(fs::read(target.join("personal.txt"))?, b"do not replace");
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn windows_locked_executable_rolls_back_already_replaced_files() -> Result<()> {
        use std::os::windows::fs::OpenOptionsExt;
        let (fixture, plan, target) = windows_fixture()?;
        let lock = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(target.join("easy-connect-gui.exe"))?;
        assert!(apply_windows_fixture(&fixture.0, &plan).is_err());
        drop(lock);
        assert_eq!(fs::read(target.join("easy-connect.exe"))?, b"old");
        assert_eq!(fs::read(target.join("easy-connect-gui.exe"))?, b"old");
        assert_eq!(fs::read(target.join("personal.txt"))?, b"do not replace");
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn windows_archive_extraction_rejects_parent_paths() -> Result<()> {
        let fixture = TestDirectory::new();
        let create = fixture.0.join("create.ps1");
        fs::write(
            &create,
            "param([string]$Archive,[string]$Entry)\n$ErrorActionPreference='Stop'\nAdd-Type -AssemblyName System.IO.Compression.FileSystem\n$zip=[System.IO.Compression.ZipFile]::Open($Archive,[System.IO.Compression.ZipArchiveMode]::Create)\ntry { $stream=$zip.CreateEntry($Entry).Open(); try { $bytes=[System.Text.Encoding]::UTF8.GetBytes('fixture'); $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() } } finally { $zip.Dispose() }\n",
        )?;
        let unpack = fixture.0.join("unpack.ps1");
        fs::write(&unpack, include_str!("windows-unpack.ps1"))?;
        for (index, entry) in ["LICENSES/license.txt", "../outside.txt"]
            .iter()
            .enumerate()
        {
            let archive = fixture.0.join(format!("{index}.zip"));
            let destination = fixture.0.join(format!("extracted-{index}"));
            fs::create_dir(&destination)?;
            run(
                Command::new(powershell()?)
                    .args([
                        "-NoProfile",
                        "-NonInteractive",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-File",
                    ])
                    .arg(&create)
                    .arg("-Archive")
                    .arg(&archive)
                    .arg("-Entry")
                    .arg(entry),
                "create fixture",
            )?;
            let result = run(
                Command::new(powershell()?)
                    .args([
                        "-NoProfile",
                        "-NonInteractive",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-File",
                    ])
                    .arg(&unpack)
                    .arg("-Archive")
                    .arg(&archive)
                    .arg("-Destination")
                    .arg(&destination),
                "extract fixture",
            );
            if index == 0 {
                result?;
                assert_eq!(
                    fs::read(destination.join("LICENSES/license.txt"))?,
                    b"fixture"
                );
            } else {
                assert!(result.is_err());
                assert!(!fixture.0.join("outside.txt").exists());
            }
        }
        Ok(())
    }
}
