//! Background commands must not allocate a console when launched from the GUI.
use std::{
    ffi::OsStr,
    io,
    os::windows::process::CommandExt,
    process::{Command, Output},
};
use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

pub(crate) fn command(program: impl AsRef<OsStr>) -> Command {
    let mut command = Command::new(program);
    command.creation_flags(CREATE_NO_WINDOW);
    command
}

pub(crate) fn powershell(script: &str) -> io::Result<Output> {
    // Cmdlet failures are non-terminating by default, and redirected Windows
    // PowerShell output otherwise uses the machine's legacy code page.
    command("powershell.exe")
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"])
        .arg(format!(
            "$ErrorActionPreference = 'Stop'; [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); {script}"
        ))
        .output()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn background_commands_do_not_allocate_a_console() -> anyhow::Result<()> {
        const CHILD: &str = "EASY_CONNECT_TEST_NO_CONSOLE";
        if std::env::var_os(CHILD).is_some() {
            // SAFETY: GetConsoleWindow has no arguments and only queries our console.
            let console = unsafe { windows_sys::Win32::System::Console::GetConsoleWindow() };
            std::process::exit(i32::from(!console.is_null()));
        }
        let output = command(std::env::current_exe()?)
            .args([
                "--exact",
                "windows::tests::background_commands_do_not_allocate_a_console",
            ])
            .env(CHILD, "1")
            .output()?;
        assert!(
            output.status.success(),
            "child allocated a console: {output:?}"
        );
        Ok(())
    }

    #[test]
    fn powershell_preserves_unicode_for_route_snapshots() -> anyhow::Result<()> {
        // Keep the command itself ASCII; output encoding must preserve aliases
        // that contain characters outside the system's current code page.
        let output = powershell("[string][char]0x7f51 + [char]0x5361 + [char]0xe9")?;
        assert!(output.status.success());
        assert_eq!(String::from_utf8(output.stdout)?.trim(), "网卡é");
        Ok(())
    }

    #[test]
    fn powershell_does_not_report_failed_cmdlets_as_success() -> anyhow::Result<()> {
        let output = powershell("Write-Error 'simulated route lookup failure'; Write-Output '[]'")?;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        Ok(())
    }
}
