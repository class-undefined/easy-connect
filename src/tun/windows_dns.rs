use anyhow::{Result, bail};
use std::process::Command;

pub struct SplitDns {
    comment: String,
}
fn powershell(script: &str) -> Result<()> {
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()?;
    if !output.status.success() {
        bail!(
            "Windows split DNS operation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}
pub fn cleanup_pid(pid: u32) -> Result<()> {
    powershell(&format!(
        "Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq 'EasyConnect:{pid}' }} | Remove-DnsClientNrptRule -Force -ErrorAction Stop"
    ))
}
impl SplitDns {
    pub fn install(_: &str, port: u16, domains: &[String]) -> Result<Self> {
        if port != 53 {
            bail!("Windows system DNS requires local port 53");
        }
        let owner = Self {
            comment: format!("EasyConnect:{}", std::process::id()),
        };
        for domain in domains {
            if !domain
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-'))
            {
                bail!("invalid DNS match domain");
            }
            powershell(&format!(
                "Add-DnsClientNrptRule -Namespace '.{domain}' -NameServers '127.0.0.1' -Comment '{}' -ErrorAction Stop",
                owner.comment
            ))?;
        }
        Ok(owner)
    }
}
impl Drop for SplitDns {
    fn drop(&mut self) {
        if let Err(error) = cleanup_pid(std::process::id()) {
            eprintln!("Split DNS cleanup: {error}");
        }
    }
}
