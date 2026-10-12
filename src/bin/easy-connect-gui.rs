#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
fn main() -> anyhow::Result<()> {
    easy_connect::desktop::run()
}
