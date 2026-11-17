pub mod cli;
#[cfg(feature = "desktop")]
pub mod desktop;
mod resources;
pub mod service;
mod tun;
#[cfg(target_os = "windows")]
mod windows;
pub(crate) use cli::shutdown_signal;
