pub mod cli;
#[cfg(feature = "desktop")]
pub mod desktop;
mod resources;
pub mod service;
mod tun;
pub(crate) use cli::shutdown_signal;
