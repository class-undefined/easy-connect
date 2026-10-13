#[cfg(not(target_os = "linux"))]
fn main() -> anyhow::Result<()> {
    easy_connect::cli::run()
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    match easy_connect::cli::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error:#}");
            let confirmed_logout = error
                .downcast_ref::<easy_connect::cli::SessionEnded>()
                .is_some_and(|end| {
                    end.0 != ec_compat::session_status::SessionEndReason::ConnectionLost
                });
            std::process::ExitCode::from(if confirmed_logout { 77 } else { 1 })
        }
    }
}
