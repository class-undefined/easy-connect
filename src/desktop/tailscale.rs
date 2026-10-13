//! Client-only subnet access: never authenticate a second VPN session.
use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::{collections::BTreeSet, path::PathBuf, process::Command};

#[derive(Clone, Debug)]
pub(super) struct Summary {
    pub routers: usize,
    pub routes: usize,
}

trait Runner {
    fn run(&self, args: &[&str]) -> Result<Vec<u8>>;
}
struct Cli;
impl Runner for Cli {
    fn run(&self, args: &[&str]) -> Result<Vec<u8>> {
        let program = executable();
        let mut command = Command::new(program);
        command.args(args);
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let output = command
            .output()
            .context("未找到 Tailscale，请先安装并登录 Tailscale")?;
        if !output.status.success() {
            bail!(
                "Tailscale 操作失败：{}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(output.stdout)
    }
}
fn executable() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        let app = PathBuf::from("/Applications/Tailscale.app/Contents/MacOS/Tailscale");
        if app.is_file() {
            return app;
        }
    }
    #[cfg(target_os = "windows")]
    if let Some(directory) = std::env::var_os("ProgramFiles") {
        let cli = PathBuf::from(directory).join("Tailscale/tailscale.exe");
        if cli.is_file() {
            return cli;
        }
    }
    PathBuf::from("tailscale")
}
fn summarize(status: &Value, router: &str) -> Result<Summary> {
    if status["BackendState"].as_str() != Some("Running") {
        bail!("请先启动并登录 Tailscale");
    }
    let router = router.trim().trim_end_matches('.');
    let peers = status["Peer"]
        .as_object()
        .context("Tailscale 暂未发现子网出口")?;
    let mut routes = BTreeSet::new();
    let mut routers = 0;
    for peer in peers.values() {
        let selected = router.is_empty()
            || ["HostName", "DNSName"].iter().any(|key| {
                peer[key]
                    .as_str()
                    .is_some_and(|name| name.trim_end_matches('.').eq_ignore_ascii_case(router))
            })
            || peer["TailscaleIPs"]
                .as_array()
                .is_some_and(|ips| ips.iter().any(|ip| ip.as_str() == Some(router)));
        if !selected || peer["Online"].as_bool() != Some(true) {
            continue;
        }
        let ipv4: Vec<_> = peer["PrimaryRoutes"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter(|route| {
                route.split_once('/').is_some_and(|(ip, prefix)| {
                    ip.parse::<std::net::Ipv4Addr>().is_ok()
                        && prefix.parse::<u8>().is_ok_and(|p| (1..=32).contains(&p))
                })
            })
            .collect();
        if !ipv4.is_empty() {
            routers += 1;
            routes.extend(ipv4.into_iter().map(str::to_owned));
        }
    }
    if routers == 0 {
        bail!("未找到在线且已批准的 IPv4 子网出口，请检查主机配置和 Tailscale 路由批准状态");
    }
    Ok(Summary {
        routers,
        routes: routes.len(),
    })
}
fn inspect(cli: &impl Runner, router: &str) -> Result<Summary> {
    let status: Value = serde_json::from_slice(&cli.run(&["status", "--json"])?)?;
    summarize(&status, router)
}
fn set_routes(cli: &impl Runner, enabled: bool) -> Result<()> {
    cli.run(&[
        "set",
        if enabled {
            "--accept-routes=true"
        } else {
            "--accept-routes=false"
        },
    ])?;
    Ok(())
}
fn enable(cli: &impl Runner, router: &str) -> Result<(Summary, bool)> {
    let summary = inspect(cli, router)?;
    let prefs: Value = serde_json::from_slice(&cli.run(&["debug", "prefs"])?)?;
    let before = prefs["RouteAll"]
        .as_bool()
        .context("无法读取 Tailscale 子网路由设置")?;
    set_routes(cli, true)?;
    Ok((summary, before))
}
pub(super) fn activate(router: &str) -> Result<(Summary, bool)> {
    enable(&Cli, router)
}
pub(super) fn check(router: &str) -> Result<Summary> {
    let summary = inspect(&Cli, router)?;
    set_routes(&Cli, true)?;
    Ok(summary)
}
pub(super) fn restore(enabled: bool) -> Result<()> {
    set_routes(&Cli, enabled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    struct Fake {
        events: Mutex<Vec<Vec<String>>>,
    }
    impl Runner for Fake {
        fn run(&self, args: &[&str]) -> Result<Vec<u8>> {
            self.events
                .lock()
                .unwrap()
                .push(args.iter().map(|s| s.to_string()).collect());
            let value = if args == ["debug", "prefs"] {
                serde_json::json!({"RouteAll":false})
            } else {
                serde_json::json!({"BackendState":"Running","Peer":{"peer":{"HostName":"vpn-router","DNSName":"vpn-router.example.ts.net.","Online":true,"TailscaleIPs":["100.64.0.7"],"PrimaryRoutes":["192.0.2.0/24","2001:db8::/64"]}}})
            };
            Ok(serde_json::to_vec(&value)?)
        }
    }
    #[test]
    fn activation_selects_router_and_preserves_prior_route_setting_without_vpn_login() {
        let cli = Fake {
            events: Default::default(),
        };
        let (summary, before) = enable(&cli, "vpn-router").unwrap();
        assert_eq!(summary.routers, 1);
        assert_eq!(summary.routes, 1);
        assert!(!before);
        set_routes(&cli, before).unwrap();
        assert_eq!(
            *cli.events.lock().unwrap(),
            vec![
                vec!["status", "--json"],
                vec!["debug", "prefs"],
                vec!["set", "--accept-routes=true"],
                vec!["set", "--accept-routes=false"]
            ]
        );
    }
    #[test]
    fn unapproved_or_offline_exit_never_enables_route_acceptance() {
        for peer in [
            serde_json::json!({"HostName":"vpn-router","Online":true,"AllowedIPs":["192.0.2.0/24"]}),
            serde_json::json!({"HostName":"vpn-router","Online":false,"PrimaryRoutes":["192.0.2.0/24"]}),
        ] {
            assert!(
                summarize(
                    &serde_json::json!({"BackendState":"Running","Peer":{"p":peer}}),
                    "vpn-router"
                )
                .is_err()
            );
        }
        let cli = Fake {
            events: Default::default(),
        };
        assert!(enable(&cli, "unmatched-router").is_err());
        assert_eq!(cli.events.lock().unwrap().len(), 1);
    }
}
