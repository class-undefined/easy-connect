//! Linux IP-only sharing. Publish only installed VPN resource routes, preserving
//! unrelated Tailscale advertisements. A persisted record also permits cleanup
//! after an interrupted worker or systemd SIGKILL.
use super::routes::Cidr;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    process::Command,
};

const DIRECTORY: &str = "/run/easy-connect";
const STATE: &str = "/run/easy-connect/tailscale-routes.json";

#[derive(Serialize, Deserialize)]
struct Record {
    added: BTreeSet<String>,
    forwarding_before: String,
}

trait Commands {
    fn run(&self, program: &str, args: &[&str]) -> Result<Vec<u8>>;
}
struct System;
impl Commands for System {
    fn run(&self, program: &str, args: &[&str]) -> Result<Vec<u8>> {
        let output = Command::new(program)
            .args(args)
            .output()
            .with_context(|| format!("cannot execute {program}"))?;
        if !output.status.success() {
            bail!(
                "{program} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(output.stdout)
    }
}
fn advertised(commands: &impl Commands) -> Result<BTreeSet<String>> {
    let prefs: serde_json::Value =
        serde_json::from_slice(&commands.run("tailscale", &["debug", "prefs"])?)?;
    match &prefs["AdvertiseRoutes"] {
        serde_json::Value::Null => Ok(BTreeSet::new()),
        serde_json::Value::Array(rows) => rows
            .iter()
            .map(|row| Ok(row.as_str().context("invalid Tailscale route")?.to_owned()))
            .collect(),
        _ => bail!("invalid Tailscale preferences"),
    }
}
fn set_routes(commands: &impl Commands, routes: &BTreeSet<String>) -> Result<()> {
    commands.run(
        "tailscale",
        &[
            "set",
            &format!(
                "--advertise-routes={}",
                routes.iter().cloned().collect::<Vec<_>>().join(",")
            ),
        ],
    )?;
    Ok(())
}
fn shared_prefixes(routes: &[Cidr]) -> Result<BTreeSet<String>> {
    let protected = [
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "0.0.0.0/8",
    ];
    let protected: Vec<_> = protected
        .into_iter()
        .map(Cidr::parse)
        .collect::<Result<_>>()?;
    for route in routes {
        if protected.iter().any(|range| range.overlaps(*route)) {
            bail!(
                "VPN resource route {} overlaps a protected network",
                route.text()
            );
        }
    }
    if routes.is_empty() {
        bail!("VPN supplied no IPv4 routes to share");
    }
    Ok(routes.iter().map(|route| route.text()).collect())
}
pub fn validate_routes(routes: &[Cidr]) -> Result<()> {
    shared_prefixes(routes).map(|_| ())
}
fn restore(commands: &impl Commands, record: &Record) -> Result<()> {
    let current = advertised(commands)?;
    let remaining = current.difference(&record.added).cloned().collect();
    if current != remaining {
        set_routes(commands, &remaining)?;
    }
    if record.forwarding_before == "0" && remaining.is_empty() {
        commands.run("sysctl", &["-w", "net.ipv4.ip_forward=0"])?;
    }
    Ok(())
}
fn root_directory() -> Result<()> {
    // SAFETY: geteuid has no pointer arguments.
    if unsafe { libc::geteuid() } != 0 {
        bail!("Linux sharing cleanup requires root");
    }
    fs::create_dir_all(DIRECTORY)?;
    let metadata = fs::symlink_metadata(DIRECTORY)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        bail!("Linux runtime directory must be root-owned and not writable by other users");
    }
    Ok(())
}
pub fn cleanup() -> Result<()> {
    root_directory()?;
    let path = Path::new(STATE);
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        bail!("untrusted Linux sharing state file");
    }
    let record: Record = serde_json::from_slice(&fs::read(path)?)?;
    restore(&System, &record)?;
    fs::remove_file(path)?;
    Ok(())
}

pub struct Sharing {
    active: bool,
}
impl Sharing {
    pub fn install(routes: &[Cidr], interface: &str) -> Result<Self> {
        cleanup()?;
        let wanted = shared_prefixes(routes)?;
        let prefs: serde_json::Value =
            serde_json::from_slice(&System.run("tailscale", &["debug", "prefs"])?)?;
        if prefs["NoSNAT"].as_bool() == Some(true) {
            bail!("Tailscale subnet SNAT must be enabled for VPN sharing");
        }
        let status: serde_json::Value =
            serde_json::from_slice(&System.run("tailscale", &["status", "--json"])?)?;
        if status["BackendState"].as_str() != Some("Running") {
            bail!("Tailscale is not logged in and running");
        }
        let previous = advertised(&System)?;
        let combined = previous.union(&wanted).cloned().collect();
        let record = Record {
            added: wanted.difference(&previous).cloned().collect(),
            forwarding_before: String::from_utf8(
                System.run("sysctl", &["-n", "net.ipv4.ip_forward"])?,
            )?
            .trim()
            .to_owned(),
        };
        let temporary =
            Path::new(DIRECTORY).join(format!("tailscale-routes-{}.tmp", std::process::id()));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        use std::io::Write;
        file.write_all(&serde_json::to_vec(&record)?)?;
        file.sync_all()?;
        fs::rename(temporary, STATE)?;
        let guard = Self { active: true };
        System.run("sysctl", &["-w", "net.ipv4.ip_forward=1"])?;
        set_routes(&System, &combined)?;
        println!(
            "Tailscale shared {} VPN IPv4 routes through {interface}; route approval may be required",
            wanted.len()
        );
        println!("VPN_SHARED_ROUTES {}", serde_json::to_string(&wanted)?);
        Ok(guard)
    }
}
impl Drop for Sharing {
    fn drop(&mut self) {
        if self.active
            && let Err(error) = cleanup()
        {
            eprintln!("Linux sharing cleanup failed: {error:#}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    struct Fake {
        routes: Mutex<BTreeSet<String>>,
        events: Mutex<Vec<String>>,
    }
    impl Commands for Fake {
        fn run(&self, program: &str, args: &[&str]) -> Result<Vec<u8>> {
            if args == ["debug", "prefs"] {
                return Ok(serde_json::to_vec(
                    &serde_json::json!({"AdvertiseRoutes":*self.routes.lock().unwrap()}),
                )?);
            }
            self.events
                .lock()
                .unwrap()
                .push(format!("{program} {}", args.join(" ")));
            if let Some(value) = args
                .iter()
                .find_map(|arg| arg.strip_prefix("--advertise-routes="))
            {
                *self.routes.lock().unwrap() = value
                    .split(',')
                    .filter(|r| !r.is_empty())
                    .map(str::to_owned)
                    .collect();
            }
            Ok(vec![])
        }
    }
    #[test]
    fn shutdown_removes_only_own_routes_and_preserves_concurrent_advertisements() {
        let fake = Fake {
            routes: Mutex::new(BTreeSet::from([
                "192.0.2.0/24".into(),
                "10.8.0.0/16".into(),
                "198.51.100.7/32".into(),
            ])),
            events: Default::default(),
        };
        restore(
            &fake,
            &Record {
                added: BTreeSet::from(["10.8.0.0/16".into()]),
                forwarding_before: "0".into(),
            },
        )
        .unwrap();
        assert_eq!(
            *fake.routes.lock().unwrap(),
            BTreeSet::from(["192.0.2.0/24".into(), "198.51.100.7/32".into()])
        );
        assert!(
            !fake
                .events
                .lock()
                .unwrap()
                .iter()
                .any(|event| event.contains("ip_forward=0"))
        );
    }
    #[test]
    fn rejects_tailnet_overlap_and_publishes_exact_resource_prefixes() {
        assert!(shared_prefixes(&[Cidr::parse("100.64.0.0/10").unwrap()]).is_err());
        assert_eq!(
            shared_prefixes(&[
                Cidr::parse("10.8.0.0/16").unwrap(),
                Cidr::parse("192.0.2.7/32").unwrap()
            ])
            .unwrap(),
            BTreeSet::from(["10.8.0.0/16".into(), "192.0.2.7/32".into()])
        );
    }
}

/// Exercise the exact kernel forwarding + SNAT contract required by the packet
/// relay. The namespace has no path to the VPN gateway and uses documentation IPs.
pub async fn self_test_forwarding() -> Result<()> {
    super::preflight()?;
    let source: std::net::Ipv4Addr = "198.51.100.2".parse()?;
    let target: std::net::Ipv4Addr = "192.0.2.1".parse()?;
    let device = super::create_device(source, 1400)?;
    let interface = device.name()?;
    let _routes = super::routes::RouteManager::install(
        super::routes::SystemRoutes,
        interface.clone(),
        BTreeSet::new(),
        vec![Cidr::host(target)],
    )?;
    let namespace = format!("ec-test-{}", std::process::id());
    let host = format!("ecv{}", std::process::id());
    let peer = format!("ecp{}", std::process::id());
    struct Cleanup {
        namespace: String,
        host: String,
        nat: Vec<String>,
        forward: String,
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let args: Vec<_> = self.nat.iter().map(String::as_str).collect();
            let _ = System.run("iptables", &args);
            let _ = System.run("ip", &["netns", "del", &self.namespace]);
            let _ = System.run("ip", &["link", "del", &self.host]);
            let _ = System.run(
                "sysctl",
                &["-w", &format!("net.ipv4.ip_forward={}", self.forward)],
            );
        }
    }
    let nat: Vec<String> = [
        "-t",
        "nat",
        "-D",
        "POSTROUTING",
        "-s",
        "10.254.254.2/32",
        "-d",
        "192.0.2.1/32",
        "-o",
        &interface,
        "-m",
        "comment",
        "--comment",
        &namespace,
        "-j",
        "MASQUERADE",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let _cleanup = Cleanup {
        namespace: namespace.clone(),
        host: host.clone(),
        nat: nat.clone(),
        forward: String::from_utf8(System.run("sysctl", &["-n", "net.ipv4.ip_forward"])?)?
            .trim()
            .into(),
    };
    System.run("ip", &["netns", "add", &namespace])?;
    System.run(
        "ip",
        &["link", "add", &host, "type", "veth", "peer", "name", &peer],
    )?;
    System.run("ip", &["link", "set", &peer, "netns", &namespace])?;
    System.run("ip", &["addr", "add", "10.254.254.1/30", "dev", &host])?;
    System.run("ip", &["link", "set", &host, "up"])?;
    System.run(
        "ip",
        &[
            "-n",
            &namespace,
            "addr",
            "add",
            "10.254.254.2/30",
            "dev",
            &peer,
        ],
    )?;
    System.run("ip", &["-n", &namespace, "link", "set", &peer, "up"])?;
    System.run("ip", &["-n", &namespace, "link", "set", "lo", "up"])?;
    System.run(
        "ip",
        &[
            "-n",
            &namespace,
            "route",
            "add",
            "192.0.2.1/32",
            "via",
            "10.254.254.1",
        ],
    )?;
    System.run("sysctl", &["-w", "net.ipv4.ip_forward=1"])?;
    let mut add = nat;
    add[2] = "-A".into();
    System.run(
        "iptables",
        &add.iter().map(String::as_str).collect::<Vec<_>>(),
    )?;
    let mut ping = tokio::process::Command::new("ip")
        .args([
            "netns",
            "exec",
            &namespace,
            "ping",
            "-n",
            "-c",
            "1",
            "-W",
            "3",
            "192.0.2.1",
        ])
        .kill_on_drop(true)
        .spawn()?;
    let exchange = async {
        let mut packet = [0_u8; 65535];
        let size = loop {
            let size = device.recv(&mut packet).await?;
            if ec_compat::engine::ip_packet::validate_ipv4_packet(&packet[..size], None).is_err() {
                continue;
            }
            if packet[16..20] != target.octets() {
                continue;
            }
            break size;
        };
        if packet[12..16] != source.octets() {
            let actual = std::net::Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            bail!("forwarded IPv4 source {actual} was not SNATed to VPN address {source}");
        }
        let reply = super::echo_reply(&packet[..size])?;
        if device.send(&reply).await? != reply.len() {
            bail!("partial forwarding self-test reply");
        }
        let status = ping.wait().await?;
        if !status.success() {
            bail!("namespace did not receive the ICMP reply after reverse NAT");
        }
        Ok::<_, anyhow::Error>(())
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), exchange)
        .await
        .context("Linux forwarding self-test timed out")??;
    println!("Linux TUN forwarding/SNAT self-test passed; namespace, NAT rule and routes removed");
    Ok(())
}
