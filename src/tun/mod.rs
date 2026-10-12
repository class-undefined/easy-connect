#[cfg(any(target_os = "macos", target_os = "windows"))]
mod dns;
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub mod routes;
#[cfg(target_os = "windows")]
mod windows_dns;
#[cfg(target_os = "windows")]
pub(crate) fn cleanup_worker_dns(pid: u32) {
    if let Err(error) = windows_dns::cleanup_pid(pid) {
        eprintln!("stale worker DNS cleanup: {error}");
    }
}

use crate::resources::PublishedResources;
use anyhow::{Result, bail};
use ec_compat::engine::{data_plane::EasyConnectDataPlane, policy::RoutePolicy};
use serde_json::Value;
use std::{net::Ipv4Addr, sync::Arc};

pub fn preflight() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: geteuid has no pointer arguments.
        if unsafe { libc::geteuid() } != 0 {
            bail!("TUN needs administrator privileges; install the background service or use sudo");
        }
        Ok(())
    }
    #[cfg(target_os = "windows")]
    {
        // SAFETY: IsUserAnAdmin has no pointer arguments.
        if unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() } == 0 {
            bail!("TUN needs administrator privileges; install the background service");
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    bail!("TUN supports macOS and Windows")
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn echo_reply(request: &[u8]) -> Result<Vec<u8>> {
    use ec_compat::engine::ip_packet::validate_ipv4_packet;
    validate_ipv4_packet(request, None)?;
    let header = usize::from(request[0] & 0xf) * 4;
    if request[9] != 1 || request.len() < header + 8 || request[header] != 8 {
        bail!("expected ICMP echo request");
    }
    let mut reply = request.to_vec();
    reply[12..16].copy_from_slice(&request[16..20]);
    reply[16..20].copy_from_slice(&request[12..16]);
    reply[header] = 0;
    reply[header + 2..header + 4].fill(0);
    let checksum = internet_checksum(&reply[header..]);
    reply[header + 2..header + 4].copy_from_slice(&checksum.to_be_bytes());
    reply[10..12].fill(0);
    let checksum = internet_checksum(&reply[..header]);
    reply[10..12].copy_from_slice(&checksum.to_be_bytes());
    Ok(reply)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for chunk in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub async fn self_test() -> Result<()> {
    use anyhow::Context;
    use std::collections::BTreeSet;
    preflight()?;
    let local: Ipv4Addr = "198.51.100.2".parse()?;
    let target: Ipv4Addr = "192.0.2.1".parse()?;
    let device = create_device(local, 1400)?;
    let interface = device.name()?;
    let owner = routes::RouteManager::install(
        routes::SystemRoutes,
        interface.clone(),
        BTreeSet::new(),
        vec![routes::Cidr::host(target)],
    )?;
    println!("Local utun ICMP test on {interface}; no VPN credentials or gateway traffic");
    let mut ping = tokio::task::spawn_blocking(move || ping_once(target));
    let reflected = async {
        let mut packet = [0_u8; 65535];
        loop {
            let count = device.recv(&mut packet).await?;
            if let Ok(reply) = echo_reply(&packet[..count]) {
                if reply[16..20] != local.octets() || reply[12..16] != target.octets() {
                    continue;
                }
                if device.send(&reply).await? != reply.len() {
                    bail!("partial ICMP reply write");
                }
                return Ok::<_, anyhow::Error>(());
            }
        }
    };
    let reflection = tokio::select! {
        result=tokio::time::timeout(std::time::Duration::from_secs(5),reflected)=>result.context("utun did not capture an ICMP echo")?,
        result=crate::shutdown_signal()=>{result?;Err(anyhow::anyhow!("self-test interrupted"))},
    };
    let output = tokio::time::timeout(std::time::Duration::from_secs(5), &mut ping)
        .await
        .context("local ping timed out")???;
    drop(owner);
    drop(device);
    reflection?;
    if !output.status.success() {
        bail!(
            "kernel did not accept reflected ICMP reply: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
    println!("{}", String::from_utf8_lossy(&output.stdout).trim());
    println!("utun ICMP self-test passed; temporary route and interface removed");
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub async fn self_test() -> Result<()> {
    bail!("utun self-test supports macOS only")
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub async fn run(
    plane: EasyConnectDataPlane,
    published: PublishedResources,
    policy: Arc<RoutePolicy>,
    config: Value,
    dns_servers: Vec<Ipv4Addr>,
    mtu: usize,
) -> Result<()> {
    use anyhow::Context;
    use std::{collections::BTreeSet, sync::Mutex};
    use zeroize::Zeroizing;

    let sockets = plane.shutdown_handle();
    let address = plane.assigned_address();
    let peer = match plane.peer_address()?.ip() {
        std::net::IpAddr::V4(ip) => ip,
        _ => bail!("TUN outer transport must use IPv4"),
    };
    let mut excluded = BTreeSet::from([peer, address, Ipv4Addr::LOCALHOST]);
    if let Some(gateway) = routes::physical_gateway(peer)? {
        excluded.insert(gateway);
    }
    let (domains, cidrs) = published.effective_routes(&config)?;
    let planned = routes::plan_routes(&cidrs, &dns_servers, &excluded)?;
    if planned.is_empty() && domains.is_empty() {
        bail!("gateway supplied no usable TUN destinations");
    }
    let device = Arc::new(create_device(address, mtu)?);
    let interface = device.name()?;
    let count = planned.len();
    let interface_for_routes = interface.clone();
    let routes = tokio::task::spawn_blocking(move || {
        routes::RouteManager::install(
            routes::SystemRoutes,
            interface_for_routes,
            excluded,
            planned,
        )
    })
    .await??;
    let routes: routes::SharedRoutes = Arc::new(Mutex::new(Box::new(routes)));
    let dns_proxy = dns::DnsProxy::bind(
        address,
        dns_servers,
        published.hosts,
        policy,
        routes.clone(),
    )
    .await?;
    let dns_registration = if domains.is_empty() {
        None
    } else {
        Some(dns::SplitDns::install(
            &interface,
            dns_proxy.port()?,
            &domains.into_iter().collect::<Vec<_>>(),
        )?)
    };
    // DNS registration and another VPN's teardown may rebuild the kernel routes.
    let check_routes = routes.clone();
    let restored = tokio::task::spawn_blocking(move || {
        check_routes
            .lock()
            .map_err(|_| anyhow::anyhow!("route lock poisoned"))?
            .audit_and_repair()
    })
    .await??;
    if restored > 0 {
        eprintln!("Restored {restored} TUN routes before marking the connection ready");
    }
    let (_lease, mut sender, mut receiver) = plane.split();
    let (upload, mut outgoing) = tokio::sync::mpsc::channel::<Zeroizing<Vec<u8>>>(256);
    let (download, mut incoming) = tokio::sync::mpsc::channel::<Zeroizing<Vec<u8>>>(256);
    let (fail, mut failure) = tokio::sync::mpsc::unbounded_channel::<anyhow::Error>();
    let writer_fail = fail.clone();
    let writer = tokio::task::spawn_blocking(move || {
        while let Some(packet) = outgoing.blocking_recv() {
            if let Err(error) = sender.send_ipv4(&packet) {
                let _ = writer_fail.send(error.into());
                break;
            }
        }
    });
    let reader = tokio::task::spawn_blocking(move || {
        loop {
            match receiver.receive_ipv4() {
                Ok(packet) => {
                    if download.blocking_send(packet).is_err() {
                        break;
                    }
                }
                Err(error) => {
                    let _ = fail.send(error.into());
                    break;
                }
            }
        }
    });
    println!(
        "TUN ready: {interface}, IPv4 {address}, MTU {mtu}, {count} routes; TCP/UDP/ICMP forwarding enabled"
    );
    let pump = relay(
        device.as_ref(),
        address,
        &routes,
        &upload,
        &mut incoming,
        &mut failure,
    );
    let outcome = tokio::select! {
        result=pump=>result,
        result=dns_proxy.serve()=>result,
        result=crate::shutdown_signal()=>result,
        result=monitor_routes(&routes)=>result,
    };
    // Unblock network reads and bounded channels before waiting for workers.
    drop(dns_registration);
    drop(dns_proxy);
    drop(sockets);
    drop(upload);
    drop(incoming);
    writer.await.context("TUN upload worker failed")?;
    reader.await.context("TUN download worker failed")?;
    drop(_lease);
    tokio::task::spawn_blocking(move || {
        routes
            .lock()
            .map_err(|_| anyhow::anyhow!("route lock poisoned"))?
            .clear();
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    // Interface closure also makes the kernel remove its attached routes after abrupt exit.
    drop(device);
    outcome
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
async fn monitor_routes(routes: &routes::SharedRoutes) -> Result<()> {
    let mut timer = tokio::time::interval(std::time::Duration::from_secs(3));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        timer.tick().await;
        let table = routes.clone();
        let restored = tokio::task::spawn_blocking(move || {
            table
                .lock()
                .map_err(|_| anyhow::anyhow!("route lock poisoned"))?
                .audit_and_repair()
        })
        .await??;
        if restored > 0 {
            eprintln!(
                "Restored {restored} missing TUN routes; another network service may have removed them"
            );
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
trait PacketDevice: Send + Sync {
    fn recv(
        &self,
        buffer: &mut [u8],
    ) -> impl std::future::Future<Output = std::io::Result<usize>> + Send;
    fn send(
        &self,
        packet: &[u8],
    ) -> impl std::future::Future<Output = std::io::Result<usize>> + Send;
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl PacketDevice for tun_rs::AsyncDevice {
    async fn recv(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.recv(buffer).await
    }
    async fn send(&self, packet: &[u8]) -> std::io::Result<usize> {
        self.send(packet).await
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
async fn relay(
    device: &impl PacketDevice,
    address: Ipv4Addr,
    routes: &routes::SharedRoutes,
    upload: &tokio::sync::mpsc::Sender<zeroize::Zeroizing<Vec<u8>>>,
    incoming: &mut tokio::sync::mpsc::Receiver<zeroize::Zeroizing<Vec<u8>>>,
    failure: &mut tokio::sync::mpsc::UnboundedReceiver<anyhow::Error>,
) -> Result<()> {
    use anyhow::Context;
    use ec_compat::engine::ip_packet::validate_ipv4_packet;
    use zeroize::Zeroizing;
    let mut packet = [0_u8; 65535];
    loop {
        tokio::select! {
            read=device.recv(&mut packet)=>{
                let count=read?;let packet=&packet[..count];
                if validate_ipv4_packet(packet,Some(address)).is_err() {continue;}
                let destination=Ipv4Addr::new(packet[16],packet[17],packet[18],packet[19]);
                if !routes.lock().map_err(|_|anyhow::anyhow!("route lock poisoned"))?.permits(destination) {continue;}
                upload.send(Zeroizing::new(packet.to_vec())).await.context("VPN upload stopped")?;
            },
            packet=incoming.recv()=>{
                let packet=packet.context("VPN download stopped")?;
                validate_ipv4_packet(&packet,None)?;
                if packet[16..20] != address.octets() {continue;}
                let written=device.send(&packet).await?;
                if written!=packet.len() {bail!("partial utun packet write");}
            },
            error=failure.recv()=>{return Err(error.unwrap_or_else(||anyhow::anyhow!("VPN relay stopped")));}
        }
    }
}

#[cfg(all(test, any(target_os = "macos", target_os = "windows")))]
mod tests {
    use super::*;
    use std::{collections::BTreeSet, sync::Mutex};
    use tokio::sync::mpsc;
    use zeroize::Zeroizing;
    struct Device {
        outbound: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
        inbound: mpsc::Sender<Vec<u8>>,
    }
    impl PacketDevice for Device {
        async fn recv(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let packet = self
                .outbound
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
            buffer[..packet.len()].copy_from_slice(&packet);
            Ok(packet.len())
        }
        async fn send(&self, packet: &[u8]) -> std::io::Result<usize> {
            self.inbound
                .send(packet.to_vec())
                .await
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
            Ok(packet.len())
        }
    }
    struct NoSystemChanges;
    impl routes::RouteCommands for NoSystemChanges {
        fn change(&self, _: bool, _: routes::Cidr, _: &str) -> Result<()> {
            Ok(())
        }
    }
    fn icmp(source: Ipv4Addr, destination: Ipv4Addr, echo_type: u8) -> Vec<u8> {
        let mut packet = vec![0_u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet[20] = echo_type;
        packet
    }
    #[test]
    fn reflected_icmp_has_valid_ipv4_and_icmp_checksums() {
        let local = "198.51.100.2".parse().unwrap();
        let remote = "192.0.2.1".parse().unwrap();
        let request = icmp(local, remote, 8);
        let reply = echo_reply(&request).unwrap();
        assert_eq!(reply[12..16], remote.octets());
        assert_eq!(reply[16..20], local.octets());
        assert_eq!(reply[20], 0);
        assert_eq!(internet_checksum(&reply[..20]), 0);
        assert_eq!(internet_checksum(&reply[20..]), 0);
    }
    #[tokio::test]
    async fn icmp_echo_crosses_the_packet_relay_both_ways() {
        let local = "10.1.2.3".parse().unwrap();
        let remote = "10.2.0.1".parse().unwrap();
        let table = routes::RouteManager::install(
            NoSystemChanges,
            "test".into(),
            BTreeSet::new(),
            vec![routes::Cidr::parse("10.2.0.0/16").unwrap()],
        )
        .unwrap();
        let routes: routes::SharedRoutes = Arc::new(Mutex::new(Box::new(table)));
        let (os_send, os_out) = mpsc::channel(4);
        let (os_in, mut os_recv) = mpsc::channel(4);
        let device = Device {
            outbound: tokio::sync::Mutex::new(os_out),
            inbound: os_in,
        };
        let (upload, mut tunnel_recv) = mpsc::channel(4);
        let (tunnel_send, mut incoming) = mpsc::channel(4);
        let (stop, mut failure) = mpsc::unbounded_channel();
        let pump = relay(
            &device,
            local,
            &routes,
            &upload,
            &mut incoming,
            &mut failure,
        );
        let scenario = async {
            // Wrong-source and non-resource traffic must be discarded before the echo request.
            os_send.send(icmp(remote, remote, 8)).await.unwrap();
            os_send
                .send(icmp(local, "192.0.2.1".parse().unwrap(), 8))
                .await
                .unwrap();
            let request = icmp(local, remote, 8);
            os_send.send(request.clone()).await.unwrap();
            assert_eq!(&**tunnel_recv.recv().await.unwrap(), &request);
            let reply = icmp(remote, local, 0);
            tunnel_send
                .send(Zeroizing::new(reply.clone()))
                .await
                .unwrap();
            assert_eq!(os_recv.recv().await.unwrap(), reply);
            stop.send(anyhow::anyhow!("test shutdown")).unwrap();
        };
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let (result, ()) = tokio::join!(pump, scenario);
            assert!(result.is_err());
        })
        .await
        .unwrap();
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub async fn run(
    _: EasyConnectDataPlane,
    _: PublishedResources,
    _: Arc<RoutePolicy>,
    _: Value,
    _: Vec<Ipv4Addr>,
    _: usize,
) -> Result<()> {
    bail!("TUN supports macOS only")
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn create_device(address: Ipv4Addr, mtu: usize) -> Result<tun_rs::AsyncDevice> {
    let builder = tun_rs::DeviceBuilder::new()
        .mtu(mtu as u16)
        .ipv4(address, 32, Some(address));
    #[cfg(target_os = "macos")]
    let builder = builder.with(|b| {
        b.associate_route(false);
        b.packet_information(false);
    });
    #[cfg(target_os = "windows")]
    let builder = {
        let dll = std::env::current_exe()?.with_file_name("wintun.dll");
        if !dll.is_file() {
            bail!(
                "wintun.dll is missing beside easy-connect.exe; use the complete release package"
            );
        }
        builder.name("EasyConnectRust").with(|b| {
            b.wintun_file(dll.to_string_lossy().into_owned());
        })
    };
    Ok(builder.build_async()?)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn ping_once(target: Ipv4Addr) -> std::io::Result<std::process::Output> {
    #[cfg(target_os = "macos")]
    let result = std::process::Command::new("/sbin/ping")
        .args(["-n", "-c", "1", "-t", "5", &target.to_string()])
        .output();
    #[cfg(target_os = "windows")]
    let result = std::process::Command::new("ping.exe")
        .args(["-n", "1", "-w", "2000", &target.to_string()])
        .output();
    result
}
