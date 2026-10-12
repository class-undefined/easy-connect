use anyhow::{Context, Result, bail};
use std::{collections::BTreeSet, net::Ipv4Addr, process::Command, sync::Mutex};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Cidr {
    network: u32,
    prefix: u8,
}

impl Cidr {
    pub fn parse(value: &str) -> Result<Self> {
        let (address, prefix) = value.split_once('/').context("CIDR requires prefix")?;
        let address: Ipv4Addr = address.parse()?;
        let prefix: u8 = prefix.parse()?;
        if !(1..=32).contains(&prefix) {
            bail!("TUN does not accept a default route");
        }
        let mask = u32::MAX << (32 - prefix);
        let network = u32::from(address);
        if network & mask != network {
            bail!("CIDR must use its network address");
        }
        Ok(Self { network, prefix })
    }
    pub fn host(ip: Ipv4Addr) -> Self {
        Self {
            network: u32::from(ip),
            prefix: 32,
        }
    }
    pub fn contains(self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & (u32::MAX << (32 - self.prefix)) == self.network
    }
    pub fn without(self, ip: Ipv4Addr) -> Vec<Self> {
        if !self.contains(ip) {
            return vec![self];
        }
        if self.prefix == 32 {
            return Vec::new();
        }
        let left = Self {
            network: self.network,
            prefix: self.prefix + 1,
        };
        let right = Self {
            network: self.network | (1 << (31 - self.prefix)),
            prefix: self.prefix + 1,
        };
        [left.without(ip), right.without(ip)].concat()
    }
    pub fn text(self) -> String {
        format!("{}/{}", Ipv4Addr::from(self.network), self.prefix)
    }
}

pub fn plan_routes(
    values: &BTreeSet<String>,
    dns: &[Ipv4Addr],
    excluded: &BTreeSet<Ipv4Addr>,
) -> Result<Vec<Cidr>> {
    let mut routes = BTreeSet::new();
    for value in values {
        routes.insert(Cidr::parse(value)?);
    }
    for ip in dns {
        if excluded.contains(ip) {
            bail!("VPN DNS overlaps a protected outer address");
        }
        routes.insert(Cidr::host(*ip));
    }
    let mut result = BTreeSet::new();
    for cidr in routes {
        let mut fragments = vec![cidr];
        for ip in excluded {
            fragments = fragments.into_iter().flat_map(|c| c.without(*ip)).collect();
        }
        result.extend(fragments);
    }
    // More-specific routes first make overlap handling deterministic.
    let mut result: Vec<_> = result.into_iter().collect();
    result.sort_by_key(|c| (std::cmp::Reverse(c.prefix), c.network));
    let mut minimized: Vec<Cidr> = Vec::new();
    for cidr in &result {
        if !result
            .iter()
            .any(|other| other.prefix < cidr.prefix && other.contains(Ipv4Addr::from(cidr.network)))
        {
            minimized.push(*cidr);
        }
    }
    if minimized.len() > 4096 {
        bail!("too many TUN routes");
    }
    Ok(minimized)
}

pub trait RouteCommands: Send + Sync {
    fn change(&self, add: bool, cidr: Cidr, interface: &str) -> Result<()>;
    fn snapshot(&self) -> Result<Option<BTreeSet<(Cidr, String)>>> {
        Ok(None)
    }
}

/// macOS netstat abbreviates networks (e.g. `166.111/16`, `10/8`).
#[cfg(any(target_os = "macos", test))]
fn table_cidr(value: &str) -> Result<Cidr> {
    let (address, explicit_prefix) = value
        .split_once('/')
        .map_or((value, None), |(a, p)| (a, Some(p)));
    if address == "default" {
        bail!("default route is not a resource route");
    }
    let octets: Vec<u8> = address
        .split('.')
        .map(str::parse)
        .collect::<std::result::Result<_, _>>()?;
    if octets.is_empty() || octets.len() > 4 {
        bail!("invalid route-table destination");
    }
    let prefix = match explicit_prefix {
        Some(prefix) => prefix.parse()?,
        None => (octets.len() * 8) as u8,
    };
    let mut full = [0_u8; 4];
    full[..octets.len()].copy_from_slice(&octets);
    Cidr::parse(&format!("{}/{prefix}", Ipv4Addr::from(full)))
}

#[cfg(any(target_os = "macos", test))]
fn parse_route_table(text: &str) -> Result<BTreeSet<(Cidr, String)>> {
    let mut interface_column = None;
    let mut routes = BTreeSet::new();
    for line in text.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.first() == Some(&"Destination") {
            interface_column = fields.iter().position(|field| *field == "Netif");
            continue;
        }
        if let Some(column) = interface_column
            && fields.len() > column
            && let Ok(cidr) = table_cidr(fields[0])
        {
            routes.insert((cidr, fields[column].to_owned()));
        }
    }
    if interface_column.is_none() {
        bail!("macOS route table format was not recognized");
    }
    Ok(routes)
}

pub struct SystemRoutes;
impl RouteCommands for SystemRoutes {
    #[cfg(target_os = "macos")]
    fn change(&self, add: bool, cidr: Cidr, interface: &str) -> Result<()> {
        let output = Command::new("/sbin/route")
            .args([
                "-n",
                if add { "add" } else { "delete" },
                "-inet",
                "-net",
                &cidr.text(),
                "-interface",
                interface,
            ])
            .output()
            .context("cannot execute route")?;
        if !output.status.success() {
            bail!(
                "route {} {} via {} failed: {}",
                if add { "add" } else { "delete" },
                cidr.text(),
                interface,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    fn snapshot(&self) -> Result<Option<BTreeSet<(Cidr, String)>>> {
        let output = Command::new("/usr/sbin/netstat")
            .args(["-rn", "-f", "inet"])
            .env("LC_ALL", "C")
            .output()
            .context("cannot read kernel route table")?;
        if !output.status.success() {
            bail!("cannot read kernel route table");
        }
        Ok(Some(parse_route_table(&String::from_utf8(output.stdout)?)?))
    }
    #[cfg(target_os = "windows")]
    fn change(&self, add: bool, cidr: Cidr, interface: &str) -> Result<()> {
        let prefix = format!("prefix={}", cidr.text());
        let alias = format!("interface={interface}");
        let mut command = Command::new("netsh.exe");
        command.args([
            "interface",
            "ipv4",
            if add { "add" } else { "delete" },
            "route",
            &prefix,
            &alias,
            "store=active",
        ]);
        if add {
            command.args(["nexthop=0.0.0.0", "metric=5"]);
        }
        let output = command.output()?;
        if !output.status.success() {
            bail!(
                "Windows route operation failed: {}",
                String::from_utf8_lossy(&output.stdout)
            );
        }
        Ok(())
    }
    #[cfg(target_os = "windows")]
    fn snapshot(&self) -> Result<Option<BTreeSet<(Cidr, String)>>> {
        let output=Command::new("powershell.exe").args(["-NoProfile","-NonInteractive","-Command","Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore | Select-Object DestinationPrefix,InterfaceAlias | ConvertTo-Json -Compress"]).output()?;
        if !output.status.success() {
            bail!("cannot inspect Windows route table");
        }
        let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        let values = match value {
            serde_json::Value::Array(rows) => rows,
            serde_json::Value::Null => vec![],
            value => vec![value],
        };
        let mut table = BTreeSet::new();
        for row in values {
            if let (Some(prefix), Some(alias)) = (
                row["DestinationPrefix"].as_str(),
                row["InterfaceAlias"].as_str(),
            ) && let Ok(cidr) = Cidr::parse(prefix)
            {
                table.insert((cidr, alias.to_owned()));
            }
        }
        Ok(Some(table))
    }
}

pub struct RouteManager<R: RouteCommands = SystemRoutes> {
    commands: R,
    interface: String,
    excluded: BTreeSet<Ipv4Addr>,
    installed: Vec<Cidr>,
}

impl<R: RouteCommands> RouteManager<R> {
    pub fn install(
        commands: R,
        interface: String,
        excluded: BTreeSet<Ipv4Addr>,
        routes: Vec<Cidr>,
    ) -> Result<Self> {
        let mut owner = Self {
            commands,
            interface,
            excluded,
            installed: Vec::new(),
        };
        for route in routes {
            owner.add(route)?;
        }
        owner.audit_and_repair()?;
        Ok(owner)
    }
    fn add(&mut self, cidr: Cidr) -> Result<()> {
        self.commands.change(true, cidr, &self.interface)?;
        self.installed.push(cidr);
        Ok(())
    }
    pub fn permits(&self, ip: Ipv4Addr) -> bool {
        !self.excluded.contains(&ip) && self.installed.iter().any(|c| c.contains(ip))
    }
    pub fn ensure_hosts(&mut self, addresses: &[Ipv4Addr]) -> Result<()> {
        for ip in addresses {
            if self.excluded.contains(ip)
                || ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || ip.is_broadcast()
            {
                bail!("DNS answer points to a protected or invalid TUN destination");
            }
            if !self.permits(*ip) {
                if self.installed.len() >= 4096 {
                    bail!("dynamic TUN route limit exceeded");
                }
                self.add(Cidr::host(*ip))?;
            }
        }
        Ok(())
    }
    pub fn clear(&mut self) {
        let snapshot = match self.commands.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                eprintln!(
                    "Cannot verify route ownership during cleanup; closing utun will remove its routes: {error}"
                );
                self.installed.clear();
                return;
            }
        };
        for cidr in self.installed.drain(..).rev() {
            // An external writer may have removed/replaced this route. Never delete theirs.
            if let Some(snapshot) = &snapshot
                && !snapshot.contains(&(cidr, self.interface.clone()))
            {
                continue;
            }
            if let Err(error) = self.commands.change(false, cidr, &self.interface) {
                eprintln!("TUN route cleanup: {error}");
            }
        }
    }
    pub fn audit_and_repair(&mut self) -> Result<usize> {
        let Some(snapshot) = self.commands.snapshot()? else {
            return Ok(0);
        };
        let mut restored = 0;
        for cidr in &self.installed {
            if !snapshot.contains(&(*cidr, self.interface.clone())) {
                // `add` preserves conflicting routes; it never changes or flushes them.
                self.commands
                    .change(true, *cidr, &self.interface)
                    .with_context(|| format!("cannot restore missing TUN route {}", cidr.text()))?;
                restored += 1;
            }
        }
        if restored > 0 {
            let verified = self
                .commands
                .snapshot()?
                .context("route verification unavailable")?;
            let missing: Vec<_> = self
                .installed
                .iter()
                .filter(|cidr| !verified.contains(&(**cidr, self.interface.clone())))
                .map(|c| c.text())
                .collect();
            if !missing.is_empty() {
                bail!(
                    "TUN routes vanished after installation: {}",
                    missing.join(", ")
                );
            }
        }
        Ok(restored)
    }
}
impl<R: RouteCommands> Drop for RouteManager<R> {
    fn drop(&mut self) {
        self.clear();
    }
}

pub fn physical_gateway(peer: Ipv4Addr) -> Result<Option<Ipv4Addr>> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("/sbin/route")
            .args(["-n", "get", "-inet", &peer.to_string()])
            .output()?;
        if !output.status.success() {
            bail!("cannot inspect outer VPN route");
        }
        let text = String::from_utf8(output.stdout)?;
        Ok(text.lines().find_map(|l| {
            l.trim()
                .strip_prefix("gateway:")
                .and_then(|v| v.trim().parse().ok())
        }))
    }
    #[cfg(target_os = "windows")]
    {
        let script = format!(
            "Find-NetRoute -RemoteIPAddress '{peer}' | Where-Object {{ $_.NextHop -and $_.NextHop -ne '0.0.0.0' }} | Select-Object -First 1 -ExpandProperty NextHop"
        );
        let output = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output()?;
        if !output.status.success() {
            bail!("cannot inspect Windows VPN outer route");
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().parse().ok())
    }
}

pub trait RoutingTable: Send {
    fn permits(&self, ip: Ipv4Addr) -> bool;
    fn ensure_hosts(&mut self, addresses: &[Ipv4Addr]) -> Result<()>;
    fn clear(&mut self);
    fn audit_and_repair(&mut self) -> Result<usize> {
        Ok(0)
    }
}

impl<R: RouteCommands> RoutingTable for RouteManager<R> {
    fn permits(&self, ip: Ipv4Addr) -> bool {
        self.permits(ip)
    }
    fn ensure_hosts(&mut self, addresses: &[Ipv4Addr]) -> Result<()> {
        self.ensure_hosts(addresses)
    }
    fn clear(&mut self) {
        self.clear();
    }
    fn audit_and_repair(&mut self) -> Result<usize> {
        self.audit_and_repair()
    }
}

pub type SharedRoutes = std::sync::Arc<Mutex<Box<dyn RoutingTable>>>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    #[test]
    fn parses_macos_abbreviated_network_and_host_routes() {
        let table = "Routing tables\nInternet:\nDestination Gateway Flags Netif Expire\ndefault 1.2.3.4 UGSc en0\n166.111/16 utun10 USc utun10\n192.168.10.2 utun10 UHS utun10\n10/8 link#2 UCS en0\n";
        let parsed = parse_route_table(table).unwrap();
        assert!(parsed.contains(&(Cidr::parse("166.111.0.0/16").unwrap(), "utun10".into())));
        assert!(parsed.contains(&(Cidr::host("192.168.10.2".parse().unwrap()), "utun10".into())));
        assert!(parsed.contains(&(Cidr::parse("10.0.0.0/8").unwrap(), "en0".into())));
        assert!(parse_route_table("unexpected output").is_err());
    }
    struct Kernel {
        table: Arc<Mutex<BTreeSet<(Cidr, String)>>>,
        events: Arc<Mutex<Vec<(bool, String)>>>,
    }
    impl RouteCommands for Kernel {
        fn change(&self, add: bool, cidr: Cidr, interface: &str) -> Result<()> {
            self.events.lock().unwrap().push((add, cidr.text()));
            let mut table = self.table.lock().unwrap();
            if add {
                if table.iter().any(|(existing, _)| *existing == cidr) {
                    bail!("conflicting route");
                }
                table.insert((cidr, interface.into()));
            } else {
                table.remove(&(cidr, interface.into()));
            }
            Ok(())
        }
        fn snapshot(&self) -> Result<Option<BTreeSet<(Cidr, String)>>> {
            Ok(Some(self.table.lock().unwrap().clone()))
        }
    }
    #[test]
    fn restores_externally_removed_subnet_and_preserves_replaced_routes() {
        let cidr = Cidr::parse("192.168.10.0/24").unwrap();
        let table = Arc::new(Mutex::new(BTreeSet::new()));
        let events = Arc::new(Mutex::new(Vec::new()));
        let kernel = Kernel {
            table: table.clone(),
            events: events.clone(),
        };
        let mut manager =
            RouteManager::install(kernel, "utun10".into(), BTreeSet::new(), vec![cidr]).unwrap();
        table.lock().unwrap().clear();
        assert_eq!(manager.audit_and_repair().unwrap(), 1);
        assert!(table.lock().unwrap().contains(&(cidr, "utun10".into())));
        table.lock().unwrap().clear();
        table.lock().unwrap().insert((cidr, "en0".into()));
        assert!(manager.audit_and_repair().is_err());
        events.lock().unwrap().clear();
        drop(manager);
        assert!(events.lock().unwrap().is_empty());
        assert!(table.lock().unwrap().contains(&(cidr, "en0".into())));
    }
    #[test]
    fn excludes_outer_server_without_losing_its_neighbors() {
        let peer = "166.111.77.32".parse().unwrap();
        let routes = plan_routes(
            &BTreeSet::from(["166.111.0.0/16".into()]),
            &[],
            &BTreeSet::from([peer]),
        )
        .unwrap();
        assert!(!routes.iter().any(|c| c.contains(peer)));
        for neighbor in [
            "166.111.77.31",
            "166.111.77.33",
            "166.111.0.0",
            "166.111.255.255",
        ] {
            assert!(routes.iter().any(|c| c.contains(neighbor.parse().unwrap())));
        }
        assert!(
            !routes
                .iter()
                .any(|c| c.contains("166.112.0.1".parse().unwrap()))
        );
    }
    #[test]
    fn includes_dns_and_deduplicates_overlaps() {
        let routes = plan_routes(
            &BTreeSet::from(["10.0.0.0/8".into(), "10.1.0.0/16".into()]),
            &["10.2.0.53".parse().unwrap(), "192.0.2.53".parse().unwrap()],
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(routes.len(), 2);
        assert!(Cidr::parse("0.0.0.0/0").is_err());
        assert!(Cidr::parse("10.0.1.0/16").is_err());
    }
    struct Fake {
        events: Arc<Mutex<Vec<(bool, String)>>>,
        fail: Option<Cidr>,
    }
    impl RouteCommands for Fake {
        fn change(&self, add: bool, cidr: Cidr, _: &str) -> Result<()> {
            self.events.lock().unwrap().push((add, cidr.text()));
            if add && self.fail == Some(cidr) {
                bail!("existing route must not be replaced");
            }
            Ok(())
        }
    }
    #[test]
    fn setup_failure_rolls_back_only_owned_routes() {
        let first = Cidr::parse("10.0.0.0/8").unwrap();
        let second = Cidr::parse("192.0.2.0/24").unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        assert!(
            RouteManager::install(
                Fake {
                    events: events.clone(),
                    fail: Some(second)
                },
                "utun9".into(),
                BTreeSet::new(),
                vec![first, second]
            )
            .is_err()
        );
        assert_eq!(
            *events.lock().unwrap(),
            vec![
                (true, first.text()),
                (true, second.text()),
                (false, first.text())
            ]
        );
    }
}
