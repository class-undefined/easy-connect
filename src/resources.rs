use anyhow::{Context, Result, bail};
use ec_compat::engine::policy::RoutePolicy;
use ec_compat::engine::proxy::{NameResolver, ResolveFuture};
use ec_compat::xml::parse_xml;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
    sync::Arc,
};
use url::Url;

pub struct PublishedResources {
    pub domains: BTreeSet<String>,
    pub cidrs: BTreeSet<String>,
    pub hosts: BTreeMap<String, Ipv4Addr>,
    pub dns_servers: BTreeSet<Ipv4Addr>,
    pub entries: Vec<Value>,
    pub groups: Vec<Value>,
    pub default_resource: String,
    pub skipped_hosts: usize,
}

impl PublishedResources {
    pub fn parse(xml: &[u8]) -> Result<Self> {
        let doc = parse_xml(xml, "published resource list")?;
        let root = doc
            .descendants()
            .find(|n| n.is_element() && n.tag_name().name() == "Resource")
            .context("gateway supplied no Resource element")?;
        let mut result = Self {
            domains: BTreeSet::new(),
            cidrs: BTreeSet::new(),
            hosts: BTreeMap::new(),
            dns_servers: BTreeSet::new(),
            entries: Vec::new(),
            groups: Vec::new(),
            default_resource: String::new(),
            skipped_hosts: 0,
        };
        for node in root.descendants().filter(|n| n.is_element()) {
            match node.tag_name().name() {
                "Rc" => {
                    result.entries.push(json!({
                        "id": node.attribute("id").unwrap_or(""),
                        "name": node.attribute("name").unwrap_or(""),
                        "group_id": node.attribute("rc_grp_id").unwrap_or(""),
                        "host": node.attribute("host").unwrap_or(""),
                        "port": node.attribute("port").unwrap_or(""),
                        "type": node.attribute("type").unwrap_or("")
                    }));
                    for host in node.attribute("host").unwrap_or("").split([';', ',']).map(str::trim).filter(|h| !h.is_empty()) {
                        if result.add_host(host).is_err() { result.skipped_hosts += 1; }
                    }
                },
                "RcGroup" | "RcGrp" | "Group" => result.groups.push(json!({"id": node.attribute("id").unwrap_or(""), "name": node.attribute("name").unwrap_or("")})),
                "Other" => result.default_resource = node.attribute("defaultRcId").unwrap_or("").to_owned(),
                "Dns" => {
                    for address in node.attribute("dnsserver").unwrap_or("").split([';', ',']) {
                        if let Ok(ip) = address.trim().parse::<Ipv4Addr>() && usable_ip(ip) {
                            result.dns_servers.insert(ip);
                        }
                    }
                    for row in node.attribute("data").unwrap_or("").split(';') {
                        let fields: Vec<_> = row.split(':').collect();
                        if fields.len() == 3 && let Ok(ip) = fields[2].trim().parse::<Ipv4Addr>() {
                                let domain = fields[1].trim().trim_end_matches('.').to_ascii_lowercase();
                                if valid_domain(&domain) && usable_ip(ip) {
                                    result.hosts.insert(domain.clone(), ip);
                                    result.domains.insert(domain);
                                    result.cidrs.insert(format!("{ip}/32"));
                                }
                        }
                    }
                },
                _ => {}
            }
        }
        if result.entries.len() > 10_000 {
            bail!("too many published resources");
        }
        Ok(result)
    }

    fn add_host(&mut self, host: &str) -> Result<()> {
        if let Some((first, last)) = host.split_once('~').or_else(|| {
            host.split_once('-')
                .filter(|(a, b)| a.parse::<Ipv4Addr>().is_ok() && b.parse::<Ipv4Addr>().is_ok())
        }) {
            let first: Ipv4Addr = first.trim().parse()?;
            let last: Ipv4Addr = last.trim().parse()?;
            if !usable_ip(first) || !usable_ip(last) {
                bail!("invalid resource range");
            }
            self.cidrs.extend(range_to_cidrs(first, last)?);
            return Ok(());
        }
        if let Some((address, mask)) = host
            .split_once('/')
            .filter(|(a, _)| a.parse::<Ipv4Addr>().is_ok())
        {
            let address: Ipv4Addr = address.parse()?;
            let prefix: u32 = match mask.parse::<u32>() {
                Ok(prefix) if prefix <= 32 => prefix,
                _ => {
                    let mask = u32::from(mask.parse::<Ipv4Addr>()?);
                    let prefix = mask.leading_ones();
                    if prefix == 0 || mask != u32::MAX.checked_shl(32 - prefix).unwrap_or(0) {
                        bail!("non-contiguous netmask");
                    }
                    prefix
                }
            };
            if prefix == 0 || !usable_ip(address) {
                bail!("default/invalid resource route");
            }
            let network = u32::from(address) & (u32::MAX << (32 - prefix));
            self.cidrs
                .insert(format!("{}/{prefix}", Ipv4Addr::from(network)));
            return Ok(());
        }
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            if !usable_ip(ip) {
                bail!("invalid resource IP");
            }
            self.cidrs.insert(format!("{ip}/32"));
            return Ok(());
        }
        let parsed = Url::parse(if host.contains("://") { host } else { "" })
            .or_else(|_| Url::parse(&format!("https://{host}")))?;
        let name = parsed
            .host_str()
            .context("resource has no host")?
            .trim_start_matches("*.")
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if let Ok(ip) = name.parse::<Ipv4Addr>() {
            if !usable_ip(ip) {
                bail!("invalid resource IP");
            }
            self.cidrs.insert(format!("{ip}/32"));
        } else {
            if !valid_domain(&name) {
                bail!("unrecognized resource host");
            }
            self.domains.insert(name);
        }
        Ok(())
    }

    pub fn route_policy(&self, config: &Value) -> Result<RoutePolicy> {
        let (domains, cidrs) = self.effective_routes(config)?;
        RoutePolicy::from_config(
            &json!({"proxy": {"route_domains": domains, "route_ipv4_cidrs": cidrs}}),
        )
        .context("no usable routes or too many routes in gateway resources")
    }

    pub fn effective_routes(&self, config: &Value) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
        let auto = config["proxy"]["auto_resources"].as_bool().unwrap_or(true);
        let mut routes = Vec::new();
        for (key, published) in [
            ("route_domains", &self.domains),
            ("route_ipv4_cidrs", &self.cidrs),
        ] {
            let mut values = if auto {
                published.clone()
            } else {
                BTreeSet::new()
            };
            for value in config["proxy"][key]
                .as_array()
                .context("route list must be an array")?
            {
                values.insert(value.as_str().context("route must be a string")?.to_owned());
            }
            routes.push(values);
        }
        let cidrs = routes.pop().context("missing CIDRs")?;
        let domains = routes.pop().context("missing domains")?;
        Ok((domains, cidrs))
    }

    pub fn summary(&self) -> Value {
        json!({"default_resource_id": self.default_resource, "groups": self.groups, "resources": self.entries, "route_domains": self.domains, "route_ipv4_cidrs": self.cidrs, "static_dns_records": self.hosts.len(), "skipped_hosts": self.skipped_hosts})
    }
}

fn valid_domain(host: &str) -> bool {
    let config = json!({"proxy":{"route_domains":[host],"route_ipv4_cidrs":[]}});
    RoutePolicy::from_config(&config).is_ok()
}

fn usable_ip(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast()
}

fn range_to_cidrs(first: Ipv4Addr, last: Ipv4Addr) -> Result<Vec<String>> {
    let mut start = u64::from(u32::from(first));
    let end = u64::from(u32::from(last));
    if start > end {
        bail!("reversed IPv4 range");
    }
    let mut cidrs = Vec::new();
    while start <= end {
        let alignment = start.trailing_zeros().min(32);
        let size = 63 - (end - start + 1).leading_zeros();
        let bits = alignment.min(size);
        if bits == 32 {
            bail!("default route is not supported");
        }
        cidrs.push(format!("{}/{}", Ipv4Addr::from(start as u32), 32 - bits));
        start += 1_u64 << bits;
    }
    Ok(cidrs)
}

pub struct ResourceResolver {
    pub hosts: BTreeMap<String, Ipv4Addr>,
    pub fallback: Arc<dyn NameResolver>,
}

impl NameResolver for ResourceResolver {
    fn resolve_ipv4<'a>(&'a self, host: &'a str) -> ResolveFuture<'a> {
        Box::pin(async move {
            if let Some(ip) = self
                .hosts
                .get(&host.trim_end_matches('.').to_ascii_lowercase())
            {
                return Ok(*ip);
            }
            self.fallback.resolve_ipv4(host).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn published_groups_ranges_masks_and_dns_become_routes() {
        let xml = br#"<Resource><RcGroups><RcGroup id="g1" name="Campus"/></RcGroups><Rcs><Rc id="r1" name="Core" rc_grp_id="g1" host="10.2.0.1~10.2.0.6;10.3.1.2/255.255.0.0;https://intranet.example.edu:8443/x"/></Rcs><Dns data="r2:static.example.edu:10.4.0.5"/><Other defaultRcId="r1"/></Resource>"#;
        let resources = PublishedResources::parse(xml).unwrap();
        assert_eq!(resources.default_resource, "r1");
        assert_eq!(resources.groups.len(), 1);
        assert!(resources.cidrs.contains("10.3.0.0/16"));
        let policy = resources
            .route_policy(&json!({"proxy":{"route_domains":[],"route_ipv4_cidrs":[]}}))
            .unwrap();
        assert!(policy.allows_ipv4("10.2.0.1".parse().unwrap()));
        assert!(policy.allows_ipv4("10.2.0.6".parse().unwrap()));
        assert!(!policy.allows_ipv4("10.2.0.0".parse().unwrap()));
        assert!(!policy.allows_ipv4("10.2.0.7".parse().unwrap()));
        assert!(policy.allows_domain("static.example.edu"));
        assert!(!policy.allows_domain("unrelated.example.edu"));
    }
    #[test]
    fn unknown_hosts_do_not_broaden_routes() {
        let resources = PublishedResources::parse(br#"<Resource><Rcs><Rc host="0.0.0.0/0;10.0.0.0/255.0.255.0;10.0.0.2~10.0.0.1"/></Rcs></Resource>"#).unwrap();
        assert_eq!(resources.skipped_hosts, 3);
        assert!(resources.cidrs.is_empty());
    }
}
