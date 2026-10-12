use crate::{Error, Result};
use serde_json::Value;
use std::net::Ipv4Addr;

const MAX_DOMAIN_SUFFIXES: usize = 128;
const MAX_IPV4_CIDRS: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Ipv4Cidr {
    network: u32,
    mask: u32,
}

impl Ipv4Cidr {
    fn parse(value: &str) -> Result<Self> {
        let value = value.trim();
        let (address, prefix) = value
            .split_once('/')
            .filter(|(_, prefix)| !prefix.contains('/'))
            .ok_or_else(|| Error("route IPv4 CIDR must contain one prefix length".into()))?;
        let address = address
            .parse::<Ipv4Addr>()
            .map_err(|_| Error("route IPv4 CIDR contains an invalid address".into()))?;
        let prefix = prefix
            .parse::<u8>()
            .ok()
            .filter(|prefix| (1..=32).contains(prefix))
            .ok_or_else(|| Error("route IPv4 CIDR prefix must be within 1..32".into()))?;
        let mask = u32::MAX << (32 - u32::from(prefix));
        let network = u32::from_be_bytes(address.octets());
        if network & mask != network {
            return Err(Error(
                "route IPv4 CIDR must use its canonical network address".into(),
            ));
        }
        Ok(Self { network, mask })
    }

    fn contains(self, address: Ipv4Addr) -> bool {
        u32::from_be_bytes(address.octets()) & self.mask == self.network
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutePolicy {
    domain_suffixes: Vec<String>,
    ipv4_cidrs: Vec<Ipv4Cidr>,
}

impl RoutePolicy {
    pub fn from_config(config: &Value) -> Result<Self> {
        let domain_suffixes = parse_string_array(
            &config["proxy"]["route_domains"],
            "proxy.route_domains",
            MAX_DOMAIN_SUFFIXES,
            normalize_domain,
        )?;
        let ipv4_cidrs = parse_string_array(
            &config["proxy"]["route_ipv4_cidrs"],
            "proxy.route_ipv4_cidrs",
            MAX_IPV4_CIDRS,
            Ipv4Cidr::parse,
        )?;
        if domain_suffixes.is_empty() && ipv4_cidrs.is_empty() {
            return Err(Error(
                "route policy must allow at least one domain suffix or IPv4 CIDR".into(),
            ));
        }
        Ok(Self {
            domain_suffixes,
            ipv4_cidrs,
        })
    }

    pub fn allows_domain(&self, host: &str) -> bool {
        let Ok(host) = normalize_domain(host) else {
            return false;
        };
        self.domain_suffixes.iter().any(|suffix| {
            host == *suffix
                || host
                    .strip_suffix(suffix)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        })
    }

    pub fn allows_ipv4(&self, address: Ipv4Addr) -> bool {
        self.ipv4_cidrs
            .iter()
            .any(|network| network.contains(address))
    }
}

fn parse_string_array<T: Eq>(
    value: &Value,
    name: &str,
    limit: usize,
    parse: impl Fn(&str) -> Result<T>,
) -> Result<Vec<T>> {
    let values = value
        .as_array()
        .ok_or_else(|| Error(format!("{name} must be an array")))?;
    if values.len() > limit {
        return Err(Error(format!("{name} exceeds its entry limit")));
    }
    let mut parsed = Vec::new();
    for value in values {
        let value = value
            .as_str()
            .ok_or_else(|| Error(format!("{name} entries must be strings")))?;
        let value = parse(value)?;
        if !parsed.contains(&value) {
            parsed.push(value);
        }
    }
    Ok(parsed)
}

fn normalize_domain(value: &str) -> Result<String> {
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 253
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        || value.split('.').any(|label| {
            label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-')
        })
    {
        return Err(Error("route domain suffix has an invalid shape".into()));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn policy() -> RoutePolicy {
        RoutePolicy::from_config(&json!({
            "proxy": {
                "route_domains": ["hkust-gz.edu.cn", "HKUST.EDU.HK."],
                "route_ipv4_cidrs": ["198.51.100.0/24", "192.0.2.9/32"]
            }
        }))
        .unwrap()
    }

    #[test]
    fn domain_matching_is_canonical_and_label_aware() {
        let policy = policy();
        assert!(policy.allows_domain("hkust-gz.edu.cn"));
        assert!(policy.allows_domain("LIBRARY.HKUST-GZ.EDU.CN."));
        assert!(policy.allows_domain("hpc.hkust.edu.hk"));
        assert!(!policy.allows_domain("evil-hkust-gz.edu.cn"));
        assert!(!policy.allows_domain("hkust-gz.edu.cn.example"));
        assert!(!policy.allows_domain("example.com"));
    }

    #[test]
    fn ipv4_matching_stays_inside_explicit_cidrs() {
        let policy = policy();
        assert!(policy.allows_ipv4(Ipv4Addr::new(198, 51, 100, 0)));
        assert!(policy.allows_ipv4(Ipv4Addr::new(198, 51, 100, 255)));
        assert!(policy.allows_ipv4(Ipv4Addr::new(192, 0, 2, 9)));
        assert!(!policy.allows_ipv4(Ipv4Addr::new(198, 51, 99, 255)));
        assert!(!policy.allows_ipv4(Ipv4Addr::new(198, 51, 101, 0)));
        assert!(!policy.allows_ipv4(Ipv4Addr::new(192, 0, 2, 10)));
    }

    #[test]
    fn invalid_or_unrestricted_policies_fail_closed() {
        for cidr in ["0.0.0.0/0", "198.51.100.1/24", "198.51.100.0/33", "bad"] {
            assert!(
                RoutePolicy::from_config(&json!({
                    "proxy": {
                        "route_domains": [],
                        "route_ipv4_cidrs": [cidr]
                    }
                }))
                .is_err(),
                "{cidr}"
            );
        }
        assert!(
            RoutePolicy::from_config(&json!({
                "proxy": {
                    "route_domains": [],
                    "route_ipv4_cidrs": []
                }
            }))
            .is_err()
        );
    }
}
