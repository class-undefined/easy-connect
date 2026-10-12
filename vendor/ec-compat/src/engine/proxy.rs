use crate::{Error, Result};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;

const MAX_DOMAIN_BYTES: usize = 253;

pub type ResolveFuture<'a> = Pin<Box<dyn Future<Output = Result<Ipv4Addr>> + Send + 'a>>;

pub trait NameResolver: Send + Sync {
    fn resolve_ipv4<'a>(&'a self, host: &'a str) -> ResolveFuture<'a>;
}

pub struct RejectDomainResolver;

impl NameResolver for RejectDomainResolver {
    fn resolve_ipv4<'a>(&'a self, _host: &'a str) -> ResolveFuture<'a> {
        Box::pin(async {
            Err(Error(
                "proxy domain requests require the VPN DNS module".into(),
            ))
        })
    }
}

pub struct SystemDnsResolver;

/// 198.18.0.0/15 is reserved for benchmarking and is commonly used by
/// fake-IP TUN proxies. It cannot be a real campus destination and must not be
/// injected into the independent VPN data plane.
pub fn is_synthetic_fake_ipv4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    octets[0] == 198 && matches!(octets[1], 18 | 19)
}

impl NameResolver for SystemDnsResolver {
    fn resolve_ipv4<'a>(&'a self, host: &'a str) -> ResolveFuture<'a> {
        Box::pin(async move {
            let addresses = tokio::net::lookup_host((host, 1))
                .await
                .map_err(|_| Error("system DNS resolution failed".into()))?;
            let mut saw_synthetic = false;
            for address in addresses {
                if let IpAddr::V4(address) = address.ip() {
                    if address.is_unspecified() {
                        continue;
                    }
                    if is_synthetic_fake_ipv4(address) {
                        saw_synthetic = true;
                        continue;
                    }
                    return Ok(address);
                }
            }
            if saw_synthetic {
                Err(Error(
                    "system DNS returned only synthetic fake-IP addresses".into(),
                ))
            } else {
                Err(Error("system DNS returned no IPv4 address".into()))
            }
        })
    }
}

pub fn validate_domain(host: &str) -> Result<()> {
    if host.len() > MAX_DOMAIN_BYTES
        || host.is_empty()
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        || host
            .split('.')
            .any(|label| label.is_empty() || label.len() > 63)
    {
        return Err(Error("proxy domain has an invalid shape".into()));
    }
    Ok(())
}

pub async fn resolve_host(host: &str, resolver: &dyn NameResolver) -> Result<Ipv4Addr> {
    if let Ok(address) = host.parse::<Ipv4Addr>() {
        if address.is_unspecified() {
            return Err(Error("proxy destination is unspecified".into()));
        }
        return Ok(address);
    }
    validate_domain(host)?;
    resolver.resolve_ipv4(host).await
}

pub async fn resolve_authority(
    authority: &str,
    default_port: Option<u16>,
    resolver: &dyn NameResolver,
) -> Result<SocketAddr> {
    let authority = authority.trim();
    if authority.is_empty()
        || authority.contains(['/', '\\', '@', '[', ']'])
        || authority.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(Error("proxy authority has an invalid shape".into()));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, encoded_port)) if !host.is_empty() && !encoded_port.is_empty() => {
            let port = encoded_port
                .parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
                .ok_or_else(|| Error("proxy authority has an invalid port".into()))?;
            (host, port)
        }
        Some(_) => return Err(Error("proxy authority is incomplete".into())),
        None => (
            authority,
            default_port.ok_or_else(|| Error("proxy authority is missing a port".into()))?,
        ),
    };
    let address = resolve_host(host, resolver).await?;
    Ok(SocketAddr::new(IpAddr::V4(address), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StaticResolver;

    impl NameResolver for StaticResolver {
        fn resolve_ipv4<'a>(&'a self, host: &'a str) -> ResolveFuture<'a> {
            Box::pin(async move {
                if host == "campus.example" {
                    Ok(Ipv4Addr::new(198, 51, 100, 40))
                } else {
                    Err(Error("not found".into()))
                }
            })
        }
    }

    #[test]
    fn domain_validation_is_bounded() {
        assert!(validate_domain("hpc3.internal.example").is_ok());
        assert!(validate_domain("").is_err());
        assert!(validate_domain("bad/domain").is_err());
        assert!(validate_domain("a..b").is_err());
        assert!(validate_domain(&format!("{}.example", "a".repeat(64))).is_err());
    }

    #[test]
    fn identifies_only_the_synthetic_fake_ip_range() {
        assert!(is_synthetic_fake_ipv4(Ipv4Addr::new(198, 18, 0, 0)));
        assert!(is_synthetic_fake_ipv4(Ipv4Addr::new(198, 19, 255, 255)));
        assert!(!is_synthetic_fake_ipv4(Ipv4Addr::new(198, 17, 255, 255)));
        assert!(!is_synthetic_fake_ipv4(Ipv4Addr::new(198, 20, 0, 0)));
        assert!(!is_synthetic_fake_ipv4(Ipv4Addr::new(192, 0, 2, 30)));
    }

    #[tokio::test]
    async fn authority_resolution_requires_a_safe_host_and_port() {
        let resolver = StaticResolver;
        assert_eq!(
            resolve_authority("campus.example:443", None, &resolver)
                .await
                .unwrap(),
            "198.51.100.40:443".parse().unwrap()
        );
        assert_eq!(
            resolve_authority("198.51.100.3", Some(80), &resolver)
                .await
                .unwrap(),
            "198.51.100.3:80".parse().unwrap()
        );
        assert!(
            resolve_authority("user@campus.example:443", None, &resolver)
                .await
                .is_err()
        );
        assert!(
            resolve_authority("[::1]:443", None, &resolver)
                .await
                .is_err()
        );
    }
}
