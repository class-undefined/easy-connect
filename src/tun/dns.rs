use super::routes::SharedRoutes;
use anyhow::{Context, Result, bail};
use ec_compat::engine::policy::RoutePolicy;
use std::{collections::BTreeMap, net::Ipv4Addr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::Semaphore,
    task::JoinSet,
};

struct Question {
    name: String,
    kind: u16,
    end: usize,
}

fn name_at(packet: &[u8], mut offset: usize) -> Result<(String, usize)> {
    let mut labels = Vec::new();
    let mut consumed = None;
    for _ in 0..128 {
        let length = *packet.get(offset).context("truncated DNS name")?;
        if length & 0xc0 == 0xc0 {
            let next = *packet.get(offset + 1).context("truncated DNS pointer")?;
            consumed.get_or_insert(offset + 2);
            offset = (usize::from(length & 0x3f) << 8) | usize::from(next);
        } else if length == 0 {
            return Ok((
                labels.join(".").to_ascii_lowercase(),
                consumed.unwrap_or(offset + 1),
            ));
        } else {
            if length > 63 {
                bail!("invalid DNS label");
            }
            offset += 1;
            let bytes = packet
                .get(offset..offset + usize::from(length))
                .context("truncated DNS label")?;
            let label = std::str::from_utf8(bytes).context("DNS label is not UTF-8")?;
            if !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            {
                bail!("invalid DNS hostname");
            }
            labels.push(label.to_owned());
            if labels.iter().map(String::len).sum::<usize>() + labels.len() > 254 {
                bail!("DNS name too long");
            }
            offset += usize::from(length);
        }
    }
    bail!("DNS compression pointer loop")
}

fn question(packet: &[u8]) -> Result<Question> {
    if packet.len() < 12 || packet.len() > 4096 || packet[4..6] != [0, 1] {
        bail!("DNS requires one bounded question");
    }
    let (name, end) = name_at(packet, 12)?;
    let tail = packet.get(end..end + 4).context("truncated DNS question")?;
    if tail[2..4] != [0, 1] {
        bail!("DNS class must be IN");
    }
    Ok(Question {
        name,
        kind: u16::from_be_bytes([tail[0], tail[1]]),
        end: end + 4,
    })
}

fn response(query: &[u8], q: &Question, code: u8, address: Option<Ipv4Addr>) -> Vec<u8> {
    let mut response = query[..q.end].to_vec();
    response[2] = 0x80 | (query[2] & 1);
    response[3] = 0x80 | code;
    response[6..12].fill(0);
    if let Some(ip) = address {
        response[7] = 1;
        response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4]);
        response.extend_from_slice(&ip.octets());
    }
    response
}

fn answer_addresses(packet: &[u8]) -> Result<Vec<Ipv4Addr>> {
    let q = question(packet)?;
    let answers = u16::from_be_bytes([packet[6], packet[7]]);
    if answers > 128 {
        bail!("too many DNS answers");
    }
    let mut cursor = q.end;
    let mut addresses = Vec::new();
    for _ in 0..answers {
        let (_, end) = name_at(packet, cursor)?;
        let header = packet.get(end..end + 10).context("truncated DNS answer")?;
        let size = usize::from(u16::from_be_bytes([header[8], header[9]]));
        let value = packet
            .get(end + 10..end + 10 + size)
            .context("truncated DNS answer data")?;
        if header[..4] == [0, 1, 0, 1] && size == 4 {
            addresses.push(Ipv4Addr::new(value[0], value[1], value[2], value[3]));
        }
        cursor = end + 10 + size;
    }
    Ok(addresses)
}

struct DnsState {
    hosts: BTreeMap<String, Ipv4Addr>,
    servers: Vec<Ipv4Addr>,
    source: Ipv4Addr,
    policy: Arc<RoutePolicy>,
    routes: SharedRoutes,
}
impl DnsState {
    async fn query(&self, query: &[u8]) -> Result<Vec<u8>> {
        let q = question(query)?;
        if query[2] & 0xf8 != 0 {
            bail!("DNS opcode or QR unsupported");
        }
        if !self.policy.allows_domain(&q.name) {
            return Ok(response(query, &q, 5, None));
        }
        // The current data plane is IPv4: prevent applications selecting an unrouted AAAA target.
        if q.kind == 28 {
            return Ok(response(query, &q, 0, None));
        }
        if q.kind == 1
            && let Some(address) = self.hosts.get(&q.name)
        {
            let address = *address;
            let routes = self.routes.clone();
            tokio::task::spawn_blocking(move || {
                routes
                    .lock()
                    .map_err(|_| anyhow::anyhow!("route lock poisoned"))?
                    .ensure_hosts(&[address])
            })
            .await??;
            return Ok(response(query, &q, 0, Some(address)));
        }
        for server in &self.servers {
            let socket = UdpSocket::bind((self.source, 0)).await?;
            socket.connect((*server, 53)).await?;
            let attempt = async {
                socket.send(query).await?;
                let mut buffer = [0_u8; 4096];
                let count = socket.recv(&mut buffer).await?;
                let packet = &buffer[..count];
                let returned = question(packet)?;
                if packet[..2] != query[..2]
                    || packet[2] & 0x80 == 0
                    || returned.name != q.name
                    || returned.kind != q.kind
                {
                    bail!("DNS answer does not match request");
                }
                let addresses = answer_addresses(packet)?;
                let routes = self.routes.clone();
                tokio::task::spawn_blocking(move || {
                    routes
                        .lock()
                        .map_err(|_| anyhow::anyhow!("route lock poisoned"))?
                        .ensure_hosts(&addresses)
                })
                .await??;
                Ok::<_, anyhow::Error>(packet.to_vec())
            };
            if let Ok(Ok(packet)) = tokio::time::timeout(Duration::from_secs(3), attempt).await {
                return Ok(packet);
            }
        }
        Ok(response(query, &q, 2, None))
    }
}

pub struct DnsProxy {
    udp: Arc<UdpSocket>,
    tcp: TcpListener,
    state: Arc<DnsState>,
}
impl DnsProxy {
    pub async fn bind(
        source: Ipv4Addr,
        servers: Vec<Ipv4Addr>,
        hosts: BTreeMap<String, Ipv4Addr>,
        policy: Arc<RoutePolicy>,
        routes: SharedRoutes,
    ) -> Result<Self> {
        #[cfg(target_os = "macos")]
        let port = 0;
        #[cfg(target_os = "windows")]
        let port = 53;
        let udp = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).await?);
        let tcp = TcpListener::bind(udp.local_addr()?).await?;
        Ok(Self {
            udp,
            tcp,
            state: Arc::new(DnsState {
                source,
                servers,
                hosts,
                policy,
                routes,
            }),
        })
    }
    pub fn port(&self) -> Result<u16> {
        Ok(self.udp.local_addr()?.port())
    }
    pub async fn serve(&self) -> Result<()> {
        let limit = Arc::new(Semaphore::new(64));
        let mut tasks = JoinSet::new();
        let mut buffer = [0_u8; 4096];
        loop {
            tokio::select! {
                received = self.udp.recv_from(&mut buffer) => {
                    let (count,peer) = received?;
                    if !peer.ip().is_loopback() { continue; }
                    let Ok(permit) = limit.clone().try_acquire_owned() else { continue; };
                    let query = buffer[..count].to_vec(); let state=self.state.clone(); let udp=self.udp.clone();
                    tasks.spawn(async move { let _permit=permit; if let Ok(answer)=state.query(&query).await { let _=udp.send_to(&answer,peer).await; } });
                },
                accepted = self.tcp.accept() => {
                    let (mut socket,peer)=accepted?;
                    if !peer.ip().is_loopback() { continue; }
                    let Ok(permit)=limit.clone().try_acquire_owned() else { continue; };
                    let state=self.state.clone();
                    tasks.spawn(async move {
                        let _permit=permit;
                        let transaction=async {
                            // One query per connection; the system resolver can reconnect for more.
                            let size=socket.read_u16().await?;
                            if size>4096 { bail!("DNS TCP query too large"); }
                            let mut query=vec![0;usize::from(size)];socket.read_exact(&mut query).await?;
                            let answer=state.query(&query).await?;
                            socket.write_u16(answer.len() as u16).await?;socket.write_all(&answer).await?;
                            Ok::<_,anyhow::Error>(())
                        };
                        let _=tokio::time::timeout(Duration::from_secs(15),transaction).await;
                    });
                },
                _ = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use core_foundation::{
        array::CFArray, base::TCFType, dictionary::CFDictionary, number::CFNumber, string::CFString,
    };
    use system_configuration::dynamic_store::{SCDynamicStore, SCDynamicStoreBuilder};
    use system_configuration_sys::dynamic_store::SCDynamicStoreAddTemporaryValue;

    pub struct SplitDns {
        store: SCDynamicStore,
        key: String,
    }
    impl SplitDns {
        pub fn install(interface: &str, port: u16, domains: &[String]) -> Result<Self> {
            let store = SCDynamicStoreBuilder::new("easy-connect split DNS").build();
            let key = format!(
                "State:/Network/Service/easy-connect-{}-{interface}/DNS",
                std::process::id()
            );
            let addresses = CFArray::from_CFTypes(&[CFString::new("127.0.0.1")]);
            let matches = CFArray::from_CFTypes(
                &domains.iter().map(|d| CFString::new(d)).collect::<Vec<_>>(),
            );
            let dictionary = CFDictionary::from_CFType_pairs(&[
                (CFString::new("ServerAddresses"), addresses.as_CFType()),
                (
                    CFString::new("ServerPort"),
                    CFNumber::from(i32::from(port)).as_CFType(),
                ),
                (
                    CFString::new("SupplementalMatchDomains"),
                    matches.as_CFType(),
                ),
                (
                    CFString::new("SupplementalMatchDomainsNoSearch"),
                    CFNumber::from(1_i32).as_CFType(),
                ),
                (
                    CFString::new("SearchOrder"),
                    CFNumber::from(1_i32).as_CFType(),
                ),
            ]);
            let cf_key = CFString::new(&key);
            // SAFETY: the store, key and property-list dictionary are retained CF objects.
            // AddTemporaryValue copies their values and binds cleanup to this store session.
            let success = unsafe {
                SCDynamicStoreAddTemporaryValue(
                    store.as_concrete_TypeRef(),
                    cf_key.as_concrete_TypeRef(),
                    dictionary.as_CFTypeRef(),
                )
            };
            if success == 0 {
                bail!("cannot register temporary macOS split DNS");
            }
            Ok(Self { store, key })
        }
    }
    impl Drop for SplitDns {
        fn drop(&mut self) {
            if !self.store.remove(self.key.as_str()) {
                eprintln!("split DNS key was already removed or could not be removed");
            }
        }
    }
}
#[cfg(target_os = "windows")]
pub use super::windows_dns::SplitDns;
#[cfg(target_os = "macos")]
pub use platform::SplitDns;
#[cfg(test)]
mod tests {
    use super::*;
    fn query() -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(b"\x08internal\x07example\x03edu\0\0\x01\0\x01");
        q
    }
    struct FakeRoutes;
    impl super::super::routes::RoutingTable for FakeRoutes {
        fn permits(&self, _: Ipv4Addr) -> bool {
            true
        }
        fn ensure_hosts(&mut self, _: &[Ipv4Addr]) -> Result<()> {
            Ok(())
        }
        fn clear(&mut self) {}
    }
    #[test]
    fn static_a_answer_retains_question_and_identifier() {
        let query = query();
        let q = question(&query).unwrap();
        assert_eq!(q.name, "internal.example.edu");
        let answer = response(&query, &q, 0, Some("10.2.3.4".parse().unwrap()));
        assert_eq!(&answer[..2], &query[..2]);
        assert_eq!(
            answer_addresses(&answer).unwrap(),
            vec!["10.2.3.4".parse::<Ipv4Addr>().unwrap()]
        );
    }
    #[test]
    fn malformed_pointers_and_truncated_answers_fail() {
        assert!(name_at(&[0xc0, 0], 0).is_err());
        let query = query();
        let q = question(&query).unwrap();
        let mut answer = response(&query, &q, 0, Some("10.1.1.1".parse().unwrap()));
        answer.pop();
        assert!(answer_addresses(&answer).is_err());
    }
    #[tokio::test]
    async fn serves_static_a_and_suppresses_unrouted_ipv6() {
        let policy=Arc::new(RoutePolicy::from_config(&serde_json::json!({"proxy":{"route_domains":["example.edu"],"route_ipv4_cidrs":[]}})).unwrap());
        let routes: SharedRoutes = Arc::new(std::sync::Mutex::new(Box::new(FakeRoutes)));
        let state = DnsState {
            hosts: BTreeMap::from([("internal.example.edu".into(), "10.1.2.3".parse().unwrap())]),
            servers: vec![],
            source: Ipv4Addr::LOCALHOST,
            policy,
            routes,
        };
        assert_eq!(
            answer_addresses(&state.query(&query()).await.unwrap()).unwrap(),
            vec!["10.1.2.3".parse::<Ipv4Addr>().unwrap()]
        );
        let mut ipv6 = query();
        let end = ipv6.len();
        ipv6[end - 3] = 28;
        assert_eq!(state.query(&ipv6).await.unwrap()[6..8], [0, 0]);
    }
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn loopback_dns_handles_udp_and_tcp_without_system_changes() {
        let policy=Arc::new(RoutePolicy::from_config(&serde_json::json!({"proxy":{"route_domains":["example.edu"],"route_ipv4_cidrs":[]}})).unwrap());
        let routes: SharedRoutes = Arc::new(std::sync::Mutex::new(Box::new(FakeRoutes)));
        let proxy = DnsProxy::bind(
            Ipv4Addr::LOCALHOST,
            vec![],
            BTreeMap::from([("internal.example.edu".into(), "10.1.2.3".parse().unwrap())]),
            policy,
            routes,
        )
        .await
        .unwrap();
        let port = proxy.port().unwrap();
        let server = tokio::spawn(async move { proxy.serve().await });
        let scenario = async {
            let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            udp.connect((Ipv4Addr::LOCALHOST, port)).await.unwrap();
            udp.send(&query()).await.unwrap();
            let mut buffer = [0_u8; 4096];
            let count = udp.recv(&mut buffer).await.unwrap();
            assert_eq!(
                answer_addresses(&buffer[..count]).unwrap(),
                vec!["10.1.2.3".parse::<Ipv4Addr>().unwrap()]
            );
            let mut tcp = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                .await
                .unwrap();
            tcp.write_u16(query().len() as u16).await.unwrap();
            tcp.write_all(&query()).await.unwrap();
            let size = tcp.read_u16().await.unwrap();
            let mut answer = vec![0; usize::from(size)];
            tcp.read_exact(&mut answer).await.unwrap();
            assert_eq!(
                answer_addresses(&answer).unwrap(),
                vec!["10.1.2.3".parse::<Ipv4Addr>().unwrap()]
            );
        };
        let result = tokio::time::timeout(Duration::from_secs(2), scenario).await;
        server.abort();
        let _ = server.await;
        result.unwrap();
    }
}
