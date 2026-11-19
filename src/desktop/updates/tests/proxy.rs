use super::*;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::Stdio,
    time::Instant,
};

const URLS: &str = "EASY_CONNECT_TEST_UPDATE_PROXY_URLS";
const HOSTS: [&str; 3] = [
    "api.github.invalid",
    "github.invalid",
    "assets.github.invalid",
];

#[test]
fn update_requests_follow_proxies_and_bypass_rules() -> Result<()> {
    // Give each probe its own environment without mutating the test runner's
    // process-wide proxy settings or changing the user's OS proxy settings.
    if let Ok(urls) = std::env::var(URLS) {
        return tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                for url in urls.lines() {
                    // The fixture rejects CONNECT / SOCKS or closes during TLS.
                    // The parent verifies where these requests actually arrived.
                    assert!(
                        client(Duration::from_secs(3))?
                            .get(url)
                            .send()
                            .await
                            .is_err()
                    );
                }
                Ok(())
            });
    }

    for (variable, scheme, bypass) in [
        ("HTTPS_PROXY", "http", false),
        ("https_proxy", "http", false),
        ("HTTPS_PROXY", "socks5h", false),
        ("HTTPS_PROXY", "http", true),
    ] {
        let proxy = TcpListener::bind("127.0.0.1:0")?;
        proxy.set_nonblocking(true)?;
        let target = TcpListener::bind("127.0.0.1:0")?;
        target.set_nonblocking(true)?;
        let urls = if bypass {
            (0..3)
                .map(|n| format!("https://{}/request-{n}", target.local_addr().unwrap()))
                .collect::<Vec<_>>()
        } else {
            HOSTS.map(|host| format!("https://{host}/update")).to_vec()
        };
        #[cfg(target_os = "windows")]
        let mut command = crate::windows::command(std::env::current_exe()?);
        #[cfg(not(target_os = "windows"))]
        let mut command = std::process::Command::new(std::env::current_exe()?);
        command.args([
            "--exact",
            "desktop::updates::tests::proxy::update_requests_follow_proxies_and_bypass_rules",
        ]);
        for name in [
            "HTTP_PROXY",
            "http_proxy",
            "HTTPS_PROXY",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
            "NO_PROXY",
            "no_proxy",
            "REQUEST_METHOD",
        ] {
            command.env_remove(name);
        }
        command
            .env(URLS, urls.join("\n"))
            .env(variable, format!("{scheme}://{}", proxy.local_addr()?))
            .env("NO_PROXY", if bypass { "127.0.0.1" } else { "" })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn()?;
        let result = (|| -> Result<()> {
            let listener = if bypass { &target } else { &proxy };
            let deadline = Instant::now() + Duration::from_secs(12);
            for host in HOSTS {
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            if Instant::now() >= deadline {
                                bail!(
                                    "update request did not reach {variable} ({scheme}, bypass={bypass})"
                                );
                            }
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => return Err(error.into()),
                    }
                };
                stream.set_nonblocking(false)?;
                stream.set_read_timeout(Some(Duration::from_secs(3)))?;
                stream.set_write_timeout(Some(Duration::from_secs(3)))?;
                if bypass {
                    let mut first = [0];
                    stream.read_exact(&mut first)?;
                    assert_eq!(first, [0x16], "direct request must still use TLS");
                } else if scheme == "http" {
                    reject_connect(&mut stream, host)?;
                } else {
                    reject_socks(&mut stream, host)?;
                }
            }
            assert!(matches!(
                if bypass { proxy.accept() } else { target.accept() },
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
            ));
            Ok(())
        })();
        if result.is_err() {
            let _ = child.kill();
        }
        let output = child.wait_with_output()?;
        result?;
        assert!(output.status.success(), "proxy probe failed: {output:?}");
    }
    Ok(())
}

fn reject_connect(stream: &mut TcpStream, host: &str) -> Result<()> {
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        headers.push(byte[0]);
        assert!(headers.len() <= 4096);
    }
    assert!(String::from_utf8(headers)?.starts_with(&format!("CONNECT {host}:443 HTTP/1.1\r\n")));
    stream.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")?;
    Ok(())
}

fn reject_socks(stream: &mut TcpStream, host: &str) -> Result<()> {
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting)?;
    assert_eq!(greeting[0], 5);
    let mut methods = vec![0; greeting[1] as usize];
    stream.read_exact(&mut methods)?;
    assert!(methods.contains(&0));
    stream.write_all(&[5, 0])?;
    let mut request = [0; 5];
    stream.read_exact(&mut request)?;
    assert_eq!(
        &request[..4],
        &[5, 1, 0, 3],
        "SOCKS must resolve the hostname at the proxy"
    );
    let mut domain = vec![0; request[4] as usize];
    stream.read_exact(&mut domain)?;
    assert_eq!(String::from_utf8(domain)?, host);
    let mut port = [0; 2];
    stream.read_exact(&mut port)?;
    assert_eq!(u16::from_be_bytes(port), 443);
    stream.write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0])?;
    Ok(())
}
