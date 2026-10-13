//! Explicit leaf-certificate pinning for private gateways.
use crate::{Error, Result};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use subtle::ConstantTimeEq;

#[derive(Debug)]
struct PinnedVerifier {
    pin: [u8; 32],
    signatures: Arc<WebPkiServerVerifier>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let actual: [u8; 32] = Sha256::digest(leaf.as_ref()).into();
        if bool::from(actual.ct_eq(&self.pin)) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "gateway certificate pin mismatch".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.signatures.verify_tls12_signature(message, cert, dss)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.signatures.verify_tls13_signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.signatures.supported_verify_schemes()
    }
}

pub fn tls_config(pin: Option<[u8; 32]>) -> Result<ClientConfig> {
    let roots = Arc::new(RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
    ));
    let builder = ClientConfig::builder();
    match pin {
        None => Ok(builder.with_root_certificates(roots).with_no_client_auth()),
        Some(pin) => {
            let signatures = WebPkiServerVerifier::builder(roots)
                .build()
                .map_err(|_| Error("cannot create certificate signature verifier".into()))?;
            Ok(builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(PinnedVerifier { pin, signatures }))
                .with_no_client_auth())
        }
    }
}

/// Observe the public leaf certificate without sending HTTP or credentials.
/// The observation is deliberately unauthenticated; callers must persist the
/// first fingerprint and use `tls_config(Some(pin))` for all credential traffic.
pub fn fetch_certificate_sha256(gateway: &str) -> Result<String> {
    use std::net::{TcpStream, ToSocketAddrs};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    let url = url::Url::parse(gateway).map_err(|_| Error("invalid gateway URL".into()))?;
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return Err(Error(
            "certificate discovery requires an HTTPS gateway".into(),
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| Error("missing gateway host".into()))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| Error("missing gateway port".into()))?;
    let timeout = Duration::from_secs(8);
    let deadline = Instant::now() + timeout;
    let addresses = (host, port).to_socket_addrs()?;
    let mut socket = None;
    for address in addresses {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        if let Ok(stream) = TcpStream::connect_timeout(&address, remaining) {
            socket = Some(stream);
            break;
        }
    }
    let mut socket = socket.ok_or_else(|| Error("无法连接网关，请检查地址、端口和网络".into()))?;
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;
    let leaf = Arc::new(Mutex::new(None));
    let roots = Arc::new(RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
    ));
    let signatures = WebPkiServerVerifier::builder(roots)
        .build()
        .map_err(|_| Error("cannot create certificate signature verifier".into()))?;
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ObservedVerifier {
            leaf: leaf.clone(),
            signatures: PinnedVerifier {
                pin: [0; 32],
                signatures,
            },
        }))
        .with_no_client_auth();
    let name =
        ServerName::try_from(host.to_owned()).map_err(|_| Error("invalid gateway host".into()))?;
    let mut connection = rustls::ClientConnection::new(Arc::new(config), name)
        .map_err(|_| Error("cannot create certificate discovery connection".into()))?;
    // The verifier stops the handshake immediately after recording the leaf.
    let _ = connection.complete_io(&mut socket);
    leaf.lock()
        .map_err(|_| Error("certificate observation unavailable".into()))?
        .take()
        .ok_or_else(|| Error("无法获取网关证书，请检查网络和 TLS 支持".into()))
}

#[derive(Debug)]
struct ObservedVerifier {
    leaf: Arc<std::sync::Mutex<Option<String>>>,
    signatures: PinnedVerifier,
}
impl ServerCertVerifier for ObservedVerifier {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        *self
            .leaf
            .lock()
            .map_err(|_| rustls::Error::General("certificate observation unavailable".into()))? =
            Some(hex::encode(Sha256::digest(leaf.as_ref())));
        Err(rustls::Error::General(
            "certificate observation complete".into(),
        ))
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.signatures.verify_tls12_signature(message, cert, dss)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.signatures.verify_tls13_signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.signatures.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn observation_records_certificate_but_never_accepts_it() {
        let leaf = CertificateDer::from(b"synthetic certificate".to_vec());
        let captured = Arc::new(std::sync::Mutex::new(None));
        let roots = Arc::new(RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        ));
        let verifier = ObservedVerifier {
            leaf: captured.clone(),
            signatures: PinnedVerifier {
                pin: [0; 32],
                signatures: WebPkiServerVerifier::builder(roots).build().unwrap(),
            },
        };
        let name = ServerName::try_from("example.com").unwrap();
        assert!(
            verifier
                .verify_server_cert(&leaf, &[], &name, &[], UnixTime::now())
                .is_err()
        );
        assert_eq!(
            captured.lock().unwrap().as_deref(),
            Some(hex::encode(Sha256::digest(leaf.as_ref())).as_str())
        );
    }

    #[test]
    fn pin_accepts_only_exact_leaf() {
        let leaf = CertificateDer::from(b"synthetic certificate".to_vec());
        let roots = Arc::new(RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        ));
        let verifier = PinnedVerifier {
            pin: Sha256::digest(leaf.as_ref()).into(),
            signatures: WebPkiServerVerifier::builder(roots).build().unwrap(),
        };
        let name = ServerName::try_from("example.com").unwrap();
        assert!(
            verifier
                .verify_server_cert(&leaf, &[], &name, &[], UnixTime::now())
                .is_ok()
        );
        let changed = CertificateDer::from(b"different certificate".to_vec());
        assert!(
            verifier
                .verify_server_cert(&changed, &[], &name, &[], UnixTime::now())
                .is_err()
        );
    }
}
