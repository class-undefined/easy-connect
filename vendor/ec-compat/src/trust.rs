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

#[cfg(test)]
mod tests {
    use super::*;
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
