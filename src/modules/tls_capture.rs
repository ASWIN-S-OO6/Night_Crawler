use anyhow::Result;
use rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::types::HttpInfo;

/// Connect with TLS, accept any certificate, and capture the presented leaf cert.
pub async fn capture_tls_cert(ip: IpAddr, port: u16) -> Result<Vec<u8>> {
    // Ensure a process-wide crypto provider is installed (ring).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let captured: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let verifier = CaptureVerifier {
        captured: captured.clone(),
    };

    let config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(verifier))
    .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let addr = ServerName::IpAddress(rustls::pki_types::IpAddr::from(ip));

    let tcp = TcpStream::connect((ip, port)).await?;
    let _tls = tokio::time::timeout(Duration::from_secs(8), connector.connect(addr, tcp)).await??;

    let guard = captured.lock().unwrap();
    guard
        .first()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("no certificate presented"))
}

#[derive(Debug)]
struct CaptureVerifier {
    captured: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl ServerCertVerifier for CaptureVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.captured
            .lock()
            .unwrap()
            .push(end_entity.as_ref().to_vec());
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
        ]
    }
}

/// Parse a DER certificate into the tidbits we care about.
pub fn parse_cert(der: &[u8]) -> Result<(Option<String>, Option<String>, Vec<String>, Option<String>)> {
    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|e| anyhow::anyhow!("cert parse: {}", e))?;

    let subject_cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok().map(|s| s.to_string()));

    let issuer_cn = cert
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok().map(|s| s.to_string()));

    let mut sans: Vec<String> = Vec::new();
    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for gn in &san_ext.value.general_names {
            match gn {
                x509_parser::extensions::GeneralName::DNSName(s) => sans.push(s.to_string()),
                x509_parser::extensions::GeneralName::RFC822Name(s) => sans.push(s.to_string()),
                x509_parser::extensions::GeneralName::IPAddress(b) => {
                    if b.len() == 4 {
                        sans.push(format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]));
                    } else if b.len() == 16 {
                        let mut arr = [0u8; 16];
                        arr.copy_from_slice(b);
                        sans.push(std::net::Ipv6Addr::from(arr).to_string());
                    }
                }
                _ => {}
            }
        }
    }

    let not_after = cert.validity().not_after.to_string();

    Ok((subject_cn, issuer_cn, sans, Some(not_after)))
}

/// Convenience: capture + parse TLS identity for an endpoint.
pub async fn tls_identity(ip: IpAddr, port: u16) -> Option<(Option<String>, Option<String>, Vec<String>, Option<String>)> {
    let der = capture_tls_cert(ip, port).await.ok()?;
    parse_cert(&der).ok()
}

/// Attach TLS info to an HttpInfo when we could grab it.
pub async fn enrich_http_tls(http: &mut HttpInfo, ip: IpAddr, port: u16, is_https: bool) {
    if !is_https {
        return;
    }
    if let Some((subject, issuer, sans, until)) = tls_identity(ip, port).await {
        http.tls_subject = subject;
        http.tls_issuer = issuer;
        http.tls_san = sans;
        http.tls_valid_until = until;
    }
}
