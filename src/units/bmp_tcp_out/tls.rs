use std::net::SocketAddr;
use std::sync::Arc;

use log::info;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use sha2::{Digest, Sha256};
use tokio_rustls::TlsAcceptor;

/// Build a `TlsAcceptor` from user-provided PEM files or an auto-generated
/// self-signed certificate.
pub fn build_tls_acceptor(
    tls_cert: Option<&str>,
    tls_key: Option<&str>,
    listen_addr: &SocketAddr,
) -> Result<TlsAcceptor, String> {
    let (certs, key) = match (tls_cert, tls_key) {
        (Some(cert_path), Some(key_path)) => {
            load_pem_files(cert_path, key_path)?
        }
        _ => {
            let (cert, key) = generate_self_signed(listen_addr);
            log_certificate_fingerprint(cert.as_ref());
            (vec![cert], key)
        }
    };

    let config = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| format!("TLS protocol version error: {e}"))?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|e| format!("TLS certificate error: {e}"))?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Load certificate chain and private key from PEM files.
fn load_pem_files(
    cert_path: &str,
    key_path: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
    let cert_data = std::fs::read(cert_path).map_err(|e| {
        format!("Failed to read TLS certificate file '{}': {}", cert_path, e)
    })?;
    let key_data = std::fs::read(key_path).map_err(|e| {
        format!("Failed to read TLS key file '{}': {}", key_path, e)
    })?;

    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_data.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Failed to parse certificate PEM: {e}"))?;

    if certs.is_empty() {
        return Err(format!("No certificates found in '{}'", cert_path));
    }

    let key = rustls_pemfile::private_key(&mut key_data.as_slice())
        .map_err(|e| format!("Failed to parse private key PEM: {e}"))?
        .ok_or_else(|| format!("No private key found in '{}'", key_path))?;

    Ok((certs, key))
}

/// Generate a self-signed ECDSA P-256 certificate.
fn generate_self_signed(
    listen_addr: &SocketAddr,
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
        .expect("empty SAN list should not fail");

    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "netom-bmp-out");

    let ip = listen_addr.ip();
    if ip.is_unspecified() {
        params
            .subject_alt_names
            .push(rcgen::SanType::DnsName("localhost".try_into().unwrap()));
    } else {
        params.subject_alt_names.push(rcgen::SanType::IpAddress(ip));
    }

    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2035, 1, 1);

    let key_pair =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("key generation should not fail");
    let cert = params
        .self_signed(&key_pair)
        .expect("self-signed certificate generation should not fail");

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        key_pair.serialize_der(),
    ));

    (cert_der, key_der)
}

/// Log the SHA-256 fingerprint of a DER-encoded certificate.
fn log_certificate_fingerprint(cert_der: &[u8]) {
    let hash = Sha256::digest(cert_der);
    let fingerprint: String = hash
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":");
    info!(
        "Self-signed TLS certificate fingerprint (SHA-256): {}",
        fingerprint
    );
}
