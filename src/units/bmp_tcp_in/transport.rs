//! Outbound BMP transport. The collector still only receives BMP messages.
use std::{
    io,
    net::SocketAddr,
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use rustls::{
    client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
    ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use serde::Deserialize;
use socket2::{SockRef, TcpKeepalive};
use tokio::{
    io::{AsyncRead, ReadBuf},
    net::TcpStream,
    sync::oneshot,
    time::timeout,
};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawConnection")]
pub enum Connection {
    Listen(SocketAddr),
    Connect(ActiveConnection),
}

#[derive(Deserialize)]
struct RawConnection {
    listen: Option<SocketAddr>,
    connect: Option<String>,
    tls: Option<TlsConfig>,
}

impl TryFrom<RawConnection> for Connection {
    type Error = String;
    fn try_from(raw: RawConnection) -> Result<Self, String> {
        match (raw.listen, raw.connect, raw.tls) {
            (Some(addr), None, None) => Ok(Self::Listen(addr)),
            (None, Some(endpoint), tls) => {
                endpoint_host(&endpoint)?;
                if let Some(tls) = &tls {
                    if tls.insecure && tls.ca_file.is_some() {
                        return Err("tls.ca_file and tls.insecure are mutually exclusive".into());
                    }
                    if let Some(name) = &tls.server_name {
                        ServerName::try_from(name.clone()).map_err(|e| e.to_string())?;
                    }
                }
                Ok(Self::Connect(ActiveConnection { endpoint, tls }))
            }
            _ => Err("bmp-tcp-in requires exactly one of listen or connect; tls is only valid with connect".into()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveConnection {
    pub endpoint: String,
    pub tls: Option<TlsConfig>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub ca_file: Option<PathBuf>,
    pub server_name: Option<String>,
    /// Encryption-only compatibility with exporters using self-signed certs.
    #[serde(default)]
    pub insecure: bool,
}

fn endpoint_host(endpoint: &str) -> Result<&str, String> {
    let invalid = || {
        format!("invalid BMP endpoint {endpoint:?}: expected host:port or [IPv6]:port")
    };
    let (host, port) = endpoint.rsplit_once(':').ok_or_else(invalid)?;
    if port.parse::<u16>().ok().filter(|p| *p != 0).is_none() {
        return Err(invalid());
    }
    if host.starts_with('[') {
        let ip = host
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .ok_or_else(invalid)?;
        ip.parse::<std::net::Ipv6Addr>().map_err(|_| invalid())?;
        Ok(ip)
    } else if host.is_empty()
        || host.contains([':', '/', '[', ']'])
        || host.chars().any(char::is_whitespace)
    {
        Err(invalid())
    } else {
        Ok(host)
    }
}

pub type Reader = Box<dyn AsyncRead + Send + Unpin>;

/// Bound DNS, TCP connect and TLS handshake together; gate processing outside
/// this future can cancel any of them immediately on reconfigure/shutdown.
pub async fn connect(
    config: &ActiveConnection,
) -> io::Result<(Reader, SocketAddr)> {
    timeout(Duration::from_secs(15), async {
        let stream = TcpStream::connect(&config.endpoint).await?;
        let addr = stream.peer_addr()?;
        let ka = TcpKeepalive::new()
            .with_time(super::unit::TCP_KEEPALIVE_IDLE)
            .with_interval(super::unit::TCP_KEEPALIVE_INTERVAL);
        if let Err(err) = SockRef::from(&stream).set_tcp_keepalive(&ka) {
            log::debug!(
                "bmp-in: failed to set TCP keepalive for {addr}: {err}"
            );
        }
        let Some(tls) = &config.tls else {
            return Ok((Box::new(stream) as Reader, addr));
        };
        let client = tls.client_config().await?;
        let host = tls.server_name.as_deref().unwrap_or(
            endpoint_host(&config.endpoint).map_err(io::Error::other)?,
        );
        let name = ServerName::try_from(host.to_owned())
            .map_err(io::Error::other)?;
        let stream = tokio_rustls::TlsConnector::from(Arc::new(client))
            .connect(name, stream)
            .await?;
        Ok((Box::new(stream) as Reader, addr))
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "BMP connect/TLS handshake exceeded 15 seconds",
        )
    })?
}

impl TlsConfig {
    async fn client_config(&self) -> io::Result<ClientConfig> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?;
        if self.insecure {
            return Ok(builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(EncryptionOnly(
                    provider,
                )))
                .with_no_client_auth());
        }
        let mut roots = RootCertStore::empty();
        if let Some(path) = &self.ca_file {
            let pem = tokio::fs::read(path).await?;
            for cert in rustls_pemfile::certs(&mut pem.as_slice()) {
                roots.add(cert?).map_err(io::Error::other)?;
            }
            if roots.is_empty() {
                return Err(io::Error::other(
                    "BMP TLS CA file contains no certificates",
                ));
            }
        } else {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        Ok(builder.with_root_certificates(roots).with_no_client_auth())
    }
}

#[derive(Debug)]
struct EncryptionOnly(Arc<rustls::crypto::CryptoProvider>);
impl ServerCertVerifier for EncryptionOnly {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Cancellation appears as EOF so the handler runs its normal peer withdrawal
/// and ingress cleanup, even when the exporter is idle or sent a partial frame.
pub struct CancellableReader<T> {
    inner: T,
    stop: oneshot::Receiver<()>,
    cancelled: bool,
}
impl<T> CancellableReader<T> {
    pub fn new(inner: T, stop: oneshot::Receiver<()>) -> Self {
        Self {
            inner,
            stop,
            cancelled: false,
        }
    }
}
impl<T: AsyncRead + Unpin> AsyncRead for CancellableReader<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        use std::future::Future;
        if self.cancelled || Pin::new(&mut self.stop).poll(cx).is_ready() {
            self.cancelled = true;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

/// Flapping sessions retain exponential backoff. Only five healthy minutes
/// reset it; a server accepting and immediately closing cannot cause a spin.
#[derive(Default)]
pub struct Backoff(u64);
impl Backoff {
    pub fn next_delay(&mut self) -> Duration {
        self.0 = if self.0 == 0 {
            1
        } else {
            (self.0 * 2).min(300)
        };
        Duration::from_secs(self.0)
    }
    pub fn reset(&mut self) {
        self.0 = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn endpoint_validation() {
        for endpoint in
            ["localhost:11019", "192.0.2.1:123", "[2001:db8::1]:443"]
        {
            assert!(endpoint_host(endpoint).is_ok(), "{endpoint}");
        }
        for endpoint in [
            "",
            ":123",
            "localhost",
            "host:0",
            "host:65536",
            "https://host:443",
            "2001:db8::1:443",
            "[bad]:443",
            "a b:123",
        ] {
            assert!(endpoint_host(endpoint).is_err(), "{endpoint}");
        }
    }

    #[test]
    fn retry_is_bounded_and_resets() {
        let mut retry = Backoff::default();
        let delays: Vec<_> =
            (0..12).map(|_| retry.next_delay().as_secs()).collect();
        assert_eq!(delays, [1, 2, 4, 8, 16, 32, 64, 128, 256, 300, 300, 300]);
        retry.reset();
        assert_eq!(retry.next_delay(), Duration::from_secs(1));
    }

    #[tokio::test]
    async fn cancellation_interrupts_partial_read_and_stays_eof() {
        let (mut writer, reader) = tokio::io::duplex(32);
        writer.write_all(&[3, 0]).await.unwrap();
        let (stop, stopped) = oneshot::channel();
        let mut reader = CancellableReader::new(reader, stopped);
        let mut buf = [0; 5];
        let mut read = Box::pin(reader.read_exact(&mut buf));
        assert!(timeout(Duration::from_millis(10), read.as_mut())
            .await
            .is_err());
        stop.send(()).unwrap();
        assert_eq!(
            read.await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(reader.read(&mut buf).await.unwrap(), 0);
    }

    async fn tls_server() -> (SocketAddr, String, tokio::task::JoinHandle<()>)
    {
        let cert =
            rcgen::generate_simple_self_signed(vec!["localhost".into()])
                .unwrap();
        use base64::Engine;
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            base64::engine::general_purpose::STANDARD.encode(cert.cert.der())
        );
        let server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(
                cert.key_pair.serialize_der(),
            )
            .into(),
        )
        .unwrap();
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            if let Ok(mut stream) =
                tokio_rustls::TlsAcceptor::from(Arc::new(server))
                    .accept(stream)
                    .await
            {
                let _ = stream.write_all(b"BMP").await;
            }
        });
        (addr, pem, task)
    }

    #[tokio::test]
    async fn tls_accepts_explicit_ca_and_insecure_mode() {
        for insecure in [false, true] {
            let (addr, pem, task) = tls_server().await;
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("ca.pem");
            std::fs::write(&path, pem).unwrap();
            let config = ActiveConnection {
                endpoint: addr.to_string(),
                tls: Some(TlsConfig {
                    ca_file: (!insecure).then_some(path),
                    server_name: Some("localhost".into()),
                    insecure,
                }),
            };
            let (mut reader, _) = connect(&config).await.unwrap();
            let mut buf = [0; 3];
            reader.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"BMP");
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn tls_rejects_untrusted_certificate_and_wrong_name() {
        for trusted in [false, true] {
            let (addr, pem, task) = tls_server().await;
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("ca.pem");
            std::fs::write(&path, pem).unwrap();
            let config = ActiveConnection {
                endpoint: addr.to_string(),
                tls: Some(TlsConfig {
                    ca_file: trusted.then_some(path),
                    server_name: Some("wrong.example".into()),
                    insecure: false,
                }),
            };
            assert!(connect(&config).await.is_err());
            task.await.unwrap();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn tls_handshake_has_a_deadline() {
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = ActiveConnection {
            endpoint: listener.local_addr().unwrap().to_string(),
            tls: Some(TlsConfig {
                insecure: true,
                ..Default::default()
            }),
        };
        let task = tokio::spawn(async move { connect(&config).await });
        let (_idle, _) = listener.accept().await.unwrap();
        tokio::time::advance(Duration::from_secs(16)).await;
        assert_eq!(
            task.await.unwrap().err().unwrap().kind(),
            io::ErrorKind::TimedOut
        );
    }
}
