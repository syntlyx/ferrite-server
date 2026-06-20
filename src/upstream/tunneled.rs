//! Upstream DNS routed through an egress (tunnel).
//!
//! Normally ferrite's own upstream queries leave via the OS network stack
//! (`hickory`/`reqwest` own their sockets). A userspace WireGuard egress has no
//! OS interface, so those libraries can't see it — to put ferrite's *own* DNS on
//! the tunnel we must write the bytes through the egress stream ourselves.
//!
//! [`TunneledResolver`] does exactly that: it opens a byte stream to the resolver
//! IP **through a named egress**, then speaks DNS-over-TCP (RFC 7766 framing) over
//! it — adding a TLS layer when configured as DoT (RFC 7858). Both the query and
//! its bytes ride the tunnel, so the local network sees only encrypted WireGuard.
//!
//! The resolver address is always a literal IP (validated at build time), so there
//! is no bootstrap loop ("resolve the resolver"). When the egress is missing,
//! unhealthy, or fails to connect, the resolver **falls back to a direct
//! connection** — a downed tunnel degrades to plain resolution rather than
//! dropping DNS entirely.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwapOption;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

use crate::error::{FeriteError, Result};
use crate::proxy::{EgressConn, ProxyState};

/// Late-bound handle to the proxy registry. The upstream pool is built *before*
/// `ProxyState` exists (the proxy resolves through this same pool), so the handle
/// starts empty and is filled in once the proxy is constructed. An empty handle
/// just means "no egress available" → direct.
pub type ProxyHandle = Arc<ArcSwapOption<ProxyState>>;

/// An empty proxy handle (egress lookups always miss → direct). Used to seed the
/// handle at startup and in tests that don't exercise tunneling.
pub fn no_proxy() -> ProxyHandle {
    Arc::new(ArcSwapOption::empty())
}

const IO_TIMEOUT: Duration = Duration::from_secs(8);

/// A DNS resolver whose connection to `ip:port` is routed through a named egress.
/// Plain DNS-over-TCP when `tls` is `None`; DoT (TLS over the tunnel stream) when
/// `Some`. Falls back to a direct connection if the egress is unavailable.
pub struct TunneledResolver {
    proxy: ProxyHandle,
    egress_id: String,
    ip: IpAddr,
    port: u16,
    tls: Option<TlsParts>,
    label: String,
}

struct TlsParts {
    connector: TlsConnector,
    server_name: ServerName<'static>,
}

impl TunneledResolver {
    /// Plain DNS-over-TCP through `egress_id`. `address` must be a literal IP.
    pub fn plain(proxy: ProxyHandle, egress_id: &str, address: &str, port: u16) -> Result<Self> {
        let ip = parse_ip(address)?;
        Ok(Self {
            proxy,
            egress_id: egress_id.to_string(),
            ip,
            port,
            tls: None,
            label: format!("tunnel[{egress_id}]:plain://{address}:{port}"),
        })
    }

    /// DoT (DNS-over-TLS) through `egress_id`. `address` must be a literal IP;
    /// `tls_name` is the SNI / certificate name. `config` is the shared client
    /// TLS config (root store), built once per pool.
    pub fn dot(
        proxy: ProxyHandle,
        egress_id: &str,
        address: &str,
        port: u16,
        tls_name: &str,
        config: Arc<ClientConfig>,
    ) -> Result<Self> {
        let ip = parse_ip(address)?;
        let server_name = ServerName::try_from(tls_name.to_string())
            .map_err(|e| FeriteError::Config(format!("invalid DoT tls_name '{tls_name}': {e}")))?;
        Ok(Self {
            proxy,
            egress_id: egress_id.to_string(),
            ip,
            port,
            tls: Some(TlsParts {
                connector: TlsConnector::from(config),
                server_name,
            }),
            label: format!("tunnel[{egress_id}]:dot://{address}:{port}#{tls_name}"),
        })
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub async fn resolve_raw(&self, raw: Vec<u8>) -> Result<(Vec<u8>, String)> {
        let (conn, via_egress) = self.open().await?;
        // Surface a direct fallback in the query log so it's obvious when the
        // tunnel wasn't actually used (the whole point is privacy).
        let label = if via_egress {
            self.label.clone()
        } else {
            format!("{} (direct fallback)", self.label)
        };
        let resp = match &self.tls {
            Some(tls) => {
                let stream = timeout(
                    IO_TIMEOUT,
                    tls.connector.connect(tls.server_name.clone(), conn),
                )
                .await
                .map_err(|_| FeriteError::Dns(format!("{}: tls handshake timed out", self.label)))?
                .map_err(|e| FeriteError::Dns(format!("{}: tls handshake: {e}", self.label)))?;
                self.exchange(stream, &raw).await?
            }
            None => self.exchange(conn, &raw).await?,
        };
        Ok((resp, label))
    }

    /// Open a byte stream to the resolver through the egress, or directly when the
    /// egress is unavailable. Returns the stream and whether the egress was used.
    async fn open(&self) -> Result<(EgressConn, bool)> {
        if let Some(proxy) = self.proxy.load_full() {
            // Only attempt the tunnel when it's actually up; a down tunnel goes
            // straight to direct (no connect-timeout stall on every query).
            if proxy.is_egress_healthy(&self.egress_id) {
                match proxy.egress(&self.egress_id) {
                    Some(eg) => {
                        // Box the connect future: a WireGuard egress may resolve
                        // its own hostnames through the upstream pool, which can
                        // contain this very resolver — an async-recursion cycle
                        // that needs heap indirection to have a finite size.
                        let ip = self.ip.to_string();
                        let connect = Box::pin(eg.connect(&ip, self.port));
                        match timeout(IO_TIMEOUT, connect).await {
                            Ok(Ok(c)) => return Ok((c, true)),
                            Ok(Err(e)) => tracing::debug!(
                                "upstream {}: egress connect failed ({e}); falling back to direct",
                                self.label
                            ),
                            Err(_) => tracing::debug!(
                                "upstream {}: egress connect timed out; falling back to direct",
                                self.label
                            ),
                        }
                    }
                    None => tracing::debug!(
                        "upstream {}: egress '{}' not configured; direct",
                        self.label,
                        self.egress_id
                    ),
                }
            } else {
                tracing::debug!(
                    "upstream {}: egress '{}' is down; direct",
                    self.label,
                    self.egress_id
                );
            }
        }
        let tcp = timeout(IO_TIMEOUT, TcpStream::connect((self.ip, self.port)))
            .await
            .map_err(|_| FeriteError::Dns(format!("{}: direct connect timed out", self.label)))?
            .map_err(|e| FeriteError::Dns(format!("{}: direct connect: {e}", self.label)))?;
        Ok((EgressConn::Tcp(tcp), false))
    }

    /// DNS-over-TCP exchange (RFC 7766): `[u16 length][message]` in both
    /// directions. Safe without txid validation — TCP connection integrity plus a
    /// fixed resolver leave no off-path attacker to inject a forgery.
    async fn exchange<S>(&self, mut s: S, raw: &[u8]) -> Result<Vec<u8>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if raw.len() > u16::MAX as usize {
            return Err(FeriteError::Dns(format!("{}: query too large", self.label)));
        }
        let fut = async {
            let mut framed = Vec::with_capacity(raw.len() + 2);
            framed.extend_from_slice(&(raw.len() as u16).to_be_bytes());
            framed.extend_from_slice(raw);
            s.write_all(&framed).await.map_err(io_dns)?;
            s.flush().await.map_err(io_dns)?;
            let mut len = [0u8; 2];
            s.read_exact(&mut len).await.map_err(io_dns)?;
            let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
            s.read_exact(&mut buf).await.map_err(io_dns)?;
            Ok::<_, FeriteError>(buf)
        };
        timeout(IO_TIMEOUT, fut)
            .await
            .map_err(|_| FeriteError::Dns(format!("{}: query timed out", self.label)))?
    }
}

/// Shared TLS client config (Mozilla roots, ring provider) for tunneled DoT.
/// Built once per pool and cloned into each DoT resolver.
pub fn client_config() -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| FeriteError::Config(format!("tunneled DoT tls setup: {e}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Arc::new(config))
}

fn parse_ip(address: &str) -> Result<IpAddr> {
    address.parse().map_err(|_| {
        FeriteError::Config(format!(
            "tunneled upstream address must be a literal IP, got '{address}'"
        ))
    })
}

fn io_dns(e: std::io::Error) -> FeriteError {
    FeriteError::Dns(format!("tunneled dns io: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_rejects_non_ip_address() {
        // A tunneled resolver must point at a literal IP — a hostname would need
        // resolution, and resolution is exactly what we're trying to tunnel.
        assert!(TunneledResolver::plain(no_proxy(), "eg", "dns.example.com", 53).is_err());
        assert!(TunneledResolver::plain(no_proxy(), "eg", "1.1.1.1", 53).is_ok());
    }

    #[test]
    fn dot_builds_with_literal_ip_and_tls_name() {
        let cfg = client_config().expect("client config");
        assert!(
            TunneledResolver::dot(no_proxy(), "eg", "1.1.1.1", 853, "cloudflare-dns.com", cfg)
                .is_ok()
        );
    }

    #[test]
    fn egress_field_serde_roundtrips_and_skips_when_none() {
        use crate::config::UpstreamConfig;
        let with = UpstreamConfig::Plain {
            address: "10.2.0.1".into(),
            port: 53,
            egress: Some("proton".into()),
        };
        let j = serde_json::to_string(&with).unwrap();
        assert!(j.contains("proton"));
        let back: UpstreamConfig = serde_json::from_str(&j).unwrap();
        assert!(matches!(back, UpstreamConfig::Plain { egress: Some(e), .. } if e == "proton"));

        // Absent egress is omitted from the serialized form (clean configs).
        let without = UpstreamConfig::Plain {
            address: "10.2.0.1".into(),
            port: 53,
            egress: None,
        };
        assert!(!serde_json::to_string(&without).unwrap().contains("egress"));
    }

    /// End-to-end of the direct-fallback path: an empty proxy handle means no
    /// egress, so `resolve_raw` connects directly and speaks DNS-over-TCP framing.
    /// Proves the framing and the "(direct fallback)" labelling without a tunnel.
    #[tokio::test]
    async fn falls_back_to_direct_and_speaks_dns_over_tcp() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Length-prefixed echo: read [u16 len][msg], write the same back.
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut len = [0u8; 2];
            s.read_exact(&mut len).await.unwrap();
            let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
            s.read_exact(&mut buf).await.unwrap();
            let mut out = (buf.len() as u16).to_be_bytes().to_vec();
            out.extend_from_slice(&buf);
            s.write_all(&out).await.unwrap();
            s.flush().await.unwrap();
        });

        let r = TunneledResolver::plain(no_proxy(), "proton", &addr.ip().to_string(), addr.port())
            .unwrap();
        let (resp, label) = r.resolve_raw(vec![0xab, 0xcd, 0x01, 0x02]).await.unwrap();
        assert_eq!(resp, vec![0xab, 0xcd, 0x01, 0x02]);
        assert!(label.contains("direct fallback"), "label was {label}");
    }
}
