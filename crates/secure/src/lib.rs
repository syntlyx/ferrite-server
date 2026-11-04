//! Encrypted DNS for devices: DNS over TLS (Android's "Private DNS") and DNS
//! over HTTPS (iOS profiles, browsers), each able to carry a client ID — the
//! device's own name, `pixel.dns.example.com` or `/dns-query/pixel` — which
//! then picks its profile and files its queries, wherever it connects from.
//!
//! One TLS setup serves both: after the handshake the negotiated protocol
//! (ALPN) decides — `h2`/`http/1.1` is DNS over HTTPS, anything else DNS over
//! TLS — and a client that names none gets what its port is for. The
//! certificate is read from files and swapped in place when they change.

mod cert;
mod doh;
mod dot;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use parking_lot::Mutex;
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls;

use ferrite_core::config::SecureDnsConfig;
use ferrite_dns::ctx::DnsCtx;

pub use cert::CertInfo;

/// A handshake that hasn't finished in this long is dropped.
const HANDSHAKE: Duration = Duration::from_secs(10);
/// How often the certificate files are checked for a renewal.
const CERT_CHECK: Duration = Duration::from_secs(600);
/// Encrypted connections open at once, across both listeners.
const MAX_CONNECTIONS: usize = 1024;

/// What the encrypted listeners are doing — the panel's status line.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SecureDnsStatus {
    pub running: bool,
    /// Why nothing runs though switched on.
    pub error: Option<String>,
    pub dot: bool,
    pub doh: bool,
    pub dot_error: Option<String>,
    pub doh_error: Option<String>,
    pub cert: Option<CertInfo>,
    /// The certificate works, but not for everything: a name it doesn't cover.
    pub cert_warning: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Default_ {
    Tls,
    Https,
}

/// The client ID in a TLS name: the one label in front of `hostname`.
pub fn client_id_from_sni(sni: &str, hostname: &str) -> Option<String> {
    let sni = sni.trim_end_matches('.').to_ascii_lowercase();
    let label = sni.strip_suffix(hostname)?.strip_suffix('.')?;
    if label.contains('.') {
        return None;
    }
    ferrite_core::net::normalize_client_id(label)
}

/// The encrypted listeners; [`SecureDns::apply`] brings them in line with the
/// config.
pub struct SecureDns {
    certs: Arc<cert::CertStore>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    status: Mutex<SecureDnsStatus>,
    apply_lock: tokio::sync::Mutex<()>,
}

impl SecureDns {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            certs: Arc::new(cert::CertStore::default()),
            tasks: Mutex::new(Vec::new()),
            status: Mutex::new(SecureDnsStatus::default()),
            apply_lock: tokio::sync::Mutex::new(()),
        })
    }

    pub fn status(&self) -> SecureDnsStatus {
        self.status.lock().clone()
    }

    /// Stop what runs and start what `cfg` asks for.
    pub async fn apply(self: &Arc<Self>, cfg: &SecureDnsConfig, ctx: Arc<DnsCtx>) {
        let _guard = self.apply_lock.lock().await;
        // Taken out first: the lock mustn't be held across the awaits below.
        let running = std::mem::take(&mut *self.tasks.lock());
        for task in running {
            task.abort();
            let _ = task.await;
        }
        let mut status = SecureDnsStatus::default();
        if cfg.enabled {
            match self.start(cfg, ctx, &mut status).await {
                Ok(()) => status.running = status.dot || status.doh,
                Err(e) => {
                    tracing::warn!("secure dns: not started — {e}");
                    status.error = Some(e);
                }
            }
        }
        *self.status.lock() = status;
    }

    async fn start(
        self: &Arc<Self>,
        cfg: &SecureDnsConfig,
        ctx: Arc<DnsCtx>,
        status: &mut SecureDnsStatus,
    ) -> Result<(), String> {
        let hostname = cfg
            .hostname
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if hostname.is_empty() {
            return Err("set the name devices connect to".into());
        }
        let (Some(cert_file), Some(key_file)) = (cfg.cert_file.clone(), cfg.key_file.clone())
        else {
            return Err("set the certificate and its key".into());
        };
        let (key, info) = cert::load(&cert_file, &key_file)?;
        status.cert_warning = if !info.covers(&hostname) {
            Some(format!("the certificate isn't for {hostname}"))
        } else if !info.covers(&format!("x.{hostname}")) {
            Some(format!(
                "the certificate has no *.{hostname} — client IDs work over HTTPS only"
            ))
        } else {
            None
        };
        status.cert = Some(info);
        self.certs.set(key);

        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS setup failed: {e}"))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::clone(&self.certs) as Arc<dyn rustls::server::ResolvesServerCert>);
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"dot".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(tls));
        let connections = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));

        let mut tasks = Vec::new();
        let mut ports: Vec<(u16, Default_)> = Vec::new();
        if cfg.dot_port != 0 {
            ports.push((cfg.dot_port, Default_::Tls));
        }
        if cfg.doh_port != 0 && cfg.doh_port != cfg.dot_port {
            ports.push((cfg.doh_port, Default_::Https));
        }
        for (port, default) in ports {
            match bind(port).await {
                Ok(listener) => {
                    match default {
                        Default_::Tls => status.dot = true,
                        Default_::Https => status.doh = true,
                    }
                    // One port serving both protocols: both are up.
                    if cfg.doh_port == cfg.dot_port {
                        status.doh = true;
                    }
                    tracing::info!(
                        "secure dns: {} on :{port} as {hostname}",
                        if default == Default_::Tls {
                            "DNS over TLS"
                        } else {
                            "DNS over HTTPS"
                        }
                    );
                    tasks.push(tokio::spawn(accept_loop(
                        listener,
                        acceptor.clone(),
                        default,
                        hostname.clone(),
                        Arc::clone(&ctx),
                        Arc::clone(&connections),
                    )));
                }
                Err(e) => {
                    let msg = match e.kind() {
                        std::io::ErrorKind::AddrInUse => format!("port {port} is taken"),
                        std::io::ErrorKind::PermissionDenied => {
                            format!("no permission for port {port}")
                        }
                        _ => format!("couldn't open port {port}: {e}"),
                    };
                    match default {
                        Default_::Tls => status.dot_error = Some(msg),
                        Default_::Https => status.doh_error = Some(msg),
                    }
                }
            }
        }
        tasks.push(tokio::spawn(
            Arc::clone(self).watch_cert(cert_file, key_file),
        ));
        *self.tasks.lock() = tasks;
        Ok(())
    }

    /// Swap in a renewed certificate when its files change.
    async fn watch_cert(self: Arc<Self>, cert_file: PathBuf, key_file: PathBuf) {
        let stamp = |p: &PathBuf| std::fs::metadata(p).and_then(|m| m.modified()).ok();
        let mut seen: (Option<SystemTime>, Option<SystemTime>) =
            (stamp(&cert_file), stamp(&key_file));
        loop {
            tokio::time::sleep(CERT_CHECK).await;
            let now = (stamp(&cert_file), stamp(&key_file));
            if now == seen {
                continue;
            }
            seen = now;
            match cert::load(&cert_file, &key_file) {
                Ok((key, info)) => {
                    tracing::info!("secure dns: certificate reloaded");
                    self.certs.set(key);
                    self.status.lock().cert = Some(info);
                }
                Err(e) => tracing::warn!("secure dns: renewed certificate not loaded — {e}"),
            }
        }
    }
}

async fn bind(port: u16) -> std::io::Result<TcpListener> {
    match TcpListener::bind(SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port))).await {
        Ok(l) => Ok(l),
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => Err(e),
        Err(_) => TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port))).await,
    }
}

async fn accept_loop(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    default: Default_,
    hostname: String,
    ctx: Arc<DnsCtx>,
    connections: Arc<tokio::sync::Semaphore>,
) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!("secure dns: accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(slot) = Arc::clone(&connections).try_acquire_owned() else {
            continue; // full: drop the connection
        };
        let _ = stream.set_nodelay(true);
        let (acceptor, hostname, ctx) = (acceptor.clone(), hostname.clone(), Arc::clone(&ctx));
        tokio::spawn(async move {
            let peer = SocketAddr::new(ferrite_core::net::unmap_v4(peer.ip()), peer.port());
            let tls = match tokio::time::timeout(HANDSHAKE, acceptor.accept(stream)).await {
                Ok(Ok(tls)) => tls,
                _ => return,
            };
            let (sni_id, alpn) = {
                let (_, conn) = tls.get_ref();
                (
                    conn.server_name()
                        .and_then(|s| client_id_from_sni(s, &hostname)),
                    conn.alpn_protocol().map(<[u8]>::to_vec),
                )
            };
            let https = match alpn.as_deref() {
                Some(b"h2") | Some(b"http/1.1") => true,
                Some(_) => false,
                None => default == Default_::Https,
            };
            if https {
                doh::serve(tls, peer, sni_id, ctx).await;
            } else {
                dot::serve(tls, peer, sni_id, ctx).await;
            }
            drop(slot);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_ids_come_from_the_label_in_front() {
        let h = "dns.example.com";
        assert_eq!(
            client_id_from_sni("pixel.dns.example.com", h).as_deref(),
            Some("pixel")
        );
        assert_eq!(
            client_id_from_sni("Pixel.DNS.example.com.", h).as_deref(),
            Some("pixel")
        );
        assert_eq!(client_id_from_sni("dns.example.com", h), None);
        assert_eq!(client_id_from_sni("a.b.dns.example.com", h), None);
        assert_eq!(client_id_from_sni("xdns.example.com", h), None);
        assert_eq!(client_id_from_sni("other.com", h), None);
    }
}
