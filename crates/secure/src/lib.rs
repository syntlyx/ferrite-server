//! Encrypted DNS for devices: DNS over TLS (Android's "Private DNS") and DNS
//! over HTTPS (iOS profiles, browsers), each able to carry a client ID — the
//! device's own name, `pixel.dns.example.com` or `/dns-query/pixel` — which
//! then picks its profile and files its queries, wherever it connects from.
//!
//! One TLS setup serves both: after the handshake the negotiated protocol
//! (ALPN) decides — `h2`/`http/1.1` is DNS over HTTPS, anything else DNS over
//! TLS — and a client that names none gets what its port is for.
//!
//! The certificate comes from Let's Encrypt, which ferrite asks itself and
//! renews (see [`acme`]), or from files kept elsewhere; either way it is
//! swapped in place, without closing a listener.
//!
//! A port Tunnels already listens on (443, usually) is shared rather than
//! fought over: Tunnels reads the name a connection asks for and hands the
//! ones for our name here ([`SecureDns::claims`], [`SecureDns::take`]).

mod acme;
mod cert;
mod cloudflare;
mod doh;
mod dot;
mod gate;
mod profile;
mod rewind;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use arc_swap::ArcSwapOption;
use parking_lot::Mutex;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls;

use ferrite_core::config::{AcmeConfig, CertSource, SecureDnsConfig};
use ferrite_dns::ctx::DnsCtx;

pub use cert::CertInfo;
pub use gate::TurnedAway;

/// A handshake that hasn't finished in this long is dropped.
const HANDSHAKE: Duration = Duration::from_secs(10);
/// How often certificate files kept elsewhere are checked for a renewal.
const CERT_CHECK: Duration = Duration::from_secs(600);
/// How often a Let's Encrypt certificate is looked at, at the most.
const RENEW_CHECK: Duration = Duration::from_secs(12 * 3600);
/// Encrypted connections open at once, across all listeners.
const MAX_CONNECTIONS: usize = 1024;
/// How long a link to a device's profile works.
const PROFILE_LINK: Duration = Duration::from_secs(15 * 60);

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
    /// Comes in through Tunnels' listener on the same port.
    pub dot_shared: bool,
    pub doh_shared: bool,
    pub cert: Option<CertInfo>,
    /// The certificate works, but not for everything: a name it doesn't cover.
    pub cert_warning: Option<String>,
    /// With Let's Encrypt: getting and renewing the certificate.
    pub acme: Option<AcmeStatus>,
    /// Queries from outside home that named no device of the list.
    pub turned_away: u64,
    pub last_turned_away: Option<TurnedAway>,
}

/// Where getting the certificate from Let's Encrypt stands.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AcmeStatus {
    /// `working`, `ok` or `error`.
    pub state: &'static str,
    /// What it is doing while `working`.
    pub step: Option<&'static str>,
    pub error: Option<String>,
    /// Unix seconds: the next attempt after an error, or when renewal is due.
    pub next: Option<i64>,
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

/// Is a connection asking for `sni` one for `hostname` — itself or a name
/// under it?
fn is_ours(sni: &str, hostname: &str) -> bool {
    let sni = sni.trim_end_matches('.').to_ascii_lowercase();
    sni == hostname
        || sni
            .strip_suffix(hostname)
            .is_some_and(|front| front.ends_with('.'))
}

pub(crate) fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// What serving one connection takes, wherever it was accepted.
struct Serving {
    acceptor: TlsAcceptor,
    hostname: String,
    ctx: Arc<DnsCtx>,
    connections: Arc<Semaphore>,
    gate: Arc<gate::Gate>,
}

/// A port shared with Tunnels.
struct Shared {
    serving: Arc<Serving>,
    default: Default_,
}

/// What to renew, started once the listeners are up.
struct Renewal {
    hostname: String,
    acme: AcmeConfig,
    dir: PathBuf,
}

/// The encrypted listeners; [`SecureDns::apply`] brings them in line with the
/// config.
pub struct SecureDns {
    /// Where Let's Encrypt certificates and the account are kept.
    dir: PathBuf,
    certs: Arc<cert::CertStore>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    status: Mutex<SecureDnsStatus>,
    apply_lock: tokio::sync::Mutex<()>,
    shared: ArcSwapOption<Shared>,
    /// Pinged to ask Let's Encrypt again right away.
    retry: Notify,
    gate: Arc<gate::Gate>,
    /// What runs now, with the Tunnels port it shares — a change to the
    /// device list alone needn't touch the listeners.
    applied: Mutex<Option<(SecureDnsConfig, Option<u16>)>>,
    /// Profile links handed out: token → (device, made at).
    links: Mutex<HashMap<String, (String, Instant)>>,
}

impl SecureDns {
    /// `dir` keeps what Let's Encrypt hands out.
    pub fn new(dir: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            dir,
            certs: Arc::new(cert::CertStore::default()),
            tasks: Mutex::new(Vec::new()),
            status: Mutex::new(SecureDnsStatus::default()),
            apply_lock: tokio::sync::Mutex::new(()),
            shared: ArcSwapOption::empty(),
            retry: Notify::new(),
            gate: Arc::new(gate::Gate::default()),
            applied: Mutex::new(None),
            links: Mutex::new(HashMap::new()),
        })
    }

    pub fn status(&self) -> SecureDnsStatus {
        let mut status = self.status.lock().clone();
        (status.turned_away, status.last_turned_away) = self.gate.turned_away();
        status
    }

    /// A link that hands out `device`'s profile for a while, to whoever has
    /// it: the profile is opened by the device's own browser, which carries
    /// no panel credentials.
    pub fn profile_link(&self, device: &str) -> String {
        let mut bytes = [0u8; 16];
        let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes);
        let token = hex::encode(bytes);
        let mut links = self.links.lock();
        links.retain(|_, (_, made)| made.elapsed() < PROFILE_LINK);
        links.insert(token.clone(), (device.to_string(), Instant::now()));
        token
    }

    /// The device a profile link is for, while it works.
    pub fn redeem(&self, token: &str) -> Option<String> {
        let links = self.links.lock();
        links
            .get(token)
            .filter(|(_, made)| made.elapsed() < PROFILE_LINK)
            .map(|(device, _)| device.clone())
    }

    /// The `.mobileconfig` for `device` under `cfg`; `None` when no protocol
    /// an Apple device can use is on.
    pub fn profile(cfg: &SecureDnsConfig, device: &str) -> Option<String> {
        profile::mobileconfig(&cfg.hostname, device, cfg.doh_port, cfg.dot_port)
    }

    /// Ask Let's Encrypt again now rather than at the next try.
    pub fn retry_now(&self) {
        self.retry.notify_one();
    }

    /// Stop what runs and start what `cfg` asks for. `tunnels_port` is the
    /// port Tunnels listens on, when it does: that one is shared, not bound.
    pub async fn apply(
        self: &Arc<Self>,
        cfg: &SecureDnsConfig,
        ctx: Arc<DnsCtx>,
        tunnels_port: Option<u16>,
    ) {
        let _guard = self.apply_lock.lock().await;
        self.gate.set_devices(&cfg.devices);
        self.gate.set_proxies(&cfg.proxies);
        // Only the device or proxy list (or self-setup) changed, and what
        // runs is fine: nothing to restart. Anything that failed gets
        // another go.
        let key = (
            SecureDnsConfig {
                devices: Vec::new(),
                proxies: Vec::new(),
                self_setup: Default::default(),
                ..cfg.clone()
            },
            tunnels_port,
        );
        let healthy = {
            let st = self.status.lock();
            st.error.is_none() && st.dot_error.is_none() && st.doh_error.is_none()
        };
        if healthy && self.applied.lock().as_ref() == Some(&key) {
            return;
        }
        *self.applied.lock() = Some(key);
        // Taken out first: the lock mustn't be held across the awaits below.
        let running = std::mem::take(&mut *self.tasks.lock());
        for task in running {
            task.abort();
            let _ = task.await;
        }
        self.shared.store(None);
        let mut status = SecureDnsStatus::default();
        let mut renewal = None;
        if cfg.enabled {
            match self.start(cfg, ctx, tunnels_port, &mut status).await {
                Ok(r) => {
                    status.running = status.dot || status.doh;
                    renewal = r;
                }
                Err(e) => {
                    tracing::warn!("secure dns: not started — {e}");
                    status.error = Some(e);
                }
            }
        } else {
            self.certs.clear();
        }
        *self.status.lock() = status;
        if let Some(r) = renewal {
            let task = tokio::spawn(Arc::clone(self).renew(r));
            self.tasks.lock().push(task);
        }
    }

    async fn start(
        self: &Arc<Self>,
        cfg: &SecureDnsConfig,
        ctx: Arc<DnsCtx>,
        tunnels_port: Option<u16>,
        status: &mut SecureDnsStatus,
    ) -> Result<Option<Renewal>, String> {
        let hostname = cfg
            .hostname
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if hostname.is_empty() {
            return Err("set the name devices connect to".into());
        }

        let mut tasks = Vec::new();
        let mut renewal = None;
        match cfg.certificate {
            CertSource::Files => {
                let (Some(cert_file), Some(key_file)) =
                    (cfg.cert_file.clone(), cfg.key_file.clone())
                else {
                    return Err("set the certificate and its key".into());
                };
                let (key, info) = cert::load(&cert_file, &key_file)?;
                status.cert_warning = coverage_warning(&info, &hostname);
                status.cert = Some(info);
                self.certs.set(key);
                tasks.push(tokio::spawn(
                    Arc::clone(self).watch_cert(cert_file, key_file),
                ));
            }
            CertSource::Letsencrypt => {
                if cfg
                    .acme
                    .cloudflare_token
                    .as_deref()
                    .is_none_or(|t| t.trim().is_empty())
                {
                    return Err("set a Cloudflare API token for Let's Encrypt".into());
                }
                let dir = if cfg.acme.staging {
                    self.dir.join("staging")
                } else {
                    self.dir.clone()
                };
                let (cert_file, key_file) = acme::files(&dir, &hostname);
                match cert::load(&cert_file, &key_file) {
                    Ok((key, info)) => {
                        self.certs.set(key);
                        status.cert = Some(info);
                    }
                    // Not got yet: handshakes fail until it is.
                    Err(_) => self.certs.clear(),
                }
                status.acme = Some(AcmeStatus {
                    state: "working",
                    ..AcmeStatus::default()
                });
                renewal = Some(Renewal {
                    hostname: hostname.clone(),
                    acme: cfg.acme.clone(),
                    dir,
                });
            }
        }

        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS setup failed: {e}"))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::clone(&self.certs) as Arc<dyn rustls::server::ResolvesServerCert>);
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"dot".to_vec()];
        let serving = Arc::new(Serving {
            acceptor: TlsAcceptor::from(Arc::new(tls)),
            hostname: hostname.clone(),
            ctx,
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            gate: Arc::clone(&self.gate),
        });

        let mut ports: Vec<(u16, Default_)> = Vec::new();
        if cfg.dot_port != 0 {
            ports.push((cfg.dot_port, Default_::Tls));
        }
        if cfg.doh_port != 0 && cfg.doh_port != cfg.dot_port {
            ports.push((cfg.doh_port, Default_::Https));
        }
        // One port serving both protocols: whatever comes of it, comes of both.
        let both = cfg.doh_port == cfg.dot_port;
        for (port, default) in ports {
            let mark =
                |status: &mut SecureDnsStatus, up: bool, shared: bool, err: Option<String>| {
                    if default == Default_::Tls || both {
                        status.dot = up;
                        status.dot_shared = shared;
                        status.dot_error = err.clone();
                    }
                    if default == Default_::Https || both {
                        status.doh = up;
                        status.doh_shared = shared;
                        status.doh_error = err;
                    }
                };
            if tunnels_port == Some(port) {
                tracing::info!("secure dns: sharing :{port} with Tunnels as {hostname}");
                self.shared.store(Some(Arc::new(Shared {
                    serving: Arc::clone(&serving),
                    default,
                })));
                mark(status, true, true, None);
                continue;
            }
            match bind(port).await {
                Ok(listener) => {
                    tracing::info!(
                        "secure dns: {} on :{port} as {hostname}",
                        if default == Default_::Tls {
                            "DNS over TLS"
                        } else {
                            "DNS over HTTPS"
                        }
                    );
                    mark(status, true, false, None);
                    tasks.push(tokio::spawn(accept_loop(
                        listener,
                        Arc::clone(&serving),
                        default,
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
                    mark(status, false, false, Some(msg));
                }
            }
        }
        *self.tasks.lock() = tasks;
        Ok(renewal)
    }

    /// Whether a TLS connection asking for `sni` is ours. Asked by Tunnels'
    /// listener for every connection on the port it shares with us.
    pub fn claims(&self, sni: &str) -> bool {
        self.shared
            .load()
            .as_ref()
            .is_some_and(|s| is_ours(sni, &s.serving.hostname))
    }

    /// Whether a TLS connection that names no host is ours: one from a
    /// trusted proxy, which by default doesn't name the box it passes a
    /// request on to (nginx, and so Nginx Proxy Manager).
    pub fn claims_unnamed(&self, peer: SocketAddr) -> bool {
        self.shared.load().is_some() && self.gate.trusts(peer.ip())
    }

    /// Serve a connection Tunnels' listener accepted; `peeked` is what it
    /// already read of it.
    pub async fn take(&self, stream: TcpStream, peeked: Vec<u8>, peer: SocketAddr) {
        let Some(shared) = self.shared.load_full() else {
            return;
        };
        let Ok(slot) = Arc::clone(&shared.serving.connections).try_acquire_owned() else {
            return;
        };
        let _ = stream.set_nodelay(true);
        serve(
            rewind::Rewind::new(peeked, stream),
            peer,
            &shared.serving,
            shared.default,
        )
        .await;
        drop(slot);
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

    fn set_acme(&self, acme: AcmeStatus) {
        self.status.lock().acme = Some(acme);
    }

    /// Get the certificate from Let's Encrypt when there is none for the name
    /// or it is due, and look again when it next could be.
    async fn renew(self: Arc<Self>, r: Renewal) {
        let wildcard = format!("x.{}", r.hostname);
        let mut failures: u32 = 0;
        loop {
            let now = unix_now();
            let current = self.status.lock().cert.clone();
            let wait = match current {
                Some(c) if c.covers(&r.hostname) && c.covers(&wildcard) && !c.due(now) => {
                    failures = 0;
                    let due = c.not_after - (c.not_after - c.not_before).max(0) / 3;
                    self.set_acme(AcmeStatus {
                        state: "ok",
                        next: Some(due),
                        ..AcmeStatus::default()
                    });
                    Duration::from_secs((due - now).max(60) as u64).min(RENEW_CHECK)
                }
                _ => {
                    self.set_acme(AcmeStatus {
                        state: "working",
                        ..AcmeStatus::default()
                    });
                    let me = Arc::clone(&self);
                    let step = move |s: &'static str| {
                        if let Some(a) = me.status.lock().acme.as_mut() {
                            a.step = Some(s);
                        }
                    };
                    tracing::info!("secure dns: asking Let's Encrypt for {}", r.hostname);
                    let issued = acme::issue(&r.dir, &r.hostname, &r.acme, &step).await;
                    let (cert_file, key_file) = acme::files(&r.dir, &r.hostname);
                    match issued.and_then(|()| cert::load(&cert_file, &key_file)) {
                        Ok((key, info)) => {
                            tracing::info!(
                                "secure dns: certificate for {} from Let's Encrypt",
                                r.hostname
                            );
                            self.certs.set(key);
                            let mut st = self.status.lock();
                            st.cert_warning = None;
                            st.cert = Some(info);
                            continue; // the loop above says when to renew
                        }
                        Err(e) => {
                            failures += 1;
                            // Let's Encrypt allows a few failures an hour for
                            // a name; back off well inside that.
                            let backoff = Duration::from_secs(15 * 60)
                                .saturating_mul(2u32.saturating_pow(failures - 1))
                                .min(RENEW_CHECK);
                            tracing::warn!(
                                "secure dns: no certificate from Let's Encrypt — {e}; trying again in {} min",
                                backoff.as_secs() / 60
                            );
                            self.set_acme(AcmeStatus {
                                state: "error",
                                error: Some(e),
                                next: Some(now + backoff.as_secs() as i64),
                                ..AcmeStatus::default()
                            });
                            backoff
                        }
                    }
                }
            };
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = self.retry.notified() => {}
            }
        }
    }
}

/// The certificate works but leaves a name out.
fn coverage_warning(info: &CertInfo, hostname: &str) -> Option<String> {
    if !info.covers(hostname) {
        Some(format!("the certificate isn't for {hostname}"))
    } else if !info.covers(&format!("x.{hostname}")) {
        Some(format!(
            "the certificate has no *.{hostname} — client IDs work over HTTPS only"
        ))
    } else {
        None
    }
}

async fn bind_once(port: u16) -> std::io::Result<TcpListener> {
    match TcpListener::bind(SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port))).await {
        Ok(l) => Ok(l),
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => Err(e),
        Err(_) => TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port))).await,
    }
}

/// A port Tunnels (or the previous setup) is letting go of may take a moment
/// to come free.
async fn bind(port: u16) -> std::io::Result<TcpListener> {
    let mut tries = 0;
    loop {
        match bind_once(port).await {
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse && tries < 12 => {
                tries += 1;
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            other => return other,
        }
    }
}

async fn accept_loop(listener: TcpListener, serving: Arc<Serving>, default: Default_) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!("secure dns: accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(slot) = Arc::clone(&serving.connections).try_acquire_owned() else {
            continue; // full: drop the connection
        };
        let _ = stream.set_nodelay(true);
        let serving = Arc::clone(&serving);
        tokio::spawn(async move {
            serve(stream, peer, &serving, default).await;
            drop(slot);
        });
    }
}

/// The handshake, then DNS over HTTPS or over TLS as it negotiated.
async fn serve<S>(stream: S, peer: SocketAddr, serving: &Serving, default: Default_)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let peer = SocketAddr::new(ferrite_core::net::unmap_v4(peer.ip()), peer.port());
    let tls = match tokio::time::timeout(HANDSHAKE, serving.acceptor.accept(stream)).await {
        Ok(Ok(tls)) => tls,
        _ => return,
    };
    let (sni_id, alpn) = {
        let (_, conn) = tls.get_ref();
        (
            conn.server_name()
                .and_then(|s| client_id_from_sni(s, &serving.hostname)),
            conn.alpn_protocol().map(<[u8]>::to_vec),
        )
    };
    let https = match alpn.as_deref() {
        Some(b"h2") | Some(b"http/1.1") => true,
        Some(_) => false,
        None => default == Default_::Https,
    };
    let (ctx, gate) = (Arc::clone(&serving.ctx), Arc::clone(&serving.gate));
    if https {
        doh::serve(tls, peer, sni_id, ctx, gate).await;
    } else {
        dot::serve(tls, peer, sni_id, ctx, gate).await;
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

    #[test]
    fn only_our_name_and_names_under_it_are_ours() {
        let h = "dns.example.com";
        assert!(is_ours("dns.example.com", h));
        assert!(is_ours("Pixel.dns.example.com.", h));
        assert!(is_ours("a.b.dns.example.com", h));
        assert!(!is_ours("xdns.example.com", h));
        assert!(!is_ours("example.com", h));
        assert!(!is_ours("www.youtube.com", h));
    }
}
