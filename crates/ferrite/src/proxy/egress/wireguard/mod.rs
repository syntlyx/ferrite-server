//! Userspace WireGuard egress: boringtun (protocol) + smoltcp (TCP/IP) over a
//! plain UDP socket — no TUN device, no root, fully in-process.
//!
//! Architecture (design A, channel-bridged; mirrors `onetun`):
//! a single supervised task owns the boringtun `Tunn`, the smoltcp `Interface`/
//! `SocketSet`, the packet-shuttling [`device::WgDevice`], and the UDP socket.
//! `connect()` asks that task (via `Ctrl::Open`) to open a virtual TCP socket and
//! hands back one end of a `tokio::io::duplex` pipe; a small per-connection bridge
//! task moves bytes between that pipe and the loop's mpsc channels. The loop
//! itself never does async per-connection I/O and never holds a lock across an
//! `.await` (freeze-safety).
//!
//! Both the traffic *and* the DNS lookup for a routed domain go through the
//! tunnel: [`WgEgress::connect`] resolves hostnames by querying the `.conf`'s DNS
//! server over the tunnel (DNS-over-TCP), so the lookup neither leaks to the
//! local resolver nor geo-mismatches the exit (a CDN sees the VPN's location).
//! Literal-IP destinations skip resolution; if the `.conf` set no DNS we fall
//! back to ferrite's upstream. Resolutions are cached per egress by DNS TTL.

mod conf;
mod device;

use conf::WgConf;
pub use conf::parse;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use parking_lot::Mutex;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, mpsc, oneshot};
use tokio::time::timeout;

use crate::config::EgressConfig;
use crate::error::{FeriteError, Result};
use crate::upstream::ZoneRouter;

use device::WgDevice;

/// Default inner MTU (WireGuard's standard for a 1500 path MTU).
const DEFAULT_MTU: usize = 1420;
/// Per-connection smoltcp ring sizes (RAM: 2×16 KiB per active connection).
/// Default per-connection socket buffer (KiB) when the egress sets none. The TCP
/// window scales with this (smoltcp supports RFC 1323), so it bounds single-
/// connection throughput — roughly buffer / RTT.
const DEFAULT_BUFFER_KB: u32 = 256;
/// Clamp for a configured buffer (KiB): below ~16 TCP barely flows; the upper
/// bound caps worst-case RAM (buffer × 2 × active connections).
const MIN_BUFFER_KB: u32 = 16;
const MAX_BUFFER_KB: u32 = 16 * 1024;
/// In-memory pipe capacity between the caller stream and its bridge task.
const DUPLEX_CAP: usize = 64 * 1024;
/// Bounded staging depth (chunks) for the caller→peer direction, per connection.
/// This is what makes uploads apply backpressure: the bridge blocks on a full
/// channel, so a client that writes faster than the tunnel drains is throttled at
/// its own socket instead of the loop buffering the difference without limit.
const CALLER_QUEUE: usize = 16;
/// How long a virtual TCP connect may take to reach ESTABLISHED before it is
/// reported as failed. Without this a connect to a dead host behind a healthy
/// tunnel would hang until the splice's idle timeout instead of failing fast (and
/// the circuit breaker would never see it).
const WG_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// smoltcp per-socket timeout: abort a connection whose peer stops responding for
/// this long. Bounds how long a stalled upload (peer not draining the TX ring)
/// can pin a socket + its bridge before the connection is reaped.
const SOCKET_TIMEOUT: Duration = Duration::from_secs(60);
/// Tunnel supervision backoff bounds: after the tunnel task exits (endpoint
/// unresolvable at boot, bind failure, or a stalled handshake) it is retried,
/// starting at `INITIAL_BACKOFF` and doubling up to `MAX_BACKOFF`.
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// A run that stayed up at least this long resets the backoff to the initial value
/// (so an occasional drop doesn't slow reconnects, but a crash-loop still backs off).
const STABLE_RUN: Duration = Duration::from_secs(60);
/// If the handshake hasn't (re)completed within this window the tunnel task exits
/// so the supervisor re-resolves the endpoint and rebuilds it — this is how a
/// moved endpoint (DDNS) or a boot-time "network not up yet" recovers on its own.
const REVIVE_AFTER: Duration = Duration::from_secs(120);
/// boringtun timer cadence (rekey, keepalive, retransmit).
const TIMER_TICK: Duration = Duration::from_millis(250);
/// Max inbound datagrams drained per wake before yielding to the other select
/// branches — high enough to swallow a large-window burst, capped so a sustained
/// stream can't starve ctrl/timer handling.
const UDP_DRAIN_BURST: usize = 1024;
/// WireGuard's REJECT_AFTER_TIME: a session older than this is dead. We treat the
/// tunnel as healthy only while the last handshake is still inside this window.
const SESSION_MAX_AGE: Duration = Duration::from_secs(180);
/// Proactively initiate a fresh handshake once the session is this old. WireGuard
/// only rekeys when real data flows — keepalives keep the NAT binding alive but
/// do NOT renew the session — so an *idle* tunnel's session would age past
/// [`SESSION_MAX_AGE`], flip health down, and fail-closed rules would then drop
/// the very traffic that could revive it. Renewing early keeps an idle tunnel
/// permanently warm; the 30s margin absorbs several REKEY_TIMEOUT (5s) retries
/// before the old session actually expires.
const REHANDSHAKE_AFTER: Duration = Duration::from_secs(150);
/// Keepalive (seconds) applied when the `.conf` omits `PersistentKeepalive`, so an
/// idle always-on tunnel never silently expires. Explicit `0` (off) is respected.
const DEFAULT_KEEPALIVE: u16 = 25;
/// Scratch buffer for encrypt/decrypt (inner MTU + WireGuard overhead headroom).
const CRYPT_BUF: usize = DEFAULT_MTU + 148;
/// Timeout for a single tunnel-DNS lookup (connect + query round-trip).
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
/// Clamp DNS-provided TTLs into a sane caching window.
const DNS_MIN_TTL: Duration = Duration::from_secs(30);
const DNS_MAX_TTL: Duration = Duration::from_secs(3600);
/// Soft cap on the per-egress resolution cache (bounds memory; evicts expired).
const DNS_CACHE_CAP: usize = 1024;

/// A WireGuard egress backend. Cheap handle; the tunnel runs in its own task.
pub struct WgEgress {
    id: String,
    ctrl: mpsc::Sender<Ctrl>,
    /// Fallback resolver used only when the `.conf` configured no DNS server.
    upstream: Arc<ZoneRouter>,
    healthy: Arc<AtomicBool>,
    /// Unix seconds of the last successful handshake (0 = never), refreshed by
    /// the tunnel loop alongside `healthy`. Diagnostic only.
    last_handshake: Arc<AtomicU64>,
    /// DNS servers from the `.conf`, queried *through* the tunnel.
    dns: Vec<IpAddr>,
    /// Per-egress resolution cache (host → IP), expired by DNS TTL.
    cache: DnsCache,
}

/// A small bounded TTL cache for tunnel DNS resolutions, holding both positive
/// answers and negative (NXDOMAIN / "no address") results so a name that doesn't
/// resolve isn't re-queried on every connection. Evicts expired entries on insert,
/// and hard-evicts the soonest-to-expire entry when full of live ones so it can't
/// grow past its cap. Locks are never held across an `.await`.
#[derive(Default)]
struct DnsCache {
    map: Mutex<HashMap<String, CacheEntry>>,
}

struct CacheEntry {
    /// `Some(ip)` for a resolved name; `None` for a cached negative result.
    result: Option<IpAddr>,
    expires: Instant,
}

/// The outcome of a cache lookup.
enum Cached {
    /// A live positive answer.
    Hit(IpAddr),
    /// A live negative answer (the name is known not to resolve).
    Negative,
    /// Not cached (or expired).
    Miss,
}

impl DnsCache {
    fn get(&self, key: &str) -> Cached {
        let mut map = self.map.lock();
        match map.get(key) {
            Some(e) if e.expires > Instant::now() => match e.result {
                Some(ip) => Cached::Hit(ip),
                None => Cached::Negative,
            },
            Some(_) => {
                map.remove(key);
                Cached::Miss
            }
            None => Cached::Miss,
        }
    }

    fn put(&self, key: &str, result: Option<IpAddr>, ttl: Duration) {
        let mut map = self.map.lock();
        if map.len() >= DNS_CACHE_CAP {
            let now = Instant::now();
            map.retain(|_, e| e.expires > now);
            // Still full of live entries → drop the one expiring soonest so the map
            // is strictly bounded even under a flood of fresh names (e.g. a wildcard
            // rule fronting many subdomains).
            while map.len() >= DNS_CACHE_CAP {
                if let Some(oldest) = map
                    .iter()
                    .min_by_key(|(_, e)| e.expires)
                    .map(|(k, _)| k.clone())
                {
                    map.remove(&oldest);
                } else {
                    break;
                }
            }
        }
        map.insert(
            key.to_string(),
            CacheEntry {
                result,
                expires: Instant::now() + ttl,
            },
        );
    }
}

enum Ctrl {
    /// Open a virtual TCP connection to `remote`; `io` is the loop's end of the
    /// caller pipe. The reply is deferred until the virtual socket reaches
    /// ESTABLISHED (Ok) or fails (Err, already classified egress vs destination).
    Open {
        remote: SocketAddr,
        io: DuplexStream,
        reply: oneshot::Sender<std::result::Result<(), super::ConnectError>>,
    },
}

/// Per-connection smoltcp socket ring sizes (bytes), allocated up-front for
/// every virtual TCP connection. RX bounds the download window, TX the upload
/// window — split so the (rarely-saturated) upload side doesn't have to pay
/// for a download-sized ring.
#[derive(Clone, Copy)]
struct SockBuffers {
    rx: usize,
    tx: usize,
}

impl WgEgress {
    /// Parse `cfg.config` and spawn the tunnel task. Must be called within a
    /// tokio runtime (it is — egresses are built at app init / API reload).
    pub fn from_config(cfg: &EgressConfig, upstream: Arc<ZoneRouter>) -> Result<Self> {
        let text = cfg
            .config
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| {
                FeriteError::Config(format!(
                    "wireguard egress '{}' requires a `config` (.conf text)",
                    cfg.id
                ))
            })?;
        let conf = parse(text)?;
        let dns = conf.dns.clone();
        // Per-connection socket buffers (bytes), clamped; RX drives the download
        // TCP window. TX defaults to half of RX: both rings are allocated
        // up-front per connection and tunnel traffic is download-dominant, so a
        // symmetric TX ring would mostly be dead weight.
        let rx_kb = cfg
            .buffer_kb
            .unwrap_or(DEFAULT_BUFFER_KB)
            .clamp(MIN_BUFFER_KB, MAX_BUFFER_KB);
        let tx_kb = cfg
            .tx_buffer_kb
            .unwrap_or(rx_kb / 2)
            .clamp(MIN_BUFFER_KB, MAX_BUFFER_KB);
        let buffers = SockBuffers {
            rx: rx_kb as usize * 1024,
            tx: tx_kb as usize * 1024,
        };

        let (ctrl_tx, ctrl_rx) = mpsc::channel(64);
        let healthy = Arc::new(AtomicBool::new(false));
        let last_handshake = Arc::new(AtomicU64::new(0));
        let id = cfg.id.clone();

        let loop_healthy = Arc::clone(&healthy);
        let loop_handshake = Arc::clone(&last_handshake);
        let loop_id = id.clone();
        // NB: the supervisor holds ONLY the receiver. When this WgEgress is dropped
        // (config reload / shutdown) `ctrl_tx` goes away, the receiver closes, and
        // the supervisor returns — no orphaned tunnels. Between runs it retries with
        // backoff so a tunnel that couldn't come up at boot recovers on its own.
        tokio::spawn(supervise_tunnel(
            loop_id,
            conf,
            buffers,
            ctrl_rx,
            loop_healthy,
            loop_handshake,
        ));

        Ok(Self {
            id,
            ctrl: ctrl_tx,
            upstream,
            healthy,
            last_handshake,
            dns,
            cache: DnsCache::default(),
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    /// Seconds since the last successful handshake, `None` before the first one.
    pub fn handshake_age_secs(&self) -> Option<u64> {
        match self.last_handshake.load(Ordering::Relaxed) {
            0 => None,
            at => Some(unix_now_secs().saturating_sub(at)),
        }
    }

    /// Open a tunneled TCP connection to `host:port`. Hostnames are resolved
    /// *through* the tunnel (see [`Self::resolve`]); literal IPs connect directly.
    ///
    /// A resolution failure is destination-class (the name didn't resolve — the
    /// tunnel is fine, and intrinsic health already gates a down tunnel before we
    /// get here); a failure to reach the tunnel loop is egress-class.
    pub async fn connect(
        &self,
        host: &str,
        port: u16,
    ) -> std::result::Result<DuplexStream, super::ConnectError> {
        let ip = match IpAddr::from_str(host) {
            Ok(ip) => ip,
            Err(_) => self
                .resolve(host)
                .await
                .map_err(super::ConnectError::destination)?,
        };
        self.open(SocketAddr::new(ip, port)).await
    }

    /// Ask the tunnel loop to open a virtual TCP socket to `remote` and hand back
    /// the caller's end of the bridged pipe. The loop reports the connect outcome
    /// already classified (egress vs destination); failing to even reach the loop
    /// is egress-class (the tunnel task is gone).
    async fn open(
        &self,
        remote: SocketAddr,
    ) -> std::result::Result<DuplexStream, super::ConnectError> {
        let (caller, loop_half) = tokio::io::duplex(DUPLEX_CAP);
        let (reply_tx, reply_rx) = oneshot::channel();
        self.ctrl
            .send(Ctrl::Open {
                remote,
                io: loop_half,
                reply: reply_tx,
            })
            .await
            .map_err(|_| {
                super::ConnectError::egress(FeriteError::Dns("wireguard tunnel is down".into()))
            })?;
        reply_rx.await.map_err(|_| {
            super::ConnectError::egress(FeriteError::Dns("wireguard tunnel did not respond".into()))
        })??;
        Ok(caller)
    }

    /// Resolve `host` to an IP by querying the `.conf` DNS server through the
    /// tunnel (DNS-over-TCP). Cached by TTL. Falls back to ferrite's upstream
    /// only when the `.conf` configured no DNS server.
    async fn resolve(&self, host: &str) -> Result<IpAddr> {
        let key = host.trim_end_matches('.').to_ascii_lowercase();
        match self.cache.get(&key) {
            Cached::Hit(ip) => return Ok(ip),
            Cached::Negative => {
                return Err(FeriteError::Dns(format!(
                    "{host} does not resolve (cached)"
                )));
            }
            Cached::Miss => {}
        }
        // Prefer the tunnel's DNS (no leak, geo-correct). Prefer A, then AAAA.
        if let Some(&dns) = self.dns.first() {
            for rtype in [RecordType::A, RecordType::AAAA] {
                match self.lookup(dns, host, rtype).await {
                    Ok(DnsAnswer::Found(ip, ttl)) => {
                        self.cache.put(&key, Some(ip), ttl);
                        return Ok(ip);
                    }
                    Ok(DnsAnswer::NoData) => {} // no record of this type — try the next
                    Ok(DnsAnswer::NxDomain) => {
                        // The name genuinely doesn't exist. Negative-cache it and
                        // fail fast — ferrite's upstream would only say the same, so
                        // there's no point falling back and re-hammering it.
                        self.cache.put(&key, None, DNS_MIN_TTL);
                        return Err(FeriteError::Dns(format!(
                            "{host} does not exist (NXDOMAIN)"
                        )));
                    }
                    Err(e) => {
                        // A tunnel-DNS hiccup must NOT fail the connection (that
                        // shows up as a page loading "every other time"). Fall back
                        // to ferrite's upstream; the traffic still goes through the
                        // tunnel, only the lookup didn't.
                        tracing::debug!(
                            "wg '{}': tunnel DNS for {host} failed ({e}); using upstream",
                            self.id
                        );
                        break;
                    }
                }
            }
        }
        // Fallback: resolve via ferrite's upstream (no tunnel DNS configured, it
        // hiccuped, or it returned NODATA for both A and AAAA). Cache a positive
        // answer by its short TTL, but do NOT negative-cache a *failure* here: an
        // upstream timeout/SERVFAIL is transient, and caching it would blackhole the
        // host for the whole DNS_MIN_TTL (a hard outage under fail-closed, a direct
        // leak under fail-open) off a single blip. Only an authoritative NXDOMAIN
        // from the tunnel DNS above is negative-cached.
        let ip = super::direct::resolve_host(&self.upstream, host).await?;
        self.cache.put(&key, Some(ip), DNS_MIN_TTL);
        Ok(ip)
    }

    /// One DNS-over-TCP query to `dns:53` routed through the tunnel. Classifies the
    /// reply by RCODE so the caller can negative-cache a non-existent name instead
    /// of re-querying it. No txid/anti-spoof dance is needed: the query rides an
    /// authenticated, encrypted tunnel to a fixed resolver — there is no off-path
    /// attacker to inject a forgery.
    async fn lookup(&self, dns: IpAddr, host: &str, rtype: RecordType) -> Result<DnsAnswer> {
        let name = Name::from_str(&format!("{}.", host.trim_end_matches('.')))
            .map_err(|e| FeriteError::Dns(format!("invalid host '{host}': {e}")))?;
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.add_query(Query::query(name, rtype));
        let query = msg
            .to_bytes()
            .map_err(|e| FeriteError::Dns(format!("encode dns query: {e}")))?;

        let resp = timeout(DNS_TIMEOUT, async {
            let mut s = self
                .open(SocketAddr::new(dns, 53))
                .await
                .map_err(|e| e.into_inner())?;
            let mut framed = Vec::with_capacity(query.len() + 2);
            framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
            framed.extend_from_slice(&query);
            s.write_all(&framed).await.map_err(io_dns)?;
            let mut len = [0u8; 2];
            s.read_exact(&mut len).await.map_err(io_dns)?;
            let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
            s.read_exact(&mut buf).await.map_err(io_dns)?;
            Ok::<_, FeriteError>(buf)
        })
        .await
        .map_err(|_| FeriteError::Dns(format!("tunnel DNS lookup of '{host}' timed out")))??;

        let parsed = Message::from_bytes(&resp)
            .map_err(|e| FeriteError::Dns(format!("parse dns response: {e}")))?;

        // A name that doesn't exist is authoritative and worth negative-caching;
        // SERVFAIL and friends are transient, so surface them as an error and let
        // the caller fall back to ferrite's upstream.
        match parsed.metadata.response_code {
            ResponseCode::NoError => {}
            ResponseCode::NXDomain => return Ok(DnsAnswer::NxDomain),
            other => {
                return Err(FeriteError::Dns(format!(
                    "tunnel DNS for '{host}' returned {other}"
                )));
            }
        }

        let found = parsed.answers.iter().find_map(|rr| {
            let ttl = Duration::from_secs(u64::from(rr.ttl)).clamp(DNS_MIN_TTL, DNS_MAX_TTL);
            match &rr.data {
                RData::A(a) => Some((IpAddr::V4(a.0), ttl)),
                RData::AAAA(a) => Some((IpAddr::V6(a.0), ttl)),
                _ => None,
            }
        });
        Ok(match found {
            Some((ip, ttl)) => DnsAnswer::Found(ip, ttl),
            None => DnsAnswer::NoData, // NOERROR but no A/AAAA of this type
        })
    }
}

/// The classified result of a single tunnel-DNS query.
enum DnsAnswer {
    /// An address record and its (clamped) TTL.
    Found(IpAddr, Duration),
    /// NOERROR with no address record of the queried type (try the other type).
    NoData,
    /// The name does not exist (NXDOMAIN) — safe to negative-cache.
    NxDomain,
}

/// Map an I/O error from the tunneled DNS exchange into a DNS error.
fn io_dns(e: std::io::Error) -> FeriteError {
    FeriteError::Dns(format!("tunnel DNS io: {e}"))
}

/// A loop → caller message: decrypted bytes, or a half-close signal once the
/// remote peer has sent FIN and all its data has been delivered.
enum ToCaller {
    Data(Vec<u8>),
    Eof,
}

/// Per-connection state held by the loop.
struct Conn {
    /// Loop → caller bytes (decrypted from the tunnel) and the EOF marker.
    to_caller: mpsc::Sender<ToCaller>,
    /// Caller → loop bytes, per-connection and **bounded** ([`CALLER_QUEUE`]): the
    /// loop pulls from here into the TX ring only while the ring has room, so a
    /// fast uploader blocks its bridge (and thus its own socket) instead of the
    /// loop buffering the surplus without limit.
    from_caller: mpsc::Receiver<Vec<u8>>,
    /// The current caller→peer chunk not yet fully accepted by the TX ring (holds
    /// at most one chunk — the next is pulled from `from_caller` only once this is
    /// drained, so it can't grow without bound).
    pending: Vec<u8>,
    /// The connection reached ESTABLISHED at least once. Until then a closed
    /// socket means "still connecting", not "remote hung up" (avoids a spurious
    /// EOF during the SYN handshake).
    established: bool,
    /// The remote-FIN EOF marker has been forwarded to the caller (send once).
    eof_sent: bool,
    /// The bridge has signalled the caller closed; flush then drop.
    closing: bool,
    /// The virtual local port, tracked so a new connection doesn't reuse a port
    /// still held by a live one (avoids a 4-tuple clash after the counter wraps).
    local_port: u16,
    /// Keeps the global WG-connection gauge honest: dropped on reap, close, or
    /// whole-tunnel teardown alike.
    _live: crate::memstats::GaugeGuard,
    /// Held open until the connect resolves: fired `Ok` once ESTABLISHED, or `Err`
    /// on refusal / [`WG_CONNECT_TIMEOUT`]. Deferring the reply (instead of acking
    /// the SYN immediately) means a dead destination fails fast rather than hanging
    /// until the splice idle-times-out. The error is classified destination-class
    /// (refused/timed-out is a property of the target, not the tunnel), so a dead
    /// site doesn't trip the egress circuit breaker.
    connect_reply: Option<oneshot::Sender<std::result::Result<(), super::ConnectError>>>,
    /// Deadline for the connect to reach ESTABLISHED.
    connect_deadline: Instant,
}

/// Why the tunnel task returned.
enum RunOutcome {
    /// The control channel closed — the egress was dropped. Stop for good.
    Shutdown,
    /// The run ended abnormally (couldn't come up, or the handshake stalled). The
    /// supervisor retries after a backoff.
    Failed(FeriteError),
}

/// Supervise the tunnel: (re)run it, and on any abnormal exit wait a backoff and
/// try again — re-resolving the endpoint each attempt so a boot-time "no network
/// yet" or a moved (DDNS) endpoint recovers without a config change. Returns only
/// when the egress is dropped (control channel closed).
async fn supervise_tunnel(
    id: String,
    conf: WgConf,
    buffers: SockBuffers,
    mut ctrl_rx: mpsc::Receiver<Ctrl>,
    healthy: Arc<AtomicBool>,
    last_handshake: Arc<AtomicU64>,
) {
    let mut backoff = INITIAL_BACKOFF;
    loop {
        let started = Instant::now();
        match run_tunnel(&id, &conf, buffers, &mut ctrl_rx, &healthy, &last_handshake).await {
            RunOutcome::Shutdown => {
                tracing::debug!("wg '{}': egress dropped, tunnel stopped", id);
                return;
            }
            RunOutcome::Failed(e) => {
                healthy.store(false, Ordering::Relaxed);
                // A run that stayed up a while is a transient blip, not a crash
                // loop — reset the backoff so it reconnects promptly.
                if started.elapsed() >= STABLE_RUN {
                    backoff = INITIAL_BACKOFF;
                }
                tracing::warn!(
                    "proxy: wireguard egress '{}' exited: {}; reconnecting in {:?}",
                    id,
                    e,
                    backoff
                );
                // Wait out the backoff, but keep answering Open requests (fail fast
                // so callers don't hang) and notice if the egress is dropped.
                if !wait_backoff(&mut ctrl_rx, backoff).await {
                    return; // egress dropped during backoff
                }
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}

/// Sleep for `backoff` while the tunnel is down, replying to any Open request with
/// an error immediately (so a routed connection fails fast instead of blocking).
/// Returns `false` if the control channel closed (egress dropped) — the caller
/// should then stop supervising.
async fn wait_backoff(ctrl_rx: &mut mpsc::Receiver<Ctrl>, backoff: Duration) -> bool {
    let deadline = tokio::time::sleep(backoff);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => return true,
            msg = ctrl_rx.recv() => match msg {
                None => return false, // egress dropped
                Some(Ctrl::Open { reply, .. }) => {
                    // The tunnel really is down (reconnecting) — egress-class.
                    let _ = reply.send(Err(super::ConnectError::egress(FeriteError::Dns(
                        "wireguard tunnel is down (reconnecting)".into(),
                    ))));
                }
            },
        }
    }
}

/// The single tunnel task. Owns all WireGuard + smoltcp state for one run; the
/// supervisor restarts it on failure.
async fn run_tunnel(
    id: &str,
    conf: &WgConf,
    buffers: SockBuffers,
    ctrl_rx: &mut mpsc::Receiver<Ctrl>,
    healthy: &Arc<AtomicBool>,
    last_handshake: &AtomicU64,
) -> RunOutcome {
    // ── UDP socket to the peer endpoint (resolved via the system resolver —
    //    bootstrap, must not depend on the tunnel). Re-resolved every run so a
    //    moved endpoint (DDNS) or a boot without network recovers on retry. ──
    let endpoint = match resolve_endpoint(&conf.endpoint).await {
        Ok(ep) => ep,
        Err(e) => return RunOutcome::Failed(e),
    };
    let udp = match UdpSocket::bind(("0.0.0.0", 0)).await {
        Ok(s) => s,
        Err(e) => return RunOutcome::Failed(e.into()),
    };
    if let Err(e) = udp.connect(endpoint).await {
        return RunOutcome::Failed(e.into());
    }
    // A large TCP window lets the peer send big bursts; grow the kernel UDP
    // buffers so the single loop doesn't drop packets between drains (which would
    // stall individual connections). Best-effort — the kernel may clamp to
    // net.core.rmem_max/wmem_max.
    {
        let sock = socket2::SockRef::from(&udp);
        // ONE UDP socket serves every connection on this egress, so its kernel
        // buffer must hold the AGGREGATE burst = per-conn window × concurrent
        // downloads. Size it for several concurrent windows (≈8×), floored at
        // 8 MiB and capped at 32 MiB. The kernel clamps to net.core.rmem_max — so
        // large per-conn buffers still need rmem_max raised to be reliable.
        let want = buffers
            .rx
            .saturating_mul(8)
            .clamp(8 * 1024 * 1024, 32 * 1024 * 1024);
        let _ = sock.set_recv_buffer_size(want);
        let _ = sock.set_send_buffer_size((want / 2).max(2 * 1024 * 1024));
        // Warn only when the EFFECTIVE recv buffer is actually smaller than one
        // window (raising net.core.rmem_max would then help); otherwise just note it.
        // Compare in usable bytes — the raw read-back is 2× on Linux, which would
        // otherwise hide a too-small buffer (and overstate the logged figure 2×).
        if let Ok(rcv) = sock.recv_buffer_size() {
            let usable = super::usable_rcvbuf_bytes(rcv);
            if usable < buffers.rx {
                tracing::warn!(
                    "wg '{}': kernel UDP recv buffer {} KiB < per-conn buffer {} KiB — large bursts may drop; raise net.core.rmem_max",
                    id,
                    usable / 1024,
                    buffers.rx / 1024,
                );
            } else {
                tracing::info!("wg '{}': UDP recv buffer {} KiB", id, usable / 1024);
            }
        }
    }

    // ── boringtun tunnel ──
    let static_private = StaticSecret::from(conf.private_key);
    let peer_public = PublicKey::from(conf.peer_public_key);
    // Default a keepalive when the .conf omits one. As an always-on egress behind
    // NAT we are always the initiator: without keepalive an idle session expires
    // (REJECT_AFTER_TIME), health drops, and fail-closed then blocks the very
    // connection that would re-trigger the handshake. An explicit `0` (disabled)
    // is respected — only `None` gets the default.
    let keepalive = conf.persistent_keepalive.or(Some(DEFAULT_KEEPALIVE));
    let mut tunn = Tunn::new(
        static_private,
        peer_public,
        conf.preshared_key,
        keepalive,
        0,
        None,
    );

    // ── smoltcp interface over the packet-shuttle device ──
    let mtu = conf.mtu.map(|m| m as usize).unwrap_or(DEFAULT_MTU);
    let mut device = WgDevice::new(mtu);
    let mut iface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut device,
        smol_now(&start_clock()),
    );
    iface.update_ip_addrs(|addrs| {
        for (ip, prefix) in &conf.addresses {
            let _ = addrs.push(IpCidr::new(IpAddress::from(*ip), *prefix));
        }
    });
    iface.set_any_ip(true);
    // Default routes so off-link destinations egress to the device (the gateway
    // value is unused on a point-to-point medium-ip interface).
    if let Some((IpAddr::V4(v4), _)) = conf.addresses.iter().find(|(ip, _)| ip.is_ipv4()) {
        let _ = iface.routes_mut().add_default_ipv4_route(*v4);
    }
    if let Some((IpAddr::V6(v6), _)) = conf.addresses.iter().find(|(ip, _)| ip.is_ipv6()) {
        let _ = iface.routes_mut().add_default_ipv6_route(*v6);
    }

    let mut sockets = SocketSet::new(Vec::new());
    let mut conns: HashMap<SocketHandle, Conn> = HashMap::new();
    let mut next_port: u16 = 49152;
    // Bridge → loop "connection closed" signals, on their own channel so the
    // loop holding a sender here does NOT keep `ctrl_rx` alive (that channel is
    // what signals egress teardown).
    let (close_tx, mut close_rx) = mpsc::channel::<SocketHandle>(64);
    let wake = Arc::new(Notify::new());
    let clock = start_clock();
    // When the handshake was last healthy — used to restart a stalled tunnel.
    let mut unhealthy_since: Option<Instant> = None;

    let mut crypt = vec![0u8; CRYPT_BUF];
    let mut udp_buf = vec![0u8; 65_535];

    // Kick off the handshake.
    match tunn.format_handshake_initiation(&mut crypt, false) {
        TunnResult::WriteToNetwork(p) => {
            let _ = udp.send(p).await;
        }
        TunnResult::Err(e) => tracing::debug!("wg '{}' handshake init: {:?}", id, e),
        _ => {}
    }

    let timer = tokio::time::sleep(TIMER_TICK);
    tokio::pin!(timer);

    loop {
        tokio::select! {
            // Open a new connection (or tear down when the egress is dropped).
            ctrl = ctrl_rx.recv() => match ctrl {
                None => return RunOutcome::Shutdown, // WgEgress dropped → tear down
                Some(Ctrl::Open { remote, io, reply }) => {
                    open_conn(
                        &mut sockets, &mut iface, &mut conns, &mut next_port,
                        remote, io, buffers, &close_tx, &wake, reply,
                    );
                }
            },

            // A bridge reported its connection closed.
            Some(h) = close_rx.recv() => {
                if let Some(c) = conns.get_mut(&h) {
                    c.closing = true;
                }
            }

            // Inbound ciphertext from the peer. Drain the whole burst before the
            // service cycle below: a big TCP window means thousands of datagrams
            // arrive back-to-back, and reading one-per-iteration (with O(conns)
            // work each) lets the kernel UDP buffer overflow and drop packets,
            // stalling individual connections. Capped so we still yield to the
            // other branches under a sustained stream.
            r = udp.recv(&mut udp_buf) => {
                if let Ok(n) = r {
                    decapsulate_all(&mut tunn, &udp_buf[..n], &mut device, &mut crypt, &udp).await;
                    for _ in 0..UDP_DRAIN_BURST {
                        match udp.try_recv(&mut udp_buf) {
                            Ok(n) => {
                                decapsulate_all(&mut tunn, &udp_buf[..n], &mut device, &mut crypt, &udp).await;
                            }
                            Err(_) => break, // WouldBlock — burst drained
                        }
                    }
                }
            }

            // Periodic WireGuard timers (rekey / keepalive).
            _ = &mut timer => {
                match tunn.update_timers(&mut crypt) {
                    TunnResult::WriteToNetwork(p) => { let _ = udp.send(p).await; }
                    TunnResult::Err(e) => tracing::debug!("wg '{}' timer: {:?}", id, e),
                    _ => {}
                }
                // Keep an idle session from expiring (see REHANDSHAKE_AFTER):
                // `force=false` makes this a no-op while an initiation is already
                // in flight, so ticking every 250ms cannot spam the peer.
                if matches!(tunn.time_since_last_handshake(), Some(age) if age >= REHANDSHAKE_AFTER) {
                    match tunn.format_handshake_initiation(&mut crypt, false) {
                        TunnResult::WriteToNetwork(p) => {
                            tracing::debug!("wg '{}': proactive re-handshake (idle session renewal)", id);
                            let _ = udp.send(p).await;
                        }
                        TunnResult::Err(e) => tracing::debug!("wg '{}' re-handshake: {:?}", id, e),
                        _ => {}
                    }
                }
                timer.as_mut().reset(tokio::time::Instant::now() + TIMER_TICK);
            }

            _ = wake.notified() => {}
        }

        // ── Service the netstack after any event. ──
        service_sockets(&mut sockets, &mut conns);
        let _ = iface.poll(smol_now(&clock), &mut device, &mut sockets);
        settle_connects(&mut sockets, &mut conns, Instant::now());
        pump_to_callers(&mut sockets, &mut conns);
        flush_egress(&mut tunn, &mut device, &mut crypt, &udp).await;
        // Health tracks the live handshake, not data flow: it must be true the
        // moment the session is up so the proxy's fail-closed gate lets the FIRST
        // connection through (otherwise no data ever flows and it never recovers).
        refresh_health(&tunn, healthy, last_handshake);

        // Restart a tunnel whose handshake has been down too long, so the
        // supervisor re-resolves the endpoint (DDNS / network-came-up-late). A
        // healthy tunnel clears the timer; only a sustained outage trips it.
        if healthy.load(Ordering::Relaxed) {
            unhealthy_since = None;
        } else if unhealthy_since.get_or_insert_with(Instant::now).elapsed() > REVIVE_AFTER {
            return RunOutcome::Failed(FeriteError::Dns(format!(
                "wg '{id}': handshake down for over {REVIVE_AFTER:?}, restarting"
            )));
        }
    }
}

/// Set `healthy` from boringtun's session state: up while the last successful
/// handshake is still within [`SESSION_MAX_AGE`], down otherwise. Also records
/// when that handshake happened (unix seconds) for the stats API.
fn refresh_health(tunn: &Tunn, healthy: &AtomicBool, last_handshake: &AtomicU64) {
    let since = tunn.time_since_last_handshake();
    let up = matches!(since, Some(age) if age < SESSION_MAX_AGE);
    healthy.store(up, Ordering::Relaxed);
    if let Some(age) = since {
        last_handshake.store(
            unix_now_secs().saturating_sub(age.as_secs()),
            Ordering::Relaxed,
        );
    }
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Allocate a virtual TCP socket, start connecting, and spawn its bridge task. The
/// connect `reply` is held in the [`Conn`] and fired later (by [`settle_connects`])
/// once the handshake completes or fails — not acked here on the mere SYN.
#[allow(clippy::too_many_arguments)] // all loop-owned state; grouping would just shuffle it
fn open_conn(
    sockets: &mut SocketSet<'static>,
    iface: &mut Interface,
    conns: &mut HashMap<SocketHandle, Conn>,
    next_port: &mut u16,
    remote: SocketAddr,
    io: DuplexStream,
    buffers: SockBuffers,
    close_tx: &mpsc::Sender<SocketHandle>,
    wake: &Arc<Notify>,
    reply: oneshot::Sender<std::result::Result<(), super::ConnectError>>,
) {
    let mut sock = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; buffers.rx]),
        tcp::SocketBuffer::new(vec![0u8; buffers.tx]),
    );
    // Abort a connection whose peer goes silent (stops ACKing) for this long, so a
    // stalled upload can't pin the socket forever: without it the peer never
    // draining the TX ring would leave the bridge blocked on a full `from_caller`
    // and the conn un-reapable until the whole tunnel restarts.
    sock.set_timeout(Some(smoltcp::time::Duration::from_secs(
        SOCKET_TIMEOUT.as_secs(),
    )));
    let local_port = alloc_port(next_port, conns);

    let remote_ep = (IpAddress::from(remote.ip()), remote.port());
    if let Err(e) = sock.connect(iface.context(), remote_ep, local_port) {
        let _ = reply.send(Err(super::ConnectError::destination(FeriteError::Dns(
            format!("wireguard connect {remote}: {e:?}"),
        ))));
        return;
    }

    let handle = sockets.add(sock);
    let (to_caller_tx, to_caller_rx) = mpsc::channel::<ToCaller>(64);
    let (from_caller_tx, from_caller_rx) = mpsc::channel::<Vec<u8>>(CALLER_QUEUE);
    conns.insert(
        handle,
        Conn {
            to_caller: to_caller_tx,
            from_caller: from_caller_rx,
            pending: Vec::new(),
            established: false,
            eof_sent: false,
            closing: false,
            local_port,
            connect_reply: Some(reply),
            connect_deadline: Instant::now() + WG_CONNECT_TIMEOUT,
            _live: crate::memstats::WG_CONNS.guard(),
        },
    );

    tokio::spawn(bridge(
        io,
        handle,
        from_caller_tx,
        to_caller_rx,
        close_tx.clone(),
        Arc::clone(wake),
    ));
}

/// Pick a virtual local port not currently held by a live connection. The counter
/// walks the ephemeral range and wraps; skipping in-use ports avoids a 4-tuple
/// clash when it laps (with the low connection counts here it effectively never
/// scans more than a handful).
fn alloc_port(next_port: &mut u16, conns: &HashMap<SocketHandle, Conn>) -> u16 {
    // Scan each ephemeral port at most once. A free one is found almost immediately
    // at these connection counts; if somehow every port were live the loop still
    // terminates and returns the last candidate (harmless at these counts).
    let mut candidate = *next_port;
    let mut chosen = candidate;
    for _ in 0..=(u16::MAX - 49152) {
        chosen = candidate;
        candidate = if candidate == u16::MAX {
            49152
        } else {
            candidate + 1
        };
        if !conns.values().any(|c| c.local_port == chosen) {
            break;
        }
    }
    *next_port = candidate;
    chosen
}

/// Fire the deferred connect reply for any connection that has resolved: `Ok` once
/// the socket can send (ESTABLISHED), `Err` if it closed without connecting or the
/// connect deadline passed (the latter two also mark the connection for teardown).
fn settle_connects(
    sockets: &mut SocketSet<'static>,
    conns: &mut HashMap<SocketHandle, Conn>,
    now: Instant,
) {
    for (h, c) in conns.iter_mut() {
        if c.connect_reply.is_none() {
            continue;
        }
        let sock = sockets.get_mut::<tcp::Socket>(*h);
        if sock.may_send() {
            // Reached ESTABLISHED — the connection is usable.
            if let Some(tx) = c.connect_reply.take() {
                let _ = tx.send(Ok(()));
            }
        } else if sock.state() == tcp::State::Closed {
            // Refused / reset before establishing — a destination problem (the
            // tunnel carried the SYN fine), so it must not trip the egress breaker.
            if let Some(tx) = c.connect_reply.take() {
                let _ = tx.send(Err(super::ConnectError::destination(FeriteError::Dns(
                    "wireguard: connection refused".into(),
                ))));
            }
            c.closing = true;
        } else if now >= c.connect_deadline {
            // No SYN-ACK in time — also a destination property (tunnel liveness is
            // tracked separately by `healthy`).
            if let Some(tx) = c.connect_reply.take() {
                let _ = tx.send(Err(super::ConnectError::destination(FeriteError::Dns(
                    "wireguard: connect timed out".into(),
                ))));
            }
            c.closing = true;
        }
    }
}

/// Pull caller→peer bytes into each socket's TX ring, **only while the ring has
/// room**. This is the upload backpressure: a chunk is taken from `from_caller`
/// only once the previous one is fully in the ring, so a client uploading faster
/// than the tunnel drains blocks on its (bounded) channel instead of the loop
/// growing an unbounded `pending`.
fn service_sockets(sockets: &mut SocketSet<'static>, conns: &mut HashMap<SocketHandle, Conn>) {
    for (h, c) in conns.iter_mut() {
        let sock = sockets.get_mut::<tcp::Socket>(*h);
        loop {
            // Flush the leftover of the current chunk first.
            if !c.pending.is_empty() {
                if !sock.can_send() {
                    break; // ring full — keep the leftover for next time
                }
                match sock.send_slice(&c.pending) {
                    Ok(sent) if sent > 0 => {
                        c.pending.drain(..sent);
                    }
                    _ => break,
                }
                if !c.pending.is_empty() {
                    break; // ring filled mid-chunk
                }
            }
            // Chunk drained: pull the next one only if the ring can take more.
            if !sock.can_send() {
                break;
            }
            match c.from_caller.try_recv() {
                Ok(chunk) => c.pending = chunk,
                Err(_) => break, // nothing queued (or bridge gone) — done for now
            }
        }
    }
}

/// Drain socket RX rings into the per-connection caller channels (bounded — when
/// a channel is full we leave bytes in the ring so the TCP window closes), and
/// propagate a remote FIN to the caller as a half-close EOF.
fn pump_to_callers(sockets: &mut SocketSet<'static>, conns: &mut HashMap<SocketHandle, Conn>) {
    let mut done: Vec<SocketHandle> = Vec::new();
    // One scratch shared by every socket; queued chunks are cut to exact size,
    // so a small chunk waiting in `to_caller` doesn't pin an 8 KiB allocation
    // (a full queue of tiny chunks used to hold 64 × 8 KiB per connection).
    let mut scratch = [0u8; 8192];
    for (h, c) in conns.iter_mut() {
        let sock = sockets.get_mut::<tcp::Socket>(*h);
        c.established |= sock.may_recv();
        while sock.can_recv() {
            // Reserve the channel slot BEFORE recv_slice: recv dequeues from the
            // socket ring, so send-after-recv on a full channel would drop those
            // bytes on the floor — mid-stream corruption under backpressure.
            // Reserving first leaves unread bytes in the ring for the next pass.
            let permit = match c.to_caller.try_reserve() {
                Ok(p) => p,
                Err(mpsc::error::TrySendError::Full(())) => break, // backpressure
                Err(mpsc::error::TrySendError::Closed(())) => {
                    c.closing = true;
                    break;
                }
            };
            match sock.recv_slice(&mut scratch) {
                Ok(0) | Err(_) => break,
                Ok(n) => permit.send(ToCaller::Data(scratch[..n].to_vec())),
            }
        }
        // Remote sent FIN and we've delivered everything it sent: tell the caller
        // (read side hits EOF) while its write side stays open for a half-close.
        if c.established
            && !c.eof_sent
            && !sock.may_recv()
            && c.to_caller.try_send(ToCaller::Eof).is_ok()
        {
            c.eof_sent = true;
        }
        // Close only once every caller→peer byte is in the ring: `from_caller` may
        // still hold the final chunk when the bridge signalled close, and closing
        // early would drop an upload's tail.
        if c.closing && c.pending.is_empty() && c.from_caller.is_empty() {
            sock.close();
        }
        // Reap when the caller closed and the socket finished closing, OR the socket
        // died on its own — peer RST, or the `set_timeout` above aborting a stalled
        // upload. The second case is essential: a bridge parked on a full
        // `from_caller` (peer not draining) never sends `close_tx`, so `closing`
        // stays false; removing the Conn here drops `from_caller`, which makes the
        // bridge's `send()` error out and the task exit. `!is_active()` is only true
        // in Closed/TimeWait, so a still-connecting socket is never reaped early.
        if !sock.is_active() && (c.closing || c.established) {
            done.push(*h);
        }
    }
    for h in done {
        conns.remove(&h);
        sockets.remove(h);
    }
}

/// Encapsulate every IP packet smoltcp produced and send it to the peer.
async fn flush_egress(tunn: &mut Tunn, device: &mut WgDevice, crypt: &mut [u8], udp: &UdpSocket) {
    while let Some(packet) = device.take_outbound() {
        match tunn.encapsulate(&packet, crypt) {
            TunnResult::WriteToNetwork(p) => {
                let _ = udp.send(p).await;
            }
            TunnResult::Err(e) => tracing::debug!("wg encapsulate: {:?}", e),
            _ => {}
        }
    }
}

/// Decapsulate one inbound datagram, re-pumping boringtun until `Done`, and feed
/// decrypted IP packets into the device for smoltcp to process.
async fn decapsulate_all(
    tunn: &mut Tunn,
    datagram: &[u8],
    device: &mut WgDevice,
    crypt: &mut [u8],
    udp: &UdpSocket,
) {
    // The first call consumes `datagram`; subsequent re-pump calls pass an empty
    // input until boringtun has nothing more to emit (the #1 boringtun pitfall).
    let mut input: &[u8] = datagram;
    loop {
        // `crypt` is the shared scratch (same one encapsulate/timers use — calls
        // are sequential, never concurrent). The returned `TunnResult` borrows it,
        // so we copy out the one produced packet before the next iteration reuses
        // the buffer; that single `to_vec` is the only per-packet allocation.
        let result = match tunn.decapsulate(None, input, crypt) {
            TunnResult::Done => None,
            TunnResult::Err(e) => {
                tracing::debug!("wg decapsulate: {:?}", e);
                None
            }
            TunnResult::WriteToNetwork(p) => Some(Emit::Net(p.to_vec())),
            TunnResult::WriteToTunnelV4(p, _) | TunnResult::WriteToTunnelV6(p, _) => {
                Some(Emit::Tunnel(p.to_vec()))
            }
        };
        match result {
            None => break,
            Some(Emit::Net(p)) => {
                let _ = udp.send(&p).await;
                input = &[]; // re-pump
            }
            Some(Emit::Tunnel(p)) => {
                device.push_inbound(p);
                break;
            }
        }
    }
}

enum Emit {
    Net(Vec<u8>),
    Tunnel(Vec<u8>),
}

/// Per-connection async bridge: caller pipe ⇄ loop mpsc channels. `to_loop` is
/// this connection's own bounded channel, so `send().await` blocks when the loop
/// hasn't drained it — the backpressure that bounds upload memory.
async fn bridge(
    mut io: DuplexStream,
    handle: SocketHandle,
    to_loop: mpsc::Sender<Vec<u8>>,
    mut from_loop: mpsc::Receiver<ToCaller>,
    close_tx: mpsc::Sender<SocketHandle>,
    wake: Arc<Notify>,
) {
    let mut buf = vec![0u8; 8192];
    loop {
        tokio::select! {
            r = io.read(&mut buf) => match r {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if to_loop.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                    wake.notify_one();
                }
            },
            msg = from_loop.recv() => match msg {
                Some(ToCaller::Data(data)) => {
                    if io.write_all(&data).await.is_err() {
                        break;
                    }
                }
                // Remote half-closed: give the caller EOF on its read side, but
                // keep reading its write side (above) for a clean half-close.
                Some(ToCaller::Eof) => {
                    let _ = io.shutdown().await;
                }
                None => break, // loop dropped this connection entirely
            },
        }
    }
    let _ = close_tx.send(handle).await;
    wake.notify_one();
}

async fn resolve_endpoint(endpoint: &str) -> Result<SocketAddr> {
    tokio::net::lookup_host(endpoint)
        .await
        .map_err(|e| FeriteError::Config(format!("wireguard endpoint '{endpoint}': {e}")))?
        .next()
        .ok_or_else(|| {
            FeriteError::Config(format!("wireguard endpoint '{endpoint}' did not resolve"))
        })
}

fn start_clock() -> std::time::Instant {
    std::time::Instant::now()
}

fn smol_now(clock: &std::time::Instant) -> SmolInstant {
    SmolInstant::from_micros(clock.elapsed().as_micros() as i64)
}

#[cfg(test)]
mod cache_tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn caches_live_entries_and_misses_expired() {
        let cache = DnsCache::default();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

        cache.put("example.com", Some(ip), Duration::from_secs(3600));
        assert!(
            matches!(cache.get("example.com"), Cached::Hit(got) if got == ip),
            "fresh entry should hit"
        );

        // A negative result is remembered so the name isn't re-queried.
        cache.put("nope.example", None, Duration::from_secs(3600));
        assert!(
            matches!(cache.get("nope.example"), Cached::Negative),
            "negative entry should be remembered"
        );

        // A zero-TTL entry is already expired the instant we read it back.
        cache.put("stale.example", Some(ip), Duration::ZERO);
        assert!(
            matches!(cache.get("stale.example"), Cached::Miss),
            "expired entry should miss"
        );

        assert!(
            matches!(cache.get("never-stored"), Cached::Miss),
            "unknown key should miss"
        );
    }

    #[test]
    fn hard_evicts_when_full_of_live_entries() {
        let cache = DnsCache::default();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        // Insert well past the cap, all long-lived so `retain` frees nothing — the
        // hard-evict path must still keep the map bounded.
        for i in 0..(DNS_CACHE_CAP + 50) {
            cache.put(
                &format!("host{i}.example"),
                Some(ip),
                Duration::from_secs(3600),
            );
        }
        assert!(
            cache.map.lock().len() <= DNS_CACHE_CAP,
            "cache must stay within its cap even when full of fresh entries"
        );
    }
}

#[cfg(test)]
mod smoke {
    //! Real-network end-to-end check against a live WireGuard peer. Ignored by
    //! default (needs outbound UDP and a real `.conf`); run it explicitly:
    //!
    //! ```text
    //! WG_SMOKE_CONF=/path/to/wireguard.conf \
    //!   cargo test proxy::egress::wireguard::smoke -- --ignored --nocapture
    //! ```
    //!
    //! It proves the layers a unit test can't: the boringtun handshake against a
    //! real peer, and a TCP byte exchange routed all the way through the tunnel.
    use super::*;
    use crate::config::{EgressConfig, UpstreamConfig};
    use crate::upstream::{UpstreamPool, ZoneRouter, no_proxy};

    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RData, RecordType};
    use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
    use std::str::FromStr;
    use tokio::time::{Instant, sleep, timeout};

    fn upstream() -> Arc<ZoneRouter> {
        // Plain 1.1.1.1 — used only to resolve hostnames the test connects to
        // (the IP-literal connects below skip it entirely).
        let pool = UpstreamPool::from_config(
            &[UpstreamConfig::Plain {
                address: "1.1.1.1".into(),
                port: 53,
                egress: None,
            }],
            no_proxy(),
        )
        .expect("upstream pool");
        ZoneRouter::new(&[], pool).expect("zone router")
    }

    fn egress(conf_text: String) -> EgressConfig {
        EgressConfig {
            id: "smoke".into(),
            name: "smoke".into(),
            enabled: true,
            kind: "wireguard".into(),
            address: None,
            port: None,
            username: None,
            password: None,
            config: Some(conf_text),
            seg_position: None,
            buffer_kb: None,
            tx_buffer_kb: None,
        }
    }

    /// Send one DNS-over-TCP query down `s` and return the resolved A records.
    async fn dns_over_tcp(s: &mut DuplexStream, host: &str) -> Vec<String> {
        let mut msg = Message::new(0x4242, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.add_query(Query::query(Name::from_str(host).unwrap(), RecordType::A));
        let query = msg.to_bytes().unwrap();

        let mut framed = Vec::with_capacity(query.len() + 2);
        framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
        framed.extend_from_slice(&query);
        s.write_all(&framed).await.expect("write dns query");

        let mut len_buf = [0u8; 2];
        timeout(Duration::from_secs(10), s.read_exact(&mut len_buf))
            .await
            .expect("dns length read timed out")
            .expect("read dns length");
        let mut resp = vec![0u8; u16::from_be_bytes(len_buf) as usize];
        timeout(Duration::from_secs(10), s.read_exact(&mut resp))
            .await
            .expect("dns body read timed out")
            .expect("read dns body");

        let parsed = Message::from_bytes(&resp).expect("parse dns response");
        parsed
            .answers
            .iter()
            .filter_map(|rr| match &rr.data {
                RData::A(a) => Some(a.0.to_string()),
                _ => None,
            })
            .collect()
    }

    /// The proactive renewal must fire comfortably before the session expires:
    /// the margin absorbs several REKEY_TIMEOUT (5s) handshake retries.
    #[test]
    fn rehandshake_fires_well_before_session_expiry() {
        assert!(REHANDSHAKE_AFTER + Duration::from_secs(20) <= SESSION_MAX_AGE);
    }

    /// Regression for "tunnels flap when idle": keepalives keep the NAT open but
    /// don't renew the WireGuard session, so without the proactive re-handshake
    /// in the timer branch an idle tunnel's handshake age crosses
    /// [`SESSION_MAX_AGE`] and health flips down (fail-closed rules then drop
    /// the very traffic that would revive it). This idles well past that age,
    /// asserting health never dips, then proves the data path is still live.
    /// Takes ~4 minutes of wall clock — run explicitly.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs network + WG_SMOKE_CONF; idles ~4 minutes"]
    async fn idle_tunnel_stays_healthy_past_session_age() {
        let path =
            std::env::var("WG_SMOKE_CONF").expect("set WG_SMOKE_CONF=/path/to/wireguard.conf");
        let text = std::fs::read_to_string(&path).expect("read conf file");
        let eg = WgEgress::from_config(&egress(text), upstream()).expect("bring up egress");

        let deadline = Instant::now() + Duration::from_secs(15);
        while !eg.is_healthy() {
            assert!(
                Instant::now() < deadline,
                "handshake did not complete within 15s"
            );
            sleep(Duration::from_millis(100)).await;
        }
        let started = Instant::now();
        let idle_for = SESSION_MAX_AGE + Duration::from_secs(45);
        println!("[smoke] handshake up — idling for {idle_for:?} (no traffic)…");

        while started.elapsed() < idle_for {
            assert!(
                eg.is_healthy(),
                "tunnel went unhealthy after {:?} idle — proactive re-handshake failed",
                started.elapsed()
            );
            sleep(Duration::from_secs(2)).await;
        }
        println!(
            "[smoke] ✅ stayed healthy for {:?} (past SESSION_MAX_AGE {SESSION_MAX_AGE:?})",
            started.elapsed()
        );

        // And the session is genuinely usable, not just reported healthy.
        let mut s = timeout(
            WG_CONNECT_TIMEOUT + Duration::from_secs(5),
            eg.connect("1.1.1.1", 53),
        )
        .await
        .expect("tunnel connect timed out")
        .expect("tunnel connect failed");
        let ips = dns_over_tcp(&mut s, "cloudflare.com.").await;
        assert!(!ips.is_empty(), "no A records after the idle stretch");
        println!("[smoke] ✅ data path live after idle: cloudflare.com -> {ips:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs network + WG_SMOKE_CONF pointing at a real .conf"]
    async fn handshake_and_data_path() {
        let path =
            std::env::var("WG_SMOKE_CONF").expect("set WG_SMOKE_CONF=/path/to/wireguard.conf");
        let text = std::fs::read_to_string(&path).expect("read conf file");

        let eg = WgEgress::from_config(&egress(text), upstream()).expect("bring up egress");

        // 1) Handshake — health flips true the moment the peer's response decrypts.
        let deadline = Instant::now() + Duration::from_secs(15);
        while !eg.is_healthy() {
            assert!(
                Instant::now() < deadline,
                "handshake did not complete within 15s"
            );
            sleep(Duration::from_millis(100)).await;
        }
        println!("[smoke] ✅ handshake complete — tunnel healthy");

        // 2) Data path — DNS-over-TCP to 1.1.1.1:53 routed through the tunnel. The
        //    outer bound must exceed WG_CONNECT_TIMEOUT so the egress's own connect
        //    deadline (and its classified error) surfaces rather than this racing it.
        let mut s = timeout(
            WG_CONNECT_TIMEOUT + Duration::from_secs(5),
            eg.connect("1.1.1.1", 53),
        )
        .await
        .expect("tunnel connect timed out")
        .expect("tunnel connect failed");
        let ips = dns_over_tcp(&mut s, "cloudflare.com.").await;
        assert!(!ips.is_empty(), "no A records came back through the tunnel");
        println!("[smoke] ✅ DNS-over-TCP through tunnel: cloudflare.com -> {ips:?}");

        // 3) DNS through the tunnel — resolve via the .conf's own DNS server,
        //    queried over the tunnel (proves the lookup itself is tunneled, and
        //    that the resolver supports DNS-over-TCP).
        let ip = eg
            .resolve("one.one.one.one")
            .await
            .expect("tunnel DNS resolve failed");
        println!("[smoke] ✅ resolved through tunnel DNS: one.one.one.one -> {ip}");
        assert!(
            matches!(ip, IpAddr::V4(v4) if v4.octets()[0] == 1),
            "unexpected resolve: {ip}"
        );
        // Second lookup must be served from cache (no panic, same answer).
        assert_eq!(eg.resolve("one.one.one.one").await.unwrap(), ip);

        // 4) Exit IP — plain-HTTP GET through the tunnel; should print a Proton
        //    NL address, NOT this host's real IP. Best-effort (won't fail the run).
        match eg.connect("checkip.amazonaws.com", 80).await {
            Ok(mut http) => {
                let req =
                    b"GET / HTTP/1.0\r\nHost: checkip.amazonaws.com\r\nConnection: close\r\n\r\n";
                if http.write_all(req).await.is_ok() {
                    let mut body = Vec::new();
                    let _ = timeout(Duration::from_secs(10), http.read_to_end(&mut body)).await;
                    let text = String::from_utf8_lossy(&body);
                    let ip = text.lines().last().unwrap_or("").trim();
                    println!("[smoke] ✅ tunnel exit IP (expect ProtonVPN NL): {ip}");
                }
            }
            Err(e) => println!("[smoke] (exit-IP check skipped: {e})"),
        }

        // 5) MTU / large transfer — pull a 1 MB file over plain HTTP through the
        //    tunnel. A correct inner MTU streams ~700 full segments cleanly; an
        //    MTU mismatch is where big transfers stall. Best-effort (external host).
        match eg.connect("speedtest.tele2.net", 80).await {
            Ok(mut http) => {
                let req = b"GET /1MB.zip HTTP/1.0\r\nHost: speedtest.tele2.net\r\nConnection: close\r\n\r\n";
                if http.write_all(req).await.is_ok() {
                    let mut body = Vec::new();
                    let got = timeout(Duration::from_secs(60), http.read_to_end(&mut body)).await;
                    match got {
                        Ok(Ok(_)) => {
                            assert!(
                                body.len() > 100_000,
                                "large transfer truncated: {} bytes (MTU bug?)",
                                body.len()
                            );
                            println!(
                                "[smoke] ✅ large transfer through tunnel: {} bytes",
                                body.len()
                            );
                        }
                        _ => println!(
                            "[smoke] (large-transfer check inconclusive: {} bytes before timeout)",
                            body.len()
                        ),
                    }
                }
            }
            Err(e) => println!("[smoke] (large-transfer check skipped: {e})"),
        }
    }
}
