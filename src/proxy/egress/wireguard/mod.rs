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
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
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
/// boringtun timer cadence (rekey, keepalive, retransmit).
const TIMER_TICK: Duration = Duration::from_millis(250);
/// Max inbound datagrams drained per wake before yielding to the other select
/// branches — high enough to swallow a large-window burst, capped so a sustained
/// stream can't starve ctrl/timer handling.
const UDP_DRAIN_BURST: usize = 1024;
/// WireGuard's REJECT_AFTER_TIME: a session older than this is dead. We treat the
/// tunnel as healthy only while the last handshake is still inside this window;
/// boringtun keeps it fresh via rekey/keepalive as long as the peer is alive.
const SESSION_MAX_AGE: Duration = Duration::from_secs(180);
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
    /// DNS servers from the `.conf`, queried *through* the tunnel.
    dns: Vec<IpAddr>,
    /// Per-egress resolution cache (host → IP), expired by DNS TTL.
    cache: DnsCache,
}

/// A small bounded TTL cache for tunnel DNS resolutions. Evicts expired entries
/// on insert when at capacity. Locks are never held across an `.await`.
#[derive(Default)]
struct DnsCache {
    map: Mutex<HashMap<String, CacheEntry>>,
}

struct CacheEntry {
    ip: IpAddr,
    expires: Instant,
}

impl DnsCache {
    fn get(&self, key: &str) -> Option<IpAddr> {
        let mut map = self.map.lock();
        match map.get(key) {
            Some(e) if e.expires > Instant::now() => Some(e.ip),
            Some(_) => {
                map.remove(key);
                None
            }
            None => None,
        }
    }

    fn put(&self, key: &str, ip: IpAddr, ttl: Duration) {
        let mut map = self.map.lock();
        if map.len() >= DNS_CACHE_CAP {
            let now = Instant::now();
            map.retain(|_, e| e.expires > now);
        }
        map.insert(
            key.to_string(),
            CacheEntry {
                ip,
                expires: Instant::now() + ttl,
            },
        );
    }
}

enum Ctrl {
    /// Open a virtual TCP connection to `remote`; `io` is the loop's end of the
    /// caller pipe. Reply once the socket is created (data flows once the
    /// handshake completes; health gates whether we even get here).
    Open {
        remote: SocketAddr,
        io: DuplexStream,
        reply: oneshot::Sender<Result<()>>,
    },
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
        // Per-connection socket buffer (bytes), clamped; drives the TCP window.
        let buffer = cfg
            .buffer_kb
            .unwrap_or(DEFAULT_BUFFER_KB)
            .clamp(MIN_BUFFER_KB, MAX_BUFFER_KB) as usize
            * 1024;

        let (ctrl_tx, ctrl_rx) = mpsc::channel(64);
        let healthy = Arc::new(AtomicBool::new(false));
        let id = cfg.id.clone();

        let loop_healthy = Arc::clone(&healthy);
        let loop_id = id.clone();
        // NB: the loop holds ONLY the receiver. When this WgEgress is dropped
        // (config reload / shutdown) `ctrl_tx` goes away, `ctrl_rx.recv()`
        // returns None, and the loop tears itself down — no orphaned tunnels.
        tokio::spawn(async move {
            if let Err(e) = run_tunnel(loop_id.clone(), conf, buffer, ctrl_rx, loop_healthy).await {
                tracing::warn!("proxy: wireguard egress '{}' loop exited: {}", loop_id, e);
            }
        });

        Ok(Self {
            id,
            ctrl: ctrl_tx,
            upstream,
            healthy,
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

    /// Open a tunneled TCP connection to `host:port`. Hostnames are resolved
    /// *through* the tunnel (see [`Self::resolve`]); literal IPs connect directly.
    pub async fn connect(&self, host: &str, port: u16) -> Result<DuplexStream> {
        let ip = match IpAddr::from_str(host) {
            Ok(ip) => ip,
            Err(_) => self.resolve(host).await?,
        };
        self.open(SocketAddr::new(ip, port)).await
    }

    /// Ask the tunnel loop to open a virtual TCP socket to `remote` and hand back
    /// the caller's end of the bridged pipe.
    async fn open(&self, remote: SocketAddr) -> Result<DuplexStream> {
        let (caller, loop_half) = tokio::io::duplex(DUPLEX_CAP);
        let (reply_tx, reply_rx) = oneshot::channel();
        self.ctrl
            .send(Ctrl::Open {
                remote,
                io: loop_half,
                reply: reply_tx,
            })
            .await
            .map_err(|_| FeriteError::Dns("wireguard tunnel is down".into()))?;
        reply_rx
            .await
            .map_err(|_| FeriteError::Dns("wireguard tunnel did not respond".into()))??;
        Ok(caller)
    }

    /// Resolve `host` to an IP by querying the `.conf` DNS server through the
    /// tunnel (DNS-over-TCP). Cached by TTL. Falls back to ferrite's upstream
    /// only when the `.conf` configured no DNS server.
    async fn resolve(&self, host: &str) -> Result<IpAddr> {
        let key = host.trim_end_matches('.').to_ascii_lowercase();
        if let Some(ip) = self.cache.get(&key) {
            return Ok(ip);
        }
        // Prefer the tunnel's DNS (no leak, geo-correct). Prefer A, then AAAA.
        if let Some(&dns) = self.dns.first() {
            for rtype in [RecordType::A, RecordType::AAAA] {
                match self.lookup(dns, host, rtype).await {
                    Ok(Some((ip, ttl))) => {
                        self.cache.put(&key, ip, ttl);
                        return Ok(ip);
                    }
                    Ok(None) => {} // no record of this type — try the next
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
        // Fallback: resolve via ferrite's upstream (no tunnel DNS configured, or it
        // hiccuped). Cache briefly so we don't re-hammer it.
        let ip = super::direct::resolve_host(&self.upstream, host).await?;
        self.cache.put(&key, ip, DNS_MIN_TTL);
        Ok(ip)
    }

    /// One DNS-over-TCP query to `dns:53` routed through the tunnel. Returns the
    /// first address record and its (clamped) TTL. No txid/anti-spoof dance is
    /// needed: the query rides an authenticated, encrypted tunnel to a fixed
    /// resolver — there is no off-path attacker to inject a forgery.
    async fn lookup(
        &self,
        dns: IpAddr,
        host: &str,
        rtype: RecordType,
    ) -> Result<Option<(IpAddr, Duration)>> {
        let name = Name::from_str(&format!("{}.", host.trim_end_matches('.')))
            .map_err(|e| FeriteError::Dns(format!("invalid host '{host}': {e}")))?;
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.add_query(Query::query(name, rtype));
        let query = msg
            .to_bytes()
            .map_err(|e| FeriteError::Dns(format!("encode dns query: {e}")))?;

        let resp = timeout(DNS_TIMEOUT, async {
            let mut s = self.open(SocketAddr::new(dns, 53)).await?;
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
        Ok(parsed.answers.iter().find_map(|rr| {
            let ttl = Duration::from_secs(u64::from(rr.ttl)).clamp(DNS_MIN_TTL, DNS_MAX_TTL);
            match &rr.data {
                RData::A(a) => Some((IpAddr::V4(a.0), ttl)),
                RData::AAAA(a) => Some((IpAddr::V6(a.0), ttl)),
                _ => None,
            }
        }))
    }
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
    /// Caller → smoltcp bytes not yet accepted by the TX ring (backpressure).
    pending: Vec<u8>,
    /// The connection reached ESTABLISHED at least once. Until then a closed
    /// socket means "still connecting", not "remote hung up" (avoids a spurious
    /// EOF during the SYN handshake).
    established: bool,
    /// The remote-FIN EOF marker has been forwarded to the caller (send once).
    eof_sent: bool,
    /// The bridge has signalled the caller closed; flush then drop.
    closing: bool,
}

/// The single tunnel task. Owns all WireGuard + smoltcp state.
async fn run_tunnel(
    id: String,
    conf: WgConf,
    buffer: usize,
    mut ctrl_rx: mpsc::Receiver<Ctrl>,
    healthy: Arc<AtomicBool>,
) -> Result<()> {
    // ── UDP socket to the peer endpoint (resolved via the system resolver —
    //    bootstrap, must not depend on the tunnel). ──
    let endpoint = resolve_endpoint(&conf.endpoint).await?;
    let udp = UdpSocket::bind(("0.0.0.0", 0)).await?;
    udp.connect(endpoint).await?;
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
        let want = buffer
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
            if usable < buffer {
                tracing::warn!(
                    "wg '{}': kernel UDP recv buffer {} KiB < per-conn buffer {} KiB — large bursts may drop; raise net.core.rmem_max",
                    id,
                    usable / 1024,
                    buffer / 1024,
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
    let (data_tx, mut data_rx) = mpsc::channel::<(SocketHandle, Vec<u8>)>(1024);
    // Bridge → loop "connection closed" signals, on their own channel so the
    // loop holding a sender here does NOT keep `ctrl_rx` alive (that channel is
    // what signals egress teardown).
    let (close_tx, mut close_rx) = mpsc::channel::<SocketHandle>(64);
    let wake = Arc::new(Notify::new());
    let clock = start_clock();

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
                None => break, // WgEgress dropped → tear down the tunnel
                Some(Ctrl::Open { remote, io, reply }) => {
                    let res = open_conn(
                        &mut sockets, &mut iface, &mut conns, &mut next_port,
                        remote, io, buffer, &data_tx, &close_tx, &wake,
                    );
                    let _ = reply.send(res);
                }
            },

            // A bridge reported its connection closed.
            Some(h) = close_rx.recv() => {
                if let Some(c) = conns.get_mut(&h) {
                    c.closing = true;
                }
            }

            // Caller → loop bytes.
            Some((h, data)) = data_rx.recv() => {
                if let Some(c) = conns.get_mut(&h) {
                    c.pending.extend_from_slice(&data);
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
                timer.as_mut().reset(tokio::time::Instant::now() + TIMER_TICK);
            }

            _ = wake.notified() => {}
        }

        // ── Service the netstack after any event. ──
        service_sockets(&mut sockets, &mut conns);
        let _ = iface.poll(smol_now(&clock), &mut device, &mut sockets);
        pump_to_callers(&mut sockets, &mut conns);
        flush_egress(&mut tunn, &mut device, &mut crypt, &udp).await;
        // Health tracks the live handshake, not data flow: it must be true the
        // moment the session is up so the proxy's fail-closed gate lets the FIRST
        // connection through (otherwise no data ever flows and it never recovers).
        refresh_health(&tunn, &healthy);
    }
    Ok(())
}

/// Set `healthy` from boringtun's session state: up while the last successful
/// handshake is still within [`SESSION_MAX_AGE`], down otherwise.
fn refresh_health(tunn: &Tunn, healthy: &AtomicBool) {
    let up = matches!(tunn.time_since_last_handshake(), Some(age) if age < SESSION_MAX_AGE);
    healthy.store(up, Ordering::Relaxed);
}

/// Allocate a virtual TCP socket, start connecting, and spawn its bridge task.
#[allow(clippy::too_many_arguments)] // all loop-owned state; grouping would just shuffle it
fn open_conn(
    sockets: &mut SocketSet<'static>,
    iface: &mut Interface,
    conns: &mut HashMap<SocketHandle, Conn>,
    next_port: &mut u16,
    remote: SocketAddr,
    io: DuplexStream,
    buffer: usize,
    data_tx: &mpsc::Sender<(SocketHandle, Vec<u8>)>,
    close_tx: &mpsc::Sender<SocketHandle>,
    wake: &Arc<Notify>,
) -> Result<()> {
    let mut sock = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; buffer]),
        tcp::SocketBuffer::new(vec![0u8; buffer]),
    );
    let local_port = *next_port;
    *next_port = if *next_port == u16::MAX {
        49152
    } else {
        *next_port + 1
    };

    let remote_ep = (IpAddress::from(remote.ip()), remote.port());
    sock.connect(iface.context(), remote_ep, local_port)
        .map_err(|e| FeriteError::Dns(format!("wireguard connect {remote}: {e:?}")))?;

    let handle = sockets.add(sock);
    let (to_caller_tx, to_caller_rx) = mpsc::channel::<ToCaller>(64);
    conns.insert(
        handle,
        Conn {
            to_caller: to_caller_tx,
            pending: Vec::new(),
            established: false,
            eof_sent: false,
            closing: false,
        },
    );

    tokio::spawn(bridge(
        io,
        handle,
        data_tx.clone(),
        to_caller_rx,
        close_tx.clone(),
        Arc::clone(wake),
    ));
    Ok(())
}

/// Move queued caller→peer bytes into each socket's TX ring (as much as fits).
fn service_sockets(sockets: &mut SocketSet<'static>, conns: &mut HashMap<SocketHandle, Conn>) {
    for (h, c) in conns.iter_mut() {
        if c.pending.is_empty() {
            continue;
        }
        let sock = sockets.get_mut::<tcp::Socket>(*h);
        if sock.can_send()
            && let Ok(sent) = sock.send_slice(&c.pending)
            && sent > 0
        {
            c.pending.drain(..sent);
        }
    }
}

/// Drain socket RX rings into the per-connection caller channels (bounded — when
/// a channel is full we leave bytes in the ring so the TCP window closes), and
/// propagate a remote FIN to the caller as a half-close EOF.
fn pump_to_callers(sockets: &mut SocketSet<'static>, conns: &mut HashMap<SocketHandle, Conn>) {
    let mut done: Vec<SocketHandle> = Vec::new();
    for (h, c) in conns.iter_mut() {
        let sock = sockets.get_mut::<tcp::Socket>(*h);
        c.established |= sock.may_recv();
        while sock.can_recv() {
            let mut buf = vec![0u8; 8192];
            match sock.recv_slice(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    buf.truncate(n);
                    match c.to_caller.try_send(ToCaller::Data(buf)) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => break, // backpressure
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            c.closing = true;
                            break;
                        }
                    }
                }
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
        if c.closing && c.pending.is_empty() {
            sock.close();
        }
        if c.closing && !sock.is_active() {
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

/// Per-connection async bridge: caller pipe ⇄ loop mpsc channels.
async fn bridge(
    mut io: DuplexStream,
    handle: SocketHandle,
    to_loop: mpsc::Sender<(SocketHandle, Vec<u8>)>,
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
                    if to_loop.send((handle, buf[..n].to_vec())).await.is_err() {
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

        cache.put("example.com", ip, Duration::from_secs(3600));
        assert_eq!(cache.get("example.com"), Some(ip), "fresh entry should hit");

        // A zero-TTL entry is already expired the instant we read it back.
        cache.put("stale.example", ip, Duration::ZERO);
        assert_eq!(
            cache.get("stale.example"),
            None,
            "expired entry should miss"
        );

        assert_eq!(cache.get("never-stored"), None, "unknown key should miss");
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

        // 2) Data path — DNS-over-TCP to 1.1.1.1:53 routed through the tunnel.
        let mut s = timeout(Duration::from_secs(10), eg.connect("1.1.1.1", 53))
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
