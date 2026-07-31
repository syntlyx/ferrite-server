//! The **kernel** WireGuard backend (Linux, `CAP_NET_ADMIN`).
//!
//! Instead of decrypting in-process, this backend creates a real `wireguard`
//! netdev over netlink and lets the kernel carry the tunnel: multicore crypto,
//! GSO/GRO, and real TCP sockets with autotuning — per-connection throughput
//! scales to the link instead of a configured window, and fq_codel on the
//! netdev keeps latency sane under load (no bufferbloat from a static buffer).
//!
//! Wiring per egress (all netlink, no shell-outs, torn down on drop):
//! * a `wireguard` link named [`ifname`] (deterministic from the egress id),
//!   configured via the `wireguard` genetlink family (key, peer, allowed-ips),
//! * the `.conf` addresses on that link,
//! * the allowed-ips as routes in a **dedicated table** [`table_id`] — plus an
//!   `unreachable` default guard when allowed-ips isn't a full tunnel, so
//!   traffic outside it fails instead of leaking out the WAN,
//! * `ip rule fwmark <mark> lookup <table>` — the *only* global routing state
//!   we touch, with `mark == table_id`. The main table is never modified:
//!   every egress socket gets `SO_MARK` set (CAP_NET_ADMIN, which this backend
//!   requires anyway) and `bind()`s to the tunnel address for its source IP.
//!   The mark — not the source address — is what steers the lookup, because
//!   VPN providers hand out the *same* interface address in every config
//!   (e.g. Proton's 10.2.0.2/32): with two such egresses, `from <addr>` rules
//!   are identical selectors and all tunnel traffic collapses into whichever
//!   table wins. The encrypted UDP to the peer endpoint carries no mark and
//!   keeps using the main table, so there is no routing loop by construction.
//!
//! Health mirrors the userspace backend: the last handshake must be younger
//! than `SESSION_MAX_AGE`. The kernel re-handshakes whenever traffic (including
//! persistent keepalives) needs a fresh session; as belt-and-braces for
//! keepalive-less confs, the monitor sends a tiny DNS probe through the tunnel
//! when the session grows stale (see `REHANDSHAKE_AFTER`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use futures_util::{StreamExt, TryStreamExt};
use netlink_packet_core::{NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload};
use netlink_packet_generic::GenlMessage;
use netlink_packet_wireguard::{
    WireguardAddressFamily, WireguardAllowedIp, WireguardAllowedIpAttr, WireguardAttribute,
    WireguardCmd, WireguardMessage, WireguardPeer, WireguardPeerAttribute,
};
use rtnetlink::packet_route::route::{RouteAttribute, RouteMessage, RouteType};
use rtnetlink::packet_route::rule::{RuleAction, RuleAttribute, RuleMessage};
use rtnetlink::{Handle, IpVersion, LinkUnspec, LinkWireguard, RouteMessageBuilder};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::timeout;

use ferrite_core::config::EgressConfig;
use ferrite_core::error::FeriteError;
use ferrite_upstream::ZoneRouter;

use super::super::ConnectError;
use super::conf::WgConf;
use super::dns::TunnelResolver;
use super::{
    DEFAULT_KEEPALIVE, DEFAULT_MTU, REHANDSHAKE_AFTER, SESSION_MAX_AGE, WG_CONNECT_TIMEOUT,
    resolve_endpoint, unix_now_secs,
};

/// How often the monitor polls the device for its last-handshake time.
const POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Minimum gap between session-warming probe packets (see module docs).
const KICK_MIN_GAP: Duration = Duration::from_secs(15);
/// Consecutive `WG_CMD_GET_DEVICE` failures before the netdev is rebuilt (it
/// was most likely deleted externally).
const GENL_FAIL_LIMIT: u32 = 3;
/// Setup retry backoff bounds (endpoint unresolvable at boot, netlink races).
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// `ip rule` priority for the per-egress fwmark rules — anywhere below the
/// local-table rule (0) and above the main-table rule (32766). Sharing one
/// priority is fine: each rule's fwmark selector matches only its own egress.
const RULE_PRIORITY: u32 = 16000;

// Raw errnos from netlink acks (no libc dependency for four constants).
const EPERM: i32 = 1;
const EEXIST: i32 = 17;
const ENODEV: i32 = 19;
const EOPNOTSUPP: i32 = 95;

/// One-shot availability probe result, set by [`detect`] at startup and read by
/// the façade's backend selection. Never probed lazily: egress construction is
/// synchronous, and a deterministic startup decision beats a per-egress race.
static KERNEL_STATUS: OnceLock<std::result::Result<(), String>> = OnceLock::new();

/// Whether the kernel backend came up in the [`detect`] probe.
pub(super) fn available() -> bool {
    matches!(KERNEL_STATUS.get(), Some(Ok(())))
}

/// Why the kernel backend is unavailable (for a forced `backend = "kernel"`).
pub(super) fn unavailable_reason() -> String {
    match KERNEL_STATUS.get() {
        Some(Err(e)) => e.clone(),
        Some(Ok(())) => unreachable!("caller checks available() first"),
        None => "kernel backend detection has not run".into(),
    }
}

/// Probe for kernel-WireGuard support (create + delete a throwaway wg link) and
/// cache the outcome. Called once from the binary at startup, before the proxy
/// is built; requires a tokio runtime.
pub(super) async fn detect() -> bool {
    let status = probe().await;
    match &status {
        Ok(()) => tracing::info!("kernel WireGuard backend available (netlink wg netdev)"),
        Err(e) => tracing::info!(
            "kernel WireGuard backend unavailable: {e}; wireguard egresses will use the userspace backend"
        ),
    }
    let _ = KERNEL_STATUS.set(status);
    available()
}

const PROBE_LINK: &str = "frt-probe0";

async fn probe() -> std::result::Result<(), String> {
    let (conn, rt, _) = rtnetlink::new_connection().map_err(|e| format!("netlink socket: {e}"))?;
    tokio::spawn(conn);
    if let Err(e) = rt
        .link()
        .add(LinkWireguard::new(PROBE_LINK).build())
        .execute()
        .await
    {
        match errno(&e) {
            // A leftover probe link from a crashed run still proves support.
            Some(EEXIST) => {}
            Some(EPERM) => return Err("missing CAP_NET_ADMIN".into()),
            Some(EOPNOTSUPP) => {
                return Err(
                    "the 'wireguard' kernel module is unavailable (modprobe wireguard on the host)"
                        .into(),
                );
            }
            _ => return Err(format!("create probe link: {e}")),
        }
    }
    if let Ok(Some(idx)) = link_index(&rt, PROBE_LINK).await {
        let _ = rt.link().del(idx).execute().await;
    }
    Ok(())
}

/// The kernel WireGuard backend. Cheap handle; the netdev is owned by a
/// supervisor task and deleted when this handle drops.
pub(super) struct KernelWg {
    id: String,
    /// The netdev, addresses, routes and rules are in place (connects may go).
    ready: Arc<AtomicBool>,
    healthy: Arc<AtomicBool>,
    /// Unix seconds of the last successful handshake (0 = never).
    last_handshake: Arc<AtomicU64>,
    /// Tunnel-local source addresses connections bind to (from `Address =`).
    bind4: Option<Ipv4Addr>,
    bind6: Option<Ipv6Addr>,
    /// `SO_MARK` for every socket of this egress (== [`table_id`]); the fwmark
    /// rule keys the routing on it, since the bind address may be shared with
    /// other egresses (identical provider confs).
    fwmark: u32,
    /// Host → IP through the tunnel, cached by TTL (shared with userspace).
    resolver: TunnelResolver,
    /// Dropped with the handle → the supervisor tears the netdev down.
    _shutdown: mpsc::Sender<()>,
}

impl KernelWg {
    /// Spawn the supervisor that brings up (and keeps up) the netdev. Must be
    /// called within a tokio runtime.
    pub(super) fn spawn(cfg: &EgressConfig, conf: WgConf, upstream: Arc<ZoneRouter>) -> Self {
        let id = cfg.id.clone();
        let bind4 = conf.addresses.iter().find_map(|(ip, _)| match ip {
            IpAddr::V4(v4) => Some(*v4),
            IpAddr::V6(_) => None,
        });
        let bind6 = conf.addresses.iter().find_map(|(ip, _)| match ip {
            IpAddr::V6(v6) => Some(*v6),
            IpAddr::V4(_) => None,
        });
        let dns = conf.dns.clone();
        let ready = Arc::new(AtomicBool::new(false));
        let healthy = Arc::new(AtomicBool::new(false));
        let last_handshake = Arc::new(AtomicU64::new(0));
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        tokio::spawn(supervise(
            id.clone(),
            conf,
            Arc::clone(&ready),
            Arc::clone(&healthy),
            Arc::clone(&last_handshake),
            shutdown_rx,
        ));

        Self {
            id: id.clone(),
            ready,
            healthy,
            last_handshake,
            bind4,
            bind6,
            fwmark: table_id(&id),
            resolver: TunnelResolver::new(id, dns, upstream),
            _shutdown: shutdown_tx,
        }
    }

    pub(super) fn id(&self) -> &str {
        &self.id
    }

    pub(super) fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    /// Seconds since the last successful handshake, `None` before the first one.
    pub(super) fn handshake_age_secs(&self) -> Option<u64> {
        match self.last_handshake.load(Ordering::Relaxed) {
            0 => None,
            at => Some(unix_now_secs().saturating_sub(at)),
        }
    }

    /// Open a tunneled TCP connection to `host:port`: a plain socket marked
    /// with the egress fwmark (which routes it into the wg netdev) and bound
    /// to the tunnel address (which gives it the tunnel-internal source IP).
    pub(super) async fn connect(
        &self,
        host: &str,
        port: u16,
    ) -> std::result::Result<TcpStream, ConnectError> {
        if !self.ready.load(Ordering::Relaxed) {
            return Err(ConnectError::egress(FeriteError::Dns(
                "kernel wireguard tunnel is down".into(),
            )));
        }
        let ip = match host.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => self
                .resolver
                .resolve(host, |addr| self.open_tcp(addr))
                .await
                .map_err(ConnectError::destination)?,
        };
        self.open_tcp(SocketAddr::new(ip, port)).await
    }

    /// One TCP connect bound to the tunnel-local address of the right family.
    /// Bind failures are egress-class (our side is broken); a refused or timed
    /// out connect is destination-class — the tunnel carried the SYN fine, and
    /// tunnel liveness is tracked separately by health.
    async fn open_tcp(&self, remote: SocketAddr) -> std::result::Result<TcpStream, ConnectError> {
        let (socket, bind) = match remote {
            SocketAddr::V4(_) => {
                let Some(b4) = self.bind4 else {
                    return Err(ConnectError::destination(FeriteError::Dns(
                        "tunnel has no IPv4 address".into(),
                    )));
                };
                (
                    TcpSocket::new_v4().map_err(io_egress)?,
                    SocketAddr::new(IpAddr::V4(b4), 0),
                )
            }
            SocketAddr::V6(_) => {
                let Some(b6) = self.bind6 else {
                    return Err(ConnectError::destination(FeriteError::Dns(
                        "tunnel has no IPv6 address".into(),
                    )));
                };
                (
                    TcpSocket::new_v6().map_err(io_egress)?,
                    SocketAddr::new(IpAddr::V6(b6), 0),
                )
            }
        };
        // The mark is load-bearing, not advisory: without it the lookup falls
        // through to the main table and the SYN leaves via the WAN with the
        // tunnel source address. Refuse the connect rather than leak.
        socket2::SockRef::from(&socket)
            .set_mark(self.fwmark)
            .map_err(io_egress)?;
        socket.bind(bind).map_err(io_egress)?;
        match timeout(WG_CONNECT_TIMEOUT, socket.connect(remote)).await {
            Err(_) => Err(ConnectError::destination(FeriteError::Dns(format!(
                "wireguard: connect {remote} timed out"
            )))),
            Ok(Err(e)) => Err(ConnectError::destination(FeriteError::Dns(format!(
                "wireguard: connect {remote}: {e}"
            )))),
            Ok(Ok(stream)) => {
                super::super::enable_keepalive(&stream);
                Ok(stream)
            }
        }
    }
}

fn io_egress(e: std::io::Error) -> ConnectError {
    ConnectError::egress(FeriteError::Dns(format!("kernel wireguard: {e}")))
}

/// Why one supervised run ended.
enum RunOutcome {
    /// The handle was dropped — the netdev has been torn down. Stop for good.
    Shutdown,
    /// Setup or monitoring failed; the supervisor backs off and rebuilds.
    Failed(String),
}

/// Bring the netdev up, monitor it, and rebuild it (with backoff) on failure.
/// Returns only when the egress handle is dropped; tears the netdev down then.
async fn supervise(
    id: String,
    conf: WgConf,
    ready: Arc<AtomicBool>,
    healthy: Arc<AtomicBool>,
    last_handshake: Arc<AtomicU64>,
    mut shutdown_rx: mpsc::Receiver<()>,
) {
    let ifname = ifname(&id);
    let table = table_id(&id);
    let mut backoff = INITIAL_BACKOFF;
    loop {
        let started = Instant::now();
        let outcome = run(
            &id,
            &conf,
            &ifname,
            table,
            &ready,
            &healthy,
            &last_handshake,
            &mut shutdown_rx,
        )
        .await;
        ready.store(false, Ordering::Relaxed);
        healthy.store(false, Ordering::Relaxed);
        match outcome {
            RunOutcome::Shutdown => {
                tracing::debug!("wg '{id}': egress dropped, netdev torn down");
                return;
            }
            RunOutcome::Failed(e) => {
                if started.elapsed() >= Duration::from_secs(60) {
                    backoff = INITIAL_BACKOFF;
                }
                tracing::warn!(
                    "proxy: kernel wireguard egress '{id}' failed: {e}; rebuilding in {backoff:?}"
                );
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = shutdown_rx.recv() => return, // dropped during backoff — nothing is up
                }
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}

/// Netlink state for one run of the tunnel (one netdev generation).
struct NetState {
    rt: Handle,
    genl: genetlink::GenetlinkHandle,
    if_index: u32,
    /// Rules and routes we added, replayed as deletes on teardown. (Device
    /// routes die with the link; the `unreachable` guards and the rules would
    /// otherwise outlive it.)
    rules: Vec<RuleMessage>,
    routes: Vec<RouteMessage>,
}

#[allow(clippy::too_many_arguments)] // all supervisor-owned state; a struct would just shuffle it
async fn run(
    id: &str,
    conf: &WgConf,
    ifname: &str,
    table: u32,
    ready: &AtomicBool,
    healthy: &AtomicBool,
    last_handshake: &AtomicU64,
    shutdown_rx: &mut mpsc::Receiver<()>,
) -> RunOutcome {
    let mut state = match bring_up(id, conf, ifname, table).await {
        Ok(s) => s,
        Err(e) => return RunOutcome::Failed(e),
    };
    ready.store(true, Ordering::Relaxed);
    tracing::info!("wg '{id}': kernel netdev '{ifname}' up (table {table})");

    let kick = kick_target(conf);
    let mut last_kick: Option<Instant> = None;
    let mut genl_fails: u32 = 0;
    let mut poll = tokio::time::interval(POLL_INTERVAL);
    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                // Handle dropped (config reload / shutdown) — remove everything.
                tear_down(&state, ifname).await;
                return RunOutcome::Shutdown;
            }
            _ = poll.tick() => {}
        }

        match wg_last_handshake(&mut state.genl, ifname).await {
            Ok(handshake) => {
                genl_fails = 0;
                let age = handshake.map(|at| unix_now_secs().saturating_sub(at));
                if let Some(at) = handshake {
                    last_handshake.store(at, Ordering::Relaxed);
                }
                healthy.store(
                    matches!(age, Some(a) if a < SESSION_MAX_AGE.as_secs()),
                    Ordering::Relaxed,
                );
                // Session missing or growing stale: the kernel only handshakes
                // when something sends, so give it something to send. Keepalives
                // normally cover this; the probe is the keepalive-less fallback.
                let stale = match age {
                    None => true,
                    Some(a) => a >= REHANDSHAKE_AFTER.as_secs(),
                };
                let gap_ok = last_kick.is_none_or(|at| at.elapsed() >= KICK_MIN_GAP);
                if stale
                    && gap_ok
                    && let Some(target) = kick
                {
                    send_kick(conf, target, table).await;
                    last_kick = Some(Instant::now());
                }
            }
            Err(e) => {
                genl_fails += 1;
                healthy.store(false, Ordering::Relaxed);
                if genl_fails >= GENL_FAIL_LIMIT {
                    // The device is most likely gone (deleted externally) —
                    // rebuild from scratch. Best-effort cleanup of the rest.
                    tear_down(&state, ifname).await;
                    return RunOutcome::Failed(format!("device poll failed {genl_fails}x: {e}"));
                }
            }
        }
    }
}

/// Create and fully wire the netdev. On any error the partially-created state
/// is removed before returning (the next attempt starts from a clean slate).
async fn bring_up(
    id: &str,
    conf: &WgConf,
    ifname: &str,
    table: u32,
) -> std::result::Result<NetState, String> {
    let (conn, rt, _) = rtnetlink::new_connection().map_err(|e| format!("netlink socket: {e}"))?;
    tokio::spawn(conn);
    let (gconn, genl, _) =
        genetlink::new_connection().map_err(|e| format!("genetlink socket: {e}"))?;
    tokio::spawn(gconn);

    // The peer endpoint is resolved via the system resolver on every build
    // (bootstrap — must not depend on the tunnel), so DDNS moves recover.
    let endpoint = resolve_endpoint(&conf.endpoint)
        .await
        .map_err(|e| e.to_string())?;

    // A previous run of this egress (crash, kill -9) may have left the link,
    // rules or guard routes behind — sweep them before building.
    clean_slate(&rt, ifname, table).await;

    let mut state = NetState {
        rt,
        genl,
        if_index: 0,
        rules: Vec::new(),
        routes: Vec::new(),
    };
    if let Err(e) = wire_up(&mut state, conf, ifname, table, endpoint).await {
        tear_down(&state, ifname).await;
        return Err(e);
    }
    let _ = id; // attribution lives in the caller's logs
    Ok(state)
}

/// The actual netlink sequence: link → wg config → addresses → mtu/up →
/// routes → rules. Split out so `bring_up` can tear down on any failure.
async fn wire_up(
    state: &mut NetState,
    conf: &WgConf,
    ifname: &str,
    table: u32,
    endpoint: SocketAddr,
) -> std::result::Result<(), String> {
    state
        .rt
        .link()
        .add(LinkWireguard::new(ifname).build())
        .execute()
        .await
        .map_err(|e| match errno(&e) {
            Some(EPERM) => "create link: missing CAP_NET_ADMIN".to_string(),
            Some(EOPNOTSUPP) => "create link: 'wireguard' kernel module unavailable".to_string(),
            _ => format!("create link '{ifname}': {e}"),
        })?;
    state.if_index = link_index(&state.rt, ifname)
        .await?
        .ok_or_else(|| format!("link '{ifname}' vanished after create"))?;

    wg_configure(&mut state.genl, ifname, conf, endpoint).await?;

    for (ip, prefix) in &conf.addresses {
        state
            .rt
            .address()
            .add(state.if_index, *ip, *prefix)
            .execute()
            .await
            .map_err(|e| format!("add address {ip}/{prefix}: {e}"))?;
    }

    let mtu = conf.mtu.unwrap_or(DEFAULT_MTU as u32);
    state
        .rt
        .link()
        .set(
            LinkUnspec::new_with_index(state.if_index)
                .mtu(mtu)
                .up()
                .build(),
        )
        .execute()
        .await
        .map_err(|e| format!("set mtu/up: {e}"))?;

    // Routes: the allowed-ips networks via the netdev, in our dedicated table.
    let allowed = effective_allowed_ips(conf);
    for (ip, prefix) in &allowed {
        let msg = match ip {
            IpAddr::V4(v4) => RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(*v4, *prefix)
                .output_interface(state.if_index)
                .table_id(table)
                .build(),
            IpAddr::V6(v6) => RouteMessageBuilder::<Ipv6Addr>::new()
                .destination_prefix(*v6, *prefix)
                .output_interface(state.if_index)
                .table_id(table)
                .build(),
        };
        state
            .rt
            .route()
            .add(msg.clone())
            .execute()
            .await
            .map_err(|e| format!("add route {ip}/{prefix}: {e}"))?;
        state.routes.push(msg);
    }
    // Leak guards: when allowed-ips is not a full tunnel, a destination outside
    // it must fail here — without these the lookup would fall through to the
    // main table and leave via the WAN with the tunnel source address.
    let has_v4_default = allowed.iter().any(|(ip, p)| ip.is_ipv4() && *p == 0);
    let has_v6_default = allowed.iter().any(|(ip, p)| ip.is_ipv6() && *p == 0);
    if !has_v4_default && conf.addresses.iter().any(|(ip, _)| ip.is_ipv4()) {
        let msg = RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
            .table_id(table)
            .kind(RouteType::Unreachable)
            .build();
        state
            .rt
            .route()
            .add(msg.clone())
            .execute()
            .await
            .map_err(|e| format!("add v4 unreachable guard: {e}"))?;
        state.routes.push(msg);
    }
    if !has_v6_default && conf.addresses.iter().any(|(ip, _)| ip.is_ipv6()) {
        let msg = RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix(Ipv6Addr::UNSPECIFIED, 0)
            .table_id(table)
            .kind(RouteType::Unreachable)
            .build();
        state
            .rt
            .route()
            .add(msg.clone())
            .execute()
            .await
            .map_err(|e| format!("add v6 unreachable guard: {e}"))?;
        state.routes.push(msg);
    }

    // Steering rules: `fwmark <table> lookup <table>` — what routes a marked
    // socket into the tunnel without touching the main table. Keyed on the
    // mark, NOT the source address: identical provider confs give several
    // egresses the same tunnel address, and `from <addr>` rules would then all
    // match the same sockets, collapsing every tunnel into one table.
    if conf.addresses.iter().any(|(ip, _)| ip.is_ipv4()) {
        let mut req = state
            .rt
            .rule()
            .add()
            .v4()
            .fw_mark(table)
            .table_id(table)
            .priority(RULE_PRIORITY)
            .action(RuleAction::ToTable);
        let msg = req.message_mut().clone();
        req.execute()
            .await
            .map_err(|e| format!("add v4 rule: {e}"))?;
        state.rules.push(msg);
    }
    if conf.addresses.iter().any(|(ip, _)| ip.is_ipv6()) {
        let mut req = state
            .rt
            .rule()
            .add()
            .v6()
            .fw_mark(table)
            .table_id(table)
            .priority(RULE_PRIORITY)
            .action(RuleAction::ToTable);
        let msg = req.message_mut().clone();
        req.execute()
            .await
            .map_err(|e| format!("add v6 rule: {e}"))?;
        state.rules.push(msg);
    }
    Ok(())
}

/// Delete everything this run created: rules first (stop steering traffic),
/// then the link (device routes die with it), then any surviving table routes
/// (the `unreachable` guards have no device). All best-effort.
async fn tear_down(state: &NetState, ifname: &str) {
    for rule in &state.rules {
        let _ = state.rt.rule().del(rule.clone()).execute().await;
    }
    if let Ok(Some(idx)) = link_index(&state.rt, ifname).await {
        let _ = state.rt.link().del(idx).execute().await;
    }
    for route in &state.routes {
        // Routes through the link are already gone with it; only the guards
        // remain. Deleting an already-gone route is a harmless ENOENT/ESRCH.
        let _ = state.rt.route().del(route.clone()).execute().await;
    }
}

/// Remove leftovers of a previous process generation (deterministic names make
/// them findable): the link by name, rules and routes by our table id.
async fn clean_slate(rt: &Handle, ifname: &str, table: u32) {
    if let Ok(Some(idx)) = link_index(rt, ifname).await {
        tracing::info!("wg: removing stale netdev '{ifname}' from a previous run");
        let _ = rt.link().del(idx).execute().await;
    }
    for version in [IpVersion::V4, IpVersion::V6] {
        let mut rules = rt.rule().get(version).execute();
        while let Ok(Some(msg)) = rules.try_next().await {
            if rule_table(&msg) == Some(table) {
                let _ = rt.rule().del(msg).execute().await;
            }
        }
    }
    let v4_filter = RouteMessageBuilder::<Ipv4Addr>::new()
        .table_id(table)
        .build();
    flush_table_routes(rt, v4_filter, table).await;
    let v6_filter = RouteMessageBuilder::<Ipv6Addr>::new()
        .table_id(table)
        .build();
    flush_table_routes(rt, v6_filter, table).await;
}

async fn flush_table_routes(rt: &Handle, filter: RouteMessage, table: u32) {
    let mut routes = rt.route().get(filter).execute();
    while let Ok(Some(msg)) = routes.try_next().await {
        if route_table(&msg) == table {
            let _ = rt.route().del(msg).execute().await;
        }
    }
}

/// The table a rule points at — tables > 255 live in the `Table` attribute,
/// smaller ones in the header byte.
fn rule_table(msg: &RuleMessage) -> Option<u32> {
    msg.attributes
        .iter()
        .find_map(|a| match a {
            RuleAttribute::Table(t) => Some(*t),
            _ => None,
        })
        .or({
            let t = msg.header.table as u32;
            (t != 0).then_some(t)
        })
}

/// Same header-byte/attribute split for routes.
fn route_table(msg: &RouteMessage) -> u32 {
    msg.attributes
        .iter()
        .find_map(|a| match a {
            RouteAttribute::Table(t) => Some(*t),
            _ => None,
        })
        .unwrap_or(msg.header.table as u32)
}

/// Find a link's ifindex by name; `Ok(None)` when it doesn't exist.
async fn link_index(rt: &Handle, name: &str) -> std::result::Result<Option<u32>, String> {
    let mut links = rt.link().get().match_name(name.to_string()).execute();
    match links.try_next().await {
        Ok(link) => Ok(link.map(|l| l.header.index)),
        Err(e) if errno_rt(&e) == Some(ENODEV) => Ok(None),
        Err(e) => Err(format!("lookup link '{name}': {e}")),
    }
}

/// Push the device configuration over the `wireguard` genetlink family.
async fn wg_configure(
    genl: &mut genetlink::GenetlinkHandle,
    ifname: &str,
    conf: &WgConf,
    endpoint: SocketAddr,
) -> std::result::Result<(), String> {
    let mut peer = vec![
        WireguardPeerAttribute::PublicKey(conf.peer_public_key),
        WireguardPeerAttribute::Endpoint(endpoint),
        // Same default as the userspace backend: an always-on egress behind NAT
        // needs keepalives or an idle session expires. Explicit 0 is respected.
        WireguardPeerAttribute::PersistentKeepalive(
            conf.persistent_keepalive.unwrap_or(DEFAULT_KEEPALIVE),
        ),
        WireguardPeerAttribute::AllowedIps(allowed_ip_attrs(&effective_allowed_ips(conf))),
    ];
    if let Some(psk) = conf.preshared_key {
        peer.push(WireguardPeerAttribute::PresharedKey(psk));
    }
    let genlmsg: GenlMessage<WireguardMessage> = GenlMessage::from_payload(WireguardMessage {
        cmd: WireguardCmd::SetDevice,
        attributes: vec![
            WireguardAttribute::IfName(ifname.to_string()),
            WireguardAttribute::PrivateKey(conf.private_key),
            WireguardAttribute::Peers(vec![WireguardPeer(peer)]),
        ],
    });
    let mut nlmsg = NetlinkMessage::from(genlmsg);
    nlmsg.header.flags = NLM_F_REQUEST | NLM_F_ACK;
    let mut responses = genl
        .request(nlmsg)
        .await
        .map_err(|e| format!("wg set '{ifname}': {e}"))?;
    while let Some(m) = responses.next().await {
        let m = m.map_err(|e| format!("wg set '{ifname}': {e}"))?;
        if let NetlinkPayload::Error(err) = m.payload
            && err.code.is_some()
        {
            return Err(format!("wg set '{ifname}': {}", err.to_io()));
        }
    }
    Ok(())
}

/// Read the peer's last-handshake time (unix seconds); `None` = never.
async fn wg_last_handshake(
    genl: &mut genetlink::GenetlinkHandle,
    ifname: &str,
) -> std::result::Result<Option<u64>, String> {
    let genlmsg: GenlMessage<WireguardMessage> = GenlMessage::from_payload(WireguardMessage {
        cmd: WireguardCmd::GetDevice,
        attributes: vec![WireguardAttribute::IfName(ifname.to_string())],
    });
    let mut nlmsg = NetlinkMessage::from(genlmsg);
    nlmsg.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    let mut responses = genl
        .request(nlmsg)
        .await
        .map_err(|e| format!("wg get '{ifname}': {e}"))?;
    let mut latest: Option<u64> = None;
    while let Some(m) = responses.next().await {
        let m = m.map_err(|e| format!("wg get '{ifname}': {e}"))?;
        match m.payload {
            NetlinkPayload::InnerMessage(genl_msg) => {
                for attr in genl_msg.payload.attributes {
                    let WireguardAttribute::Peers(peers) = attr else {
                        continue;
                    };
                    for WireguardPeer(peer_attrs) in peers {
                        for pa in peer_attrs {
                            if let WireguardPeerAttribute::LastHandshake(ts) = pa
                                && ts.seconds > 0
                            {
                                let at = ts.seconds as u64;
                                latest = Some(latest.map_or(at, |cur| cur.max(at)));
                            }
                        }
                    }
                }
            }
            NetlinkPayload::Error(err) if err.code.is_some() => {
                return Err(format!("wg get '{ifname}': {}", err.to_io()));
            }
            _ => {}
        }
    }
    Ok(latest)
}

/// A tiny DNS query sent through the tunnel to make the kernel (re)handshake —
/// the response is irrelevant, the *send* is what arms the session. Marked like
/// every other egress socket; unmarked it would miss the fwmark rule and leave
/// via the WAN (never reaching the tunnel it is supposed to warm).
async fn send_kick(conf: &WgConf, target: SocketAddr, fwmark: u32) {
    let bind = conf
        .addresses
        .iter()
        .find_map(|(ip, _)| (ip.is_ipv4() == target.is_ipv4()).then_some(SocketAddr::new(*ip, 0)));
    let Some(bind) = bind else { return };
    let Ok(sock) = UdpSocket::bind(bind).await else {
        return;
    };
    if socket2::SockRef::from(&sock).set_mark(fwmark).is_err() {
        return;
    }
    let _ = sock.send_to(&kick_query(), target).await;
}

/// A well-formed (if pointless) DNS A query — politer than garbage bytes when
/// the kick target is a resolver.
fn kick_query() -> Vec<u8> {
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use hickory_proto::serialize::binary::BinEncodable;
    use std::str::FromStr;
    let mut msg = Message::new(0x6672, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    if let Ok(name) = Name::from_str("example.com.") {
        msg.add_query(Query::query(name, RecordType::A));
    }
    msg.to_bytes().unwrap_or_default()
}

/// Where to send the session-warming probe: the `.conf` DNS server if any,
/// else a public resolver when the tunnel covers it, else nowhere (rely on
/// keepalives and real traffic).
fn kick_target(conf: &WgConf) -> Option<SocketAddr> {
    if let Some(&dns) = conf.dns.first() {
        return Some(SocketAddr::new(dns, 53));
    }
    let fallback = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    effective_allowed_ips(conf)
        .iter()
        .any(|net| cidr_contains(*net, fallback))
        .then_some(SocketAddr::new(fallback, 53))
}

/// The networks routed through the peer. An empty `AllowedIPs` (or a `.conf`
/// without one) means full tunnel — mirroring what every provider conf spells
/// out explicitly.
fn effective_allowed_ips(conf: &WgConf) -> Vec<(IpAddr, u8)> {
    if conf.allowed_ips.is_empty() {
        vec![
            (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        ]
    } else {
        conf.allowed_ips.clone()
    }
}

fn allowed_ip_attrs(list: &[(IpAddr, u8)]) -> Vec<WireguardAllowedIp> {
    list.iter()
        .map(|(ip, prefix)| {
            let family = match ip {
                IpAddr::V4(_) => WireguardAddressFamily::Ipv4,
                IpAddr::V6(_) => WireguardAddressFamily::Ipv6,
            };
            WireguardAllowedIp(vec![
                WireguardAllowedIpAttr::Family(family),
                WireguardAllowedIpAttr::IpAddr(*ip),
                WireguardAllowedIpAttr::Cidr(*prefix),
            ])
        })
        .collect()
}

/// Does `net` (address + prefix) contain `ip`? Families must match.
fn cidr_contains(net: (IpAddr, u8), ip: IpAddr) -> bool {
    match (net.0, ip) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            let bits = 32u32.saturating_sub(net.1 as u32);
            let mask = if bits >= 32 { 0 } else { u32::MAX << bits };
            (u32::from(n) & mask) == (u32::from(a) & mask)
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            let bits = 128u32.saturating_sub(net.1 as u32);
            let mask = if bits >= 128 { 0 } else { u128::MAX << bits };
            (u128::from(n) & mask) == (u128::from(a) & mask)
        }
        _ => false,
    }
}

/// Deterministic netdev name for an egress id: `frt-`, a readable slug prefix,
/// then a hash tail — ≤ 15 chars (IFNAMSIZ − NUL). The hash keeps two egresses
/// whose ids share a 7-char prefix from colliding.
fn ifname(id: &str) -> String {
    let slug: String = id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(7)
        .collect();
    format!("frt-{slug}{:04x}", fnv1a32(id) & 0xFFFF)
}

/// Deterministic routing-table id: a private 20-bit space under 0x666, far
/// from the reserved tables (253–255) and anything a human would type.
fn table_id(id: &str) -> u32 {
    0x6660_0000 | (fnv1a32(id) & 0xF_FFFF)
}

fn fnv1a32(s: &str) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for b in s.as_bytes() {
        hash ^= *b as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

/// Raw errno from an rtnetlink error ack, if that's what it is.
fn errno(e: &rtnetlink::Error) -> Option<i32> {
    errno_rt(e)
}

fn errno_rt(e: &rtnetlink::Error) -> Option<i32> {
    match e {
        rtnetlink::Error::NetlinkError(msg) => msg.to_io().raw_os_error(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ifname_is_deterministic_short_and_collision_resistant() {
        let a = ifname("my-tunnel");
        assert_eq!(a, ifname("my-tunnel"), "must be deterministic");
        assert!(a.len() <= 15, "IFNAMSIZ-1: {a}");
        assert!(a.starts_with("frt-"));
        // Same 7-char prefix, different ids → different names via the hash tail.
        assert_ne!(ifname("proton-nl-1"), ifname("proton-nl-2"));
        // Non-alphanumerics don't break the name.
        let odd = ifname("weird id!!");
        assert!(odd.len() <= 15 && odd.starts_with("frt-"));
    }

    #[test]
    fn table_id_stays_in_private_range() {
        for id in ["a", "lab", "proton-nl-1", "x".repeat(64).as_str()] {
            let t = table_id(id);
            assert!(
                (0x6660_0000..=0x666F_FFFF).contains(&t),
                "table {t:#x} out of range for '{id}'"
            );
        }
        assert_eq!(table_id("lab"), table_id("lab"));
    }

    #[test]
    fn cidr_contains_matches_prefixes() {
        let net4 = ("10.2.0.0".parse().unwrap(), 16);
        assert!(cidr_contains(net4, "10.2.13.7".parse().unwrap()));
        assert!(!cidr_contains(net4, "10.3.0.1".parse().unwrap()));
        let all4 = ("0.0.0.0".parse().unwrap(), 0);
        assert!(cidr_contains(all4, "1.1.1.1".parse().unwrap()));
        let all6 = ("::".parse().unwrap(), 0);
        assert!(cidr_contains(all6, "2606:4700::1111".parse().unwrap()));
        assert!(
            !cidr_contains(all6, "1.1.1.1".parse().unwrap()),
            "family mismatch"
        );
        let host = ("10.2.0.2".parse().unwrap(), 32);
        assert!(cidr_contains(host, "10.2.0.2".parse().unwrap()));
        assert!(!cidr_contains(host, "10.2.0.3".parse().unwrap()));
    }

    #[test]
    fn kick_target_prefers_conf_dns_then_covered_fallback() {
        let mut conf = sample_conf();
        assert_eq!(
            kick_target(&conf),
            Some("10.2.0.1:53".parse().unwrap()),
            "conf DNS wins"
        );
        conf.dns.clear();
        assert_eq!(
            kick_target(&conf),
            Some("1.1.1.1:53".parse().unwrap()),
            "full tunnel covers the public fallback"
        );
        conf.allowed_ips = vec![("10.2.0.0".parse().unwrap(), 16)];
        assert_eq!(kick_target(&conf), None, "split tunnel, no DNS → no kick");
    }

    #[test]
    fn effective_allowed_ips_defaults_to_full_tunnel() {
        let mut conf = sample_conf();
        conf.allowed_ips.clear();
        let ips = effective_allowed_ips(&conf);
        assert!(ips.contains(&(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)));
        assert!(ips.contains(&(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)));
    }

    fn sample_conf() -> WgConf {
        WgConf {
            private_key: [1u8; 32],
            addresses: vec![("10.2.0.2".parse().unwrap(), 32)],
            dns: vec!["10.2.0.1".parse().unwrap()],
            mtu: None,
            peer_public_key: [2u8; 32],
            preshared_key: None,
            endpoint: "127.0.0.1:51820".into(),
            allowed_ips: vec![("0.0.0.0".parse().unwrap(), 0), ("::".parse().unwrap(), 0)],
            persistent_keepalive: Some(25),
        }
    }

    /// Full netdev lifecycle against a real kernel — needs CAP_NET_ADMIN and
    /// the wireguard module (run in Docker: `--cap-add=NET_ADMIN`). No live
    /// peer required: it validates create → configure → addr/route/rule →
    /// teardown, not the handshake.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs CAP_NET_ADMIN + wireguard kernel module"]
    async fn netdev_lifecycle_up_and_down() {
        assert!(
            detect().await,
            "kernel backend must be detected in this env"
        );

        let conf = sample_conf();
        let name = ifname("lifecycle");
        let table = table_id("lifecycle");
        let state = bring_up("lifecycle", &conf, &name, table)
            .await
            .expect("bring up netdev");

        let (c, rt, _) = rtnetlink::new_connection().unwrap();
        tokio::spawn(c);
        assert!(
            link_index(&rt, &name).await.unwrap().is_some(),
            "netdev must exist after bring_up"
        );

        // Idempotence under leftovers: a second clean_slate + bring_up cycle
        // must succeed even though everything already exists.
        clean_slate(&rt, &name, table).await;
        assert!(
            link_index(&rt, &name).await.unwrap().is_none(),
            "clean_slate must remove the netdev"
        );
        let state2 = bring_up("lifecycle", &conf, &name, table)
            .await
            .expect("second bring_up after clean_slate");

        tear_down(&state2, &name).await;
        let _ = state;
        assert!(
            link_index(&rt, &name).await.unwrap().is_none(),
            "tear_down must remove the netdev"
        );
    }

    /// Two egresses with the SAME tunnel address — how provider confs ship
    /// (e.g. Proton assigns 10.2.0.2/32 in every config) — must be
    /// independently routable: one fwmark rule per egress, each to its own
    /// table. The former source-address rules were identical selectors here,
    /// which collapsed both tunnels into whichever table won (the "NL exits
    /// with the US IP, both probes show the same RTT" bug).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs CAP_NET_ADMIN + wireguard kernel module"]
    async fn same_address_egresses_get_distinct_fwmark_rules() {
        assert!(
            detect().await,
            "kernel backend must be detected in this env"
        );

        let conf = sample_conf(); // both egresses share 10.2.0.2/32
        let (name_a, table_a) = (ifname("dup-nl"), table_id("dup-nl"));
        let (name_b, table_b) = (ifname("dup-us"), table_id("dup-us"));
        assert_ne!(
            table_a, table_b,
            "distinct ids must hash to distinct tables"
        );

        let state_a = bring_up("dup-nl", &conf, &name_a, table_a)
            .await
            .expect("bring up first egress");
        let state_b = bring_up("dup-us", &conf, &name_b, table_b)
            .await
            .expect("bring up second egress with the same address");

        // Every rule pointing at our tables must select on the table's own
        // fwmark — that is what keeps the two same-address egresses apart.
        let (c, rt, _) = rtnetlink::new_connection().unwrap();
        tokio::spawn(c);
        let mut ours: Vec<(Option<u32>, u32)> = Vec::new();
        let mut rules = rt.rule().get(IpVersion::V4).execute();
        while let Ok(Some(msg)) = rules.try_next().await {
            let Some(t) = rule_table(&msg) else { continue };
            if t == table_a || t == table_b {
                let mark = msg.attributes.iter().find_map(|a| match a {
                    RuleAttribute::FwMark(m) => Some(*m),
                    _ => None,
                });
                ours.push((mark, t));
            }
        }
        ours.sort_unstable();
        let mut want = vec![(Some(table_a), table_a), (Some(table_b), table_b)];
        want.sort_unstable();
        assert_eq!(ours, want, "one fwmark rule per egress, mark == table");

        tear_down(&state_a, &name_a).await;
        tear_down(&state_b, &name_b).await;
    }

    /// Real end-to-end check of the kernel backend against a live WireGuard
    /// peer: handshake, health, and a DNS-over-TCP exchange routed through the
    /// netdev. Needs CAP_NET_ADMIN + the wireguard module + network + a real
    /// `.conf`:
    ///
    /// ```text
    /// docker run --rm --cap-add=NET_ADMIN -v /path/wg.conf:/wg.conf \
    ///   -e WG_SMOKE_CONF=/wg.conf -v "$PWD":/w -w /w rust:latest \
    ///   cargo test -p ferrite-proxy kernel::tests::smoke -- --ignored --nocapture
    /// ```
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs CAP_NET_ADMIN + wireguard module + network + WG_SMOKE_CONF"]
    async fn smoke_handshake_and_data_path() {
        use ferrite_core::config::UpstreamConfig;
        use ferrite_upstream::{UpstreamPool, no_proxy};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        assert!(
            detect().await,
            "kernel backend must be detected in this env"
        );
        let path =
            std::env::var("WG_SMOKE_CONF").expect("set WG_SMOKE_CONF=/path/to/wireguard.conf");
        let text = std::fs::read_to_string(&path).expect("read conf file");
        let conf = super::super::parse(&text).expect("parse conf");

        let pool = UpstreamPool::from_config(
            &[UpstreamConfig::Plain {
                address: "1.1.1.1".into(),
                port: 53,
                egress: None,
            }],
            no_proxy(),
        )
        .expect("upstream pool");
        let upstream = ZoneRouter::new(&[], pool).expect("zone router");
        let cfg = EgressConfig {
            id: "ksmoke".into(),
            name: "ksmoke".into(),
            enabled: true,
            kind: "wireguard".into(),
            address: None,
            port: None,
            username: None,
            password: None,
            config: Some(text),
            seg_position: None,
            buffer_kb: None,
            tx_buffer_kb: None,
            backend: Some("kernel".into()),
        };
        let eg = KernelWg::spawn(&cfg, conf, upstream);

        // The first connect both waits out the netdev setup and triggers the
        // initial handshake (kernel WG handshakes on demand).
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut stream = loop {
            match eg.connect("1.1.1.1", 53).await {
                Ok(s) => break s,
                Err(e) => {
                    assert!(
                        Instant::now() < deadline,
                        "no tunneled connect within 30s: {e}"
                    );
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        };
        println!("[smoke] ✅ TCP through kernel netdev established");

        // DNS-over-TCP through the tunnel proves the full data path.
        let mut msg = kick_query();
        let mut framed = Vec::with_capacity(msg.len() + 2);
        framed.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        framed.append(&mut msg);
        stream.write_all(&framed).await.expect("write dns query");
        let mut len = [0u8; 2];
        timeout(Duration::from_secs(10), stream.read_exact(&mut len))
            .await
            .expect("dns read timed out")
            .expect("read dns length");
        let mut resp = vec![0u8; u16::from_be_bytes(len) as usize];
        timeout(Duration::from_secs(10), stream.read_exact(&mut resp))
            .await
            .expect("dns body timed out")
            .expect("read dns body");
        assert!(resp.len() > 12, "short dns response");
        println!(
            "[smoke] ✅ DNS-over-TCP through the tunnel ({} bytes)",
            resp.len()
        );

        // Health follows the handshake the poll observed.
        let deadline = Instant::now() + Duration::from_secs(15);
        while !eg.is_healthy() {
            assert!(
                Instant::now() < deadline,
                "handshake happened but health never flipped"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        println!(
            "[smoke] ✅ healthy, handshake age {:?}s",
            eg.handshake_age_secs()
        );

        // Hostname path: resolve through the tunnel DNS, connect, HTTP GET.
        let mut http = eg
            .connect("checkip.amazonaws.com", 80)
            .await
            .expect("hostname connect through tunnel");
        let req = b"GET / HTTP/1.0\r\nHost: checkip.amazonaws.com\r\nConnection: close\r\n\r\n";
        http.write_all(req).await.expect("write http");
        let mut body = Vec::new();
        let _ = timeout(Duration::from_secs(10), http.read_to_end(&mut body)).await;
        let text = String::from_utf8_lossy(&body);
        let exit_ip = text.lines().last().unwrap_or("").trim().to_string();
        println!("[smoke] ✅ exit IP through kernel tunnel (expect the VPN's): {exit_ip}");
        assert!(!exit_ip.is_empty(), "no exit IP came back");
    }
}
