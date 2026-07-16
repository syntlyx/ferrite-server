//! The transparent (redirect) proxy listeners.
//!
//! Clients connect here because DNS handed them our advertise IP — so these are
//! ordinary `accept()`ed connections, not TPROXY/IP_TRANSPARENT intercepts. We
//! peek the SNI/Host, re-match the routing rule on the real host (authoritative),
//! and splice the connection through the chosen egress (or direct if the client
//! reached us for a host we don't route).

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::app::AppState;

use super::egress::{
    ConnectErrorKind, EgressConn, EvasionParams, direct_connect, enable_keepalive, write_split,
};
use super::http_host::{HostResult, parse_http_host};
use super::sni::{SniResult, parse_sni};
use super::stats::{Counted, EgressStats};

const PEEK_TIMEOUT: Duration = Duration::from_secs(5);
const PEEK_CAP: usize = 16 * 1024;
/// Reap a spliced connection after this long with no bytes in EITHER direction.
/// `copy_bidirectional` has no idle timeout, so a keep-alive / HTTP-2 idle
/// session — or a half-closed one (the peer sent FIN but the client lingers) —
/// would otherwise hold its egress connection (for a WireGuard tunnel: a smoltcp
/// socket and its per-connection buffer) open until the client physically
/// disconnects. With many such idle sessions that buffer memory is the dominant
/// proxy cost, so once a connection goes quiet we close it; clients transparently
/// reconnect on next use. The OS TCP keepalive only reaps *dead* peers, not
/// alive-but-idle ones, so it does not cover this on its own.
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone, Copy)]
enum Protocol {
    Tls,
    Http,
}

impl Protocol {
    /// The real destination port (independent of the listener port, which may be
    /// remapped for non-root dev).
    fn upstream_port(self) -> u16 {
        match self {
            Protocol::Tls => 443,
            Protocol::Http => 80,
        }
    }
}

/// The listener supervisor. Binds the proxy listeners and **rebinds them live**
/// whenever the listener settings change (`enabled` / ports / connection cap), so
/// those take effect without a process restart. Runs for the life of the process;
/// a bind failure is logged and retried on the next change (DNS/API run in other
/// tasks, so the proxy never takes the server down).
pub async fn run(state: AppState) {
    let reload = state.inner.proxy.listener_reload();
    loop {
        // Arm the wake-up BEFORE reading config so a change that lands while we're
        // binding isn't lost (a `Notified` holds one permit once enabled).
        let wait = reload.notified();
        tokio::pin!(wait);
        wait.as_mut().enable();

        let session = start_session(&state).await;

        wait.await; // a listener-affecting field changed → rebind
        for h in &session {
            h.abort();
        }
        // Await the aborted accept loops so their TcpListeners are fully dropped
        // (port freed) before we rebind — possibly on the same port. In-flight
        // proxied connections run in their own tasks and are left to finish.
        for h in session {
            let _ = h.await;
        }
    }
}

/// Bind the listeners for the current settings and spawn their accept loops,
/// returning the loop handles (empty when disabled or nothing bound). The
/// connection-cap semaphore is session-local, so a changed cap applies on rebind.
async fn start_session(state: &AppState) -> Vec<tokio::task::JoinHandle<()>> {
    let cfg = state.inner.proxy.listener_cfg();
    if !cfg.enabled {
        tracing::info!("proxy: selective routing disabled");
        return Vec::new();
    }
    let semaphore = Arc::new(Semaphore::new(cfg.max_connections));
    let https = bind(cfg.https_port).await;
    // When the panel already owns the HTTP port, don't bind a second :80 — the
    // panel's listener demuxes by Host and forwards non-panel hosts here via
    // `forward_http`. Otherwise the proxy binds its own HTTP listener.
    let http = if cfg.http_port == state.inner.config.api.bind_addr.port() {
        tracing::info!(
            "proxy: HTTP routing shared with the panel listener on :{}",
            cfg.http_port
        );
        None
    } else {
        bind(cfg.http_port).await
    };
    if https.is_none() && http.is_none() {
        tracing::warn!("proxy: no proxy-owned listeners bound this session");
        return Vec::new();
    }

    let mut handles = Vec::new();
    if let Some(listener) = https {
        tracing::info!("proxy: TLS/SNI listener on 0.0.0.0:{}", cfg.https_port);
        handles.push(tokio::spawn(accept_loop(
            listener,
            state.clone(),
            Protocol::Tls,
            Arc::clone(&semaphore),
        )));
    }
    if let Some(listener) = http {
        tracing::info!("proxy: HTTP listener on 0.0.0.0:{}", cfg.http_port);
        handles.push(tokio::spawn(accept_loop(
            listener,
            state.clone(),
            Protocol::Http,
            Arc::clone(&semaphore),
        )));
    }
    handles
}

async fn bind(port: u16) -> Option<TcpListener> {
    match TcpListener::bind(("0.0.0.0", port)).await {
        Ok(l) => Some(l),
        Err(e) => {
            tracing::warn!("proxy: failed to bind 0.0.0.0:{port}: {e}");
            None
        }
    }
}

async fn accept_loop(
    listener: TcpListener,
    state: AppState,
    proto: Protocol,
    semaphore: Arc<Semaphore>,
) {
    loop {
        let (stream, src) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("proxy accept error: {e}");
                continue;
            }
        };
        // Each proxied connection holds a permit for its whole lifetime; shed
        // load by dropping new connections once the cap is reached.
        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                // WARN (not debug) so this is visible: a dropped connection here is
                // exactly the "loads, then doesn't" symptom — either raise
                // max_connections or connections are piling up (stalled/keep-alive).
                tracing::warn!("proxy: connection cap reached, dropping {src} (max_connections)");
                continue;
            }
        };
        let state = state.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle(stream, state, proto).await {
                tracing::debug!("proxy connection {src} ended: {e}");
            }
        });
    }
}

async fn handle(mut client: TcpStream, state: AppState, proto: Protocol) -> std::io::Result<()> {
    let _live = crate::memstats::PROXY_CONNS.guard();
    enable_keepalive(&client);

    // Peek the destination host from the first bytes.
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let host = loop {
        let mut tmp = [0u8; 4096];
        let n = match timeout(PEEK_TIMEOUT, client.read(&mut tmp)).await {
            Ok(Ok(0)) => return Ok(()), // client closed before sending a host
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Ok(()), // peek timed out
        };
        buf.extend_from_slice(&tmp[..n]);
        match proto {
            Protocol::Tls => match parse_sni(&buf) {
                SniResult::Found(h) => break h,
                SniResult::Incomplete => {}
                SniResult::NotFound => return Ok(()),
            },
            Protocol::Http => match parse_http_host(&buf) {
                HostResult::Found(h) => break h,
                HostResult::Incomplete => {}
                HostResult::NotFound => return Ok(()),
            },
        }
        if buf.len() > PEEK_CAP {
            return Ok(());
        }
    };

    splice_through(client, state, proto, host, buf).await
}

/// Forward an already-peeked HTTP connection through the proxy. Used by the shared
/// :80 listener (the panel) for non-panel hosts, so plain-HTTP routing works even
/// though the proxy itself doesn't bind :80 when the panel owns it.
pub(crate) async fn forward_http(state: AppState, client: TcpStream, buf: Vec<u8>, host: String) {
    enable_keepalive(&client);
    if let Err(e) = splice_through(client, state, Protocol::Http, host, buf).await {
        tracing::debug!("proxy: http forward ended: {e}");
    }
}

/// Route `host` to its egress (or forward-direct), replay the peeked `buf`, and
/// splice both directions. Shared by the proxy's own listeners and the panel's
/// :80 demux.
async fn splice_through(
    mut client: TcpStream,
    state: AppState,
    proto: Protocol,
    host: String,
    buf: Vec<u8>,
) -> std::io::Result<()> {
    let port = proto.upstream_port();

    // Identify the connecting client for client-scoped rules (canonicalize so an
    // IPv4-mapped IPv6 peer matches the registry's plain IPv4).
    let client_addr = client.peer_addr().ok().map(|a| a.ip().to_canonical());
    let client_ip = client_addr.map(|ip| ip.to_string()).unwrap_or_default();
    let client_mac = if state.inner.proxy.has_client_rules() {
        client_addr.and_then(|ip| state.inner.client_registry.get_mac(ip))
    } else {
        None
    };

    // Decide the egress from the actual SNI/Host (authoritative). Clone the
    // egress Arc out of the snapshot so the ArcSwap guard isn't held across the
    // connect await.
    let decision = {
        let snap = state.inner.proxy.registry.load();
        snap.route(&host, &client_ip, client_mac.as_deref())
            .map(|r| {
                (
                    Arc::clone(&snap.egresses[r.egress_idx]),
                    r.fail_closed,
                    r.pattern.clone(),
                )
            })
    };

    // ClientHello-fragmentation params, set only when the chosen egress is a
    // DirectEvasion egress and the connect succeeds (not on the direct fallback).
    let mut frag: Option<EvasionParams> = None;
    // Per-egress traffic counters, set only when the connection actually goes
    // through the egress — a fail-open fallback to direct and the unrouted plain
    // forward below are not tunnel traffic.
    let mut stats: Option<Arc<EgressStats>> = None;
    let conn: EgressConn = match decision {
        Some((egress, fail_closed, pattern)) => {
            let id = egress.id().to_string();
            state.inner.proxy.stats.record_rule_hit(&pattern, &id);
            let egress_stats = state.inner.proxy.stats.egress(&id);
            if fail_closed && !state.inner.proxy.is_egress_healthy(&id) {
                egress_stats.record_fail_closed_drop();
                tracing::debug!("proxy: egress '{id}' unhealthy → fail-closed drop of {host}");
                return Ok(());
            }
            match egress.connect(&host, port).await {
                Ok(c) => {
                    state.inner.proxy.note_success(&id);
                    frag = egress.evasion_params();
                    stats = Some(egress_stats);
                    c
                }
                Err(e) => {
                    egress_stats.record_connect_fail();
                    // Only an egress-transport failure counts against the breaker.
                    // A destination that's unreachable behind a healthy tunnel/proxy
                    // proves the transport works, so tripping the breaker on it would
                    // fail-close every *other* site for the cooldown (one dead domain
                    // taking the whole egress down). Leave the breaker untouched then.
                    match e.kind() {
                        ConnectErrorKind::Egress => state.inner.proxy.note_failure(&id),
                        ConnectErrorKind::Destination => {}
                    }
                    if fail_closed {
                        egress_stats.record_fail_closed_drop();
                        tracing::debug!(
                            "proxy: egress '{id}' failed ({e}) → fail-closed drop of {host}"
                        );
                        return Ok(());
                    }
                    tracing::debug!(
                        "proxy: egress '{id}' failed ({e}) → falling back to direct for {host}"
                    );
                    match direct_connect(&state.inner.upstream_pool, &host, port).await {
                        Ok(c) => EgressConn::Tcp(c),
                        Err(_) => return Ok(()),
                    }
                }
            }
        }
        None => {
            // The client reached us for a host we don't route (it used its own
            // resolver, or a stale cache entry). Act as a plain forwarder.
            match direct_connect(&state.inner.upstream_pool, &host, port).await {
                Ok(c) => EgressConn::Tcp(c),
                Err(e) => {
                    tracing::debug!("proxy: forward-direct to {host} failed: {e}");
                    return Ok(());
                }
            }
        }
    };

    // Count bytes through the (counting) wrapper and hold the active-connection
    // gauge for the splice's whole lifetime; both are no-ops for untracked
    // (non-egress) traffic.
    let mut conn = Counted::new(conn, stats.clone());
    let _active = stats.as_ref().map(|s| s.begin_conn(&host));

    // Replay the bytes we already consumed, then splice both directions. For an
    // evasion egress on a TLS connection the ClientHello replay is fragmented so
    // the SNI is split across TCP segments (DPI bypass); everything else is a
    // single write.
    let result = async {
        match frag {
            Some(p) if matches!(proto, Protocol::Tls) => write_split(&mut conn, &buf, &p).await?,
            _ => conn.write_all(&buf).await?,
        }
        copy_bidirectional_idle(&mut client, &mut conn, IDLE_TIMEOUT).await
    }
    .await;

    // Attribute the connection's totals to its domain even when the splice ends
    // with an error — those bytes still crossed the tunnel.
    if let Some(s) = &stats {
        let (up, down) = conn.transferred();
        s.add_domain_bytes(&host, up, down);
    }
    result
}

/// Splice bytes both ways between `a` and `b` until both directions close, an I/O
/// error occurs, or no byte flows in EITHER direction for `idle`.
///
/// This is `tokio::io::copy_bidirectional` plus an idle timeout — the timeout is
/// the whole point. Without it an idle keep-alive or half-closed connection pins
/// its egress connection (and, for a WireGuard tunnel, its rx+tx socket rings)
/// open indefinitely, which is what made proxy memory grow without bound.
/// The timer is reset on every transfer, so an active-but-slow stream (e.g. a long
/// download) is never cut off — only genuinely quiet connections are reaped.
///
/// A one-way EOF half-closes that direction (the peer can still send the other
/// way), matching `copy_bidirectional`; a returned idle timeout is reported as a
/// clean close (`Ok`), not an error.
///
/// The writes track *progress*, not total duration: each chunk is written via
/// [`write_all_progressing`], which reaps only if a single write makes no headway
/// for `idle`. So a peer that stops reading entirely (zero TCP window, frozen app)
/// is reaped, but a slow-but-steady transfer that takes longer than `idle` overall
/// is carried to completion — the exact leak fix without cutting live-but-slow
/// streams.
async fn copy_bidirectional_idle<A, B>(a: &mut A, b: &mut B, idle: Duration) -> std::io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf_a = vec![0u8; 16 * 1024];
    let mut buf_b = vec![0u8; 16 * 1024];
    let mut a_open = true; // a → b still flowing
    let mut b_open = true; // b → a still flowing

    let timer = tokio::time::sleep(idle);
    tokio::pin!(timer);

    while a_open || b_open {
        tokio::select! {
            r = a.read(&mut buf_a), if a_open => match r? {
                0 => {
                    a_open = false;
                    buf_a = Vec::new(); // direction closed for good — release its 16 KiB now
                    let _ = timeout(idle, b.shutdown()).await; // propagate EOF (half-close)
                }
                n => {
                    if !write_all_progressing(b, &buf_a[..n], idle).await? {
                        return Ok(()); // write stalled (no progress for idle) → reap
                    }
                    timer.as_mut().reset(tokio::time::Instant::now() + idle);
                }
            },
            r = b.read(&mut buf_b), if b_open => match r? {
                0 => {
                    b_open = false;
                    buf_b = Vec::new();
                    let _ = timeout(idle, a.shutdown()).await;
                }
                n => {
                    if !write_all_progressing(a, &buf_b[..n], idle).await? {
                        return Ok(());
                    }
                    timer.as_mut().reset(tokio::time::Instant::now() + idle);
                }
            },
            _ = &mut timer => return Ok(()), // idle too long → reap
        }
    }
    Ok(())
}

/// Write all of `data`, bounding each individual `write` by `idle` so a peer that
/// stops accepting bytes is reaped — but resetting that bound on every byte of
/// progress, so a slow-but-advancing writer is never cut off no matter the total
/// time. Returns `Ok(true)` when fully written, `Ok(false)` when a single write
/// made no progress within `idle` (the peer's receive window is stuck → the caller
/// reaps the splice), and propagates real I/O errors.
async fn write_all_progressing<W>(w: &mut W, data: &[u8], idle: Duration) -> std::io::Result<bool>
where
    W: AsyncWrite + Unpin,
{
    let mut rest = data;
    while !rest.is_empty() {
        match timeout(idle, w.write(rest)).await {
            Ok(Ok(0)) => return Ok(false), // writer won't accept more
            Ok(Ok(n)) => rest = &rest[n..],
            Ok(Err(e)) => return Err(e),
            Err(_) => return Ok(false), // no progress within idle → stall
        }
    }
    Ok(true)
}

#[cfg(test)]
mod splice_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    /// Bytes flow both ways and the splice returns cleanly once both ends EOF.
    #[tokio::test]
    async fn forwards_both_directions_then_closes_on_eof() {
        let (mut client, mut a) = duplex(1024);
        let (mut server, mut b) = duplex(1024);
        let task =
            tokio::spawn(
                async move { copy_bidirectional_idle(&mut a, &mut b, IDLE_TIMEOUT).await },
            );

        // client → server
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        // server → client
        server.write_all(b"pong").await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        // Both peers gone → both directions EOF → splice returns Ok.
        drop(client);
        drop(server);
        let r = timeout(Duration::from_secs(2), task).await;
        assert!(matches!(r, Ok(Ok(Ok(())))), "clean close should return Ok");
    }

    /// A peer that stops reading (zero window) stalls `write_all` mid-transfer;
    /// the idle window must reap that too, not just silent connections.
    #[tokio::test]
    async fn reaps_stalled_write() {
        let (mut client, mut a) = duplex(64 * 1024);
        // Tiny pipe on the far side, and its peer never reads: the first sizeable
        // write into `b` fills the pipe and stalls forever.
        let (_server, mut b) = duplex(16);
        let idle = Duration::from_millis(100);
        let task = tokio::spawn(async move { copy_bidirectional_idle(&mut a, &mut b, idle).await });

        client.write_all(&[0u8; 8 * 1024]).await.unwrap();

        let r = timeout(Duration::from_secs(2), task).await;
        assert!(
            matches!(r, Ok(Ok(Ok(())))),
            "stalled write should reap and return Ok"
        );
    }

    /// A writer that keeps making progress, even if the whole transfer takes far
    /// longer than the idle window, is carried to completion (not cut off).
    #[tokio::test]
    async fn slow_but_progressing_write_completes() {
        let idle = Duration::from_millis(50);
        // Reader drains slowly (16 bytes per 10ms) — total time to move 4KB far
        // exceeds `idle`, but each write makes progress so it must not be reaped.
        let (mut rx, mut w) = duplex(64);
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            let mut buf = [0u8; 16];
            loop {
                match rx.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        got.extend_from_slice(&buf[..n]);
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(_) => break,
                }
            }
            got.len()
        });

        let data = vec![7u8; 4096];
        let ok = write_all_progressing(&mut w, &data, idle).await.unwrap();
        assert!(ok, "a steadily-draining reader must not be reaped");
        drop(w);
        assert_eq!(reader.await.unwrap(), 4096, "all bytes should arrive");
    }

    /// A writer whose peer stops reading entirely stalls with no progress and is
    /// reported as a reap (`Ok(false)`), not carried forever.
    #[tokio::test]
    async fn stalled_write_reports_no_progress() {
        let (_rx, mut w) = duplex(16); // peer never reads → fills, then stalls
        let idle = Duration::from_millis(50);
        let stalled = write_all_progressing(&mut w, &[0u8; 8192], idle)
            .await
            .unwrap();
        assert!(
            !stalled,
            "a peer that stops reading should report no progress"
        );
    }

    /// An idle connection (peers held open, no bytes) is reaped after the idle
    /// window instead of being pinned forever — the leak this fix addresses.
    #[tokio::test]
    async fn reaps_idle_connection() {
        // `_client`/`_server` are held (not dropped) so the streams never EOF;
        // only the idle timer can end the splice.
        let (_client, mut a) = duplex(1024);
        let (_server, mut b) = duplex(1024);
        let idle = Duration::from_millis(100);
        let task = tokio::spawn(async move { copy_bidirectional_idle(&mut a, &mut b, idle).await });

        let r = timeout(Duration::from_secs(2), task).await;
        assert!(
            matches!(r, Ok(Ok(Ok(())))),
            "idle splice should reap and return Ok"
        );
    }
}
