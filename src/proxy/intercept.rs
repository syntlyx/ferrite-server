//! The transparent (redirect) proxy listeners.
//!
//! Clients connect here because DNS handed them our advertise IP — so these are
//! ordinary `accept()`ed connections, not TPROXY/IP_TRANSPARENT intercepts. We
//! peek the SNI/Host, re-match the routing rule on the real host (authoritative),
//! and splice the connection through the chosen egress (or direct if the client
//! reached us for a host we don't route).

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::app::AppState;

use super::egress::{EgressConn, EvasionParams, direct_connect, enable_keepalive, write_split};
use super::http_host::{HostResult, parse_http_host};
use super::sni::{SniResult, parse_sni};

const PEEK_TIMEOUT: Duration = Duration::from_secs(5);
const PEEK_CAP: usize = 16 * 1024;

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
            .map(|r| (Arc::clone(&snap.egresses[r.egress_idx]), r.fail_closed))
    };

    // ClientHello-fragmentation params, set only when the chosen egress is a
    // DirectEvasion egress and the connect succeeds (not on the direct fallback).
    let mut frag: Option<EvasionParams> = None;
    let mut conn: EgressConn = match decision {
        Some((egress, fail_closed)) => {
            let id = egress.id().to_string();
            if fail_closed && !state.inner.proxy.is_egress_healthy(&id) {
                tracing::debug!("proxy: egress '{id}' unhealthy → fail-closed drop of {host}");
                return Ok(());
            }
            match egress.connect(&host, port).await {
                Ok(c) => {
                    state.inner.proxy.note_success(&id);
                    frag = egress.evasion_params();
                    c
                }
                Err(e) => {
                    state.inner.proxy.note_failure(&id);
                    if fail_closed {
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

    // Replay the bytes we already consumed, then splice both directions. For an
    // evasion egress on a TLS connection the ClientHello replay is fragmented so
    // the SNI is split across TCP segments (DPI bypass); everything else is a
    // single write.
    match frag {
        Some(p) if matches!(proto, Protocol::Tls) => write_split(&mut conn, &buf, &p).await?,
        _ => conn.write_all(&buf).await?,
    }
    tokio::io::copy_bidirectional(&mut client, &mut conn).await?;
    Ok(())
}
