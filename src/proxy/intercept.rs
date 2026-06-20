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
use tokio::time::timeout;

use crate::app::AppState;

use super::egress::{EgressConn, direct_connect, enable_keepalive};
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

/// Bind the proxy listeners and serve until the process exits. Detached: a bind
/// failure is logged and skipped rather than taking down the server (DNS/API run
/// in other tasks). No-op when proxy is disabled.
pub async fn run(state: AppState) {
    let (enabled, http_port, https_port) = {
        let proxy = &state.inner.proxy;
        (
            proxy.registry.load().enabled,
            proxy.http_port,
            proxy.https_port,
        )
    };
    if !enabled {
        return;
    }

    let https = bind(https_port).await;
    let http = bind(http_port).await;
    if https.is_none() && http.is_none() {
        tracing::warn!("proxy: no listeners bound; selective routing inactive");
        return;
    }

    let mut handles = Vec::new();
    if let Some(listener) = https {
        tracing::info!("proxy: TLS/SNI listener on 0.0.0.0:{https_port}");
        handles.push(tokio::spawn(accept_loop(
            listener,
            state.clone(),
            Protocol::Tls,
        )));
    }
    if let Some(listener) = http {
        tracing::info!("proxy: HTTP listener on 0.0.0.0:{http_port}");
        handles.push(tokio::spawn(accept_loop(
            listener,
            state.clone(),
            Protocol::Http,
        )));
    }
    for h in handles {
        let _ = h.await;
    }
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

async fn accept_loop(listener: TcpListener, state: AppState, proto: Protocol) {
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
        let permit = match state.inner.proxy.conn_semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::debug!("proxy: max_connections reached, dropping {src}");
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

    let port = proto.upstream_port();

    // Decide the egress from the actual SNI/Host (authoritative). Clone the
    // egress Arc out of the snapshot so the ArcSwap guard isn't held across the
    // connect await.
    let decision = {
        let snap = state.inner.proxy.registry.load();
        snap.route(&host)
            .map(|r| (Arc::clone(&snap.egresses[r.egress_idx]), r.fail_closed))
    };

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

    // Replay the bytes we already consumed, then splice both directions.
    conn.write_all(&buf).await?;
    tokio::io::copy_bidirectional(&mut client, &mut conn).await?;
    Ok(())
}
