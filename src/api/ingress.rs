//! Shared HTTP ingress for the panel's listener.
//!
//! The panel owns its bind address (typically `:80`). For each connection we peek
//! the HTTP `Host` and either serve the admin panel (axum, via hyper) or hand the
//! connection to the proxy ([`crate::proxy::forward_http`]). That lets one port do
//! both — `fe.te` / the panel IP reach the web UI, every other host is routed by
//! the proxy — instead of the panel and proxy fighting over `:80`.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Router;
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::app::AppState;
use crate::proxy::http_host::{HostResult, parse_http_host};

const PEEK_TIMEOUT: Duration = Duration::from_secs(5);
const PEEK_CAP: usize = 16 * 1024;

/// Handle one accepted connection: peek the `Host`, then serve the panel or hand
/// the connection to the proxy.
pub(super) async fn dispatch(mut stream: TcpStream, state: AppState, router: Router) {
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let host = loop {
        let mut tmp = [0u8; 4096];
        let n = match timeout(PEEK_TIMEOUT, stream.read(&mut tmp)).await {
            Ok(Ok(0)) => break None, // client closed before sending a request
            Ok(Ok(n)) => n,
            Ok(Err(_)) => return, // read error — drop
            Err(_) => break None, // peek timed out — treat as panel
        };
        buf.extend_from_slice(&tmp[..n]);
        match parse_http_host(&buf) {
            HostResult::Found(h) => break Some(h),
            HostResult::Incomplete => {}
            HostResult::NotFound => break None, // not HTTP / no Host → panel
        }
        if buf.len() > PEEK_CAP {
            break None;
        }
    };

    // A non-panel host is routed by the proxy (when enabled); everything else —
    // panel hosts, no-Host requests, proxy disabled — is served the panel.
    match host {
        Some(h) if state.inner.proxy.is_enabled() && !state.inner.panel_hosts.contains(&h) => {
            crate::proxy::forward_http(state, stream, buf, h).await;
        }
        _ => serve_panel(stream, buf, router).await,
    }
}

/// Serve the buffered connection as the panel: replay the peeked bytes ahead of
/// the socket and let hyper drive the axum router (HTTP/1, keep-alive).
async fn serve_panel(stream: TcpStream, prefix: Vec<u8>, router: Router) {
    let io = TokioIo::new(Prefixed::new(prefix, stream));
    let service = TowerToHyperService::new(router);
    if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
        tracing::debug!("panel connection error: {e}");
    }
}

/// An `AsyncRead`/`AsyncWrite` that yields a buffered prefix before the inner
/// stream — so bytes already peeked off the socket are replayed to the reader.
struct Prefixed<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.prefix.len() {
            let remaining = &this.prefix[this.pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            this.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
