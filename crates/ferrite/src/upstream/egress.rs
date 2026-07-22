//! The egress surface the upstream layer is allowed to see.
//!
//! Tunneled upstream DNS ([`super::tunneled`]) rides the proxy's egresses, but
//! the proxy also resolves through the upstream pool — a cycle. The upstream
//! side therefore owns this narrow contract ([`EgressConnector`] + the
//! [`EgressConn`] stream it yields) and never sees the proxy's concrete types;
//! the proxy implements the trait and is late-bound into [`ProxyHandle`] once
//! it exists.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::net::TcpStream;

use ferrite_core::error::FeriteError;

/// A bidirectional connection to a real destination, ready for splicing.
pub enum EgressConn {
    /// Direct / SOCKS5 — a real TCP stream.
    Tcp(TcpStream),
    /// WireGuard — the caller's end of an in-memory pipe to the tunnel task.
    Wg(DuplexStream),
}

impl AsyncRead for EgressConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            EgressConn::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            EgressConn::Wg(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for EgressConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            EgressConn::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            EgressConn::Wg(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            EgressConn::Tcp(s) => Pin::new(s).poll_flush(cx),
            EgressConn::Wg(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            EgressConn::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            EgressConn::Wg(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Why [`EgressConnector::connect_via`] yielded no stream. The caller treats
/// every variant as "fall back to direct", but logs them differently.
#[derive(Debug)]
pub enum EgressConnectError {
    /// No egress with this id exists in the current config.
    NotConfigured,
    /// The egress exists but is currently unhealthy (breaker open, tunnel
    /// handshake missing, or probe failure) — connecting was not attempted.
    Unhealthy,
    /// A live egress was attempted and the connect through it failed.
    Failed(FeriteError),
}

impl std::fmt::Display for EgressConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConfigured => write!(f, "egress not configured"),
            Self::Unhealthy => write!(f, "egress is down"),
            Self::Failed(e) => std::fmt::Display::fmt(e, f),
        }
    }
}

/// Boxed connect future. Boxing is load-bearing, not just a dyn-safety tax: a
/// WireGuard egress may resolve its own endpoint through the upstream pool,
/// which can contain the very resolver that is connecting — an async-recursion
/// cycle that needs heap indirection to have a finite size.
pub type EgressConnectFuture<'a> =
    Pin<Box<dyn Future<Output = Result<EgressConn, EgressConnectError>> + Send + 'a>>;

/// Opens byte streams through named egresses. Implemented by the proxy's
/// `ProxyState`; upstream code only ever sees this trait.
pub trait EgressConnector: Send + Sync {
    /// Open a stream to `host:port` through the egress `egress_id`, checking
    /// health first — a known-down egress fails fast with
    /// [`EgressConnectError::Unhealthy`] instead of stalling on a connect.
    fn connect_via<'a>(
        &'a self,
        egress_id: &'a str,
        host: &'a str,
        port: u16,
    ) -> EgressConnectFuture<'a>;
}

/// Late-bound handle to the egress connector. The upstream pool is built
/// *before* the proxy exists (the proxy resolves through this same pool), so
/// the handle starts empty and is set once the proxy is constructed. An empty
/// handle just means "no egress available" → direct.
pub type ProxyHandle = Arc<OnceLock<Arc<dyn EgressConnector>>>;

/// An empty proxy handle (egress lookups always miss → direct). Used to seed
/// the handle at startup and in tests that don't exercise tunneling.
pub fn no_proxy() -> ProxyHandle {
    Arc::new(OnceLock::new())
}
