//! Pluggable egress backends.
//!
//! Each backend's `connect(host, port)` takes the **hostname** (never a
//! pre-resolved IP) so it can resolve in its own context — Direct resolves via
//! ferrite's own upstream pool, SOCKS5 hands the name to the proxy, WireGuard
//! resolves via the upstream pool and routes the connection through the tunnel.
//! That makes "no DNS leak" a property of the design rather than extra plumbing.
//!
//! [`EgressConn`] is an enum over the concrete stream types (a plain TCP stream
//! for Direct/SOCKS5, an in-memory pipe for WireGuard) so it stays usable with
//! `tokio::io::copy_bidirectional`.

mod direct;
mod socks5;
mod wireguard;

pub use direct::{DirectEgress, direct_connect};

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use socket2::{SockRef, TcpKeepalive};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::net::TcpStream;

use crate::config::EgressConfig;
use crate::error::{FeriteError, Result};
use crate::upstream::ZoneRouter;

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

pub enum Egress {
    Direct(DirectEgress),
    Socks5(socks5::Socks5Egress),
    Wireguard(wireguard::WgEgress),
}

impl Egress {
    pub fn from_config(cfg: &EgressConfig, upstream: Arc<ZoneRouter>) -> Result<Self> {
        match cfg.kind.as_str() {
            "direct" => Ok(Self::Direct(DirectEgress::new(cfg.id.clone(), upstream))),
            "socks5" => Ok(Self::Socks5(socks5::Socks5Egress::from_config(cfg)?)),
            "wireguard" => Ok(Self::Wireguard(wireguard::WgEgress::from_config(
                cfg, upstream,
            )?)),
            other => Err(FeriteError::Config(format!(
                "egress '{}': unsupported kind '{}'",
                cfg.id, other
            ))),
        }
    }

    pub fn id(&self) -> &str {
        match self {
            Self::Direct(d) => d.id(),
            Self::Socks5(s) => s.id(),
            Self::Wireguard(w) => w.id(),
        }
    }

    /// Intrinsic readiness independent of the connect circuit-breaker. Direct and
    /// SOCKS5 are always "ready" (their failures show up via the breaker);
    /// WireGuard is ready only once its handshake has completed, so fail-closed
    /// rules don't redirect to a tunnel that isn't up yet.
    pub fn is_healthy(&self) -> bool {
        match self {
            Self::Direct(_) | Self::Socks5(_) => true,
            Self::Wireguard(w) => w.is_healthy(),
        }
    }

    pub async fn connect(&self, host: &str, port: u16) -> Result<EgressConn> {
        match self {
            Self::Direct(d) => Ok(EgressConn::Tcp(d.connect(host, port).await?)),
            Self::Socks5(s) => Ok(EgressConn::Tcp(s.connect(host, port).await?)),
            Self::Wireguard(w) => Ok(EgressConn::Wg(w.connect(host, port).await?)),
        }
    }
}

/// Validate a pasted WireGuard `.conf` (used by the API to 400 a bad paste).
pub fn validate_wireguard_conf(text: &str) -> Result<()> {
    wireguard::parse(text).map(|_| ())
}

/// Enable TCP keepalive so a dead long-lived splice is eventually reaped by the
/// OS, releasing its `max_connections` permit (the proxy holds a permit for the
/// whole connection lifetime).
pub fn enable_keepalive(stream: &TcpStream) {
    let ka = TcpKeepalive::new().with_time(Duration::from_secs(60));
    let _ = SockRef::from(stream).set_tcp_keepalive(&ka);
}
