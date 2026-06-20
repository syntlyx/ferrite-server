//! Pluggable egress backends.
//!
//! Each backend's `connect(host, port)` takes the **hostname** (never a
//! pre-resolved IP) so it can resolve in its own context — Direct resolves via
//! ferrite's own upstream pool, SOCKS5 hands the name to the proxy. That makes
//! "no DNS leak" a property of the design rather than extra plumbing.
//!
//! Both current backends yield a [`TcpStream`], so `EgressConn` is just an
//! alias today; when the userspace WireGuard backend lands it becomes an enum
//! that implements `AsyncRead`/`AsyncWrite` (still usable with
//! `copy_bidirectional`).

mod direct;
mod socks5;

pub use direct::{direct_connect, DirectEgress};

use std::sync::Arc;
use std::time::Duration;

use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpStream;

use crate::config::EgressConfig;
use crate::error::{FeriteError, Result};
use crate::upstream::ZoneRouter;

/// A bidirectional connection to a real destination, ready for splicing.
pub type EgressConn = TcpStream;

pub enum Egress {
    Direct(DirectEgress),
    Socks5(socks5::Socks5Egress),
}

impl Egress {
    pub fn from_config(cfg: &EgressConfig, upstream: Arc<ZoneRouter>) -> Result<Self> {
        match cfg.kind.as_str() {
            "direct" => Ok(Self::Direct(DirectEgress::new(cfg.id.clone(), upstream))),
            "socks5" => Ok(Self::Socks5(socks5::Socks5Egress::from_config(cfg)?)),
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
        }
    }

    pub async fn connect(&self, host: &str, port: u16) -> Result<EgressConn> {
        match self {
            Self::Direct(d) => d.connect(host, port).await,
            Self::Socks5(s) => s.connect(host, port).await,
        }
    }
}

/// Enable TCP keepalive so a dead long-lived splice is eventually reaped by the
/// OS, releasing its `max_connections` permit (the proxy holds a permit for the
/// whole connection lifetime).
pub fn enable_keepalive(stream: &TcpStream) {
    let ka = TcpKeepalive::new().with_time(Duration::from_secs(60));
    let _ = SockRef::from(stream).set_tcp_keepalive(&ka);
}
