//! Pluggable egress backends.
//!
//! Each backend's `connect(host, port)` takes the **hostname** (never a
//! pre-resolved IP) so it can resolve in its own context — Direct resolves via
//! ferrite's own upstream pool, SOCKS5 hands the name to the proxy, WireGuard
//! resolves via the upstream pool and routes the connection through the tunnel.
//! That makes "no DNS leak" a property of the design rather than extra plumbing.
//!
//! [`EgressConn`] (owned by the upstream layer, see [`ferrite_upstream::egress`])
//! is an enum over the concrete stream types (a plain TCP stream for
//! Direct/SOCKS5, an in-memory pipe for WireGuard) so it stays usable with
//! `tokio::io::copy_bidirectional`.

mod direct;
mod evasion;
mod socks5;
mod wireguard;

pub use direct::{DirectEgress, direct_connect};
pub use evasion::{EvasionParams, write_split};

use std::sync::Arc;
use std::time::Duration;

use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpStream;

use ferrite_core::config::EgressConfig;
use ferrite_core::error::{FeriteError, Result};
use ferrite_upstream::ZoneRouter;

pub use ferrite_upstream::EgressConn;

/// Why an egress connect failed — determines whether the circuit breaker counts
/// it. Getting a reply from the proxy/tunnel proves the transport works, so a
/// destination that is merely unreachable behind it must **not** trip the
/// breaker; otherwise one dead site would fail-close the egress for every other
/// destination for the whole cooldown.
#[derive(Debug)]
pub struct ConnectError {
    kind: ConnectErrorKind,
    err: FeriteError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectErrorKind {
    /// The egress transport itself is broken (tunnel down, proxy unreachable,
    /// auth rejected, connect to the proxy timed out). Counts toward the breaker.
    Egress,
    /// The egress works but the target is unreachable/refused/unresolvable. The
    /// breaker ignores this.
    Destination,
}

impl ConnectError {
    pub fn egress(err: FeriteError) -> Self {
        Self {
            kind: ConnectErrorKind::Egress,
            err,
        }
    }

    pub fn destination(err: FeriteError) -> Self {
        Self {
            kind: ConnectErrorKind::Destination,
            err,
        }
    }

    pub fn kind(&self) -> ConnectErrorKind {
        self.kind
    }

    /// The underlying error, for callers that don't care about the classification
    /// (e.g. surfacing it to a diagnostic API).
    pub fn into_inner(self) -> FeriteError {
        self.err
    }
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.err, f)
    }
}

pub enum Egress {
    Direct(DirectEgress),
    Socks5(socks5::Socks5Egress),
    Wireguard(wireguard::WgEgress),
    /// Direct connection that fragments the TLS ClientHello to evade SNI DPI.
    DirectEvasion(evasion::EvasionEgress),
}

impl Egress {
    pub fn from_config(cfg: &EgressConfig, upstream: Arc<ZoneRouter>) -> Result<Self> {
        match cfg.kind.as_str() {
            "direct" => Ok(Self::Direct(DirectEgress::new(cfg.id.clone(), upstream))),
            "socks5" => Ok(Self::Socks5(socks5::Socks5Egress::from_config(cfg)?)),
            "wireguard" => Ok(Self::Wireguard(wireguard::WgEgress::from_config(
                cfg, upstream,
            )?)),
            "evasion" => Ok(Self::DirectEvasion(evasion::EvasionEgress::new(
                cfg.id.clone(),
                upstream,
                cfg.seg_position,
            ))),
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
            Self::DirectEvasion(e) => e.id(),
        }
    }

    /// The ClientHello-fragmentation parameters, if this is a DirectEvasion
    /// egress. The intercept loop uses them to split the first TLS write.
    pub fn evasion_params(&self) -> Option<EvasionParams> {
        match self {
            Self::DirectEvasion(e) => Some(e.params()),
            _ => None,
        }
    }

    /// Intrinsic readiness independent of the connect circuit-breaker. Direct and
    /// SOCKS5 are always "ready" (their failures show up via the breaker);
    /// WireGuard is ready only once its handshake has completed, so fail-closed
    /// rules don't redirect to a tunnel that isn't up yet.
    pub fn is_healthy(&self) -> bool {
        match self {
            Self::Direct(_) | Self::Socks5(_) | Self::DirectEvasion(_) => true,
            Self::Wireguard(w) => w.is_healthy(),
        }
    }

    /// Seconds since the WireGuard handshake (stats/diagnostics); `None` for
    /// other kinds and for a tunnel that has never completed one.
    pub fn handshake_age_secs(&self) -> Option<u64> {
        match self {
            Self::Wireguard(w) => w.handshake_age_secs(),
            _ => None,
        }
    }

    /// Which implementation carries a WireGuard tunnel (`"kernel"` /
    /// `"userspace"`); `None` for other kinds.
    pub fn wg_backend(&self) -> Option<&'static str> {
        match self {
            Self::Wireguard(w) => Some(w.backend()),
            _ => None,
        }
    }

    pub async fn connect(
        &self,
        host: &str,
        port: u16,
    ) -> std::result::Result<EgressConn, ConnectError> {
        match self {
            // Direct/Evasion have no separate transport hop, so any failure is a
            // property of the destination (or its resolution), never a "the egress
            // is down" signal — classify as Destination.
            Self::Direct(d) => d
                .connect(host, port)
                .await
                .map(EgressConn::Tcp)
                .map_err(ConnectError::destination),
            Self::DirectEvasion(e) => e
                .connect(host, port)
                .await
                .map(EgressConn::Tcp)
                .map_err(ConnectError::destination),
            // SOCKS5 and WireGuard classify their own failures (proxy/tunnel
            // transport vs. destination) at the point they know which it was.
            Self::Socks5(s) => s.connect(host, port).await.map(EgressConn::Tcp),
            // WireGuard wraps its own stream type (virtual pipe or real TCP,
            // depending on the backend).
            Self::Wireguard(w) => w.connect(host, port).await,
        }
    }
}

/// Validate a pasted WireGuard `.conf` (used by the API to 400 a bad paste).
pub fn validate_wireguard_conf(text: &str) -> Result<()> {
    wireguard::parse(text).map(|_| ())
}

pub use wireguard::detect_kernel_backend as detect_kernel_wg_backend;

/// Whether the kernel WireGuard backend is usable on this host (probed once at
/// startup by [`detect_kernel_wg_backend`]).
pub fn kernel_wg_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        wireguard::kernel_available()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Why the kernel WireGuard backend is unavailable (for API error messages).
pub fn kernel_wg_unavailable_reason() -> String {
    #[cfg(target_os = "linux")]
    {
        wireguard::kernel_unavailable_reason()
    }
    #[cfg(not(target_os = "linux"))]
    {
        "the kernel backend requires Linux".to_string()
    }
}

/// Enable TCP keepalive so a dead long-lived splice is eventually reaped by the
/// OS, releasing its `max_connections` permit (the proxy holds a permit for the
/// whole connection lifetime).
pub fn enable_keepalive(stream: &TcpStream) {
    let ka = TcpKeepalive::new().with_time(Duration::from_secs(60));
    let _ = SockRef::from(stream).set_tcp_keepalive(&ka);
}

/// Translate a `SO_RCVBUF` read-back into usable bytes. Linux reports 2× the
/// granted size (the other half is reserved for `sk_buff` bookkeeping), so the
/// usable capacity is half the read-back; other platforms report it directly.
/// Keep every UDP-buffer figure we surface (API ceiling probe, tunnel log) in
/// these same usable-byte units so they're comparable against a per-connection
/// buffer setting, which is a real, single-window byte count.
pub fn usable_rcvbuf_bytes(readback: usize) -> usize {
    if cfg!(target_os = "linux") {
        readback / 2
    } else {
        readback
    }
}
