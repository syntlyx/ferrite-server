//! WireGuard egress — one façade over two interchangeable backends.
//!
//! * [`user`] — boringtun + smoltcp over a plain UDP socket, fully in-process.
//!   Portable (runs anywhere, no privileges), but single-task crypto and a
//!   static per-connection window cap its throughput.
//! * `kernel` (Linux, `CAP_NET_ADMIN`) — a netlink-managed `wireguard` netdev
//!   with source-address policy routing. The kernel does the crypto (multicore,
//!   GSO/GRO) and TCP autotuning, so per-connection throughput scales to the
//!   link instead of the buffer setting.
//!
//! Both backends keep the same contract: `connect(host, port)` resolves the
//! hostname *through* the tunnel (see [`dns::TunnelResolver`]) and returns a
//! stream carried by it; health means "the WireGuard session is fresh".

mod conf;
mod device;
mod dns;
#[cfg(target_os = "linux")]
mod kernel;
mod user;

pub use conf::parse;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ferrite_core::config::EgressConfig;
use ferrite_core::error::{FeriteError, Result};
use ferrite_upstream::{EgressConn, ZoneRouter};

use super::ConnectError;

/// Default inner MTU (WireGuard's standard for a 1500 path MTU).
const DEFAULT_MTU: usize = 1420;
/// WireGuard's REJECT_AFTER_TIME: a session older than this is dead. We treat the
/// tunnel as healthy only while the last handshake is still inside this window.
const SESSION_MAX_AGE: Duration = Duration::from_secs(180);
/// Proactively initiate a fresh handshake once the session is this old. WireGuard
/// only rekeys when real data flows — keepalives keep the NAT binding alive but
/// (in boringtun) do NOT renew the session — so an *idle* tunnel's session would
/// age past [`SESSION_MAX_AGE`], flip health down, and fail-closed rules would
/// then drop the very traffic that could revive it. Renewing early keeps an idle
/// tunnel permanently warm; the 30s margin absorbs several REKEY_TIMEOUT (5s)
/// retries before the old session actually expires.
const REHANDSHAKE_AFTER: Duration = Duration::from_secs(150);
/// Keepalive (seconds) applied when the `.conf` omits `PersistentKeepalive`, so an
/// idle always-on tunnel never silently expires. Explicit `0` (off) is respected.
const DEFAULT_KEEPALIVE: u16 = 25;
/// How long a tunneled TCP connect may take to establish before it is reported
/// as failed (virtual-socket ESTABLISHED for the userspace backend, real
/// `connect()` for the kernel one). Without this a connect to a dead host behind
/// a healthy tunnel would hang until the splice's idle timeout instead of
/// failing fast (and the circuit breaker would never see it).
const WG_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// A WireGuard egress: a cheap handle whose tunnel lives in its own task(s).
/// The backend is chosen at build time (see [`WgEgress::from_config`]).
pub struct WgEgress(Backend);

enum Backend {
    User(user::UserWg),
    #[cfg(target_os = "linux")]
    Kernel(kernel::KernelWg),
}

/// Probe once for kernel-WireGuard support (Linux + `CAP_NET_ADMIN` + the
/// `wireguard` module) and cache the verdict for every subsequent egress
/// build. Called by the binary at startup, before the proxy exists — egress
/// construction is synchronous, so the decision must already be made. Returns
/// whether the kernel backend is available.
pub async fn detect_kernel_backend() -> bool {
    #[cfg(target_os = "linux")]
    {
        kernel::detect().await
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Whether the kernel backend probe succeeded (Linux-only; see [`detect_kernel_backend`]).
#[cfg(target_os = "linux")]
pub fn kernel_available() -> bool {
    kernel::available()
}

/// Why the kernel backend is unavailable (Linux-only; empty question on other
/// targets — the caller answers it without us).
#[cfg(target_os = "linux")]
pub fn kernel_unavailable_reason() -> String {
    kernel::unavailable_reason()
}

/// Which backend a config asks for (validated here so the API can 400 a typo).
fn backend_choice(cfg: &EgressConfig) -> Result<&'static str> {
    match cfg
        .backend
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("auto")
        .to_ascii_lowercase()
        .as_str()
    {
        "auto" => Ok("auto"),
        "kernel" => Ok("kernel"),
        "userspace" => Ok("userspace"),
        other => Err(FeriteError::Config(format!(
            "wireguard egress '{}': unknown backend '{}' (auto | kernel | userspace)",
            cfg.id, other
        ))),
    }
}

impl WgEgress {
    /// Parse `cfg.config`, pick a backend, and bring up the tunnel. Must be
    /// called within a tokio runtime (it is — egresses are built at app init /
    /// API reload).
    ///
    /// Backend selection: `auto` (default) uses the kernel backend when the
    /// startup probe found it, else userspace; an explicit `kernel` fails
    /// loudly when unavailable instead of silently degrading — the operator
    /// asked for line-rate and should know they aren't getting it.
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
        let choice = backend_choice(cfg)?;

        #[cfg(target_os = "linux")]
        {
            match choice {
                "kernel" if !kernel::available() => {
                    return Err(FeriteError::Config(format!(
                        "wireguard egress '{}': kernel backend requested but unavailable: {}",
                        cfg.id,
                        kernel::unavailable_reason()
                    )));
                }
                "kernel" => {
                    return Ok(Self(Backend::Kernel(kernel::KernelWg::spawn(
                        cfg, conf, upstream,
                    ))));
                }
                "auto" if kernel::available() => {
                    return Ok(Self(Backend::Kernel(kernel::KernelWg::spawn(
                        cfg, conf, upstream,
                    ))));
                }
                _ => {}
            }
        }
        #[cfg(not(target_os = "linux"))]
        if choice == "kernel" {
            return Err(FeriteError::Config(format!(
                "wireguard egress '{}': the kernel backend requires Linux",
                cfg.id
            )));
        }

        Ok(Self(Backend::User(user::UserWg::spawn(
            cfg, conf, upstream,
        ))))
    }

    pub fn id(&self) -> &str {
        match &self.0 {
            Backend::User(u) => u.id(),
            #[cfg(target_os = "linux")]
            Backend::Kernel(k) => k.id(),
        }
    }

    /// The backend actually carrying this tunnel (stats/diagnostics).
    pub fn backend(&self) -> &'static str {
        match &self.0 {
            Backend::User(_) => "userspace",
            #[cfg(target_os = "linux")]
            Backend::Kernel(_) => "kernel",
        }
    }

    pub fn is_healthy(&self) -> bool {
        match &self.0 {
            Backend::User(u) => u.is_healthy(),
            #[cfg(target_os = "linux")]
            Backend::Kernel(k) => k.is_healthy(),
        }
    }

    /// Seconds since the last successful handshake, `None` before the first one.
    pub fn handshake_age_secs(&self) -> Option<u64> {
        match &self.0 {
            Backend::User(u) => u.handshake_age_secs(),
            #[cfg(target_os = "linux")]
            Backend::Kernel(k) => k.handshake_age_secs(),
        }
    }

    /// Open a tunneled TCP connection to `host:port`. Hostnames are resolved
    /// *through* the tunnel; literal IPs connect directly.
    pub async fn connect(
        &self,
        host: &str,
        port: u16,
    ) -> std::result::Result<EgressConn, ConnectError> {
        match &self.0 {
            Backend::User(u) => u.connect(host, port).await.map(EgressConn::Wg),
            #[cfg(target_os = "linux")]
            Backend::Kernel(k) => k.connect(host, port).await.map(EgressConn::Tcp),
        }
    }
}

/// Resolve the `.conf` peer endpoint (`host:port`) via the system resolver —
/// bootstrap, must not depend on the tunnel. Re-resolved on every tunnel
/// (re)build so a moved endpoint (DDNS) or a boot without network recovers.
async fn resolve_endpoint(endpoint: &str) -> Result<SocketAddr> {
    tokio::net::lookup_host(endpoint)
        .await
        .map_err(|e| FeriteError::Config(format!("wireguard endpoint '{endpoint}': {e}")))?
        .next()
        .ok_or_else(|| {
            FeriteError::Config(format!("wireguard endpoint '{endpoint}' did not resolve"))
        })
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
