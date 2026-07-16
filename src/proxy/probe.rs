//! Active egress probing.
//!
//! The circuit breaker and WireGuard handshake-age only tell us an egress is
//! broken *after* real traffic hits it (or, for WireGuard, that the tunnel
//! session is fresh). Neither notices an idle SOCKS5/Direct path that silently
//! died between requests. This loop closes that gap: on an interval it opens a
//! throwaway TCP connection to a known host *through* each enabled egress,
//! measures the round-trip, and records it via [`ProxyStats::record_probe`].
//!
//! The result drives three things: a latency figure on the Tunnels page and in
//! Prometheus, a "degraded" hint when RTT is high but the path still works, and
//! — after a sustained failure run — the fail-closed health gate (see
//! [`ProxyStats::probe_unhealthy`]). The probe target is configurable because it
//! must be reachable through every egress for the gating to be fair.

use std::time::{Duration, Instant};

use crate::app::AppState;
use crate::config::DEFAULT_PROBE_TARGET;

/// How often each egress is probed.
const PROBE_INTERVAL: Duration = Duration::from_secs(30);

/// Bound on a single probe connect; a hung path is a failure, not a stall.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// The probe loop. Spawned at startup; reads the live config each tick so egress
/// edits and a changed probe target apply without a restart. Runs for the life
/// of the process.
pub async fn run(state: AppState) {
    let mut interval = tokio::time::interval(PROBE_INTERVAL);
    loop {
        interval.tick().await;

        // Snapshot config without holding the lock across an await. Proxy
        // disabled → egresses are intentionally idle, so don't probe (and don't
        // let a stale probe result gate anything).
        let (enabled, target, egress_ids): (bool, String, Vec<String>) = {
            let cfg = &state.live_config.read().proxy;
            (
                cfg.enabled,
                cfg.probe_target
                    .clone()
                    .unwrap_or_else(|| DEFAULT_PROBE_TARGET.to_string()),
                cfg.egresses
                    .iter()
                    .filter(|e| e.enabled)
                    .map(|e| e.id.clone())
                    .collect(),
            )
        };
        if !enabled {
            continue;
        }
        let Some((host, port)) = split_host_port(&target) else {
            tracing::warn!("proxy: invalid probe_target '{target}', skipping probes");
            continue;
        };

        let proxy = &state.inner.proxy;
        for id in &egress_ids {
            let Some(egress) = proxy.egress(id) else {
                continue; // built lazily / mid-reload — skip this tick
            };
            let start = Instant::now();
            let rtt = match tokio::time::timeout(PROBE_TIMEOUT, egress.connect(host, port)).await {
                Ok(Ok(_conn)) => Some(start.elapsed()), // conn dropped immediately
                Ok(Err(e)) => {
                    tracing::debug!("proxy: probe of egress '{id}' failed: {e}");
                    None
                }
                Err(_) => {
                    tracing::debug!("proxy: probe of egress '{id}' timed out");
                    None
                }
            };
            proxy.stats().record_probe(id, rtt);
        }
    }
}

/// Split a `host:port` probe target. Rejects a missing/zero/oversized port. The
/// host keeps its literal form (an IP literal avoids DNS variance in the RTT).
fn split_host_port(target: &str) -> Option<(&str, u16)> {
    let (host, port) = target.rsplit_once(':')?;
    let host = host.trim();
    let port: u16 = port.trim().parse().ok()?;
    if host.is_empty() || port == 0 {
        return None;
    }
    Some((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host_and_port() {
        assert_eq!(split_host_port("1.1.1.1:443"), Some(("1.1.1.1", 443)));
        assert_eq!(split_host_port("example.com:53"), Some(("example.com", 53)));
        // IPv6 literals aren't supported as probe targets (rsplit picks the last
        // colon); use an IPv4 literal or hostname. Documented via this test.
        assert!(split_host_port("1.1.1.1").is_none());
        assert!(split_host_port("1.1.1.1:0").is_none());
        assert!(split_host_port("1.1.1.1:notaport").is_none());
        assert!(split_host_port(":443").is_none());
    }
}
