//! Per-egress traffic accounting for the selective-routing proxy.
//!
//! Counters live in [`ProxyState`](super::ProxyState) keyed by egress *id* (not
//! in the routing snapshot), so they survive hot config reloads: editing a rule
//! or an unrelated egress keeps the history, and only removing an egress from
//! the config drops its counters (see [`ProxyStats::prune`]). Everything on the
//! data path is a relaxed atomic; the only lock is the small per-egress domain
//! table, touched once per connection — never per byte.
//!
//! Bytes are counted only for traffic that actually flows *through* an egress.
//! A fail-open fallback to direct and the plain forward for an unrouted host are
//! not tunnel traffic and would make the numbers lie.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::config::ProxyConfig;

/// Cap on each egress's routed-domain table. Full + new domain → the
/// least-recently-seen entry is evicted, so the table tracks what the tunnel is
/// carrying *now* while staying bounded regardless of how many hosts pass through.
const DOMAIN_CAP: usize = 48;

/// Consecutive failed probes before the active probe marks an egress unhealthy.
/// A single miss (probe target briefly unreachable) must not flip a working
/// egress; a sustained run means the path is genuinely dead.
const PROBE_FAIL_THRESHOLD: u32 = 3;

/// All proxy traffic counters, shared across snapshot reloads.
#[derive(Default)]
pub struct ProxyStats {
    egresses: DashMap<String, Arc<EgressStats>>,
    /// Connections routed per rule, keyed by (pattern, egress id). Counted at
    /// the connection-routing decision (the authoritative match on the real
    /// SNI/Host), so a hit means "a connection actually chose this rule" — not
    /// merely that DNS answered with the advertise IP.
    rule_hits: DashMap<(String, String), AtomicU64>,
    /// Latest active-probe result per egress id (RTT + reachability), written by
    /// the probe loop and read by the stats API, metrics, and the health gate.
    probes: DashMap<String, ProbeState>,
}

/// The last active-probe outcome for one egress.
struct ProbeState {
    /// Round-trip of the last successful probe (ms); `None` if it failed.
    rtt_ms: Option<u32>,
    /// Did the last probe succeed?
    ok: bool,
    /// Consecutive failures ending at the last probe (0 right after a success).
    consecutive_fails: u32,
    /// Unix seconds of the last probe.
    last_probe_secs: u64,
}

impl ProxyStats {
    /// The (created-on-first-use) counters for egress `id`.
    pub fn egress(&self, id: &str) -> Arc<EgressStats> {
        self.egresses.entry(id.to_string()).or_default().clone()
    }

    pub fn record_rule_hit(&self, pattern: &str, egress_id: &str) {
        self.rule_hits
            .entry((pattern.to_string(), egress_id.to_string()))
            .or_default()
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Drop counters whose egress/rule is gone from the config, so deleted
    /// entries don't linger and both maps stay bounded by the config size.
    /// Disabled-but-present entries are kept: a temporary toggle shouldn't
    /// erase history.
    pub fn prune(&self, cfg: &ProxyConfig) {
        self.egresses
            .retain(|id, _| cfg.egresses.iter().any(|e| e.id == *id));
        self.rule_hits.retain(|(pattern, egress), _| {
            cfg.rules
                .iter()
                .any(|r| r.pattern == *pattern && r.egress == *egress)
        });
        self.probes
            .retain(|id, _| cfg.egresses.iter().any(|e| e.id == *id));
    }

    /// Counters for egress `id` as a serializable snapshot — zeros when the
    /// egress has never carried traffic (without creating an entry).
    pub fn egress_snapshot(&self, id: &str) -> EgressSnapshot {
        match self.egresses.get(id) {
            Some(s) => s.snapshot(),
            None => EgressSnapshot::default(),
        }
    }

    /// Every rule's hit count, unordered (the caller matches them to config
    /// rows by pattern + egress).
    pub fn rule_hits_snapshot(&self) -> Vec<RuleHits> {
        self.rule_hits
            .iter()
            .map(|e| RuleHits {
                pattern: e.key().0.clone(),
                egress: e.key().1.clone(),
                hits: e.value().load(Ordering::Relaxed),
            })
            .collect()
    }

    /// Record an active-probe outcome for egress `id`: `Some(rtt)` on a
    /// successful connect through the egress, `None` on failure/timeout.
    pub fn record_probe(&self, id: &str, rtt: Option<std::time::Duration>) {
        let mut e = self.probes.entry(id.to_string()).or_insert(ProbeState {
            rtt_ms: None,
            ok: false,
            consecutive_fails: 0,
            last_probe_secs: 0,
        });
        e.last_probe_secs = now_secs();
        match rtt {
            Some(d) => {
                e.rtt_ms = Some(d.as_millis().min(u32::MAX as u128) as u32);
                e.ok = true;
                e.consecutive_fails = 0;
            }
            None => {
                e.rtt_ms = None;
                e.ok = false;
                e.consecutive_fails = e.consecutive_fails.saturating_add(1);
            }
        }
    }

    /// The last probe result for egress `id` as a serializable snapshot, or
    /// `None` if it has never been probed.
    pub fn probe_snapshot(&self, id: &str) -> Option<ProbeSnapshot> {
        self.probes.get(id).map(|e| ProbeSnapshot {
            rtt_ms: e.rtt_ms,
            ok: e.ok,
            last_probe_secs_ago: now_secs().saturating_sub(e.last_probe_secs),
        })
    }

    /// Has the active probe declared this egress dead? True only after a
    /// sustained run of failures ([`PROBE_FAIL_THRESHOLD`]); a never-probed or
    /// briefly-flapping egress is *not* forced unhealthy (fail open until sure).
    pub fn probe_unhealthy(&self, id: &str) -> bool {
        self.probes
            .get(id)
            .is_some_and(|e| e.consecutive_fails >= PROBE_FAIL_THRESHOLD)
    }
}

/// Live counters for one egress.
#[derive(Default)]
pub struct EgressStats {
    /// Connections currently spliced through this egress.
    active: AtomicU64,
    /// Connections ever opened through this egress.
    total_conns: AtomicU64,
    /// Bytes client → destination (written into the egress).
    bytes_up: AtomicU64,
    /// Bytes destination → client (read from the egress).
    bytes_down: AtomicU64,
    /// Failed `connect()` attempts through this egress.
    connect_fails: AtomicU64,
    /// Client connections dropped by a fail-closed rule (unhealthy egress, or a
    /// connect failure with fallback disallowed).
    fail_closed_drops: AtomicU64,
    domains: Mutex<HashMap<String, DomainStat>>,
}

struct DomainStat {
    conns: u64,
    bytes_up: u64,
    bytes_down: u64,
    /// Unix seconds; drives LRU eviction and the UI's "seconds ago".
    last_seen: u64,
}

impl EgressStats {
    /// Record a connection successfully opened through this egress to `host`.
    /// The returned guard keeps the `active` gauge up for the connection's
    /// lifetime; every exit path (clean close, error, idle reap) decrements
    /// exactly once on drop.
    pub fn begin_conn(self: &Arc<Self>, host: &str) -> ActiveGuard {
        self.total_conns.fetch_add(1, Ordering::Relaxed);
        self.active.fetch_add(1, Ordering::Relaxed);
        self.touch_domain(host);
        ActiveGuard(Arc::clone(self))
    }

    pub fn record_connect_fail(&self) {
        self.connect_fails.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_fail_closed_drop(&self) {
        self.fail_closed_drops.fetch_add(1, Ordering::Relaxed);
    }

    /// Attribute a finished connection's byte totals to `host`. Upserts, so a
    /// heavy domain evicted mid-connection comes back with its traffic.
    pub fn add_domain_bytes(&self, host: &str, up: u64, down: u64) {
        if up == 0 && down == 0 {
            return;
        }
        let mut map = self.domains.lock().unwrap();
        Self::make_room(&mut map, host);
        let d = map.entry(host.to_string()).or_insert(DomainStat {
            conns: 0,
            bytes_up: 0,
            bytes_down: 0,
            last_seen: 0,
        });
        d.bytes_up += up;
        d.bytes_down += down;
        d.last_seen = now_secs();
    }

    fn touch_domain(&self, host: &str) {
        let mut map = self.domains.lock().unwrap();
        Self::make_room(&mut map, host);
        let d = map.entry(host.to_string()).or_insert(DomainStat {
            conns: 0,
            bytes_up: 0,
            bytes_down: 0,
            last_seen: 0,
        });
        d.conns += 1;
        d.last_seen = now_secs();
    }

    /// Evict the least-recently-seen domain when inserting `host` would exceed
    /// the cap.
    fn make_room(map: &mut HashMap<String, DomainStat>, host: &str) {
        if map.len() < DOMAIN_CAP || map.contains_key(host) {
            return;
        }
        if let Some(oldest) = map
            .iter()
            .min_by_key(|(_, d)| d.last_seen)
            .map(|(k, _)| k.clone())
        {
            map.remove(&oldest);
        }
    }

    fn snapshot(&self) -> EgressSnapshot {
        let now = now_secs();
        let mut domains: Vec<DomainSnapshot> = self
            .domains
            .lock()
            .unwrap()
            .iter()
            .map(|(host, d)| DomainSnapshot {
                host: host.clone(),
                conns: d.conns,
                bytes_up: d.bytes_up,
                bytes_down: d.bytes_down,
                last_seen_secs_ago: now.saturating_sub(d.last_seen),
            })
            .collect();
        // Busiest first — this is the order the UI shows.
        domains.sort_by_key(|d| std::cmp::Reverse(d.bytes_up + d.bytes_down));
        EgressSnapshot {
            active: self.active.load(Ordering::Relaxed),
            total_conns: self.total_conns.load(Ordering::Relaxed),
            bytes_up: self.bytes_up.load(Ordering::Relaxed),
            bytes_down: self.bytes_down.load(Ordering::Relaxed),
            connect_fails: self.connect_fails.load(Ordering::Relaxed),
            fail_closed_drops: self.fail_closed_drops.load(Ordering::Relaxed),
            domains,
        }
    }
}

/// RAII decrement for [`EgressStats::begin_conn`].
pub struct ActiveGuard(Arc<EgressStats>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Default, Serialize)]
pub struct EgressSnapshot {
    pub active: u64,
    pub total_conns: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub connect_fails: u64,
    pub fail_closed_drops: u64,
    pub domains: Vec<DomainSnapshot>,
}

#[derive(Serialize)]
pub struct DomainSnapshot {
    pub host: String,
    pub conns: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub last_seen_secs_ago: u64,
}

#[derive(Serialize)]
pub struct RuleHits {
    pub pattern: String,
    pub egress: String,
    pub hits: u64,
}

/// The last active-probe result for one egress, for the stats API / metrics.
#[derive(Serialize)]
pub struct ProbeSnapshot {
    /// Round-trip of the last successful probe (ms); `None` if it failed.
    pub rtt_ms: Option<u32>,
    /// Did the last probe succeed?
    pub ok: bool,
    /// Seconds since the last probe ran.
    pub last_probe_secs_ago: u64,
}

/// Byte-counting wrapper around an egress connection: every successful write
/// counts as up-traffic, every successful read as down-traffic, both into the
/// shared per-egress counters (live, so rates are visible mid-transfer) and into
/// local totals for end-of-connection domain attribution. With `stats: None`
/// (untracked traffic) it's a transparent pass-through.
pub struct Counted<S> {
    inner: S,
    stats: Option<Arc<EgressStats>>,
    up: u64,
    down: u64,
}

impl<S> Counted<S> {
    pub fn new(inner: S, stats: Option<Arc<EgressStats>>) -> Self {
        Self {
            inner,
            stats,
            up: 0,
            down: 0,
        }
    }

    /// (bytes up, bytes down) moved through this connection so far.
    pub fn transferred(&self) -> (u64, u64) {
        (self.up, self.down)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let r = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &r {
            let n = (buf.filled().len() - before) as u64;
            if n > 0 {
                this.down += n;
                if let Some(s) = &this.stats {
                    s.bytes_down.fetch_add(n, Ordering::Relaxed);
                }
            }
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let r = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &r {
            this.up += *n as u64;
            if let Some(s) = &this.stats {
                s.bytes_up.fetch_add(*n as u64, Ordering::Relaxed);
            }
        }
        r
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[tokio::test]
    async fn counted_tracks_both_directions() {
        let stats = Arc::new(EgressStats::default());
        let (mut peer, inner) = duplex(1024);
        let mut conn = Counted::new(inner, Some(Arc::clone(&stats)));

        conn.write_all(b"hello").await.unwrap(); // up: 5
        peer.write_all(b"worlds!").await.unwrap(); // down: 7
        let mut buf = [0u8; 7];
        conn.read_exact(&mut buf).await.unwrap();

        assert_eq!(conn.transferred(), (5, 7));
        assert_eq!(stats.bytes_up.load(Ordering::Relaxed), 5);
        assert_eq!(stats.bytes_down.load(Ordering::Relaxed), 7);
    }

    #[test]
    fn probe_marks_unhealthy_only_after_sustained_failures() {
        let stats = ProxyStats::default();

        // Never probed → not unhealthy, no snapshot (fail open).
        assert!(!stats.probe_unhealthy("wg"));
        assert!(stats.probe_snapshot("wg").is_none());

        // A success records RTT and clears any failure run.
        stats.record_probe("wg", Some(std::time::Duration::from_millis(42)));
        let snap = stats.probe_snapshot("wg").expect("probed");
        assert_eq!(snap.rtt_ms, Some(42));
        assert!(snap.ok);
        assert!(!stats.probe_unhealthy("wg"));

        // Failures below the threshold don't flip health (absorbs a blip).
        stats.record_probe("wg", None);
        stats.record_probe("wg", None);
        assert!(
            !stats.probe_unhealthy("wg"),
            "two failures is under the threshold"
        );

        // The third consecutive failure trips it.
        stats.record_probe("wg", None);
        assert!(stats.probe_unhealthy("wg"));
        assert_eq!(stats.probe_snapshot("wg").unwrap().rtt_ms, None);

        // A single success recovers immediately.
        stats.record_probe("wg", Some(std::time::Duration::from_millis(10)));
        assert!(!stats.probe_unhealthy("wg"));
    }

    #[test]
    fn active_guard_decrements_on_every_drop_path() {
        let stats = Arc::new(EgressStats::default());
        let a = stats.begin_conn("a.test");
        let b = stats.begin_conn("b.test");
        assert_eq!(stats.active.load(Ordering::Relaxed), 2);
        assert_eq!(stats.total_conns.load(Ordering::Relaxed), 2);
        drop(a);
        drop(b);
        assert_eq!(stats.active.load(Ordering::Relaxed), 0);
        // Totals are cumulative, not a gauge.
        assert_eq!(stats.total_conns.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn domain_table_stays_bounded() {
        let stats = Arc::new(EgressStats::default());
        for i in 0..(DOMAIN_CAP + 10) {
            drop(stats.begin_conn(&format!("host{i}.test")));
        }
        assert_eq!(stats.domains.lock().unwrap().len(), DOMAIN_CAP);
        // A known domain still updates without eviction churn.
        stats.add_domain_bytes(&format!("host{}.test", DOMAIN_CAP + 9), 10, 20);
        let snap = stats.snapshot();
        assert_eq!(snap.domains.len(), DOMAIN_CAP);
        assert_eq!(snap.domains[0].bytes_down, 20, "busiest domain sorts first");
    }

    #[test]
    fn prune_drops_removed_egresses_and_rules() {
        use crate::config::{EgressConfig, RuleConfig};

        let stats = ProxyStats::default();
        stats.egress("keep").record_connect_fail();
        stats.egress("gone").record_connect_fail();
        stats.record_rule_hit("a.test", "keep");
        stats.record_rule_hit("b.test", "keep");

        let cfg = ProxyConfig {
            egresses: vec![EgressConfig {
                id: "keep".to_string(),
                name: "keep".to_string(),
                enabled: true,
                kind: "direct".to_string(),
                address: None,
                port: None,
                username: None,
                password: None,
                config: None,
                seg_position: None,
                buffer_kb: None,
                tx_buffer_kb: None,
            }],
            rules: vec![RuleConfig {
                pattern: "a.test".to_string(),
                egress: "keep".to_string(),
                fail_closed: true,
                clients: Vec::new(),
            }],
            ..ProxyConfig::default()
        };
        stats.prune(&cfg);

        assert_eq!(stats.egress_snapshot("keep").connect_fails, 1);
        assert_eq!(stats.egress_snapshot("gone").connect_fails, 0);
        let hits = stats.rule_hits_snapshot();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].pattern, "a.test");
    }
}
