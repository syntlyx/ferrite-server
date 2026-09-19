use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::recent::QueryRingBuffer;
use crate::timeseries::InMemoryTimeseries;
use crate::top_list::TopNCounter;
use ferrite_core::recording::RecordSwitches;
use ferrite_core::types::{QueryEntry, QueryStatus};

/// In-memory live statistics: lock-free atomic counters in the DNS hot path,
/// plus top-N accumulators and a recent-query ring buffer updated in the stats writer.
#[derive(Debug)]
pub struct LiveStats {
    pub total_queries: AtomicU64,
    pub total_blocked: AtomicU64,
    pub total_allowed: AtomicU64,
    pub total_cached: AtomicU64,
    pub total_upstream: AtomicU64,
    /// Answered with the proxy's advertise IP (selective routing).
    pub total_routed: AtomicU64,
    /// Query stats dropped because the writer channel was full (back-pressure).
    /// A sustained nonzero value flags a stalled stats writer.
    pub total_dropped: AtomicU64,

    /// Top queried domains (all statuses).
    pub top_domains: TopNCounter,
    /// Top blocked domains.
    pub top_blocked: TopNCounter,
    /// Top clients by IP.
    pub top_clients: TopNCounter,
    /// Ring buffer of recent queries — source for both the live query log
    /// and the recent_domains / recent_blocked slices in the summary.
    pub recent_queries: QueryRingBuffer,
    /// Rolling 24-hour timeseries (10-min buckets).
    pub timeseries: InMemoryTimeseries,
}

impl LiveStats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            total_queries: AtomicU64::new(0),
            total_blocked: AtomicU64::new(0),
            total_allowed: AtomicU64::new(0),
            total_cached: AtomicU64::new(0),
            total_upstream: AtomicU64::new(0),
            total_routed: AtomicU64::new(0),
            total_dropped: AtomicU64::new(0),
            top_domains: TopNCounter::new(10_000),
            top_blocked: TopNCounter::new(10_000),
            top_clients: TopNCounter::new(1_000),
            recent_queries: QueryRingBuffer::new(2_000),
            timeseries: InMemoryTimeseries::new(),
        })
    }

    /// Called in the DNS handler hot path — only atomic ops, no locking. Takes
    /// the status alone: these counters carry no domain and no client, so they
    /// don't need the log entry, and the entry isn't built at all when nothing
    /// downstream is recording.
    pub fn record_query(&self, status: QueryStatus) {
        self.total_queries.fetch_add(1, Ordering::Relaxed);
        match status {
            QueryStatus::Blocked => {
                self.total_blocked.fetch_add(1, Ordering::Relaxed);
            }
            QueryStatus::Allowed => {
                self.total_allowed.fetch_add(1, Ordering::Relaxed);
            }
            QueryStatus::Cached => {
                self.total_cached.fetch_add(1, Ordering::Relaxed);
            }
            QueryStatus::Upstream => {
                self.total_upstream.fetch_add(1, Ordering::Relaxed);
            }
            QueryStatus::Routed => {
                self.total_routed.fetch_add(1, Ordering::Relaxed);
            }
        };
    }

    /// Called in the stats writer for each entry as it arrives from the channel.
    /// Updates top-N counters and the ring buffer (takes ownership for the buffer).
    ///
    /// The two surfaces are independent: the top-N counters and the 24-hour
    /// timeseries belong to statistics, the recent-queries ring belongs to the
    /// query log, and with one switched off the entry simply never lands there.
    ///
    /// The scope is read here rather than passed in by the caller. The settings
    /// handler flips a switch and then empties these very structures, so a scope
    /// read earlier in the writer's loop could push an entry into a ring that was
    /// cleared in between. Reading at the point of use narrows that to the few
    /// instructions below — it is not a lock, and the single entry being
    /// processed at the exact moment of the flip can still survive the clear.
    pub fn push_entry(&self, entry: &QueryEntry, switches: &RecordSwitches) {
        let scope = switches.scope();

        if scope.stats {
            let status = entry.status;
            self.top_domains.increment(&entry.domain);
            if status == QueryStatus::Blocked {
                self.top_blocked.increment(&entry.domain);
            }
            // Key by device (MAC when known, else IP) so the live summary matches the
            // device-keyed DB rollups. Falls back to the IP for not-yet-tagged entries.
            let device_key = if entry.device.is_empty() {
                &entry.client_ip
            } else {
                &entry.device
            };
            self.top_clients.increment(device_key);
            self.timeseries
                .increment(entry.timestamp.timestamp() as u64, status);
        }

        // Only the ring keeps the entry, so only the ring pays for a copy —
        // and not at all when the query log is switched off.
        if scope.queries {
            self.recent_queries.push(entry.clone());
        }
    }

    /// Drop the in-memory query history: the recent-queries ring buffer that
    /// backs the live query log. Called when the query log is switched off, so
    /// the last few thousand queries stop being visible in the UI immediately
    /// rather than decaying out of the buffer over the next hours.
    pub fn forget_recent(&self) {
        self.recent_queries.clear();
    }

    /// Drop the in-memory statistics: top-N counters and the rolling 24-hour
    /// timeseries. Same reasoning as [`LiveStats::forget_recent`], for the
    /// statistics switch. The lifetime counters survive — they carry no domain
    /// or device identity and are what the dashboard falls back to.
    pub fn forget_history(&self) {
        self.top_domains.clear();
        self.top_blocked.clear();
        self.top_clients.clear();
        self.timeseries.clear();
    }

    /// Reset all in-memory stats to zero. Called when the query log is cleared via the API.
    pub fn reset_all(&self) {
        self.total_queries.store(0, Ordering::Relaxed);
        self.total_blocked.store(0, Ordering::Relaxed);
        self.total_allowed.store(0, Ordering::Relaxed);
        self.total_cached.store(0, Ordering::Relaxed);
        self.total_upstream.store(0, Ordering::Relaxed);
        self.total_routed.store(0, Ordering::Relaxed);
        self.total_dropped.store(0, Ordering::Relaxed);
        self.top_domains.clear();
        self.top_blocked.clear();
        self.top_clients.clear();
        self.recent_queries.clear();
        self.timeseries.clear();
    }

    pub fn total(&self) -> u64 {
        self.total_queries.load(Ordering::Relaxed)
    }

    pub fn blocked(&self) -> u64 {
        self.total_blocked.load(Ordering::Relaxed)
    }

    pub fn dropped(&self) -> u64 {
        self.total_dropped.load(Ordering::Relaxed)
    }

    pub fn block_percentage(&self) -> f64 {
        let total = self.total();
        if total == 0 {
            return 0.0;
        }
        (self.blocked() as f64 / total as f64) * 100.0
    }
}

impl Default for LiveStats {
    fn default() -> Self {
        Arc::try_unwrap(Self::new()).expect("freshly created Arc has exactly one reference")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_core::recording::RecordScope;

    fn entry(domain: &str) -> QueryEntry {
        QueryEntry {
            id: 1,
            timestamp: chrono::Utc::now(),
            domain: domain.to_string(),
            query_type: 1,
            client_ip: "192.0.2.10".to_string(),
            device: "aa:bb:cc:dd:ee:ff".to_string(),
            status: QueryStatus::Blocked,
            latency_ms: 1,
            upstream: None,
            rcode: 0,
        }
    }

    /// Each surface follows its own switch: statistics drive the top-N counters
    /// and the 24-hour timeseries, the query log drives the recent-queries ring.
    fn push_with(scope: RecordScope) -> Arc<LiveStats> {
        let live = LiveStats::new();
        let switches = ferrite_core::recording::RecordSwitches::new(scope);
        live.push_entry(&entry("x.test"), &switches);
        live
    }

    #[test]
    fn recording_everything_fills_both_surfaces() {
        let live = push_with(RecordScope::ALL);
        assert_eq!(live.top_domains.top(10).len(), 1);
        assert_eq!(live.top_blocked.top(10).len(), 1);
        assert_eq!(live.top_clients.top(10)[0].0, "aa:bb:cc:dd:ee:ff");
        assert_eq!(live.recent_queries.recent(10).len(), 1);
        assert!(live.timeseries.buckets_24h().iter().any(|b| b.total > 0));
    }

    #[test]
    fn statistics_off_keeps_only_the_query_log() {
        let live = push_with(RecordScope {
            queries: true,
            stats: false,
        });
        assert!(live.top_domains.top(10).is_empty());
        assert!(live.top_blocked.top(10).is_empty());
        assert!(live.top_clients.top(10).is_empty());
        assert!(live.timeseries.buckets_24h().iter().all(|b| b.total == 0));
        assert_eq!(live.recent_queries.recent(10).len(), 1);
    }

    #[test]
    fn query_log_off_keeps_only_the_aggregates() {
        let live = push_with(RecordScope {
            queries: false,
            stats: true,
        });
        assert_eq!(live.top_domains.top(10).len(), 1);
        assert!(live.recent_queries.recent(10).is_empty());
    }

    #[test]
    fn recording_nothing_touches_neither() {
        let live = push_with(RecordScope::NONE);
        assert!(live.top_domains.top(10).is_empty());
        assert!(live.top_clients.top(10).is_empty());
        assert!(live.recent_queries.recent(10).is_empty());
        assert!(live.timeseries.buckets_24h().iter().all(|b| b.total == 0));
    }

    /// The switches are read at push time, so flipping one mid-run changes what
    /// the very next entry does without rebuilding anything.
    #[test]
    fn flipping_a_switch_changes_the_next_push() {
        let live = LiveStats::new();
        let switches = ferrite_core::recording::RecordSwitches::new(RecordScope::ALL);

        live.push_entry(&entry("first.test"), &switches);
        switches.set_queries(false);
        live.push_entry(&entry("second.test"), &switches);

        assert_eq!(live.recent_queries.recent(10).len(), 1);
        assert_eq!(live.top_domains.top(10).len(), 2, "statistics stayed on");
    }
}
