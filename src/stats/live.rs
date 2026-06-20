use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::dns::types::{QueryEntry, QueryStatus};
use crate::stats::recent::QueryRingBuffer;
use crate::stats::timeseries::InMemoryTimeseries;
use crate::stats::top_list::TopNCounter;

/// In-memory live statistics: lock-free atomic counters in the DNS hot path,
/// plus top-N accumulators and a recent-query ring buffer updated in the stats writer.
#[derive(Debug)]
pub struct LiveStats {
    pub total_queries: AtomicU64,
    pub total_blocked: AtomicU64,
    pub total_allowed: AtomicU64,
    pub total_cached: AtomicU64,
    pub total_upstream: AtomicU64,
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
            total_dropped: AtomicU64::new(0),
            top_domains: TopNCounter::new(10_000),
            top_blocked: TopNCounter::new(10_000),
            top_clients: TopNCounter::new(1_000),
            recent_queries: QueryRingBuffer::new(2_000),
            timeseries: InMemoryTimeseries::new(),
        })
    }

    /// Called in the DNS handler hot path — only atomic ops, no locking.
    pub fn record_query(&self, entry: &QueryEntry) {
        self.total_queries.fetch_add(1, Ordering::Relaxed);
        match entry.status {
            QueryStatus::Blocked => self.total_blocked.fetch_add(1, Ordering::Relaxed),
            QueryStatus::Allowed => self.total_allowed.fetch_add(1, Ordering::Relaxed),
            QueryStatus::Cached => self.total_cached.fetch_add(1, Ordering::Relaxed),
            QueryStatus::Upstream => self.total_upstream.fetch_add(1, Ordering::Relaxed),
        };
    }

    /// Called in the stats writer for each entry as it arrives from the channel.
    /// Updates top-N counters and the ring buffer (takes ownership for the buffer).
    pub fn push_entry(&self, entry: QueryEntry) {
        let status = entry.status.clone();
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
        self.recent_queries.push(entry);
    }

    /// Reset all in-memory stats to zero. Called when the query log is cleared via the API.
    pub fn reset_all(&self) {
        self.total_queries.store(0, Ordering::Relaxed);
        self.total_blocked.store(0, Ordering::Relaxed);
        self.total_allowed.store(0, Ordering::Relaxed);
        self.total_cached.store(0, Ordering::Relaxed);
        self.total_upstream.store(0, Ordering::Relaxed);
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
