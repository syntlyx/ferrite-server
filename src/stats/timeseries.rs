use std::collections::HashMap;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::dns::types::QueryStatus;

/// One time bucket in the 24-hour rolling window (10-minute granularity).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeseriesBucket {
    /// Unix timestamp of the start of this bucket (aligned to 600 s).
    pub bucket: u64,
    /// Total queries in this bucket.
    pub total: u64,
    /// Blocked queries in this bucket.
    pub blocked: u64,
    /// Served from DNS cache in this bucket.
    pub cached: u64,
    /// Forwarded to upstream resolvers in this bucket.
    pub upstream: u64,
}

/// Rolling 24-hour timeseries with 10-minute bucket granularity, kept in memory.
/// Updated on every query; read on dashboard polls.
pub struct InMemoryTimeseries {
    buckets: Mutex<HashMap<u64, TimeseriesBucket>>,
}

impl InMemoryTimeseries {
    pub fn new() -> Self {
        Self {
            buckets: Mutex::new(HashMap::with_capacity(150)),
        }
    }

    pub fn increment(&self, timestamp_secs: u64, status: QueryStatus) {
        const BUCKET_SECS: u64 = 600;
        // Keep 25 hours of buckets (24h window + 1 bucket of slack).
        const WINDOW_SECS: u64 = 86_400 + BUCKET_SECS;

        let bucket_ts = (timestamp_secs / BUCKET_SECS) * BUCKET_SECS;
        let mut map = self.buckets.lock();

        // Prune stale buckets only when a new bucket key is inserted (every 10 min),
        // so the HashMap stays bounded without O(n) work on every query.
        let is_new = !map.contains_key(&bucket_ts);
        let b = map.entry(bucket_ts).or_insert(TimeseriesBucket {
            bucket: bucket_ts,
            total: 0,
            blocked: 0,
            cached: 0,
            upstream: 0,
        });
        b.total += 1;
        match status {
            QueryStatus::Blocked => b.blocked += 1,
            QueryStatus::Cached => b.cached += 1,
            QueryStatus::Upstream => b.upstream += 1,
            QueryStatus::Allowed => {}
        }
        if is_new {
            let cutoff = bucket_ts.saturating_sub(WINDOW_SECS);
            map.retain(|&ts, _| ts >= cutoff);
        }
    }

    /// Returns all buckets within the last 24 hours, sorted by timestamp ascending.
    /// Empty buckets are omitted (same behaviour as the SQLite query).
    pub fn buckets_24h(&self) -> Vec<TimeseriesBucket> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let cutoff = now.saturating_sub(86400);
        let map = self.buckets.lock();
        let mut v: Vec<TimeseriesBucket> = map
            .values()
            .filter(|b| b.bucket >= cutoff)
            .cloned()
            .collect();
        v.sort_unstable_by_key(|b| b.bucket);
        v
    }

    /// Populate from persisted data (called once at startup from SQLite).
    pub fn seed(&self, buckets: &[TimeseriesBucket]) {
        let mut map = self.buckets.lock();
        for b in buckets {
            map.insert(b.bucket, b.clone());
        }
    }

    pub fn clear(&self) {
        self.buckets.lock().clear();
    }
}

impl std::fmt::Debug for InMemoryTimeseries {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryTimeseries").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_counts_status_breakdown() {
        let ts = InMemoryTimeseries::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        ts.increment(now, QueryStatus::Blocked);
        ts.increment(now, QueryStatus::Cached);
        ts.increment(now, QueryStatus::Upstream);
        ts.increment(now, QueryStatus::Allowed);

        let buckets = ts.buckets_24h();
        let bucket = buckets
            .iter()
            .find(|b| b.bucket == (now / 600) * 600)
            .unwrap();
        assert_eq!(bucket.total, 4);
        assert_eq!(bucket.blocked, 1);
        assert_eq!(bucket.cached, 1);
        assert_eq!(bucket.upstream, 1);
    }
}
