use std::time::{Duration, Instant};

use lru::LruCache;
use parking_lot::RwLock;
use std::num::NonZeroUsize;

use crate::dns::types::DnsResponse;

pub const MIN_TTL: u64 = 60;
pub const MAX_TTL: u64 = 3600;

#[derive(Debug, Clone, Copy)]
struct TtlBounds {
    min_secs: u64,
    max_secs: u64,
}

/// A single DNS cache entry containing the wire-format response and expiry.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub response: DnsResponse,
    pub expires_at: Instant,
}

impl CacheEntry {
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

/// Thread-safe DNS response cache backed by an LRU eviction policy.
pub struct DnsCache {
    inner: RwLock<LruCache<String, CacheEntry>>,
    ttl_bounds: RwLock<TtlBounds>,
}

impl DnsCache {
    pub fn new(capacity: usize, min_ttl: u64, max_ttl: u64) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap();
        Self {
            inner: RwLock::new(LruCache::new(cap)),
            ttl_bounds: RwLock::new(normalize_ttl_bounds(min_ttl, max_ttl)),
        }
    }

    /// Build a cache key from (name, qtype).
    pub fn cache_key(name: &str, qtype: u16) -> String {
        format!("{}/{}", name.to_ascii_lowercase(), qtype)
    }

    /// Retrieve a cached entry. Returns `None` if not present or expired.
    /// Uses `peek` (shared lock, no LRU promotion) — expired entries are
    /// cleaned up by the janitor task rather than proactively here.
    ///
    /// The query path uses `get_with_remaining` (which also returns the
    /// remaining TTL); this is retained for snapshot restore tests.
    #[allow(dead_code)]
    pub fn get(&self, name: &str, qtype: u16) -> Option<DnsResponse> {
        let key = Self::cache_key(name, qtype);
        let guard = self.inner.read();
        match guard.peek(&key) {
            Some(entry) if !entry.is_expired() => Some(entry.response.clone()),
            _ => None,
        }
    }

    /// Like `get`, but also returns the entry's remaining lifetime in seconds.
    /// Callers rewrite the record TTLs to this value so clients receive the
    /// real remaining TTL rather than the original (over-long) one (RFC 2181).
    pub fn get_with_remaining(&self, name: &str, qtype: u16) -> Option<(DnsResponse, u32)> {
        let key = Self::cache_key(name, qtype);
        let guard = self.inner.read();
        match guard.peek(&key) {
            Some(entry) if !entry.is_expired() => {
                let remaining = entry
                    .expires_at
                    .saturating_duration_since(Instant::now())
                    .as_secs()
                    .min(u32::MAX as u64) as u32;
                Some((entry.response.clone(), remaining))
            }
            _ => None,
        }
    }

    /// Insert a DNS response into the cache.
    pub fn insert(&self, name: &str, qtype: u16, response: DnsResponse) {
        let key = Self::cache_key(name, qtype);
        let ttl_secs = response.ttl as u64;
        let bounds = *self.ttl_bounds.read();
        let clamped = ttl_secs.max(bounds.min_secs).min(bounds.max_secs);
        let entry = CacheEntry {
            response,
            expires_at: Instant::now() + Duration::from_secs(clamped),
        };
        self.inner.write().put(key, entry);
    }

    /// Update the TTL clamp used for future cache inserts.
    pub fn set_ttl_bounds(&self, min_ttl: u64, max_ttl: u64) {
        *self.ttl_bounds.write() = normalize_ttl_bounds(min_ttl, max_ttl);
    }

    #[allow(dead_code)]
    pub fn min_ttl_secs(&self) -> u64 {
        self.ttl_bounds.read().min_secs
    }

    /// The configured max TTL — the ceiling for what any client should cache.
    pub fn max_ttl_secs(&self) -> u64 {
        self.ttl_bounds.read().max_secs
    }

    /// Explicitly evict an entry.
    #[allow(dead_code)]
    pub fn evict(&self, name: &str, qtype: u16) {
        let key = Self::cache_key(name, qtype);
        self.inner.write().pop(&key);
    }

    /// Evict every cached entry for `name`, across all qtypes. Cache keys are
    /// `name/qtype`, so this pops all keys with the `name/` prefix — covering
    /// qtypes (ANY, MX, …) that a hardcoded qtype list would miss.
    pub fn evict_domain(&self, name: &str) {
        let prefix = format!("{}/", name.to_ascii_lowercase());
        let mut guard = self.inner.write();
        let keys: Vec<String> = guard
            .iter()
            .map(|(k, _)| k.clone())
            .filter(|k| k.starts_with(&prefix))
            .collect();
        for k in keys {
            guard.pop(&k);
        }
    }

    /// Remove all expired entries. Called by the janitor task.
    pub fn evict_expired(&self) {
        let now = Instant::now();
        let mut guard = self.inner.write();
        // LruCache doesn't expose drain_filter, so collect expired keys first.
        let expired: Vec<String> = guard
            .iter()
            .filter(|(_, v)| now >= v.expires_at)
            .map(|(k, _)| k.clone())
            .collect();
        for k in expired {
            guard.pop(&k);
        }
    }

    /// Current number of entries.
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Flush the entire cache.
    #[allow(dead_code)]
    pub fn clear(&self) {
        self.inner.write().clear();
    }

    /// Export all non-expired entries for snapshotting.
    pub fn snapshot(&self) -> Vec<(String, DnsResponse, std::time::Instant)> {
        let now = std::time::Instant::now();
        self.inner
            .read()
            .iter()
            .filter(|(_, e)| e.expires_at > now)
            .map(|(k, e)| (k.clone(), e.response.clone(), e.expires_at))
            .collect()
    }

    /// Restore entries from a snapshot, skipping any that have already expired.
    /// `entries` is a list of (key, bytes, ttl, expires_unix_secs).
    pub fn restore(&self, entries: &[(String, Vec<u8>, u32, i64)]) {
        let now_instant = std::time::Instant::now();
        let now_unix = chrono::Utc::now().timestamp();
        let mut guard = self.inner.write();
        for (key, bytes, ttl, expires_unix) in entries {
            let remaining_secs = expires_unix - now_unix;
            if remaining_secs <= 0 {
                continue; // already expired
            }
            let expires_at = now_instant + std::time::Duration::from_secs(remaining_secs as u64);
            let entry = CacheEntry {
                response: DnsResponse {
                    bytes: bytes::Bytes::copy_from_slice(bytes),
                    ttl: *ttl,
                },
                expires_at,
            };
            guard.put(key.clone(), entry);
        }
    }
}

fn normalize_ttl_bounds(min_ttl: u64, max_ttl: u64) -> TtlBounds {
    let min_secs = min_ttl.clamp(MIN_TTL, MAX_TTL);
    let max_secs = max_ttl.clamp(MIN_TTL, MAX_TTL).max(min_secs);
    TtlBounds { min_secs, max_secs }
}

/// Background task that purges expired entries every minute.
pub async fn janitor(cache: std::sync::Arc<DnsCache>) {
    let interval = tokio::time::Duration::from_secs(60);
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        // evict_expired holds a write lock while iterating — move off the
        // tokio worker thread so DNS query tasks aren't stalled.
        let c = std::sync::Arc::clone(&cache);
        tokio::task::spawn_blocking(move || c.evict_expired())
            .await
            .ok();
        tracing::debug!("dns cache janitor: {} entries remaining", cache.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(ttl: u32) -> DnsResponse {
        DnsResponse {
            bytes: bytes::Bytes::from_static(b"response"),
            ttl,
        }
    }

    #[test]
    fn hot_ttl_bounds_apply_to_future_inserts() {
        let cache = DnsCache::new(8, 60, 300);
        cache.set_ttl_bounds(120, 120);
        cache.insert("example.com", 1, response(30));

        let expires_at = cache.snapshot()[0].2;
        let remaining = expires_at.saturating_duration_since(Instant::now());
        assert!(remaining.as_secs() >= 118);
    }

    #[test]
    fn ttl_bounds_are_normalized() {
        let cache = DnsCache::new(8, 7200, 30);
        assert_eq!(cache.min_ttl_secs(), MAX_TTL);
    }

    #[test]
    fn evict_domain_removes_all_qtypes_for_that_name_only() {
        let cache = DnsCache::new(16, 60, 300);
        cache.insert("router.lan", 1, response(120)); // A
        cache.insert("router.lan", 28, response(120)); // AAAA
        cache.insert("router.lan", 255, response(120)); // ANY
        cache.insert("other.lan", 1, response(120));

        cache.evict_domain("router.lan");

        assert!(cache.get("router.lan", 1).is_none());
        assert!(cache.get("router.lan", 28).is_none());
        assert!(
            cache.get("router.lan", 255).is_none(),
            "ANY must be evicted too"
        );
        // A different domain is untouched.
        assert!(cache.get("other.lan", 1).is_some());
    }
}
