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

/// Approximate fixed per-entry overhead beyond the key and response bytes:
/// String/Bytes headers, the expiry Instant, LRU node links and the hash slot.
const ENTRY_OVERHEAD: usize = 128;

/// Cost of one entry against the byte budget.
fn entry_cost(key: &str, entry: &CacheEntry) -> usize {
    key.len() + entry.response.bytes.len() + ENTRY_OVERHEAD
}

/// The LRU map plus its byte accounting — one lock, so they can't drift apart.
struct Inner {
    lru: LruCache<String, CacheEntry>,
    total_bytes: usize,
}

impl Inner {
    /// Remove `key`, keeping the byte accounting in step.
    fn pop(&mut self, key: &str) {
        if let Some(v) = self.lru.pop(key) {
            self.total_bytes -= entry_cost(key, &v);
        }
    }

    /// Insert, then shrink back under the byte budget.
    fn put(&mut self, key: String, entry: CacheEntry, max_bytes: usize) {
        self.total_bytes += entry_cost(&key, &entry);
        // `push`, not `put`: it returns the pair displaced by a same-key
        // replace AND the one evicted by the count bound — both must be
        // subtracted or the accounting drifts upward forever.
        if let Some((k, v)) = self.lru.push(key, entry) {
            self.total_bytes -= entry_cost(&k, &v);
        }
        // Byte budget: entry count alone can't bound memory (a DNSSEC answer
        // with RRSIGs is 10–20× a plain one), so evict coldest-first by bytes
        // too. `len() > 1` retains a single over-budget entry instead of
        // looping the cache down to empty.
        while self.total_bytes > max_bytes && self.lru.len() > 1 {
            match self.lru.pop_lru() {
                Some((k, v)) => self.total_bytes -= entry_cost(&k, &v),
                None => break,
            }
        }
    }
}

/// Thread-safe DNS response cache, bounded by entry count (LRU capacity) and
/// by total bytes.
pub struct DnsCache {
    inner: RwLock<Inner>,
    /// Byte budget across all entries; `usize::MAX` = unbounded.
    max_bytes: usize,
    ttl_bounds: RwLock<TtlBounds>,
}

impl DnsCache {
    /// `max_bytes == 0` disables the byte bound (count bound still applies).
    pub fn new(capacity: usize, max_bytes: usize, min_ttl: u64, max_ttl: u64) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap();
        Self {
            inner: RwLock::new(Inner {
                lru: LruCache::new(cap),
                total_bytes: 0,
            }),
            max_bytes: if max_bytes == 0 {
                usize::MAX
            } else {
                max_bytes
            },
            ttl_bounds: RwLock::new(normalize_ttl_bounds(min_ttl, max_ttl)),
        }
    }

    /// Build a cache key from (name, qtype, dnssec). DNSSEC-OK responses carry
    /// signatures and differ from the bare ones, so they're cached separately:
    /// a DO client must never be served an unsigned answer (validation would
    /// fail), nor a non-DO client the bulky signed one (oversized → truncation
    /// → TCP). The non-DO form keeps the original two-part key so snapshots
    /// written before this split still restore and match.
    pub fn cache_key(name: &str, qtype: u16, dnssec: bool) -> String {
        let name = name.to_ascii_lowercase();
        if dnssec {
            format!("{name}/{qtype}/do")
        } else {
            format!("{name}/{qtype}")
        }
    }

    /// Retrieve a cached entry. Returns `None` if not present or expired.
    /// Uses `peek` (shared lock, no LRU promotion) — expired entries are
    /// cleaned up by the janitor task rather than proactively here.
    ///
    /// The query path uses `get_with_remaining` (which also returns the
    /// remaining TTL); this is retained for snapshot restore tests.
    #[allow(dead_code)]
    pub fn get(&self, name: &str, qtype: u16, dnssec: bool) -> Option<DnsResponse> {
        let key = Self::cache_key(name, qtype, dnssec);
        let guard = self.inner.read();
        match guard.lru.peek(&key) {
            Some(entry) if !entry.is_expired() => Some(entry.response.clone()),
            _ => None,
        }
    }

    /// Like `get`, but also returns the entry's remaining lifetime in seconds.
    /// Callers rewrite the record TTLs to this value so clients receive the
    /// real remaining TTL rather than the original (over-long) one (RFC 2181).
    pub fn get_with_remaining(
        &self,
        name: &str,
        qtype: u16,
        dnssec: bool,
    ) -> Option<(DnsResponse, u32)> {
        let key = Self::cache_key(name, qtype, dnssec);
        let guard = self.inner.read();
        match guard.lru.peek(&key) {
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
    pub fn insert(&self, name: &str, qtype: u16, dnssec: bool, response: DnsResponse) {
        let key = Self::cache_key(name, qtype, dnssec);
        let ttl_secs = response.ttl as u64;
        let bounds = *self.ttl_bounds.read();
        let clamped = ttl_secs.max(bounds.min_secs).min(bounds.max_secs);
        let entry = CacheEntry {
            response,
            expires_at: Instant::now() + Duration::from_secs(clamped),
        };
        self.inner.write().put(key, entry, self.max_bytes);
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
    pub fn evict(&self, name: &str, qtype: u16, dnssec: bool) {
        let key = Self::cache_key(name, qtype, dnssec);
        self.inner.write().pop(&key);
    }

    /// Total bytes currently accounted to cache entries.
    pub fn bytes(&self) -> usize {
        self.inner.read().total_bytes
    }

    /// Evict every cached entry for `name`, across all qtypes. Cache keys are
    /// `name/qtype`, so this pops all keys with the `name/` prefix — covering
    /// qtypes (ANY, MX, …) that a hardcoded qtype list would miss.
    pub fn evict_domain(&self, name: &str) {
        let prefix = format!("{}/", name.to_ascii_lowercase());
        let mut guard = self.inner.write();
        let keys: Vec<String> = guard
            .lru
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(k, _)| k.clone())
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
            .lru
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
        self.inner.read().lru.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Flush the entire cache.
    #[allow(dead_code)]
    pub fn clear(&self) {
        let mut guard = self.inner.write();
        guard.lru.clear();
        guard.total_bytes = 0;
    }

    /// Export all non-expired entries for snapshotting.
    pub fn snapshot(&self) -> Vec<(String, DnsResponse, std::time::Instant)> {
        let now = std::time::Instant::now();
        self.inner
            .read()
            .lru
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
            guard.put(key.clone(), entry, self.max_bytes);
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
        tracing::debug!(
            "dns cache janitor: {} entries, {} KiB remaining",
            cache.len(),
            cache.bytes() / 1024
        );
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
        let cache = DnsCache::new(8, 0, 60, 300);
        cache.set_ttl_bounds(120, 120);
        cache.insert("example.com", 1, false, response(30));

        let expires_at = cache.snapshot()[0].2;
        let remaining = expires_at.saturating_duration_since(Instant::now());
        assert!(remaining.as_secs() >= 118);
    }

    #[test]
    fn ttl_bounds_are_normalized() {
        let cache = DnsCache::new(8, 0, 7200, 30);
        assert_eq!(cache.min_ttl_secs(), MAX_TTL);
    }

    #[test]
    fn evict_domain_removes_all_qtypes_for_that_name_only() {
        let cache = DnsCache::new(16, 0, 60, 300);
        cache.insert("router.lan", 1, false, response(120)); // A
        cache.insert("router.lan", 28, false, response(120)); // AAAA
        cache.insert("router.lan", 255, false, response(120)); // ANY
        cache.insert("other.lan", 1, false, response(120));
        // A DNSSEC-keyed entry shares the `router.lan/` prefix and must go too.
        cache.insert("router.lan", 1, true, response(120));

        cache.evict_domain("router.lan");

        assert!(cache.get("router.lan", 1, false).is_none());
        assert!(cache.get("router.lan", 28, false).is_none());
        assert!(
            cache.get("router.lan", 255, false).is_none(),
            "ANY must be evicted too"
        );
        assert!(
            cache.get("router.lan", 1, true).is_none(),
            "DNSSEC-keyed entry must be evicted too"
        );
        // A different domain is untouched.
        assert!(cache.get("other.lan", 1, false).is_some());
    }

    #[test]
    fn dnssec_and_plain_entries_do_not_collide() {
        let cache = DnsCache::new(8, 0, 60, 300);
        // A signed (DO) entry must never be visible to a non-DO lookup — that's
        // what bloated non-DO clients and what served unsigned answers to DO
        // clients before the cache learned the DO dimension.
        cache.insert("example.com", 1, true, response(120));
        assert!(
            cache.get("example.com", 1, false).is_none(),
            "non-DO lookup must not see the signed entry"
        );
        assert!(cache.get("example.com", 1, true).is_some());

        // The two coexist as independent entries.
        cache.insert("example.com", 1, false, response(120));
        assert!(cache.get("example.com", 1, false).is_some());
        assert!(cache.get("example.com", 1, true).is_some());
    }

    #[test]
    fn byte_budget_evicts_coldest_entries() {
        // Each entry costs key("x.test/1"=8) + body(8) + ENTRY_OVERHEAD(128) =
        // 144 bytes; a 400-byte budget fits two entries but not three.
        let cache = DnsCache::new(100, 400, 60, 300);
        cache.insert("a.test", 1, false, response(120));
        cache.insert("b.test", 1, false, response(120));
        cache.insert("c.test", 1, false, response(120));

        assert!(
            cache.get("a.test", 1, false).is_none(),
            "coldest entry must be evicted to fit the byte budget"
        );
        assert!(cache.get("b.test", 1, false).is_some());
        assert!(cache.get("c.test", 1, false).is_some());
        assert!(cache.bytes() <= 400);
    }

    #[test]
    fn byte_accounting_tracks_replaces_and_evictions() {
        // Count-capped at 2, no byte cap: exercises same-key replace and
        // capacity eviction, the two paths where `push` returns a displaced
        // entry that must be subtracted.
        let cache = DnsCache::new(2, 0, 60, 300);
        cache.insert("a.test", 1, false, response(120));
        let after_one = cache.bytes();
        cache.insert("a.test", 1, false, response(120)); // same-key replace
        assert_eq!(cache.bytes(), after_one, "replace must not double-count");

        cache.insert("b.test", 1, false, response(120));
        cache.insert("c.test", 1, false, response(120)); // capacity-evicts a.test

        cache.evict("b.test", 1, false);
        cache.evict_domain("c.test");
        assert_eq!(cache.len(), 0);
        assert_eq!(
            cache.bytes(),
            0,
            "all entries gone — accounting must return to zero"
        );
    }
}
