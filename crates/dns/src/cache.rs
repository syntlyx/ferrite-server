use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use lru::LruCache;
use parking_lot::{Mutex, RwLock};
use std::num::NonZeroUsize;

use crate::types::DnsResponse;

/// Range a cache TTL bound may be configured to, in seconds.
///
/// The lower end is `0`, not a floor of its own: `min_ttl = 0` means "keep an
/// answer exactly as long as its origin said", which is the only way to *not*
/// override the origin. A non-zero `min_ttl` trades that away for fewer upstream
/// queries — we keep serving a record whose own lifetime has expired, which is
/// wrong for the short TTLs a CDN uses to steer traffic away from a dead host.
/// How long a *client* then caches what we hand it is a separate knob
/// (`dns.client_ttl`).
pub const MIN_TTL: u64 = 0;
pub const MAX_TTL: u64 = 3600;

/// The TTL a stale answer goes out with (RFC 8767 §4 suggests 30 seconds):
/// long enough to spare the client an immediate retry, short enough that the
/// refreshed answer reaches it soon after.
pub const STALE_ANSWER_TTL: u32 = 30;

/// The longest an entry may be served past its expiry, in seconds — a week.
pub const MAX_STALE_AGE: u64 = 7 * 24 * 3600;

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
    /// Byte budget across all entries; `usize::MAX` = unbounded. Hot-patchable.
    max_bytes: AtomicUsize,
    ttl_bounds: RwLock<TtlBounds>,
    /// How long past expiry an entry is still kept and served (seconds);
    /// `0` turns the optimistic cache off. Hot-patchable.
    stale_window: AtomicU64,
    /// Keys being refreshed in the background, so a burst of stale hits on
    /// one name sends one upstream query, not one per hit.
    refreshing: Mutex<HashSet<String>>,
}

/// `0` means no byte bound.
fn byte_budget(max_bytes: usize) -> usize {
    if max_bytes == 0 {
        usize::MAX
    } else {
        max_bytes
    }
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
            max_bytes: AtomicUsize::new(byte_budget(max_bytes)),
            ttl_bounds: RwLock::new(normalize_ttl_bounds(min_ttl, max_ttl)),
            stale_window: AtomicU64::new(0),
            refreshing: Mutex::new(HashSet::new()),
        }
    }

    /// Serve entries up to `secs` past their expiry (`0` = never). Entries
    /// already dropped stay dropped; from now on expired ones are kept.
    pub fn set_stale_window(&self, secs: u64) {
        self.stale_window
            .store(secs.min(MAX_STALE_AGE), Ordering::Relaxed);
    }

    pub fn stale_window_secs(&self) -> u64 {
        self.stale_window.load(Ordering::Relaxed)
    }

    /// An entry that has expired but is still inside the stale window — for the
    /// optimistic cache to answer with while it fetches a fresh one. `None`
    /// when the window is off, the entry is fresh (use
    /// [`Self::get_with_remaining`]) or too old.
    pub fn get_stale(&self, name: &str, qtype: u16, dnssec: bool) -> Option<DnsResponse> {
        let window = self.stale_window.load(Ordering::Relaxed);
        if window == 0 {
            return None;
        }
        Self::with_key(name, qtype, dnssec, |key| {
            let guard = self.inner.read();
            let entry = guard.lru.peek(key)?;
            let now = Instant::now();
            (now >= entry.expires_at && now < entry.expires_at + Duration::from_secs(window))
                .then(|| entry.response.clone())
        })
    }

    /// Claim the background refresh of `key`. `false` when one is already
    /// running; whoever gets `true` must call [`Self::end_refresh`].
    pub fn begin_refresh(&self, key: &str) -> bool {
        self.refreshing.lock().insert(key.to_string())
    }

    pub fn end_refresh(&self, key: &str) {
        self.refreshing.lock().remove(key);
    }

    /// Build a cache key from (name, qtype, dnssec). DNSSEC-OK responses carry
    /// signatures and differ from the bare ones, so they're cached separately:
    /// a DO client must never be served an unsigned answer (validation would
    /// fail), nor a non-DO client the bulky signed one (oversized → truncation
    /// → TCP). The non-DO form keeps the original two-part key so snapshots
    /// written before this split still restore and match.
    ///
    /// Built in one allocation: called once per lookup and again per insert, so
    /// the obvious `to_ascii_lowercase()` + `format!()` pair cost two per query
    /// and copied the name twice. Lowercasing in place after the copy is the
    /// same normalisation for one.
    pub fn cache_key(name: &str, qtype: u16, dnssec: bool) -> String {
        use std::fmt::Write;
        // name + '/' + at most 5 digits + "/do"
        let mut key = String::with_capacity(name.len() + 9);
        key.push_str(name);
        key.make_ascii_lowercase();
        let _ = write!(key, "/{qtype}");
        if dnssec {
            key.push_str("/do");
        }
        key
    }

    /// The longest key that fits the stack buffer below: a 255-byte name
    /// (RFC 1035 §2.3.4) plus `/65535/do`.
    const KEY_STACK_LEN: usize = 255 + 9;

    /// Call `f` with the key for this lookup, built on the stack.
    ///
    /// A lookup only borrows the key to hash it, so the owned form above was an
    /// allocation per query that the map dropped immediately — and `write!` for
    /// the qtype cost more than the copy. An over-long name (reachable only
    /// through escaped presentation forms) falls back to the owned key.
    fn with_key<R>(name: &str, qtype: u16, dnssec: bool, f: impl FnOnce(&str) -> R) -> R {
        let mut buf = [0u8; Self::KEY_STACK_LEN];
        let mut len = name.len();
        if len + 9 > buf.len() {
            return f(&Self::cache_key(name, qtype, dnssec));
        }
        buf[..len].copy_from_slice(name.as_bytes());
        buf[..len].make_ascii_lowercase();
        buf[len] = b'/';
        len += 1;
        // The qtype, most significant digit first.
        let mut digits = [0u8; 5];
        let mut rest = qtype;
        let mut count = 0;
        loop {
            digits[count] = b'0' + (rest % 10) as u8;
            rest /= 10;
            count += 1;
            if rest == 0 {
                break;
            }
        }
        while count > 0 {
            count -= 1;
            buf[len] = digits[count];
            len += 1;
        }
        if dnssec {
            buf[len..len + 3].copy_from_slice(b"/do");
            len += 3;
        }
        // The name is a `&str` and everything appended is ASCII, so this holds;
        // the fallback keeps a surprise from turning into a panic.
        match std::str::from_utf8(&buf[..len]) {
            Ok(key) => f(key),
            Err(_) => f(&Self::cache_key(name, qtype, dnssec)),
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
        Self::with_key(name, qtype, dnssec, |key| {
            let guard = self.inner.read();
            match guard.lru.peek(key) {
                Some(entry) if !entry.is_expired() => Some(entry.response.clone()),
                _ => None,
            }
        })
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
        Self::with_key(name, qtype, dnssec, |key| {
            let guard = self.inner.read();
            match guard.lru.peek(key) {
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
        })
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
        self.inner
            .write()
            .put(key, entry, self.max_bytes.load(Ordering::Relaxed));
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
        Self::with_key(name, qtype, dnssec, |key| self.inner.write().pop(key));
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

    /// Remove all expired entries — past the stale window, when the optimistic
    /// cache is on. Called by the janitor task.
    pub fn evict_expired(&self) {
        let now = Instant::now();
        let window = Duration::from_secs(self.stale_window.load(Ordering::Relaxed));
        let mut guard = self.inner.write();
        // LruCache doesn't expose drain_filter, so collect expired keys first.
        let expired: Vec<String> = guard
            .lru
            .iter()
            .filter(|(_, v)| now >= v.expires_at + window)
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

    /// Change how many entries and how many bytes the cache holds, while it
    /// serves. Shrinking drops the coldest entries first; the hot ones stay.
    /// `max_bytes == 0` lifts the byte bound.
    pub fn resize(&self, capacity: usize, max_bytes: usize) {
        let budget = byte_budget(max_bytes);
        self.max_bytes.store(budget, Ordering::Relaxed);
        let mut guard = self.inner.write();
        let inner = &mut *guard;
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap();
        while inner.lru.len() > cap.get() {
            match inner.lru.pop_lru() {
                Some((k, v)) => inner.total_bytes -= entry_cost(&k, &v),
                None => break,
            }
        }
        inner.lru.resize(cap);
        while inner.total_bytes > budget && inner.lru.len() > 1 {
            match inner.lru.pop_lru() {
                Some((k, v)) => inner.total_bytes -= entry_cost(&k, &v),
                None => break,
            }
        }
    }

    /// Drop every cached answer for `name` (all record types, signed or not),
    /// so a local record that changed is asked afresh.
    pub fn forget_name(&self, name: &str) {
        let prefix = format!("{}/", name.trim_end_matches('.').to_ascii_lowercase());
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
    /// Takes its entries by value: the response buffers come from a snapshot
    /// that is discarded straight after, so they are moved in rather than
    /// copied — a restore used to duplicate the whole cache twice over on the
    /// way back into it.
    pub fn restore(&self, entries: Vec<(String, bytes::Bytes, u32, i64)>) {
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
                response: DnsResponse { bytes, ttl },
                expires_at,
            };
            guard.put(key, entry, self.max_bytes.load(Ordering::Relaxed));
        }
    }
}

fn normalize_ttl_bounds(min_ttl: u64, max_ttl: u64) -> TtlBounds {
    // For the ceiling, 0 means "no ceiling" (the hard MAX_TTL) — the same
    // 0-disables-the-limit convention as `cache_max_mb` and
    // `log_retention_days`. Taken literally, a 0 ceiling would stamp every
    // insert with `expires_at = now`: a cache that looks configured but never
    // serves a single hit.
    let max_ttl = if max_ttl == 0 { MAX_TTL } else { max_ttl };
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

    fn expired_now(cache: &DnsCache, name: &str) {
        // TTL 0 with no floor: expires the instant it is stored.
        cache.insert(
            name,
            1,
            false,
            DnsResponse {
                bytes: bytes::Bytes::from_static(b"x"),
                ttl: 0,
            },
        );
    }

    fn put(cache: &DnsCache, name: &str, qtype: u16) {
        cache.insert(
            name,
            qtype,
            false,
            DnsResponse {
                bytes: bytes::Bytes::from_static(b"answer"),
                ttl: 300,
            },
        );
    }

    #[test]
    fn resize_keeps_the_hottest_entries() {
        let cache = DnsCache::new(8, 0, 0, 3600);
        for n in 0..8 {
            put(&cache, &format!("n{n}.test"), 1);
        }
        // Reads peek and leave the order alone; a fresh insert is what makes
        // an entry recent, so store n0 again.
        put(&cache, "n0.test", 1);
        cache.resize(2, 0);
        assert!(
            cache.get_with_remaining("n0.test", 1, false).is_some(),
            "hot entry kept"
        );
        assert!(
            cache.get_with_remaining("n1.test", 1, false).is_none(),
            "cold entry dropped"
        );
        // Growing again leaves room for more.
        cache.resize(16, 0);
        for n in 0..10 {
            put(&cache, &format!("m{n}.test"), 1);
        }
        assert!(cache.get_with_remaining("m0.test", 1, false).is_some());
    }

    #[test]
    fn forget_name_drops_every_type_of_that_name_only() {
        let cache = DnsCache::new(16, 0, 0, 3600);
        put(&cache, "fe.te", 1);
        put(&cache, "fe.te", 28);
        put(&cache, "x.fe.te", 1);
        cache.forget_name("FE.te.");
        assert!(cache.get_with_remaining("fe.te", 1, false).is_none());
        assert!(cache.get_with_remaining("fe.te", 28, false).is_none());
        assert!(
            cache.get_with_remaining("x.fe.te", 1, false).is_some(),
            "a subdomain is another name"
        );
    }

    #[test]
    fn an_expired_entry_is_served_stale_only_inside_the_window() {
        let cache = DnsCache::new(8, 0, 0, 3600);
        expired_now(&cache, "old.test");
        assert!(cache.get_with_remaining("old.test", 1, false).is_none());
        // Off: an expired entry is gone for the query path, and for the janitor.
        assert!(cache.get_stale("old.test", 1, false).is_none());

        cache.set_stale_window(600);
        assert!(cache.get_stale("old.test", 1, false).is_some());
        // A fresh entry is not "stale".
        cache.insert(
            "new.test",
            1,
            false,
            DnsResponse {
                bytes: bytes::Bytes::from_static(b"y"),
                ttl: 300,
            },
        );
        assert!(cache.get_stale("new.test", 1, false).is_none());

        // The janitor keeps what the window still covers…
        cache.evict_expired();
        assert_eq!(cache.len(), 2);
        // …and drops it once the window is off.
        cache.set_stale_window(0);
        cache.evict_expired();
        assert_eq!(cache.len(), 1);
        // A window can't be longer than a week.
        cache.set_stale_window(u64::MAX);
        assert_eq!(cache.stale_window_secs(), MAX_STALE_AGE);
    }

    #[test]
    fn one_refresh_per_key_at_a_time() {
        let cache = DnsCache::new(8, 0, 0, 3600);
        assert!(cache.begin_refresh("a/1"));
        assert!(!cache.begin_refresh("a/1"));
        assert!(cache.begin_refresh("b/1"));
        cache.end_refresh("a/1");
        assert!(cache.begin_refresh("a/1"));
    }

    /// The two key builders must agree exactly: a lookup uses the stack form,
    /// the insert that stored the entry used the owned one.
    #[test]
    fn stack_and_owned_keys_agree() {
        let long = "a".repeat(300);
        for (name, qtype, dnssec) in [
            ("example.com", 1u16, false),
            ("Example.COM", 1, true),
            ("a", 65_535, false),
            ("", 0, true),
            (long.as_str(), 28, true), // past the stack buffer → owned fallback
        ] {
            DnsCache::with_key(name, qtype, dnssec, |key| {
                assert_eq!(key, DnsCache::cache_key(name, qtype, dnssec));
            });
        }
    }
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

    /// `min_ttl = 0` is the "don't override the origin" setting: a 5-second
    /// answer stays a 5-second answer. A non-zero floor deliberately extends it,
    /// which is the trade the setting exists to express — so assert both, or the
    /// zero case could pass with the floor silently still applied.
    #[test]
    fn zero_min_ttl_keeps_the_origin_lifetime() {
        let honest = DnsCache::new(8, 0, 0, 3600);
        assert_eq!(honest.min_ttl_secs(), 0, "no floor should survive");
        honest.insert("cdn.test", 1, false, response(5));
        let (_, remaining) = honest
            .get_with_remaining("cdn.test", 1, false)
            .expect("entry is cached");
        assert!(
            remaining <= 5,
            "must not outlive the origin's 5s TTL, got {remaining}"
        );

        let floored = DnsCache::new(8, 0, 60, 3600);
        floored.insert("cdn.test", 1, false, response(5));
        let (_, remaining) = floored
            .get_with_remaining("cdn.test", 1, false)
            .expect("entry is cached");
        assert!(
            remaining > 5,
            "a 60s floor must extend the 5s answer, got {remaining}"
        );
    }

    /// `max_ttl = 0` means "no ceiling", not "expire instantly". The dangerous
    /// shape is `{min: 0, max: 0}` — the honest-looking "don't override
    /// anything" config — which taken literally stamps every entry expired at
    /// insert and silently disables the cache.
    #[test]
    fn zero_max_ttl_means_no_ceiling_not_a_dead_cache() {
        let cache = DnsCache::new(8, 0, 0, 0);
        assert_eq!(
            cache.max_ttl_secs(),
            MAX_TTL,
            "0 must mean the hard ceiling"
        );

        // Entries survive: served with the origin lifetime (min is still 0)…
        cache.insert("cdn.test", 1, false, response(5));
        let (_, remaining) = cache
            .get_with_remaining("cdn.test", 1, false)
            .expect("a {0,0} cache must still serve hits");
        assert!(
            remaining <= 5,
            "min_ttl=0 keeps the origin's 5s, got {remaining}"
        );

        // …and the hard ceiling still applies to an over-long origin TTL.
        cache.insert("slow.test", 1, false, response(86_400));
        let (_, remaining) = cache
            .get_with_remaining("slow.test", 1, false)
            .expect("entry is cached");
        assert!(remaining as u64 <= MAX_TTL);
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
