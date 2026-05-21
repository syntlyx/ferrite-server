use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use lru::LruCache;
use parking_lot::Mutex;

/// Cache TTL for domains that passed the blocklist check.
pub const ALLOWED_TTL: u64 = 300;
/// Cache TTL for domains that were blocked.
pub const BLOCKED_TTL: u64 = 3600;

#[derive(Clone)]
struct BlockCacheEntry {
    blocked: bool,
    expires_at: Instant,
}

/// LRU cache that remembers recent block/allow decisions to avoid re-querying
/// the FST on every DNS packet.
pub struct BlocklistCache {
    inner: Mutex<LruCache<String, BlockCacheEntry>>,
}

impl BlocklistCache {
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap();
        Self {
            inner: Mutex::new(LruCache::new(cap)),
        }
    }

    /// Look up a domain in the cache.
    /// Returns `Some(true)` if blocked, `Some(false)` if allowed, `None` if not cached.
    pub fn get(&self, domain: &str) -> Option<bool> {
        let mut guard = self.inner.lock();
        match guard.get(domain) {
            Some(e) if Instant::now() < e.expires_at => Some(e.blocked),
            Some(_) => {
                guard.pop(domain);
                None
            }
            None => None,
        }
    }

    /// Insert a decision into the cache.
    pub fn insert(&self, domain: &str, blocked: bool) {
        let ttl = if blocked { BLOCKED_TTL } else { ALLOWED_TTL };
        let entry = BlockCacheEntry {
            blocked,
            expires_at: Instant::now() + Duration::from_secs(ttl),
        };
        self.inner.lock().put(domain.to_string(), entry);
    }

    /// Invalidate a single entry.
    pub fn invalidate(&self, domain: &str) {
        self.inner.lock().pop(domain);
    }

    /// Flush the entire cache.
    pub fn clear(&self) {
        self.inner.lock().clear();
    }
}
