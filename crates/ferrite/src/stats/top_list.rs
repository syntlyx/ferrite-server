use std::collections::HashMap;

use parking_lot::Mutex;

/// Tracks per-key counts in memory, capped at `max_keys` distinct entries.
/// When the cap is reached, new keys are silently dropped (existing keys keep
/// accumulating), so the hottest domains/clients are always tracked.
pub struct TopNCounter {
    counts: Mutex<HashMap<String, u64>>,
    max_keys: usize,
}

impl TopNCounter {
    pub fn new(max_keys: usize) -> Self {
        Self {
            counts: Mutex::new(HashMap::new()),
            max_keys,
        }
    }

    pub fn increment(&self, key: &str) {
        let mut map = self.counts.lock();
        if let Some(c) = map.get_mut(key) {
            *c += 1;
        } else if map.len() < self.max_keys {
            map.insert(key.to_string(), 1);
        }
    }

    pub fn top(&self, n: usize) -> Vec<(String, u64)> {
        // Clone while holding the lock, then sort outside it so the mutex
        // is not held for the O(n log n) sort on 10k entries.
        let mut v: Vec<(String, u64)> = {
            let map = self.counts.lock();
            map.iter().map(|(k, &v)| (k.clone(), v)).collect()
        };
        v.sort_unstable_by_key(|b| std::cmp::Reverse(b.1));
        v.truncate(n);
        v
    }

    /// Seed with pre-computed counts from persistent storage (called once at startup).
    pub fn seed(&self, entries: &[(String, u64)]) {
        let mut map = self.counts.lock();
        for (key, count) in entries {
            *map.entry(key.clone()).or_insert(0) += count;
        }
    }

    pub fn clear(&self) {
        self.counts.lock().clear();
    }
}

impl std::fmt::Debug for TopNCounter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TopNCounter")
            .field("max_keys", &self.max_keys)
            .finish()
    }
}
