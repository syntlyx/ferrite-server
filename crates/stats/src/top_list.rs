use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};

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

    /// The `n` highest-counted keys, busiest first.
    ///
    /// Keeps only `n` candidates while scanning and clones just those, instead
    /// of copying the whole map out and sorting it down. That matters because
    /// `/api/stats/summary` calls this three times per request and is documented
    /// as safe to poll every 1–2 seconds: the old shape allocated one `String`
    /// per tracked key (up to 10 000) on every poll, *while holding the same
    /// mutex* `increment` takes on every DNS query.
    ///
    /// Ties are broken arbitrarily, exactly as the previous `sort_unstable` did.
    pub fn top(&self, n: usize) -> Vec<(String, u64)> {
        if n == 0 {
            return Vec::new();
        }
        let mut out: Vec<(String, u64)> = {
            let map = self.counts.lock();
            // Min-heap of the best `n` so far, keyed by count: the root is the
            // weakest survivor, so one comparison decides each candidate.
            let mut heap: BinaryHeap<Reverse<(u64, &str)>> = BinaryHeap::with_capacity(n + 1);
            for (key, &count) in map.iter() {
                if heap.len() < n {
                    heap.push(Reverse((count, key.as_str())));
                } else if heap.peek().is_some_and(|Reverse((low, _))| count > *low) {
                    heap.pop();
                    heap.push(Reverse((count, key.as_str())));
                }
            }
            heap.into_iter()
                .map(|Reverse((count, key))| (key.to_string(), count))
                .collect()
        };
        out.sort_unstable_by_key(|(_, count)| Reverse(*count));
        out
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn top_returns_the_busiest_keys_in_order() {
        let c = TopNCounter::new(100);
        for _ in 0..5 {
            c.increment("five.test");
        }
        for _ in 0..9 {
            c.increment("nine.test");
        }
        c.increment("one.test");

        assert_eq!(
            c.top(2),
            vec![("nine.test".to_string(), 9), ("five.test".to_string(), 5)]
        );
        assert_eq!(c.top(0), Vec::new());
        // Asking for more than exists returns everything, still ordered.
        assert_eq!(c.top(10).len(), 3);
        assert_eq!(c.top(10)[2].1, 1);
    }

    #[test]
    fn top_survives_a_map_larger_than_n() {
        let c = TopNCounter::new(1_000);
        for i in 0..500 {
            let key = format!("d{i}.test");
            for _ in 0..=i {
                c.increment(&key);
            }
        }

        let top = c.top(3);
        assert_eq!(
            top,
            vec![
                ("d499.test".to_string(), 500),
                ("d498.test".to_string(), 499),
                ("d497.test".to_string(), 498),
            ]
        );
    }

    #[test]
    fn max_keys_caps_growth_but_known_keys_keep_counting() {
        let c = TopNCounter::new(2);
        c.increment("a.test");
        c.increment("b.test");
        c.increment("c.test"); // dropped: cap reached
        c.increment("a.test");

        let top = c.top(10);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0], ("a.test".to_string(), 2));
        assert!(!top.iter().any(|(k, _)| k == "c.test"));
    }
}
