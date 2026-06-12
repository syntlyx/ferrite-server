use std::collections::VecDeque;

use parking_lot::Mutex;

use crate::dns::types::QueryEntry;

/// Fixed-capacity ring buffer of recent query entries.
pub struct QueryRingBuffer {
    entries: Mutex<VecDeque<QueryEntry>>,
    capacity: usize,
}

impl QueryRingBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
        }
    }

    pub fn push(&self, entry: QueryEntry) {
        let mut buf = self.entries.lock();
        if buf.len() >= self.capacity {
            buf.pop_front();
        }
        buf.push_back(entry);
    }

    /// Returns up to `n` most recent entries, newest first.
    pub fn recent(&self, n: usize) -> Vec<QueryEntry> {
        let buf = self.entries.lock();
        buf.iter().rev().take(n).cloned().collect()
    }

    /// Returns up to `n` entries with `id > after_id`, newest first.
    ///
    /// Relies on ids being monotonic within the buffer (guaranteed: seeded
    /// entries come from storage in id order, and the live counter is seeded
    /// above the max persisted id at startup). Stops scanning at the first
    /// already-seen entry, so a poll with a fresh cursor is O(delta).
    pub fn recent_after(&self, after_id: u64, n: usize) -> Vec<QueryEntry> {
        let buf = self.entries.lock();
        buf.iter()
            .rev()
            .take_while(|e| e.id > after_id)
            .take(n)
            .cloned()
            .collect()
    }

    /// Returns up to `n` most recent entries matching `predicate`, newest first.
    /// Scans at most `scan_limit` entries to find them.
    pub fn recent_filtered(
        &self,
        n: usize,
        scan_limit: usize,
        predicate: impl Fn(&QueryEntry) -> bool,
    ) -> Vec<QueryEntry> {
        let buf = self.entries.lock();
        buf.iter()
            .rev()
            .take(scan_limit)
            .filter(|e| predicate(e))
            .take(n)
            .cloned()
            .collect()
    }

    /// Seed with entries from persistent storage (oldest first, so newest end up at the back).
    pub fn seed(&self, entries: Vec<QueryEntry>) {
        let mut buf = self.entries.lock();
        for entry in entries {
            if buf.len() >= self.capacity {
                buf.pop_front();
            }
            buf.push_back(entry);
        }
    }

    pub fn clear(&self) {
        self.entries.lock().clear();
    }
}

impl std::fmt::Debug for QueryRingBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueryRingBuffer")
            .field("capacity", &self.capacity)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::types::QueryStatus;

    fn entry(id: u64) -> QueryEntry {
        QueryEntry {
            id,
            timestamp: chrono::DateTime::from_timestamp(id as i64, 0).unwrap(),
            domain: format!("d{id}.test"),
            query_type: 1,
            client_ip: "192.168.1.2".to_string(),
            status: QueryStatus::Upstream,
            latency_ms: 1,
            upstream: None,
            rcode: 0,
        }
    }

    #[test]
    fn recent_after_returns_only_newer_entries_newest_first() {
        let buf = QueryRingBuffer::new(10);
        for id in 1..=5 {
            buf.push(entry(id));
        }

        let delta = buf.recent_after(3, 100);
        assert_eq!(delta.iter().map(|e| e.id).collect::<Vec<_>>(), vec![5, 4]);

        assert!(buf.recent_after(5, 100).is_empty());
        assert!(buf.recent_after(99, 100).is_empty());
    }

    #[test]
    fn recent_after_respects_limit_keeping_newest() {
        let buf = QueryRingBuffer::new(10);
        for id in 1..=5 {
            buf.push(entry(id));
        }

        let delta = buf.recent_after(0, 2);
        assert_eq!(delta.iter().map(|e| e.id).collect::<Vec<_>>(), vec![5, 4]);
    }
}
