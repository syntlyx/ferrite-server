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

    /// Returns up to `n` entries with `id > after_id`, sorted newest id first.
    ///
    /// Does NOT assume the buffer is id-monotonic: ids are assigned by an atomic
    /// counter in the DNS task but pushed to the buffer from the stats-writer
    /// task, so two concurrent queries can land out of order (e.g. `…,101,100`).
    /// A `take_while` would stop at the first such inversion and silently drop
    /// newer entries (freezing the live query log), so we filter the whole
    /// buffer and sort by id. The buffer is small and bounded, so this is cheap.
    pub fn recent_after(&self, after_id: u64, n: usize) -> Vec<QueryEntry> {
        let buf = self.entries.lock();
        let mut out: Vec<QueryEntry> = buf.iter().filter(|e| e.id > after_id).cloned().collect();
        out.sort_unstable_by_key(|e| std::cmp::Reverse(e.id));
        out.truncate(n);
        out
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

    #[test]
    fn recent_after_tolerates_out_of_order_ids() {
        // Concurrent queries can push ids out of order (id assigned in the DNS
        // task, pushed from the writer task). A take_while would stop at the
        // inversion and drop newer entries; filter+sort must not.
        let buf = QueryRingBuffer::new(10);
        for id in [1, 2, 3, 5, 4] {
            buf.push(entry(id));
        }

        // Everything newer than 3 is returned despite 5 sitting before 4.
        let delta = buf.recent_after(3, 100);
        assert_eq!(delta.iter().map(|e| e.id).collect::<Vec<_>>(), vec![5, 4]);

        // Cursor at 4 still surfaces 5 (a take_while would have returned empty).
        let delta = buf.recent_after(4, 100);
        assert_eq!(delta.iter().map(|e| e.id).collect::<Vec<_>>(), vec![5]);
    }
}
