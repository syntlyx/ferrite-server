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
