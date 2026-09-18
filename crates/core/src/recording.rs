//! What a query is allowed to leave behind.
//!
//! ferrite answers DNS for a whole household, so its query log is the single
//! most sensitive artifact on the box: a per-device browsing history. Operators
//! who don't want that history to exist can switch off the two surfaces that
//! record it — the per-query log and the aggregate statistics — without losing
//! DNS filtering itself.
//!
//! Both switches are hot: the DNS hot path and the stats writer read them per
//! query and per flush, so a change in the UI takes effect on the next query
//! with no restart. The process-lifetime counters in `LiveStats` are unaffected
//! — they live in RAM, hold no domain or client identity, and are what keeps
//! the dashboard meaningful when everything else is off.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Which recording surfaces a query may touch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordScope {
    /// Per-query history: rows in the `queries` table and the recent-queries
    /// ring buffer behind the live query log.
    pub queries: bool,
    /// Aggregates: the 10-minute rollup tables, the top-N counters and the
    /// rolling 24-hour timeseries.
    pub stats: bool,
}

impl RecordScope {
    /// Record everything — the default.
    pub const ALL: Self = Self {
        queries: true,
        stats: true,
    };

    /// Record nothing beyond the in-memory counters.
    pub const NONE: Self = Self {
        queries: false,
        stats: false,
    };

    /// True while at least one surface still records something — i.e. while it
    /// is worth handing an entry to the stats writer at all.
    pub fn records_anything(self) -> bool {
        self.queries || self.stats
    }
}

impl Default for RecordScope {
    fn default() -> Self {
        Self::ALL
    }
}

/// The live, hot-patchable form of [`RecordScope`], shared by the DNS handler,
/// the stats writer and the settings API.
#[derive(Debug)]
pub struct RecordSwitches {
    queries: AtomicBool,
    stats: AtomicBool,
}

impl RecordSwitches {
    pub fn new(scope: RecordScope) -> Arc<Self> {
        Arc::new(Self {
            queries: AtomicBool::new(scope.queries),
            stats: AtomicBool::new(scope.stats),
        })
    }

    /// Read both switches. Two relaxed loads — the pair is not atomic as a
    /// whole, which is fine: a flip mid-query only decides whether *this* query
    /// is recorded, and the settings API applies the change before it persists
    /// the config.
    pub fn scope(&self) -> RecordScope {
        RecordScope {
            queries: self.queries.load(Ordering::Relaxed),
            stats: self.stats.load(Ordering::Relaxed),
        }
    }

    pub fn set_queries(&self, on: bool) {
        self.queries.store(on, Ordering::Relaxed);
    }

    pub fn set_stats(&self, on: bool) {
        self.stats.store(on, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_switch_flips_without_disturbing_the_other() {
        let switches = RecordSwitches::new(RecordScope::ALL);

        switches.set_stats(false);
        assert_eq!(
            switches.scope(),
            RecordScope {
                queries: true,
                stats: false
            }
        );
        assert!(
            switches.scope().records_anything(),
            "the query log alone is still worth handing entries to the writer for"
        );

        switches.set_queries(false);
        assert_eq!(switches.scope(), RecordScope::NONE);
        assert!(!switches.scope().records_anything());
    }
}
