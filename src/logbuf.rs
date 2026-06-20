//! In-memory ring buffer of recent log records, fed by a `tracing` layer and
//! read by `GET /api/logs`.
//!
//! ferrite logs to stdout (journald / Docker / a redirect — wherever the
//! operator points it), so there is no canonical log *file* to tail. Instead we
//! keep the last [`CAPACITY`] records in process memory and serve them to the
//! web UI. stdout logging is unchanged; this is an additional sink.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::Serialize;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::{EnvFilter, Layer, Registry, reload};

const CAPACITY: usize = 2000;

/// Reload handle for the process-wide level filter, installed once by `main`.
/// Lets the Settings API flip debug logging at runtime without a restart.
static FILTER_HANDLE: OnceLock<reload::Handle<EnvFilter, Registry>> = OnceLock::new();

/// The env-filter directive for a debug state. Debug raises the `ferrite` target
/// to debug level only — dependencies stay at info so the log doesn't flood.
pub fn filter_directive(debug: bool) -> &'static str {
    if debug {
        "ferrite=debug"
    } else {
        "ferrite=info"
    }
}

/// Store the reload handle (called by `main` right after building the subscriber).
pub fn install_filter_handle(handle: reload::Handle<EnvFilter, Registry>) {
    let _ = FILTER_HANDLE.set(handle);
}

/// Flip debug logging live. No-op if the handle isn't installed (e.g. in tests
/// that don't initialize tracing) or if `RUST_LOG` took over the filter.
pub fn set_debug(debug: bool) {
    let Some(handle) = FILTER_HANDLE.get() else {
        return;
    };
    let state = if debug { "enabled" } else { "disabled" };
    match handle.reload(EnvFilter::new(filter_directive(debug))) {
        Ok(()) => tracing::info!("debug logging {state}"),
        Err(e) => tracing::warn!("failed to reload log filter: {e}"),
    }
}

#[derive(Clone, Serialize)]
pub struct LogEntry {
    /// Monotonic id within this process (cursor for delta polling).
    pub id: u64,
    pub timestamp: DateTime<Utc>,
    pub level: String,
    pub target: String,
    pub message: String,
}

/// A bounded, thread-safe ring of recent log records.
pub struct LogBuffer {
    entries: Mutex<VecDeque<LogEntry>>,
    next_id: AtomicU64,
}

impl LogBuffer {
    fn new() -> Self {
        Self {
            entries: Mutex::new(VecDeque::with_capacity(CAPACITY)),
            next_id: AtomicU64::new(1),
        }
    }

    fn push(&self, level: Level, target: String, message: String) {
        let entry = LogEntry {
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            timestamp: Utc::now(),
            level: level.as_str().to_string(),
            target,
            message,
        };
        let mut q = self.entries.lock();
        if q.len() == CAPACITY {
            q.pop_front();
        }
        q.push_back(entry);
    }

    /// Records with `id > after_id` and severity ≥ `min_rank`, in chronological
    /// order, capped to the most recent `limit`. The caller advances `after_id`
    /// to the last returned id for delta polling.
    pub fn recent(&self, after_id: u64, min_rank: u8, limit: usize) -> Vec<LogEntry> {
        let q = self.entries.lock();
        let mut out: Vec<LogEntry> = q
            .iter()
            .filter(|e| e.id > after_id && rank_of(&e.level) >= min_rank)
            .cloned()
            .collect();
        if out.len() > limit {
            out = out.split_off(out.len() - limit);
        }
        out
    }
}

/// The process-wide log buffer (lazily created; shared by the tracing layer and
/// the API). Lazy init means tests that never install the layer still get an
/// (empty) buffer to read.
pub fn global() -> &'static Arc<LogBuffer> {
    static BUF: OnceLock<Arc<LogBuffer>> = OnceLock::new();
    BUF.get_or_init(|| Arc::new(LogBuffer::new()))
}

/// Severity rank, higher = more severe. Used to filter "this level and above".
pub fn rank_of(level: &str) -> u8 {
    match level.to_ascii_uppercase().as_str() {
        "ERROR" => 4,
        "WARN" => 3,
        "INFO" => 2,
        "DEBUG" => 1,
        _ => 0, // TRACE / unknown
    }
}

/// A `tracing` layer that records each event into [`global`].
pub struct LogLayer;

impl<S: Subscriber> Layer<S> for LogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        global().push(*meta.level(), meta.target().to_string(), visitor.message);
    }
}

/// Pulls the human-readable `message` out of an event's fields.
#[derive(Default)]
struct MessageVisitor {
    message: String,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            // The message field's value is `fmt::Arguments`, whose Debug renders
            // the formatted text (no surrounding quotes).
            self.message = format!("{value:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_caps_filters_and_cursors() {
        let buf = LogBuffer::new();
        buf.push(Level::INFO, "ferrite::a".into(), "hello".into());
        buf.push(Level::WARN, "ferrite::b".into(), "careful".into());
        buf.push(Level::ERROR, "ferrite::c".into(), "boom".into());

        // All, chronological.
        let all = buf.recent(0, 0, 100);
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].message, "hello");
        assert_eq!(all[2].message, "boom");

        // Severity filter: warn+ → drops the info line.
        let warn = buf.recent(0, rank_of("warn"), 100);
        assert_eq!(warn.len(), 2);
        assert!(warn.iter().all(|e| e.level != "INFO"));

        // Delta cursor: only entries after the first id.
        let after = buf.recent(all[0].id, 0, 100);
        assert_eq!(after.len(), 2);
        assert!(after.iter().all(|e| e.id > all[0].id));

        // Limit keeps the most recent.
        let last = buf.recent(0, 0, 1);
        assert_eq!(last.len(), 1);
        assert_eq!(last[0].message, "boom");
    }
}
