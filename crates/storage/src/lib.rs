#[cfg(test)]
mod conformance;
pub mod memory;
pub mod schema;
pub mod sqlite;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use ferrite_core::error::Result;
use ferrite_core::recording::RecordScope;
use ferrite_core::types::QueryEntry;
use ferrite_core::types::TimeseriesBucket;

/// Filter parameters for querying the DNS log.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct QueryFilter {
    pub from_ts: Option<i64>,
    pub to_ts: Option<i64>,
    pub domain: Option<String>,
    pub client_ips: Vec<String>,
    /// Filter by device identity (MAC or IP fallback). Returns all of a device's
    /// queries regardless of which IP it used. Combined with `client_ips` via OR.
    pub devices: Vec<String>,
    pub status: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub before_id: Option<u64>,
    pub before_ts: Option<i64>,
}

/// Aggregated statistics per device (keyed by the device identity token: a MAC
/// when known, else an IP fallback — see [`ferrite_core::types::QueryEntry::device`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientStats {
    /// Device identity token (MAC or IP fallback).
    pub device: String,
    pub total: u64,
    pub blocked: u64,
    pub last_seen: i64,
}

/// Aggregated DNS query counters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SummaryStats {
    pub total: u64,
    pub blocked: u64,
    pub cached: u64,
    pub upstream: u64,
}

/// Abstract storage backend.
#[async_trait]
#[allow(dead_code)]
pub trait Storage: Send + Sync {
    /// Persist a batch of query entries, restricted to the surfaces `scope`
    /// still records: per-query rows, aggregate rollups, both or neither. An
    /// empty scope writes nothing, so flipping the privacy switches off stops
    /// the batch at the database boundary rather than somewhere upstream.
    ///
    /// Takes the batch by value: the database thread needs `'static` data, and
    /// the caller hands over a batch it is about to drop anyway — borrowing
    /// would only force a deep copy of every entry behind the scenes.
    async fn write_batch(&self, entries: Vec<QueryEntry>, scope: RecordScope) -> Result<()>;

    /// The highest query id already stored, or 0 on an empty table. The
    /// in-memory id counter resumes from here at startup so a later insert
    /// cannot collide with a row written before the restart. Deriving it from
    /// the newest rows instead would be wrong: rows are ordered by timestamp,
    /// and a clock step backwards (NTP) can leave the highest id further down.
    async fn max_query_id(&self) -> Result<u64>;

    /// Return query log entries matching the given filter.
    async fn query_range(&self, filter: &QueryFilter) -> Result<Vec<QueryEntry>>;

    /// Return the top N domains by query count in the given time range.
    async fn top_domains(&self, from_ts: i64, to_ts: i64, n: usize) -> Result<Vec<(String, u64)>>;

    /// Return the top N blocked domains by block count in the given time range.
    async fn top_blocked_domains(
        &self,
        from_ts: i64,
        to_ts: i64,
        n: usize,
    ) -> Result<Vec<(String, u64)>>;

    /// Return the top N clients by query count.
    async fn top_clients(&self, from_ts: i64, to_ts: i64, n: usize) -> Result<Vec<ClientStats>>;

    /// Return timeseries buckets for the last 24 hours.
    async fn timeseries(&self, bucket_secs: u64) -> Result<Vec<TimeseriesBucket>>;

    /// Return aggregated stats for a specific device identity token (MAC or IP).
    async fn client_stats(&self, device: &str) -> Result<Option<ClientStats>>;

    /// Return summary stats: (total, blocked) for the last `secs` seconds.
    async fn summary(&self, secs: u64) -> Result<(u64, u64)>;

    /// Return summary stats for a timestamp range.
    async fn summary_counts(&self, from_ts: i64, to_ts: i64) -> Result<SummaryStats>;

    /// Delete all query log entries.
    async fn delete_all_queries(&self) -> Result<()>;

    /// Rebuild the database file so space freed by deletes is returned to the
    /// filesystem. Deleting rows alone leaves the pages in the file, which is
    /// the wrong answer for someone who cleared the log to reclaim a flash card
    /// — or to stop a browsing history from sitting in free pages on disk.
    async fn vacuum(&self) -> Result<()>;

    /// Delete query log entries with timestamp older than `cutoff_ts` (Unix seconds).
    /// Returns the number of rows deleted.
    async fn delete_queries_older_than(&self, cutoff_ts: i64) -> Result<u64>;

    /// Make the store able to give space back, so a size cap can be met at all.
    ///
    /// Called once when a size cap is first enforced. `Ok(true)` means the
    /// store had to convert itself and that conversion was expensive, which the
    /// caller logs. A store that always releases space returns `Ok(false)`.
    async fn prepare_size_cap(&self) -> Result<bool>;

    /// Drop the oldest query log entries until the store fits in `max_bytes`,
    /// then return the space to the filesystem.
    ///
    /// Only the query log and its rollups are trimmed: the device inventory is
    /// tiny and losing it would cost every device its name, which is not what
    /// someone capping a *log* asked for.
    async fn enforce_size_cap(&self, max_bytes: u64) -> Result<SizeTrim>;

    // ── Learned device identities & IP bindings ───────────────────────────────

    /// Upsert a learned device: MAC → last-known hostname. Bumps `last_seen`.
    async fn upsert_device(&self, mac: &str, hostname: Option<&str>) -> Result<()>;

    /// Upsert the last-known IP → MAC binding ("last binding wins"). Bumps `last_seen`.
    async fn upsert_ip_binding(&self, ip: &str, mac: &str) -> Result<()>;

    /// Load all learned devices: returns (mac, hostname) pairs.
    async fn load_devices(&self) -> Result<Vec<(String, Option<String>)>>;

    /// Load all IP → MAC bindings: returns (ip, mac) pairs.
    async fn load_ip_bindings(&self) -> Result<Vec<(String, String)>>;

    /// Drop every learned IP → MAC binding. Leaves `devices` (MAC → hostname)
    /// and manual aliases intact; used when the query log is cleared.
    async fn delete_all_ip_bindings(&self) -> Result<()>;

    /// How much room the database takes, as SQLite accounts for it (page count
    /// × page size). The write-ahead log is not counted — it is checkpointed
    /// back into the file — so this is the durable size, not the peak.
    async fn database_bytes(&self) -> Result<u64>;

    /// Drop every learned device name. Manual aliases are configuration and
    /// survive; this is for the privacy switches, where a list of the MACs on
    /// the network and what they call themselves is exactly what "record
    /// nothing" must not leave behind.
    async fn delete_all_devices(&self) -> Result<()>;

    /// Refresh `last_seen = now` for the given IPs (currently-present devices), so
    /// age-based pruning keeps live bindings and only expires long-absent ones.
    /// No-op on an empty slice.
    async fn touch_ip_bindings(&self, ips: &[String]) -> Result<()>;

    /// Delete IP → MAC bindings not seen since `cutoff_ts` (unix seconds), and
    /// return the deleted IPs so the caller can drop them from its in-memory maps.
    async fn delete_ip_bindings_older_than(&self, cutoff_ts: i64) -> Result<Vec<String>>;

    // ── One-time hand-off of authored state to config.toml ────────────────────

    /// Read whatever the pre-v9 configuration tables still hold. Empty once the
    /// hand-off has run (the tables are gone), so this is cheap on every later
    /// boot. Missing tables are not an error — a database created after v9 never
    /// had them.
    async fn load_legacy_config_rows(&self) -> Result<LegacyConfigRows>;

    /// Drop the five pre-v9 tables that held authored state. Called only once
    /// the rows they held are safely in `config.toml`, so a failed config write
    /// leaves them in place for the next boot to retry.
    async fn drop_legacy_config_tables(&self) -> Result<()>;
}

/// What one pass of [`Storage::enforce_size_cap`] did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SizeTrim {
    /// Query rows deleted. Zero when the store was already under the cap.
    pub rows_deleted: u64,
    /// Size before the pass, as the store accounts for it.
    pub bytes_before: u64,
    /// Size after. Still above the cap means the pass hit its own work limit
    /// and the next one continues — it never deletes unboundedly in one go.
    pub bytes_after: u64,
}

impl SizeTrim {
    /// Nothing needed doing.
    pub fn is_noop(&self) -> bool {
        self.rows_deleted == 0
    }
}

/// Authored state found in a pre-v9 database, on its way into `config.toml`.
#[derive(Debug, Default, Clone)]
pub struct LegacyConfigRows {
    /// `custom_entries`: (domain, "whitelist" | "blacklist").
    pub custom_entries: Vec<(String, String)>,
    /// `custom_dns_records`, in the shape the config file uses.
    pub custom_records: Vec<ferrite_core::config::CustomRecordConfig>,
    /// `client_aliases`: (key, "ip" | "mac", name).
    pub client_aliases: Vec<(String, String, String)>,
}

impl LegacyConfigRows {
    /// Nothing to hand over — the common case on every boot after the first.
    pub fn is_empty(&self) -> bool {
        self.custom_entries.is_empty()
            && self.custom_records.is_empty()
            && self.client_aliases.is_empty()
    }
}

pub use memory::MemoryStorage;
pub use sqlite::SqliteStorage;
