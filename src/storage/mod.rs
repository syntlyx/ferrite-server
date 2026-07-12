pub mod schema;
pub mod sqlite;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::dns::types::QueryEntry;
use crate::error::Result;
use crate::stats::timeseries::TimeseriesBucket;

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
/// when known, else an IP fallback — see [`crate::dns::types::QueryEntry::device`]).
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
    /// Persist a batch of query entries.
    async fn write_batch(&self, entries: &[QueryEntry]) -> Result<()>;

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

    /// Delete query log entries with timestamp older than `cutoff_ts` (Unix seconds).
    /// Returns the number of rows deleted.
    async fn delete_queries_older_than(&self, cutoff_ts: i64) -> Result<u64>;

    // ── Custom whitelist / blacklist ─────────────────────────────────────────

    /// Persist a whitelist or blacklist entry. `entry_type` is "whitelist" or "blacklist".
    async fn add_custom_entry(&self, domain: &str, entry_type: &str) -> Result<()>;

    /// Remove a custom entry by domain.
    async fn remove_custom_entry(&self, domain: &str) -> Result<()>;

    /// Load all custom entries: returns (domain, entry_type) pairs.
    async fn load_custom_entries(&self) -> Result<Vec<(String, String)>>;

    // ── Custom DNS records ────────────────────────────────────────────────────

    // ── Client aliases ────────────────────────────────────────────────────────

    /// Persist a manual client alias (key + key_type → friendly name).
    async fn add_client_alias(&self, key: &str, key_type: &str, name: &str) -> Result<()>;

    /// Remove a manual client alias.
    async fn remove_client_alias(&self, key: &str, key_type: &str) -> Result<()>;

    /// Load all manual client aliases: returns (key, key_type, name) triples.
    async fn load_client_aliases(&self) -> Result<Vec<(String, String, String)>>;

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

    /// Refresh `last_seen = now` for the given IPs (currently-present devices), so
    /// age-based pruning keeps live bindings and only expires long-absent ones.
    /// No-op on an empty slice.
    async fn touch_ip_bindings(&self, ips: &[String]) -> Result<()>;

    /// Delete IP → MAC bindings not seen since `cutoff_ts` (unix seconds), and
    /// return the deleted IPs so the caller can drop them from its in-memory maps.
    async fn delete_ip_bindings_older_than(&self, cutoff_ts: i64) -> Result<Vec<String>>;

    // ── Custom DNS records ────────────────────────────────────────────────────

    async fn upsert_custom_record(
        &self,
        domain: &str,
        record_type: &str,
        value: &str,
        ttl: u32,
    ) -> Result<()>;

    async fn delete_custom_record(&self, domain: &str) -> Result<()>;

    async fn load_custom_records(&self) -> Result<Vec<crate::config::CustomRecordConfig>>;
}

pub use sqlite::SqliteStorage;
