#[cfg(feature = "storage-redis")]
pub mod redis;
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
    pub status: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub before_id: Option<u64>,
    pub before_ts: Option<i64>,
}

/// Aggregated statistics per client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientStats {
    pub client_ip: String,
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

    /// Return per-client stats for a specific IP.
    async fn client_stats(&self, client_ip: &str) -> Result<Option<ClientStats>>;

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

#[cfg(feature = "storage-redis")]
pub use redis::RedisStorage;
pub use sqlite::SqliteStorage;
