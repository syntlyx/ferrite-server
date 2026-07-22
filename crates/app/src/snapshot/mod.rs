pub mod restore;
pub mod save;

use serde::{Deserialize, Serialize};

pub const SNAPSHOT_VERSION: u32 = 3;
pub const SNAPSHOT_MAGIC: &[u8] = b"FRT2";

/// A serializable snapshot of ferrite's runtime state.
/// Saved on shutdown, restored on startup for a warm restart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub version: u32,
    /// Unix timestamp when the snapshot was created.
    pub created_at: i64,
    /// DNS response cache entries (skipped if TTL expired on restore).
    pub dns_cache: Vec<DnsCacheEntry>,
    /// Total queries processed (shown in UI immediately after restart).
    pub total_queries: u64,
    pub total_blocked: u64,
    pub total_cached: u64,
    pub total_upstream: u64,
    pub total_allowed: u64,
}

/// One serialized DNS cache entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsCacheEntry {
    /// Cache key in the form "domain/qtype".
    pub key: String,
    /// Raw DNS response bytes.
    pub bytes: Vec<u8>,
    /// Original TTL of the response.
    pub ttl: u32,
    /// Absolute expiry as Unix timestamp (seconds).
    pub expires_at: i64,
}

impl StateSnapshot {
    pub fn new() -> Self {
        Self {
            version: SNAPSHOT_VERSION,
            created_at: chrono::Utc::now().timestamp(),
            dns_cache: Vec::new(),
            total_queries: 0,
            total_blocked: 0,
            total_cached: 0,
            total_upstream: 0,
            total_allowed: 0,
        }
    }
}

impl Default for StateSnapshot {
    fn default() -> Self {
        Self::new()
    }
}
