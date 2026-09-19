pub mod restore;
pub mod save;

use bytes::Bytes;
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
    /// Raw DNS response bytes. A `Bytes`, not a `Vec<u8>`: the cache already
    /// holds the response in one, so a snapshot borrows it by refcount instead
    /// of copying every cached answer. Postcard encodes both as a length and
    /// the raw bytes, so the file format is unchanged — see
    /// `byte_field_encoding_is_unchanged`.
    pub bytes: Bytes,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The entry's byte field changed type from `Vec<u8>` to `Bytes` so a
    /// snapshot could avoid copying the cache. Postcard has to encode both the
    /// same way, or every snapshot written before the change would fail to
    /// load. This pins that: a file written from the old shape decodes into the
    /// new one, and back.
    #[test]
    fn byte_field_encoding_is_unchanged() {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct OldEntry {
            key: String,
            bytes: Vec<u8>,
            ttl: u32,
            expires_at: i64,
        }

        let old = OldEntry {
            key: "example.com/1".into(),
            bytes: vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0xff],
            ttl: 300,
            expires_at: 1_700_000_000,
        };
        let new = DnsCacheEntry {
            key: old.key.clone(),
            bytes: Bytes::from(old.bytes.clone()),
            ttl: old.ttl,
            expires_at: old.expires_at,
        };

        let from_old = postcard::to_stdvec(&old).unwrap();
        let from_new = postcard::to_stdvec(&new).unwrap();
        assert_eq!(from_old, from_new, "the wire encoding must not have moved");

        let decoded: DnsCacheEntry = postcard::from_bytes(&from_old).unwrap();
        assert_eq!(decoded.bytes, Bytes::from(old.bytes.clone()));
        let decoded_old: OldEntry = postcard::from_bytes(&from_new).unwrap();
        assert_eq!(decoded_old.bytes, old.bytes);
    }
}
