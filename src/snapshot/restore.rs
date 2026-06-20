use std::path::Path;
use std::sync::atomic::Ordering;

use crate::app::AppState;
use crate::error::Result;
use crate::snapshot::{SNAPSHOT_MAGIC, SNAPSHOT_VERSION, StateSnapshot};

/// Deserialize a `StateSnapshot` from `path`.
/// Returns `Ok(None)` if the file doesn't exist.
pub fn load_snapshot(path: &Path) -> Result<Option<StateSnapshot>> {
    if !path.exists() {
        return Ok(None);
    }

    let bytes = std::fs::read(path)?;

    // Check magic prefix. Older/incompatible snapshot formats are discarded gracefully.
    if !bytes.starts_with(SNAPSHOT_MAGIC) {
        tracing::info!("snapshot has no magic header (old format), discarding");
        return Ok(None);
    }
    let payload = &bytes[SNAPSHOT_MAGIC.len()..];

    let snapshot: StateSnapshot = postcard::from_bytes(payload)?;

    if snapshot.version != SNAPSHOT_VERSION {
        tracing::warn!(
            "snapshot version mismatch (got {}, expected {}), ignoring",
            snapshot.version,
            SNAPSHOT_VERSION
        );
        return Ok(None);
    }

    tracing::info!(
        "snapshot loaded: {} dns entries, {} queries (saved at {})",
        snapshot.dns_cache.len(),
        snapshot.total_queries,
        chrono::DateTime::from_timestamp(snapshot.created_at, 0)
            .map(|t: chrono::DateTime<chrono::Utc>| t.to_rfc3339())
            .unwrap_or_else(|| "?".into())
    );

    Ok(Some(snapshot))
}

/// Apply a snapshot to the running application state.
///
/// - DNS cache entries are restored (expired ones are skipped by `DnsCache::restore`).
/// - Live stats counters are increased from a same-day snapshot when it has
///   values newer than the storage seed.
pub fn apply_snapshot(state: &AppState, snapshot: &StateSnapshot) {
    // Restore DNS cache.
    let entries: Vec<(String, Vec<u8>, u32, i64)> = snapshot
        .dns_cache
        .iter()
        .map(|e| (e.key.clone(), e.bytes.clone(), e.ttl, e.expires_at))
        .collect();
    state.inner.dns_cache.restore(&entries);

    // Restore live stats (only if snapshot was from the same day).
    let snapshot_day = chrono::DateTime::from_timestamp(snapshot.created_at, 0)
        .map(|t: chrono::DateTime<chrono::Utc>| t.date_naive());
    let today = chrono::Utc::now().date_naive();

    if snapshot_day == Some(today) {
        let live = &state.inner.live_stats;
        store_max(&live.total_queries, snapshot.total_queries);
        store_max(&live.total_blocked, snapshot.total_blocked);
        store_max(&live.total_cached, snapshot.total_cached);
        store_max(&live.total_upstream, snapshot.total_upstream);
        store_max(&live.total_allowed, snapshot.total_allowed);
        tracing::info!("live stats merged from snapshot (same day)");
    } else {
        tracing::info!("snapshot from a previous day — live stats counters ignored");
    }
}

fn store_max(counter: &std::sync::atomic::AtomicU64, snapshot_value: u64) {
    let current = counter.load(Ordering::Relaxed);
    counter.store(current.max(snapshot_value), Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, UpstreamConfig};
    use crate::snapshot::save::save_snapshot;
    use crate::snapshot::{DnsCacheEntry, SNAPSHOT_MAGIC, SNAPSHOT_VERSION};

    #[test]
    fn snapshot_save_load_round_trips_postcard_payload() {
        let path = temp_path("roundtrip");
        let snapshot = StateSnapshot {
            version: SNAPSHOT_VERSION,
            created_at: 1_735_689_600,
            dns_cache: vec![DnsCacheEntry {
                key: "example.com/1".to_string(),
                bytes: vec![0xde, 0xad, 0xbe, 0xef],
                ttl: 300,
                expires_at: 1_735_689_900,
            }],
            total_queries: 42,
            total_blocked: 7,
            total_cached: 8,
            total_upstream: 9,
            total_allowed: 18,
        };

        save_snapshot(&snapshot, &path).unwrap();
        let loaded = load_snapshot(&path).unwrap().unwrap();

        assert_eq!(loaded.version, snapshot.version);
        assert_eq!(loaded.created_at, snapshot.created_at);
        assert_eq!(loaded.dns_cache.len(), 1);
        assert_eq!(loaded.dns_cache[0].key, "example.com/1");
        assert_eq!(loaded.dns_cache[0].bytes, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(loaded.total_queries, 42);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn bad_magic_is_ignored_without_decoding() {
        let path = temp_path("bad-magic");
        std::fs::write(&path, b"FRT1not-this-codec").unwrap();

        assert!(load_snapshot(&path).unwrap().is_none());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn version_mismatch_is_ignored() {
        let path = temp_path("version-mismatch");
        let mut snapshot = StateSnapshot::new();
        snapshot.version = SNAPSHOT_VERSION + 1;

        let mut bytes = SNAPSHOT_MAGIC.to_vec();
        bytes.extend_from_slice(&postcard::to_stdvec(&snapshot).unwrap());
        std::fs::write(&path, bytes).unwrap();

        assert!(load_snapshot(&path).unwrap().is_none());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn corrupt_postcard_payload_returns_codec_error() {
        let path = temp_path("corrupt");
        let mut bytes = SNAPSHOT_MAGIC.to_vec();
        bytes.extend_from_slice(b"this is not postcard");
        std::fs::write(&path, bytes).unwrap();

        let err = load_snapshot(&path).unwrap_err();

        assert!(err.to_string().contains("snapshot codec error"));

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn apply_snapshot_restores_only_unexpired_dns_cache_entries() {
        let (state, db_path) = temp_state("restore-cache").await;
        let now = chrono::Utc::now().timestamp();
        let snapshot = StateSnapshot {
            version: SNAPSHOT_VERSION,
            created_at: now,
            dns_cache: vec![
                DnsCacheEntry {
                    key: "fresh.test/1".to_string(),
                    bytes: b"fresh".to_vec(),
                    ttl: 120,
                    expires_at: now + 120,
                },
                DnsCacheEntry {
                    key: "expired.test/1".to_string(),
                    bytes: b"expired".to_vec(),
                    ttl: 120,
                    expires_at: now - 1,
                },
            ],
            total_queries: 0,
            total_blocked: 0,
            total_cached: 0,
            total_upstream: 0,
            total_allowed: 0,
        };

        apply_snapshot(&state, &snapshot);

        assert_eq!(
            state.inner.dns_cache.get("fresh.test", 1).unwrap().bytes,
            bytes::Bytes::from_static(b"fresh")
        );
        assert!(state.inner.dns_cache.get("expired.test", 1).is_none());

        drop(state);
        cleanup_sqlite(&db_path);
    }

    #[tokio::test]
    async fn same_day_snapshot_restores_live_counters() {
        let (state, db_path) = temp_state("same-day-stats").await;
        let snapshot = StateSnapshot {
            version: SNAPSHOT_VERSION,
            created_at: chrono::Utc::now().timestamp(),
            dns_cache: vec![],
            total_queries: 42,
            total_blocked: 7,
            total_cached: 8,
            total_upstream: 9,
            total_allowed: 18,
        };

        apply_snapshot(&state, &snapshot);

        let live = &state.inner.live_stats;
        assert_eq!(live.total_queries.load(Ordering::Relaxed), 42);
        assert_eq!(live.total_blocked.load(Ordering::Relaxed), 7);
        assert_eq!(live.total_cached.load(Ordering::Relaxed), 8);
        assert_eq!(live.total_upstream.load(Ordering::Relaxed), 9);
        assert_eq!(live.total_allowed.load(Ordering::Relaxed), 18);

        drop(state);
        cleanup_sqlite(&db_path);
    }

    #[tokio::test]
    async fn same_day_snapshot_does_not_lower_seeded_counters() {
        let (state, db_path) = temp_state("same-day-stats-max").await;
        state
            .inner
            .live_stats
            .total_queries
            .store(100, Ordering::Relaxed);
        let snapshot = StateSnapshot {
            version: SNAPSHOT_VERSION,
            created_at: chrono::Utc::now().timestamp(),
            dns_cache: vec![],
            total_queries: 42,
            total_blocked: 0,
            total_cached: 0,
            total_upstream: 0,
            total_allowed: 0,
        };

        apply_snapshot(&state, &snapshot);

        assert_eq!(
            state.inner.live_stats.total_queries.load(Ordering::Relaxed),
            100
        );

        drop(state);
        cleanup_sqlite(&db_path);
    }

    #[tokio::test]
    async fn previous_day_snapshot_does_not_restore_live_counters() {
        let (state, db_path) = temp_state("previous-day-stats").await;
        let yesterday = (chrono::Utc::now() - chrono::Duration::days(1)).timestamp();
        let snapshot = StateSnapshot {
            version: SNAPSHOT_VERSION,
            created_at: yesterday,
            dns_cache: vec![],
            total_queries: 42,
            total_blocked: 7,
            total_cached: 8,
            total_upstream: 9,
            total_allowed: 18,
        };

        apply_snapshot(&state, &snapshot);

        let live = &state.inner.live_stats;
        assert_eq!(live.total_queries.load(Ordering::Relaxed), 0);
        assert_eq!(live.total_blocked.load(Ordering::Relaxed), 0);
        assert_eq!(live.total_cached.load(Ordering::Relaxed), 0);
        assert_eq!(live.total_upstream.load(Ordering::Relaxed), 0);
        assert_eq!(live.total_allowed.load(Ordering::Relaxed), 0);

        drop(state);
        cleanup_sqlite(&db_path);
    }

    fn temp_path(name: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "ferrite-snapshot-{name}-{}-{nanos}.bin",
            std::process::id()
        ))
    }

    fn temp_db_path(name: &str) -> std::path::PathBuf {
        let mut path = temp_path(name);
        path.set_extension("db");
        path
    }

    async fn temp_state(name: &str) -> (AppState, std::path::PathBuf) {
        let db_path = temp_db_path(name);
        let mut config = Config::default();
        config.storage.path = db_path.clone();
        config.blocklist.lists.clear();
        config.upstream = vec![UpstreamConfig::Plain {
            address: "127.0.0.1".to_string(),
            port: 53,
        }];

        let state = AppState::init(&config, config.clone()).await.unwrap();
        (state, db_path)
    }

    fn cleanup_sqlite(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
    }
}
