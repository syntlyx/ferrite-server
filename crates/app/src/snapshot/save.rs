use std::path::Path;
use std::sync::atomic::Ordering;

use crate::snapshot::{DnsCacheEntry, SNAPSHOT_MAGIC, SNAPSHOT_VERSION, StateSnapshot};
use ferrite_core::error::Result;
use ferrite_core::recording::RecordScope;
use ferrite_dns::cache::DnsCache;
use ferrite_stats::live::LiveStats;

/// Build a `StateSnapshot` from the DNS cache and live stats counters.
///
/// The cached responses are keyed by domain, so the snapshot file is itself a
/// list of recently resolved names. When `scope` records nothing — the operator
/// asked for no query log and no statistics — the cache is left out and only the
/// anonymous counters are saved. That costs a cold cache after a restart, and is
/// the only honest reading of "record nothing": ferrite would otherwise keep the
/// same domains on disk under a different file name.
pub fn build_snapshot(dns_cache: &DnsCache, live: &LiveStats, scope: RecordScope) -> StateSnapshot {
    let now_unix = chrono::Utc::now().timestamp();

    // Snapshot the DNS response cache.
    let dns_cache: Vec<DnsCacheEntry> = if !scope.records_anything() {
        Vec::new()
    } else {
        dns_cache
            .snapshot()
            .into_iter()
            .map(|(key, response, expires_at)| {
                // Convert Instant to a unix timestamp by computing the offset from
                // now. Round the remaining lifetime UP: flooring would drop an entry
                // with sub-second life left (restore skips `remaining <= 0`), and
                // systematically shave up to ~1s off every restored TTL.
                let remaining = expires_at
                    .checked_duration_since(std::time::Instant::now())
                    .map(|d| d.as_secs() as i64 + i64::from(d.subsec_nanos() > 0))
                    .unwrap_or(0);
                DnsCacheEntry {
                    key,
                    bytes: response.bytes.to_vec(),
                    ttl: response.ttl,
                    expires_at: now_unix + remaining,
                }
            })
            .collect()
    };

    StateSnapshot {
        version: SNAPSHOT_VERSION,
        created_at: now_unix,
        dns_cache,
        total_queries: live.total_queries.load(Ordering::Relaxed),
        total_blocked: live.total_blocked.load(Ordering::Relaxed),
        total_cached: live.total_cached.load(Ordering::Relaxed),
        total_upstream: live.total_upstream.load(Ordering::Relaxed),
        total_allowed: live.total_allowed.load(Ordering::Relaxed),
    }
}

/// Serialize and write `snapshot` to `path`.
pub fn save_snapshot(snapshot: &StateSnapshot, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Write to a temp file then rename for atomicity.
    // A per-write temp name, not a fixed `.tmp`: several savers can be asked to
    // run at once (the periodic one, a restart, a settings change), and sharing
    // one temp file lets two writes interleave into a corrupt `state.bin` that
    // is then rejected at load — losing the warm cache the file exists for.
    let tmp = path.with_extension(format!(
        "tmp.{}.{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let payload = postcard::to_stdvec(snapshot)?;

    // Prepend magic bytes so we can detect and reject incompatible formats.
    let mut bytes = Vec::with_capacity(SNAPSHOT_MAGIC.len() + payload.len());
    bytes.extend_from_slice(SNAPSHOT_MAGIC);
    bytes.extend_from_slice(&payload);

    std::fs::write(&tmp, &bytes)?;
    std::fs::rename(&tmp, path)?;

    tracing::info!(
        "snapshot saved: {} dns entries, {} queries",
        snapshot.dns_cache.len(),
        snapshot.total_queries
    );
    Ok(())
}

/// Convenience: build and save the snapshot in one call.
pub fn save(dns_cache: &DnsCache, live: &LiveStats, path: &Path, scope: RecordScope) -> Result<()> {
    let snapshot = build_snapshot(dns_cache, live, scope);
    save_snapshot(&snapshot, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_dns::types::DnsResponse;

    fn warm_cache() -> DnsCache {
        let cache = DnsCache::new(16, 0, 0, 86_400);
        cache.insert(
            "private.example",
            1,
            false,
            DnsResponse {
                bytes: bytes::Bytes::from_static(b"\x00\x01wire"),
                ttl: 300,
            },
        );
        cache
    }

    #[test]
    fn snapshot_carries_the_dns_cache_while_anything_is_recorded() {
        let live = LiveStats::new();
        live.total_queries.store(7, Ordering::Relaxed);

        let snapshot = build_snapshot(&warm_cache(), &live, RecordScope::ALL);

        assert_eq!(snapshot.dns_cache.len(), 1);
        assert_eq!(snapshot.total_queries, 7);
    }

    #[test]
    fn recording_fully_off_keeps_domains_out_of_the_snapshot_file() {
        let live = LiveStats::new();
        live.total_queries.store(7, Ordering::Relaxed);
        live.total_blocked.store(3, Ordering::Relaxed);

        let snapshot = build_snapshot(&warm_cache(), &live, RecordScope::NONE);

        // The cached names would otherwise sit in state.bin — a query log by
        // another name. The anonymous counters still survive the restart.
        assert!(snapshot.dns_cache.is_empty());
        assert_eq!(snapshot.total_queries, 7);
        assert_eq!(snapshot.total_blocked, 3);
    }
}
