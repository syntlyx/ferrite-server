use std::path::Path;
use std::sync::atomic::Ordering;

use crate::app::AppState;
use crate::error::Result;
use crate::snapshot::{DnsCacheEntry, StateSnapshot, SNAPSHOT_MAGIC, SNAPSHOT_VERSION};

/// Build a `StateSnapshot` from the current application state.
pub fn build_snapshot(state: &AppState) -> StateSnapshot {
    let now_unix = chrono::Utc::now().timestamp();

    // Snapshot the DNS response cache.
    let dns_cache: Vec<DnsCacheEntry> = state
        .inner
        .dns_cache
        .snapshot()
        .into_iter()
        .map(|(key, response, expires_at)| {
            // Convert Instant to a unix timestamp by computing the offset from now.
            let remaining = expires_at
                .checked_duration_since(std::time::Instant::now())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            DnsCacheEntry {
                key,
                bytes: response.bytes.to_vec(),
                ttl: response.ttl,
                expires_at: now_unix + remaining,
            }
        })
        .collect();

    let live = &state.inner.live_stats;

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
    let tmp = path.with_extension("tmp");
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
pub fn save(state: &AppState, path: &Path) -> Result<()> {
    let snapshot = build_snapshot(state);
    save_snapshot(&snapshot, path)
}
