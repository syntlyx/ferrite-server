use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use fst::Map;

use crate::blocklist::{loader, AdblockStats};

/// Per-list domain cache is considered fresh for 12 hours.
pub(super) const LIST_CACHE_TTL: Duration = Duration::from_secs(12 * 3600);

/// Resolve a single list to a per-list FST binary.
///
/// Cache layers (fastest first):
///   1. Fresh `.fst` binary on disk             → return immediately
///   2. Fresh `.domains` text on disk           → build FST, save `.fst`
///   3. Network fetch                           → save `.domains`, build FST, save `.fst`
///   4. Stale `.fst` on disk (network failed)   → warn and reuse
///
/// When `force` is set, the fresh-cache fast paths (1 and 2) are skipped so the
/// list is always re-fetched and re-parsed; the stale-cache fallbacks still
/// apply if the network fetch fails. Use it for operator-triggered refreshes.
///
/// Returns `(name, fst_bytes, unique_domain_count)`. On unrecoverable failure
/// name is returned as an empty string so the caller can skip the entry.
pub(super) async fn load_or_build_list_fst(
    name: String,
    url: String,
    fst_cache: PathBuf,
    domains_cache: PathBuf,
    stats_cache: PathBuf,
    force: bool,
) -> (String, Vec<u8>, usize, Option<AdblockStats>) {
    // Fast path: fresh per-list FST on disk. The parse stats can't be recovered
    // from the binary FST, so they ride along in a sidecar written at parse time.
    if !force {
        if let Some(bytes) = load_fresh_bytes(&fst_cache).await {
            let count = Map::new(bytes.as_slice()).map(|m| m.len()).unwrap_or(0);
            let stats = load_stats_cache(&stats_cache).await;
            tracing::info!("list '{}': {} domains from FST cache", name, count);
            return (name, bytes, count, stats);
        }
    }

    // Slow path: load/fetch domain text, then build FST.
    let (domains, stats) = fetch_domains(&name, &url, &domains_cache, &stats_cache, force).await;

    if domains.is_empty() {
        if let Ok(bytes) = tokio::fs::read(&fst_cache).await {
            if let Ok(m) = Map::new(bytes.as_slice()) {
                let count = m.len();
                let stats = load_stats_cache(&stats_cache).await;
                tracing::warn!("list '{}': using stale FST ({} domains)", name, count);
                return (name, bytes, count, stats);
            }
        }
        tracing::error!("list '{}': no domains available, skipping", name);
        return (String::new(), vec![], 0, None);
    }

    let fst_cache2 = fst_cache.clone();
    match tokio::task::spawn_blocking(move || loader::build_fst(domains)).await {
        Ok(Ok(bytes)) => {
            let count = Map::new(bytes.as_slice()).map(|m| m.len()).unwrap_or(0);
            if let Err(e) = tokio::fs::write(&fst_cache2, &bytes).await {
                tracing::warn!("list '{}': could not save FST cache: {}", name, e);
            }
            (name, bytes, count, stats)
        }
        Ok(Err(e)) => {
            tracing::error!("list '{}': FST build failed: {}", name, e);
            (String::new(), vec![], 0, None)
        }
        Err(e) => {
            tracing::error!("list '{}': FST build task panicked: {}", name, e);
            (String::new(), vec![], 0, None)
        }
    }
}

/// Fetch domain names for a single list: fresh text cache first, then network.
///
/// Returns the domains plus the Adblock parse breakdown when the list is an
/// Adblock-format list. Stats are produced only by a fresh parse; on a cache
/// hit they are reloaded from the sidecar so the API can keep reporting them.
async fn fetch_domains(
    name: &str,
    url: &str,
    domains_cache: &Path,
    stats_cache: &Path,
    force: bool,
) -> (Vec<String>, Option<AdblockStats>) {
    if !force {
        if let Some(domains) = load_fresh_text_cache(domains_cache).await {
            let stats = load_stats_cache(stats_cache).await;
            tracing::debug!(
                "list '{}': {} domains from domain cache",
                name,
                domains.len()
            );
            return (domains, stats);
        }
    }

    match loader::load_list(url).await {
        Ok((domains, stats)) => {
            tracing::info!("list '{}': fetched {} domains", name, domains.len());
            save_text_cache(domains_cache, &domains).await;
            save_stats_cache(stats_cache, stats).await;
            (domains, stats)
        }
        Err(e) => {
            tracing::error!("list '{}': fetch failed: {}", name, e);
            // Stale text cache is better than nothing.
            if let Ok(content) = tokio::fs::read_to_string(domains_cache).await {
                let stale: Vec<String> = content
                    .lines()
                    .filter(|l| !l.is_empty())
                    .map(String::from)
                    .collect();
                if !stale.is_empty() {
                    let stats = load_stats_cache(stats_cache).await;
                    tracing::warn!(
                        "list '{}': using stale domain cache ({} domains)",
                        name,
                        stale.len()
                    );
                    return (stale, stats);
                }
            }
            (vec![], None)
        }
    }
}

// ── Disk cache helpers ────────────────────────────────────────────────────────

/// Read a file only if it was modified within `LIST_CACHE_TTL`.
pub(super) async fn load_fresh_bytes(path: &Path) -> Option<Vec<u8>> {
    let meta = tokio::fs::metadata(path).await.ok()?;
    let age = SystemTime::now()
        .duration_since(meta.modified().ok()?)
        .ok()?;
    if age > LIST_CACHE_TTL {
        return None;
    }
    tokio::fs::read(path).await.ok()
}

async fn load_fresh_text_cache(path: &Path) -> Option<Vec<String>> {
    let bytes = load_fresh_bytes(path).await?;
    let content = String::from_utf8(bytes).ok()?;
    let domains: Vec<String> = content
        .lines()
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect();
    if domains.is_empty() {
        None
    } else {
        Some(domains)
    }
}

async fn save_text_cache(path: &Path, domains: &[String]) {
    if let Err(e) = tokio::fs::write(path, domains.join("\n")).await {
        tracing::warn!("could not write domain cache {}: {}", path.display(), e);
    }
}

/// Persist the Adblock parse breakdown next to the domain cache. When a list is
/// not Adblock-format (`None`) any previous sidecar is removed so stale stats
/// from a list that changed format are never reported.
async fn save_stats_cache(path: &Path, stats: Option<AdblockStats>) {
    match stats {
        Some(stats) => match serde_json::to_vec(&stats) {
            Ok(bytes) => {
                if let Err(e) = tokio::fs::write(path, bytes).await {
                    tracing::warn!("could not write stats cache {}: {}", path.display(), e);
                }
            }
            Err(e) => tracing::warn!("could not serialise stats cache: {}", e),
        },
        None => {
            let _ = tokio::fs::remove_file(path).await;
        }
    }
}

/// Read the Adblock parse breakdown sidecar. Not TTL-checked: it is paired with
/// the domain/FST cache the caller already validated, so it is exactly as fresh.
async fn load_stats_cache(path: &Path) -> Option<AdblockStats> {
    let bytes = tokio::fs::read(path).await.ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Turn a user-supplied list name into a safe filesystem component.
pub(super) fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}
