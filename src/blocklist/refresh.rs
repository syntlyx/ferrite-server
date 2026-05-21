use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use fst::Map;

use crate::blocklist::loader;

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
/// Returns `(name, fst_bytes, unique_domain_count)`. On unrecoverable failure
/// name is returned as an empty string so the caller can skip the entry.
pub(super) async fn load_or_build_list_fst(
    name: String,
    url: String,
    fst_cache: PathBuf,
    domains_cache: PathBuf,
) -> (String, Vec<u8>, usize) {
    // Fast path: fresh per-list FST on disk.
    if let Some(bytes) = load_fresh_bytes(&fst_cache).await {
        let count = Map::new(bytes.as_slice()).map(|m| m.len()).unwrap_or(0);
        tracing::info!("list '{}': {} domains from FST cache", name, count);
        return (name, bytes, count);
    }

    // Slow path: load/fetch domain text, then build FST.
    let domains = fetch_domains(&name, &url, &domains_cache).await;

    if domains.is_empty() {
        if let Ok(bytes) = tokio::fs::read(&fst_cache).await {
            if let Ok(m) = Map::new(bytes.as_slice()) {
                let count = m.len();
                tracing::warn!("list '{}': using stale FST ({} domains)", name, count);
                return (name, bytes, count);
            }
        }
        tracing::error!("list '{}': no domains available, skipping", name);
        return (String::new(), vec![], 0);
    }

    let fst_cache2 = fst_cache.clone();
    match tokio::task::spawn_blocking(move || loader::build_fst(domains)).await {
        Ok(Ok(bytes)) => {
            let count = Map::new(bytes.as_slice()).map(|m| m.len()).unwrap_or(0);
            if let Err(e) = tokio::fs::write(&fst_cache2, &bytes).await {
                tracing::warn!("list '{}': could not save FST cache: {}", name, e);
            }
            (name, bytes, count)
        }
        Ok(Err(e)) => {
            tracing::error!("list '{}': FST build failed: {}", name, e);
            (String::new(), vec![], 0)
        }
        Err(e) => {
            tracing::error!("list '{}': FST build task panicked: {}", name, e);
            (String::new(), vec![], 0)
        }
    }
}

/// Fetch domain names for a single list: fresh text cache first, then network.
async fn fetch_domains(name: &str, url: &str, domains_cache: &Path) -> Vec<String> {
    if let Some(domains) = load_fresh_text_cache(domains_cache).await {
        tracing::debug!(
            "list '{}': {} domains from domain cache",
            name,
            domains.len()
        );
        return domains;
    }

    match loader::load_list(url).await {
        Ok(domains) => {
            tracing::info!("list '{}': fetched {} domains", name, domains.len());
            save_text_cache(domains_cache, &domains).await;
            domains
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
                    tracing::warn!(
                        "list '{}': using stale domain cache ({} domains)",
                        name,
                        stale.len()
                    );
                    return stale;
                }
            }
            vec![]
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
