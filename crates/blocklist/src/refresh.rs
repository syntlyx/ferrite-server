use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use fst::Map;

use crate::domains::DomainSet;
use crate::{AdblockStats, ListPolarity, loader};

/// Per-list domain cache is considered fresh for 12 hours.
pub(super) const LIST_CACHE_TTL: Duration = Duration::from_secs(12 * 3600);

/// Where a resolved per-list FST lives. `File` is the normal case — the merge
/// step mmaps it, so the k-way union never holds every list's bytes in RAM at
/// once. `Ram` carries the bytes directly when the cache write failed.
pub(super) enum ListFst {
    File(PathBuf),
    Ram(Vec<u8>),
}

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
/// Returns `(name, fst_source, unique_domain_count, stats)`. On unrecoverable
/// failure name is returned as an empty string so the caller can skip the entry.
pub(super) async fn load_or_build_list_fst(
    name: String,
    url: String,
    fst_cache: PathBuf,
    domains_cache: PathBuf,
    stats_cache: PathBuf,
    force: bool,
    polarity: ListPolarity,
) -> (String, ListFst, usize, Option<AdblockStats>) {
    // Fast path: fresh per-list FST on disk. The parse stats can't be recovered
    // from the binary FST, so they ride along in a sidecar written at parse time.
    if !force
        && is_fresh(&fst_cache).await
        && let Ok(map) = loader::mmap_fst(&fst_cache)
    {
        let count = map.len();
        let stats = load_stats_cache(&stats_cache).await;
        tracing::info!("list '{}': {} domains from FST cache", name, count);
        return (name, ListFst::File(fst_cache), count, stats);
    }

    // Slow path: load/fetch domain text, then build FST.
    let (domains, stats) =
        fetch_domains(&name, &url, &domains_cache, &stats_cache, force, polarity).await;

    if domains.is_empty() {
        if let Ok(map) = loader::mmap_fst(&fst_cache) {
            let count = map.len();
            let stats = load_stats_cache(&stats_cache).await;
            tracing::warn!("list '{}': using stale FST ({} domains)", name, count);
            return (name, ListFst::File(fst_cache), count, stats);
        }
        tracing::error!("list '{}': no domains available, skipping", name);
        return (String::new(), ListFst::Ram(Vec::new()), 0, None);
    }

    let fst_cache2 = fst_cache.clone();
    // tmp + rename: FST files are mmap'd (at merge time and by the explain
    // scan), so they must only ever be replaced atomically, never written in
    // place. The map is built straight into the temporary file — it would
    // otherwise exist in memory as well, next to the domain list it came from.
    let tmp = fst_cache2.with_extension("fst.tmp");
    let build_into = tmp.clone();
    match tokio::task::spawn_blocking(move || loader::build_fst_file(domains, &build_into)).await {
        Ok(Ok(loader::BuiltFst::File(count))) => match tokio::fs::rename(&tmp, &fst_cache2).await {
            Ok(()) => (name, ListFst::File(fst_cache2), count, stats),
            Err(e) => {
                tracing::warn!("list '{}': could not save FST cache: {}", name, e);
                let _ = tokio::fs::remove_file(&tmp).await;
                (String::new(), ListFst::Ram(Vec::new()), 0, None)
            }
        },
        // The disk refused it; serve this refresh from memory.
        Ok(Ok(loader::BuiltFst::Ram(bytes))) => {
            let count = Map::new(bytes.as_slice()).map(|m| m.len()).unwrap_or(0);
            (name, ListFst::Ram(bytes), count, stats)
        }
        Ok(Err(e)) => {
            tracing::error!("list '{}': FST build failed: {}", name, e);
            (String::new(), ListFst::Ram(Vec::new()), 0, None)
        }
        Err(e) => {
            tracing::error!("list '{}': FST build task panicked: {}", name, e);
            (String::new(), ListFst::Ram(Vec::new()), 0, None)
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
    polarity: ListPolarity,
) -> (DomainSet, Option<AdblockStats>) {
    if !force && let Some(domains) = load_fresh_text_cache(domains_cache).await {
        let stats = load_stats_cache(stats_cache).await;
        tracing::debug!(
            "list '{}': {} domains from domain cache",
            name,
            domains.len()
        );
        return (domains, stats);
    }

    match loader::load_list(url, polarity).await {
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
                // Spans over the text just read — the cache file is already the
                // shape a `DomainSet` holds, so nothing is copied.
                let stale = DomainSet::from_lines(content);
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
            (DomainSet::new(), None)
        }
    }
}

// ── Disk cache helpers ────────────────────────────────────────────────────────

/// `true` if the file exists and was modified within `LIST_CACHE_TTL`.
pub(super) async fn is_fresh(path: &Path) -> bool {
    let Ok(meta) = tokio::fs::metadata(path).await else {
        return false;
    };
    let Ok(modified) = meta.modified() else {
        return false;
    };
    matches!(SystemTime::now().duration_since(modified), Ok(age) if age <= LIST_CACHE_TTL)
}

/// Read a file only if it was modified within `LIST_CACHE_TTL`.
pub(super) async fn load_fresh_bytes(path: &Path) -> Option<Vec<u8>> {
    if !is_fresh(path).await {
        return None;
    }
    tokio::fs::read(path).await.ok()
}

async fn load_fresh_text_cache(path: &Path) -> Option<DomainSet> {
    let bytes = load_fresh_bytes(path).await?;
    let content = String::from_utf8(bytes).ok()?;
    // The file is one domain per line, which is exactly how a `DomainSet` holds
    // them — so it becomes the set's buffer as it stands, with only the spans
    // built on top.
    let domains = DomainSet::from_lines(content);
    if domains.is_empty() {
        None
    } else {
        Some(domains)
    }
}

/// Write the per-list domain cache, one bounded chunk at a time, through a
/// sibling temporary file that replaces the cache only once it is complete.
///
/// `domains.join("\n")` materialised the whole list a second time: a two-million
/// entry list is some 40 MB in one contiguous allocation, on a box whose entire
/// memory target is 20 MB — and at the worst possible moment, with the refresh
/// already holding the list as a `Vec<String>` and about to build an FST from
/// it. Chunking holds 64 KB instead. Replacing by rename also means a write cut
/// short (full disk, power loss) leaves the previous cache intact rather than a
/// truncated list that would silently unblock everything past the cut.
async fn save_text_cache(path: &Path, domains: &DomainSet) {
    use tokio::io::AsyncWriteExt;

    const CHUNK_BYTES: usize = 64 * 1024;
    let temp = path.with_extension("tmp");
    let mut file = match tokio::fs::File::create(&temp).await {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!("could not write domain cache {}: {}", path.display(), e);
            return;
        }
    };
    let mut chunk = String::with_capacity(CHUNK_BYTES + 256);
    let mut failed = false;
    for (i, domain) in domains.iter().enumerate() {
        if i > 0 {
            chunk.push('\n');
        }
        chunk.push_str(domain);
        if chunk.len() >= CHUNK_BYTES {
            if let Err(e) = file.write_all(chunk.as_bytes()).await {
                tracing::warn!("could not write domain cache {}: {}", path.display(), e);
                failed = true;
                break;
            }
            chunk.clear();
        }
    }
    if !failed && let Err(e) = file.write_all(chunk.as_bytes()).await {
        tracing::warn!("could not write domain cache {}: {}", path.display(), e);
        failed = true;
    }
    if !failed && let Err(e) = file.flush().await {
        tracing::warn!("could not flush domain cache {}: {}", path.display(), e);
        failed = true;
    }
    drop(file);
    if failed {
        let _ = tokio::fs::remove_file(&temp).await;
        return;
    }
    if let Err(e) = tokio::fs::rename(&temp, path).await {
        tracing::warn!("could not replace domain cache {}: {}", path.display(), e);
        let _ = tokio::fs::remove_file(&temp).await;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The chunked writer must produce exactly what the reader expects, across
    /// chunk boundaries — a separator dropped or doubled at a 64 KB edge would
    /// quietly corrupt a cached list.
    #[tokio::test]
    async fn domain_cache_round_trips_across_chunk_boundaries() {
        let dir = std::env::temp_dir().join(format!(
            "ferrite-domain-cache-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("list.txt");

        // Well past 64 KB, so several chunks are written.
        let domains: DomainSet = (0..20_000)
            .map(|i| format!("host{i}.example.com"))
            .collect();
        save_text_cache(&path, &domains).await;
        assert_eq!(load_fresh_text_cache(&path).await.unwrap(), domains);

        // A shorter list replaces the longer one wholesale (no leftover tail).
        let short: DomainSet = vec!["only.example.com".to_string()].into();
        save_text_cache(&path, &short).await;
        assert_eq!(load_fresh_text_cache(&path).await.unwrap(), short);

        // Empty list: a file with nothing in it, and no stale temporary left behind.
        save_text_cache(&path, &DomainSet::new()).await;
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
        assert!(!path.with_extension("tmp").exists());

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
