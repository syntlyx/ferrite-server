use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use fst::Map;

use crate::domains::DomainSet;
use crate::loader::{FetchedList, ListValidators};
use crate::{AdblockStats, ListPolarity, loader};

/// Per-list domain cache is considered fresh for 12 hours.
pub(super) const LIST_CACHE_TTL: Duration = Duration::from_secs(12 * 3600);

/// Stamped into every cache sidecar. A cached `.fst` is this crate's *output*,
/// not the file upstream served, so artifacts another ferrite built are never
/// reused — a parser change must reach them. Costs one full rebuild on the first
/// refresh after an upgrade, and nothing after that.
const CACHE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Where a resolved per-list FST lives. `File` is the normal case — the merge
/// step mmaps it, so the k-way union never holds every list's bytes in RAM at
/// once. `Ram` carries the bytes directly when the cache write failed.
pub(super) enum ListFst {
    File(PathBuf),
    Ram(Vec<u8>),
}

/// The files one list keeps between refreshes, all named after the list.
pub(super) struct ListCache {
    /// The built map — what the merge step mmaps.
    pub(super) fst: PathBuf,
    /// The parsed domains, one per line, exactly as the FST was built from them.
    domains: PathBuf,
    /// Adblock parse breakdown (Adblock-format lists only).
    stats: PathBuf,
    /// What produced the files above: fingerprint + the validators to replay.
    meta: PathBuf,
}

impl ListCache {
    pub(super) fn new(dir: &Path, list_name: &str) -> Self {
        let safe = sanitize_name(list_name);
        Self {
            fst: dir.join(format!("{safe}.fst")),
            domains: dir.join(format!("{safe}.domains")),
            stats: dir.join(format!("{safe}.stats.json")),
            meta: dir.join(format!("{safe}.meta.json")),
        }
    }
}

/// Sidecar next to a per-list `.fst`, describing what it was built from.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ListMeta {
    /// [`CACHE_VERSION`] at build time.
    version: String,
    /// Digest of the bytes the cached FST was parsed from.
    digest: String,
    /// What upstream answered with, replayed on the next fetch.
    #[serde(default)]
    validators: ListValidators,
}

/// One list's contribution to a refresh.
pub(super) struct ListOutcome {
    /// Empty when the list failed and nothing cached could stand in for it.
    pub(super) name: String,
    pub(super) fst: ListFst,
    pub(super) count: usize,
    pub(super) stats: Option<AdblockStats>,
    /// Fingerprint of what `fst` holds, when it can be proven. The merge step
    /// compares these against the fingerprints the merged FST on disk was built
    /// from and skips the union when every one of them still matches; `None`
    /// means "can't prove it", which forces the merge.
    pub(super) digest: Option<String>,
}

/// Resolve a single list to a per-list FST binary.
///
/// Cache layers (cheapest first):
///   1. Fresh `.fst` binary on disk             → return immediately
///   2. Upstream confirms nothing changed        → keep the cached `.fst`
///   3. Fresh `.domains` text on disk           → build FST, save `.fst`
///   4. Network fetch                           → save `.domains`, build FST, save `.fst`
///   5. Stale cache on disk (network failed)    → warn and reuse
///
/// `force` skips the *time-based* layers 1 and 3, so an operator-triggered
/// refresh always asks upstream. It deliberately does not skip layer 2: when
/// upstream answers 304, or returns the very bytes the cached FST was built
/// from, rebuilding can only produce that same FST again. A ferrite that would
/// parse those bytes differently carries a different [`CACHE_VERSION`], and that
/// does rebuild everything.
///
/// On unrecoverable failure the name comes back empty so the caller can skip the
/// entry.
pub(super) async fn load_or_build_list_fst(
    name: String,
    url: String,
    cache: ListCache,
    force: bool,
    polarity: ListPolarity,
) -> ListOutcome {
    // Sidecars written by another ferrite are ignored wholesale — see
    // `CACHE_VERSION`. With no usable sidecar nothing below can take a shortcut.
    let meta = load_meta(&cache.meta)
        .await
        .filter(|m| m.version == CACHE_VERSION);
    let cached_fst = loader::mmap_fst(&cache.fst).ok();

    // (1) Fresh per-list FST on disk. The parse stats can't be recovered from
    // the binary FST, so they ride along in a sidecar written at parse time.
    if !force
        && let Some(map) = &cached_fst
        && meta.is_some()
        && is_fresh(&cache.fst).await
    {
        let count = map.len();
        tracing::info!("list '{}': {} domains from FST cache", name, count);
        return ListOutcome {
            name,
            fst: ListFst::File(cache.fst),
            count,
            stats: load_stats_cache(&cache.stats).await,
            digest: meta.map(|m| m.digest),
        };
    }

    // (3) The text is fresh but the binary isn't (a previous FST write failed):
    // rebuild it without going back to the network. The sidecar still describes
    // this text, so the rebuilt FST inherits its fingerprint.
    if !force
        && cached_fst.is_none()
        && let Some(domains) = load_fresh_text_cache(&cache.domains).await
    {
        tracing::debug!(
            "list '{}': {} domains from domain cache",
            name,
            domains.len()
        );
        let stats = load_stats_cache(&cache.stats).await;
        return build_list_fst(name, domains, stats, &cache, meta).await;
    }

    // (2)/(4) Ask upstream, replaying the validators from the last fetch. Only
    // conditional while a cached FST is actually there to keep: a 304 with
    // nothing on disk would leave this list with nothing to serve.
    let prior = cached_fst
        .as_ref()
        .and(meta.as_ref())
        .map(|m| m.validators.clone())
        .filter(|v| !v.is_empty());

    match loader::load_list(&url, polarity, prior.as_ref()).await {
        // (2) Unchanged upstream — the cached binary is still the answer.
        Ok(FetchedList::NotModified) if cached_fst.is_some() => {
            let count = cached_fst.map(|m| m.len()).unwrap_or(0);
            tracing::info!(
                "list '{}': unchanged upstream, {} domains kept",
                name,
                count
            );
            ListOutcome {
                name,
                fst: ListFst::File(cache.fst),
                count,
                stats: load_stats_cache(&cache.stats).await,
                digest: meta.map(|m| m.digest),
            }
        }
        Ok(FetchedList::Parsed {
            domains,
            stats,
            digest,
            validators,
        }) if !domains.is_empty() => {
            tracing::info!("list '{}': fetched {} domains", name, domains.len());
            let unchanged = meta.as_ref().is_some_and(|m| m.digest == digest);
            let meta = ListMeta {
                version: CACHE_VERSION.to_string(),
                digest,
                validators,
            };
            // (2) Same bytes as last time under a moved (or absent) ETag: the
            // build would reproduce the cached FST byte for byte. Only the
            // validators are worth writing back.
            if unchanged && let Some(map) = cached_fst {
                let count = map.len();
                tracing::info!("list '{}': content unchanged, {} domains kept", name, count);
                let digest = Some(meta.digest.clone());
                save_meta(&cache.meta, &meta).await;
                return ListOutcome {
                    name,
                    fst: ListFst::File(cache.fst),
                    count,
                    // The sidecar holds this very parse; falling back to the one
                    // just made keeps the breakdown alive if it went missing.
                    stats: load_stats_cache(&cache.stats).await.or(stats),
                    digest,
                };
            }
            save_text_cache(&cache.domains, &domains).await;
            save_stats_cache(&cache.stats, stats).await;
            build_list_fst(name, domains, stats, &cache, Some(meta)).await
        }
        // (5) Nothing usable arrived — an error, an empty body, or a 304 whose
        // cached binary has gone missing. Stale beats blank.
        outcome => {
            match &outcome {
                Ok(_) => tracing::warn!("list '{}': upstream returned nothing usable", name),
                Err(e) => tracing::error!("list '{}': fetch failed: {}", name, e),
            }
            stale_fallback(name, cache, meta).await
        }
    }
}

/// Build the per-list FST from `domains` and replace the cache atomically.
///
/// `meta` is the sidecar to record — `Some` only when the fingerprint of what
/// went in is known. It is written *after* the FST is in place, and removed when
/// it isn't: a sidecar that describes a file which never landed would let the
/// next refresh keep a stale list believing it was current.
async fn build_list_fst(
    name: String,
    domains: DomainSet,
    stats: Option<AdblockStats>,
    cache: &ListCache,
    meta: Option<ListMeta>,
) -> ListOutcome {
    let fst_path = cache.fst.clone();
    // tmp + rename: FST files are mmap'd (at merge time and by the explain
    // scan), so they must only ever be replaced atomically, never written in
    // place. The map is built straight into the temporary file — it would
    // otherwise exist in memory as well, next to the domain list it came from.
    let tmp = fst_path.with_extension("fst.tmp");
    let build_into = tmp.clone();
    let built =
        tokio::task::spawn_blocking(move || loader::build_fst_file(domains, &build_into)).await;

    match built {
        Ok(Ok(loader::BuiltFst::File(count))) => match tokio::fs::rename(&tmp, &fst_path).await {
            Ok(()) => {
                let digest = match meta {
                    Some(meta) => {
                        save_meta(&cache.meta, &meta).await;
                        Some(meta.digest)
                    }
                    None => {
                        // Nothing provable about this build — make sure no older
                        // sidecar claims otherwise.
                        let _ = tokio::fs::remove_file(&cache.meta).await;
                        None
                    }
                };
                ListOutcome {
                    name,
                    fst: ListFst::File(fst_path),
                    count,
                    stats,
                    digest,
                }
            }
            Err(e) => {
                tracing::warn!("list '{}': could not save FST cache: {}", name, e);
                let _ = tokio::fs::remove_file(&tmp).await;
                let _ = tokio::fs::remove_file(&cache.meta).await;
                ListOutcome::skipped()
            }
        },
        // The disk refused it; serve this refresh from memory. The on-disk FST
        // is now whatever it was before, so no sidecar may vouch for it.
        Ok(Ok(loader::BuiltFst::Ram(bytes))) => {
            let _ = tokio::fs::remove_file(&cache.meta).await;
            let count = Map::new(bytes.as_slice()).map(|m| m.len()).unwrap_or(0);
            ListOutcome {
                name,
                fst: ListFst::Ram(bytes),
                count,
                stats,
                digest: None,
            }
        }
        Ok(Err(e)) => {
            tracing::error!("list '{}': FST build failed: {}", name, e);
            ListOutcome::skipped()
        }
        Err(e) => {
            tracing::error!("list '{}': FST build task panicked: {}", name, e);
            ListOutcome::skipped()
        }
    }
}

/// Serve a failed refresh from whatever the disk still holds: the built FST
/// first, then the parsed text it came from. Both keep their fingerprint — they
/// are exactly what the last successful refresh recorded.
async fn stale_fallback(name: String, cache: ListCache, meta: Option<ListMeta>) -> ListOutcome {
    if let Ok(map) = loader::mmap_fst(&cache.fst) {
        let count = map.len();
        tracing::warn!("list '{}': using stale FST ({} domains)", name, count);
        return ListOutcome {
            name,
            fst: ListFst::File(cache.fst),
            count,
            stats: load_stats_cache(&cache.stats).await,
            digest: meta.map(|m| m.digest),
        };
    }
    if let Ok(content) = tokio::fs::read_to_string(&cache.domains).await {
        // Spans over the text just read — the cache file is already the shape a
        // `DomainSet` holds, so nothing is copied.
        let stale = DomainSet::from_lines(content);
        if !stale.is_empty() {
            tracing::warn!(
                "list '{}': using stale domain cache ({} domains)",
                name,
                stale.len()
            );
            let stats = load_stats_cache(&cache.stats).await;
            return build_list_fst(name, stale, stats, &cache, meta).await;
        }
    }
    tracing::error!("list '{}': no domains available, skipping", name);
    ListOutcome::skipped()
}

impl ListOutcome {
    /// The "this list contributed nothing" outcome: an empty name tells the
    /// caller to drop it from this refresh.
    pub(super) fn skipped() -> Self {
        Self {
            name: String::new(),
            fst: ListFst::Ram(Vec::new()),
            count: 0,
            stats: None,
            digest: None,
        }
    }
}

/// Read the cache sidecar, if any.
async fn load_meta(path: &Path) -> Option<ListMeta> {
    let bytes = tokio::fs::read(path).await.ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Write the cache sidecar, replacing whatever was there.
async fn save_meta(path: &Path, meta: &ListMeta) {
    match serde_json::to_vec(meta) {
        Ok(bytes) => {
            if let Err(e) = tokio::fs::write(path, bytes).await {
                tracing::warn!("could not write cache meta {}: {}", path.display(), e);
            }
        }
        Err(e) => tracing::warn!("could not serialise cache meta: {}", e),
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

/// The fingerprint recorded for `list_name`'s cached FST, when this ferrite is
/// the one that wrote it. Synchronous on purpose: its caller is profile
/// compilation, which runs on the blocking pool, and the sidecar is a few
/// hundred bytes.
pub(super) fn list_digest(dir: &Path, list_name: &str) -> Option<String> {
    let bytes = std::fs::read(ListCache::new(dir, list_name).meta).ok()?;
    let meta: ListMeta = serde_json::from_slice(&bytes).ok()?;
    (meta.version == CACHE_VERSION).then_some(meta.digest)
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
