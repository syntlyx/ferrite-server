//! One set of subscribed lists — the blocklists or the allowlists — and the
//! merged FST built from them. Both sets run the same fetch/parse/merge
//! pipeline and keep the same bookkeeping; [`ListPolarity`] is the only
//! difference, and it only changes how Adblock-format content is read.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use arc_swap::{ArcSwap, Guard};
use fst::Map;
use parking_lot::RwLock;

use crate::loader::{self, FstMap, empty_fst};
use crate::names::matched_key;
use crate::{AdblockStats, ListPolarity, refresh};
use ferrite_core::config::ListConfig;
use ferrite_core::error::{FeriteError, Result};

pub struct Subscriptions {
    polarity: ListPolarity,
    /// The subscriptions themselves, mutable at runtime through the API.
    lists: RwLock<Vec<ListConfig>>,
    /// Merged FST of every enabled list, hot-swapped on refresh.
    fst: ArcSwap<FstMap>,
    /// Domain count per list name, updated after each refresh.
    counts: RwLock<HashMap<String, usize>>,
    /// Adblock parse breakdown per list name (Adblock-format lists only),
    /// updated after each refresh. Explains the rules-vs-domains gap in the UI.
    stats: RwLock<HashMap<String, AdblockStats>>,
    /// The merged FST on disk (`blocklist.fst`, `allowlist.fst`).
    merged_path: PathBuf,
    /// Per-list caches (`<name>.fst`, `.domains`, `.stats.json`). Each polarity
    /// has its own directory, so a blocklist and an allowlist with the same name
    /// can't collide on a cache file.
    cache_dir: PathBuf,
    /// `true` while the merged FST being served *is* the mmap of `merged_path`.
    /// Then a profile whose lists are exactly the enabled set can map that same
    /// file instead of merging the very same inputs a second time.
    merged_on_disk: AtomicBool,
}

/// What a [`Subscriptions::refresh`] did.
pub(crate) struct Refreshed {
    pub(crate) unique_count: usize,
    /// `false` when the merged FST was already what the lists would produce —
    /// nothing downstream (decision cache, profiles) needs rebuilding.
    pub(crate) changed: bool,
}

impl Subscriptions {
    pub(crate) fn new(
        polarity: ListPolarity,
        lists: Vec<ListConfig>,
        merged_path: PathBuf,
        cache_dir: PathBuf,
    ) -> Self {
        Self {
            polarity,
            lists: RwLock::new(lists),
            fst: ArcSwap::from_pointee(empty_fst()),
            counts: RwLock::new(HashMap::new()),
            stats: RwLock::new(HashMap::new()),
            merged_path,
            cache_dir,
            merged_on_disk: AtomicBool::new(false),
        }
    }

    pub fn polarity(&self) -> ListPolarity {
        self.polarity
    }

    pub fn lists(&self) -> Vec<ListConfig> {
        self.lists.read().clone()
    }

    pub fn domain_count(&self, name: &str) -> Option<usize> {
        self.counts.read().get(name).copied()
    }

    /// Adblock parse breakdown for `name`, if it is an Adblock-format list and
    /// has been refreshed at least once — for an allowlist, `kept` counts the
    /// `@@` exception domains harvested as allows. `None` for hosts/plain lists.
    pub fn parse_stats(&self, name: &str) -> Option<AdblockStats> {
        self.stats.read().get(name).copied()
    }

    pub fn add(&self, cfg: ListConfig) -> Result<()> {
        let mut lists = self.lists.write();
        if lists.iter().any(|l| l.name == cfg.name) {
            return Err(FeriteError::Config(format!(
                "{} '{}' already exists",
                self.polarity.noun(),
                cfg.name
            )));
        }
        lists.push(cfg);
        Ok(())
    }

    pub fn remove(&self, name: &str) -> bool {
        let mut lists = self.lists.write();
        let before = lists.len();
        lists.retain(|l| l.name != name);
        lists.len() < before
    }

    pub fn set_enabled(&self, name: &str, enabled: bool) -> bool {
        let mut lists = self.lists.write();
        if let Some(l) = lists.iter_mut().find(|l| l.name == name) {
            l.enabled = enabled;
            true
        } else {
            false
        }
    }

    /// Any lists configured at all, enabled or not.
    pub(crate) fn is_configured(&self) -> bool {
        !self.lists.read().is_empty()
    }

    pub(crate) fn has_enabled(&self) -> bool {
        self.lists.read().iter().any(|l| l.enabled)
    }

    /// The merged FST being served — the DNS hot path reads it on every miss.
    pub(crate) fn fst(&self) -> Guard<Arc<FstMap>> {
        self.fst.load()
    }

    pub(crate) fn merged_path(&self) -> &Path {
        &self.merged_path
    }

    pub(crate) fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    /// Map the merged FST a previous refresh left on disk, serving it via mmap
    /// so the (potentially tens-of-MB) map lives in the page cache, not
    /// anonymous RSS, and restore the per-list counts beside it. `Ok(None)` when
    /// there is no file yet (first boot); an error when the file is unusable.
    pub(crate) fn load_merged(&self) -> Result<Option<usize>> {
        if !self.merged_path.exists() {
            return Ok(None);
        }
        let fst = loader::mmap_fst(&self.merged_path)?;
        let count = fst.len();
        self.fst.store(Arc::new(fst));
        self.merged_on_disk.store(true, Ordering::Relaxed);
        self.restore_stats_from_cache();
        Ok(Some(count))
    }

    /// Restore per-list domain counts and Adblock parse stats from the on-disk
    /// caches the last refresh wrote (`<list>.fst` / `<list>.stats.json` under
    /// the cache dir). Loading the merged FST alone would leave the Lists page
    /// with blank counts after a restart until the next refresh repopulated them
    /// over the network. Read-only and synchronous — missing/garbage caches are
    /// simply skipped, and a later refresh overwrites these with authoritative
    /// values.
    fn restore_stats_from_cache(&self) {
        let lists = self.lists();
        let mut counts: HashMap<String, usize> = HashMap::new();
        let mut stats: HashMap<String, AdblockStats> = HashMap::new();
        for list in &lists {
            let safe = refresh::sanitize_name(&list.name);
            // Count = entries in the per-list FST (exactly what a refresh records).
            if let Ok(map) = loader::mmap_fst(&self.cache_dir.join(format!("{safe}.fst"))) {
                counts.insert(list.name.clone(), map.len());
            }
            if let Ok(bytes) = std::fs::read(self.cache_dir.join(format!("{safe}.stats.json")))
                && let Ok(s) = serde_json::from_slice::<AdblockStats>(&bytes)
            {
                stats.insert(list.name.clone(), s);
            }
        }
        if !counts.is_empty() {
            *self.counts.write() = counts;
        }
        if !stats.is_empty() {
            *self.stats.write() = stats;
        }
    }

    /// Fetch every enabled list and swap in the merged FST built from them.
    ///
    /// `force` bypasses the per-list disk caches (both the built `.fst` and the
    /// parsed `.domains` text), forcing a network re-fetch and a fresh parse.
    pub(crate) async fn refresh(&self, force: bool) -> Result<Refreshed> {
        let enabled: Vec<ListConfig> = self
            .lists
            .read()
            .iter()
            .filter(|l| l.enabled)
            .cloned()
            .collect();
        let set = refresh_list_set(
            &enabled,
            &self.cache_dir,
            &self.merged_path,
            force,
            self.polarity,
        )
        .await?;
        // Install the new FST and its domain counts together so a reader never
        // sees counts from one refresh paired with the FST of another.
        self.fst.store(Arc::new(set.fst));
        *self.counts.write() = set.counts;
        *self.stats.write() = set.stats;
        self.merged_on_disk.store(set.persisted, Ordering::Relaxed);
        Ok(Refreshed {
            unique_count: set.unique_count,
            changed: set.changed,
        })
    }

    /// Is any enabled list's cache past its lifetime, missing, or written by
    /// another ferrite version? Cheap — a stat and a small read per list.
    pub(crate) fn caches_stale(&self) -> bool {
        self.lists
            .read()
            .iter()
            .filter(|l| l.enabled)
            .any(|l| !refresh::cache_is_current(&self.cache_dir, &l.name))
    }

    /// The merged FST as an input for profile compilation — `None` unless the
    /// file on disk is the map currently being served.
    pub(crate) fn merged_set(&self) -> Option<MergedSet> {
        self.merged_on_disk
            .load(Ordering::Relaxed)
            .then(|| MergedSet {
                path: self.merged_path.clone(),
                names: enabled_list_names(&self.lists.read()),
            })
    }

    /// The enabled lists that contain `domain` (or a parent of it), each with
    /// the key that matched, in config order. Scans every list's own on-disk
    /// FST, which the merged hot-path FST can't attribute — so this is for the
    /// diagnostic API, never the DNS path.
    pub(crate) fn attribute<'a>(
        &self,
        domain: &'a str,
    ) -> impl Iterator<Item = (String, String)> + 'a {
        let cache_dir = self.cache_dir.clone();
        self.lists()
            .into_iter()
            .filter(|l| l.enabled)
            .filter_map(move |list| {
                let path = cache_dir.join(format!("{}.fst", refresh::sanitize_name(&list.name)));
                let map = loader::mmap_fst(&path).ok()?;
                let key = matched_key(domain, |k| map.contains_key(k.as_bytes()))?;
                Some((list.name, key))
            })
    }

    /// The key at which the merged FST matches `domain`, if any — the fallback
    /// when no per-list file could attribute a match (e.g. one went missing).
    pub(crate) fn merged_match(&self, domain: &str) -> Option<String> {
        let fst = self.fst();
        matched_key(domain, |k| fst.contains_key(k.as_bytes()))
    }
}

/// What [`refresh_list_set`] hands back.
struct ListSetRefresh {
    fst: FstMap,
    /// Per-list domain counts and Adblock parse stats, for the API.
    counts: HashMap<String, usize>,
    stats: HashMap<String, AdblockStats>,
    unique_count: usize,
    /// `false` when every list still matched the fingerprints the merged FST on
    /// disk was built from — the merge was skipped and nothing downstream (the
    /// decision cache, the compiled profiles) needs rebuilding either.
    changed: bool,
    /// `fst` is the mmap of `merged_path`, so a profile covering exactly the
    /// same lists can map that file instead of merging them a second time.
    persisted: bool,
}

/// Sidecar next to a merged FST — the global one or a profile's — recording the
/// per-list fingerprints it was built from. A compile whose lists all report the
/// same fingerprints can serve the file as it stands: the union would only
/// reproduce it.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub(crate) struct FstInputs {
    /// `(sanitised list name, digest)`, sorted — an added, removed or changed
    /// list all show up as a difference.
    pub(crate) inputs: Vec<(String, String)>,
}
const MAX_CONCURRENT_LIST_REFRESHES: usize = 2;

/// Fetch every enabled list in `lists` (at most [`MAX_CONCURRENT_LIST_REFRESHES`]
/// at a time), resolve each to a per-list FST under `cache_dir`, k-way-merge
/// them, and atomically persist + mmap the merged FST at `merged_path`. Shared
/// by both polarities through [`Subscriptions::refresh`]; `polarity`
/// only changes how Adblock-format content is parsed.
///
/// Errors when every list failed and nothing is cached — the caller decides
/// whether that is fatal.
async fn refresh_list_set(
    lists: &[ListConfig],
    cache_dir: &Path,
    merged_path: &Path,
    force: bool,
    polarity: ListPolarity,
) -> Result<ListSetRefresh> {
    let _ = tokio::fs::create_dir_all(cache_dir).await;
    let refresh_permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_LIST_REFRESHES));

    let tasks: Vec<_> = lists
        .iter()
        .map(|list| {
            let name = list.name.clone();
            let url = list.url.clone();
            let permits = Arc::clone(&refresh_permits);
            let cache = refresh::ListCache::new(cache_dir, &list.name);
            tokio::spawn(async move {
                let Ok(_permit) = permits.acquire_owned().await else {
                    return refresh::ListOutcome::skipped();
                };
                refresh::load_or_build_list_fst(name, url, cache, force, polarity).await
            })
        })
        .collect();

    let mut per_list_fsts: Vec<refresh::ListFst> = Vec::with_capacity(lists.len());
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut stats: HashMap<String, AdblockStats> = HashMap::new();
    // What this refresh would merge, for the sidecar. A list that couldn't prove
    // what its FST holds turns this into `None`, and the merge then has to run.
    // A list that contributed nothing at all is simply absent — so does it stay
    // in the recorded set, which is why a permanently failing list doesn't force
    // a merge on every refresh.
    let mut fingerprint: Option<Vec<(String, String)>> = Some(Vec::with_capacity(lists.len()));

    for task in tasks {
        let outcome = task.await.unwrap_or_else(|e| {
            tracing::error!("list task panicked: {}", e);
            refresh::ListOutcome::skipped()
        });
        if outcome.name.is_empty() {
            continue;
        }
        match (fingerprint.as_mut(), &outcome.digest) {
            (Some(inputs), Some(digest)) => {
                inputs.push((refresh::sanitize_name(&outcome.name), digest.clone()))
            }
            _ => fingerprint = None,
        }
        if let Some(list_stats) = outcome.stats {
            stats.insert(outcome.name.clone(), list_stats);
        }
        counts.insert(outcome.name, outcome.count);
        per_list_fsts.push(outcome.fst);
    }

    if !lists.is_empty() && per_list_fsts.is_empty() {
        return Err(FeriteError::Fst(format!(
            "all enabled {}s failed and no cached domains are available",
            polarity.noun()
        )));
    }

    // Nothing that went into the merged FST moved, so the file on disk is still
    // precisely what the union would produce. Map it and skip the merge — on a
    // Pi-class box that is tens of seconds, every refresh, for an identical file.
    if let Some(inputs) = fingerprint.as_mut() {
        inputs.sort();
        if load_merged_meta(merged_path)
            .await
            .is_some_and(|meta| meta.inputs == *inputs)
            && let Ok(fst) = loader::mmap_fst(merged_path)
        {
            let unique_count = fst.len();
            tracing::info!(
                "merged FST unchanged ({} domains), skipping merge",
                unique_count
            );
            return Ok(ListSetRefresh {
                fst,
                counts,
                stats,
                unique_count,
                changed: false,
                persisted: true,
            });
        }
    }

    let merged_path_owned = merged_path.to_path_buf();
    let (fst, unique_count, persisted) =
        tokio::task::spawn_blocking(move || -> Result<(FstMap, usize, bool)> {
            // Open every input as a Map first — File sources mmap straight from
            // the per-list cache, so the k-way union streams them out of the page
            // cache instead of holding each list's bytes in RAM.
            let mut maps: Vec<FstMap> = Vec::with_capacity(per_list_fsts.len());
            for src in per_list_fsts {
                let map = match src {
                    refresh::ListFst::File(p) => loader::mmap_fst(&p),
                    refresh::ListFst::Ram(b) => loader::ram_fst(b),
                };
                match map {
                    Ok(m) => maps.push(m),
                    // A cache file that vanished between fetch and merge is
                    // skipped this refresh, like any other per-list failure.
                    Err(e) => tracing::warn!("skipping list FST in merge: {}", e),
                }
            }
            if let Some(parent) = merged_path_owned.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            // Merged straight into the temporary file: the union streams out of the
            // page cache and into the disk, never existing as a second copy in RAM.
            let tmp = merged_path_owned.with_extension("fst.tmp");
            let (unique_count, ram_bytes) = match loader::merge_fsts_file(&maps, &tmp)? {
                loader::BuiltFst::File(count) => (count, None),
                loader::BuiltFst::Ram(bytes) => {
                    let count = Map::new(bytes.as_slice())
                        .map_err(|e| FeriteError::Fst(e.to_string()))?
                        .len();
                    (count, Some(bytes))
                }
            };
            let persisted =
                ram_bytes.is_none() && std::fs::rename(&tmp, &merged_path_owned).is_ok();
            let fst = if persisted {
                tracing::info!("merged FST saved to {}", merged_path_owned.display());
                // Serve from the mmap'd file: the merged map then sits in the
                // page cache (evictable) instead of RSS-pinned RAM.
                loader::mmap_fst(&merged_path_owned)
                    .or_else(|_| loader::merge_fsts(&maps).and_then(loader::ram_fst))?
            } else {
                // Either the merge never reached the disk, or the rename did not.
                let bytes = match ram_bytes {
                    Some(bytes) => bytes,
                    None => loader::merge_fsts(&maps)?,
                };
                let _ = std::fs::remove_file(&tmp);
                loader::ram_fst(bytes)?
            };
            // `persisted` says the rename landed, which is what the sidecar and
            // the profile shortcut key off: the file then *is* this merge, even
            // in the branch above where mapping it failed and we serve the RAM
            // copy instead. A reader that can't map it falls back the same way.
            Ok((fst, unique_count, persisted))
        })
        .await
        .map_err(|e| FeriteError::Internal(e.to_string()))??;

    match (persisted, fingerprint) {
        (true, Some(inputs)) => save_merged_meta(merged_path, &FstInputs { inputs }).await,
        // The file on disk isn't what we're serving, or we can't vouch for what
        // went into it — then no sidecar may claim otherwise.
        _ => {
            let _ = tokio::fs::remove_file(meta_path(merged_path)).await;
        }
    }

    Ok(ListSetRefresh {
        fst,
        counts,
        stats,
        unique_count,
        changed: true,
        persisted,
    })
}

/// Sidecar path for an FST: `blocklist.fst` → `blocklist.meta.json`.
pub(crate) fn meta_path(fst_path: &Path) -> PathBuf {
    fst_path.with_extension("meta.json")
}

async fn load_merged_meta(merged_path: &Path) -> Option<FstInputs> {
    let bytes = tokio::fs::read(meta_path(merged_path)).await.ok()?;
    serde_json::from_slice(&bytes).ok()
}

async fn save_merged_meta(merged_path: &Path, meta: &FstInputs) {
    let path = meta_path(merged_path);
    match serde_json::to_vec(meta) {
        Ok(bytes) => {
            if let Err(e) = tokio::fs::write(&path, bytes).await {
                tracing::warn!("could not write merged meta {}: {}", path.display(), e);
            }
        }
        Err(e) => tracing::warn!("could not serialise merged meta: {}", e),
    }
}

/// The merged FST on disk, plus the lists that went into it.
pub(crate) struct MergedSet {
    pub(crate) path: PathBuf,
    /// Sanitised names — the granularity the cache files, and the merge, use.
    names: BTreeSet<String>,
}

impl MergedSet {
    /// `true` when `lists` names exactly what the merged FST holds.
    pub(crate) fn covers(&self, lists: &[String]) -> bool {
        lists
            .iter()
            .map(|name| refresh::sanitize_name(name))
            .collect::<BTreeSet<String>>()
            == self.names
    }
}

/// Sanitised names of the enabled lists in `lists` — what a merge of them would
/// be recorded as.
fn enabled_list_names(lists: &[ListConfig]) -> BTreeSet<String> {
    lists
        .iter()
        .filter(|l| l.enabled)
        .map(|l| refresh::sanitize_name(&l.name))
        .collect()
}
