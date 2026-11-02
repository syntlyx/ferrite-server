//! Per-device blocking profiles: which subscription lists apply to a client,
//! its own allow/block overrides, and the merged FST compiled for it.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use regex::Regex;

use crate::cache::BlocklistCache;
use crate::engine::normalize_client_keys;
use crate::loader::{self, FstMap, empty_fst};
use crate::names::{domain_in_set, normalise, wildcard_to_regex};
use crate::refresh;
use crate::subscriptions::{FstInputs, MergedSet, meta_path};
use ferrite_core::schedule::Schedule;
use ferrite_core::services;

/// Decision-cache size for a per-device profile. Smaller than the global cache
/// (there are usually only a handful of profiles, each seeing one device's
/// traffic) so N profiles don't multiply the global figure.
const PROFILE_DECISION_CACHE: usize = 8_192;

/// A compiled per-device blocking profile: its own merged FST (a subset of the
/// subscription lists) plus a private decision cache. The manual black/whitelist
/// and `wildcard_block` are shared from the parent [`Blocklist`](crate::Blocklist), so a profile
/// only changes *which subscription lists* apply to its clients.
pub struct CompiledProfile {
    /// The profile's id, for reporting which profiles are on right now.
    pub(crate) id: String,
    /// When the profile applies; always, without windows.
    pub(crate) schedule: Schedule,
    /// Normalised client keys (IP/MAC) this profile applies to.
    pub(crate) clients: HashSet<String>,
    pub(crate) fst: FstMap,
    pub(crate) cache: BlocklistCache,
    /// Per-profile manual overrides (exact + wildcard), applied *before* the
    /// global rules for this profile's clients: `allow` beats everything
    /// (including a global block), `block` beats the global whitelist. The
    /// domains of the profile's catalog `services` are in `block_exact`.
    pub(crate) allow_exact: HashSet<String>,
    pub(crate) allow_wild: Vec<Regex>,
    pub(crate) block_exact: HashSet<String>,
    pub(crate) block_wild: Vec<Regex>,
    /// Merged FST of this profile's named allowlist subscriptions; `None` when
    /// the profile names none and inherits the global allow set.
    pub(crate) allow_fst: Option<FstMap>,
    /// Default-deny: block everything not explicitly allowed for this profile
    /// (except local-infrastructure names — see [`Blocklist::is_local_infra`](crate::Blocklist::is_local_infra)).
    pub(crate) default_deny: bool,
}

impl CompiledProfile {
    /// Does this profile apply to the querying client? Assumes the client keys
    /// are already normalised (the DNS hot path).
    pub(crate) fn matches_client(&self, client_ip: &str, mac: Option<&str>) -> bool {
        self.clients.contains(client_ip) || mac.is_some_and(|m| self.clients.contains(m))
    }

    /// Is the profile on at `minute` of the week (box-local)?
    pub(crate) fn active_at(&self, minute: u32) -> bool {
        self.schedule.is_active(minute)
    }

    /// Is `domain` explicitly allowed for this profile (exact/hierarchy or
    /// wildcard)? An allow overrides the global block and the profile's lists.
    pub(crate) fn allows(&self, domain: &str) -> bool {
        domain_in_set(domain, &self.allow_exact)
            || self.allow_wild.iter().any(|re| re.is_match(domain))
    }

    /// Is `domain` explicitly blocked for this profile (exact/hierarchy or
    /// wildcard)? A profile block overrides the global whitelist.
    pub(crate) fn blocks(&self, domain: &str) -> bool {
        domain_in_set(domain, &self.block_exact)
            || self.block_wild.iter().any(|re| re.is_match(domain))
    }
}

/// Split configured domain patterns into an exact set (matched with the
/// hierarchy walk) and compiled wildcard regexes, normalising each. Shared by
/// the profile allow/block compilation.
fn split_patterns(patterns: &[String]) -> (HashSet<String>, Vec<Regex>) {
    let mut exact = HashSet::new();
    let mut wild = Vec::new();
    for p in patterns {
        let norm = normalise(p);
        if norm.is_empty() {
            continue;
        }
        if norm.contains('*') {
            if let Ok(re) = wildcard_to_regex(&norm) {
                wild.push(re);
            }
        } else {
            exact.insert(norm);
        }
    }
    (exact, wild)
}

/// Compile every profile from its config and the per-list `.fst` caches on
/// disk. Free function taking owned-by-reference inputs so the (potentially
/// multi-second) FST merging can run on the blocking pool — see
/// [`Blocklist::rebuild_profiles_off_thread`](crate::Blocklist::rebuild_profiles_off_thread). The per-list FSTs are mmap'd,
/// so merges stream from the page cache and the compiled profile FSTs are
/// themselves mmap'd from `profile_<id>.fst` files (kept off anonymous RSS,
/// like the global FST).
///
/// With `stale_ok` (startup) a profile whose map can't be confirmed current is
/// served from the map the previous run left — see [`profile_map`]. The second
/// value says whether any profile got such a stand-in.
pub(crate) fn compile_profiles(
    configs: &[ferrite_core::config::BlocklistProfileConfig],
    list_cache_dir: &Path,
    allow_cache_dir: &Path,
    merged: Option<&MergedSet>,
    allow_merged: Option<&MergedSet>,
    stale_ok: bool,
) -> (Vec<Arc<CompiledProfile>>, bool) {
    let mut compiled: Vec<Arc<CompiledProfile>> = Vec::with_capacity(configs.len());
    let mut any_stale = false;
    for cfg in configs {
        let (fst, stale) = profile_map(merged, &cfg.id, &cfg.lists, list_cache_dir, stale_ok);
        any_stale |= stale;
        // Allowlist subset: named lists compile to the profile's own allow
        // FST; an empty selection means "inherit the global allow set"
        // (`None`), so existing profiles keep their exemptions.
        let allow_fst = if cfg.allowlists.is_empty() {
            None
        } else {
            let (fst, stale) = profile_map(
                allow_merged,
                &cfg.id,
                &cfg.allowlists,
                allow_cache_dir,
                stale_ok,
            );
            any_stale |= stale;
            Some(fst)
        };
        let clients: HashSet<String> = normalize_client_keys(&cfg.clients).into_iter().collect();
        let (allow_exact, allow_wild) = split_patterns(&cfg.allow);
        let (mut block_exact, block_wild) = split_patterns(&cfg.block);
        // Catalog services are this profile's block entries spelled by name.
        block_exact.extend(services::domains_of(&cfg.services).map(str::to_string));
        let schedule = Schedule::compile(&cfg.schedule).unwrap_or_else(|e| {
            tracing::error!(
                "profile '{}': {}; the profile stays off until its schedule is fixed",
                cfg.id,
                e
            );
            Schedule::never()
        });
        compiled.push(Arc::new(CompiledProfile {
            id: cfg.id.clone(),
            schedule,
            clients,
            fst,
            cache: BlocklistCache::new(PROFILE_DECISION_CACHE),
            allow_exact,
            allow_wild,
            block_exact,
            block_wild,
            allow_fst,
            default_deny: cfg.default_deny,
        }));
    }
    (compiled, any_stale)
}

/// The map a profile serves for `names`, and whether it is a stand-in.
///
/// At startup (`stale_ok`) a map the previous run left on disk is served as it
/// stands when its recorded inputs can't be confirmed — and after an upgrade
/// none can be, because list caches from another version are not trusted. The
/// alternative is the full merge, and startup runs it before DNS listens: on a
/// router with a million-domain profile that was fifteen seconds without DNS on
/// every restart. The stand-in is flagged; the next refresh compiles the real
/// map off the hot path.
fn profile_map(
    merged: Option<&MergedSet>,
    id: &str,
    names: &[String],
    cache_dir: &Path,
    stale_ok: bool,
) -> (FstMap, bool) {
    if let Some(map) = reuse_merged(merged, id, names, cache_dir) {
        return (map, false);
    }
    if stale_ok
        && !profile_cache_current(id, names, cache_dir)
        && let Ok(map) = loader::mmap_fst(&profile_fst_path(cache_dir, id))
    {
        tracing::info!(
            "profile '{}': serving the map from the last run until a refresh confirms it",
            id
        );
        return (map, true);
    }
    (
        build_profile_fst(id, names, cache_dir).unwrap_or_else(empty_fst),
        false,
    )
}

/// Does the profile's map on disk record exactly the inputs `names` have now?
fn profile_cache_current(id: &str, names: &[String], cache_dir: &Path) -> bool {
    let path = profile_fst_path(cache_dir, id);
    profile_fingerprint(cache_dir, names)
        .is_some_and(|inputs| load_fst_inputs(&path).is_some_and(|r| r.inputs == inputs))
}

/// A profile that selects exactly the merged set gets the merged FST itself:
/// mapping a file ferrite has already built, rather than spending the same
/// multi-second union on the same inputs to reproduce it. The common case is a
/// profile that simply narrows *who* a list applies to, not which lists.
fn reuse_merged(
    merged: Option<&MergedSet>,
    id: &str,
    lists: &[String],
    cache_dir: &Path,
) -> Option<FstMap> {
    let merged = merged.filter(|m| m.covers(lists))?;
    let fst = loader::mmap_fst(&merged.path).ok()?;
    // Whatever this profile compiled to before is now dead weight, and on an SD
    // card a duplicate of the whole blocklist is tens of megabytes.
    discard_profile_cache(&profile_fst_path(cache_dir, id));
    Some(fst)
}

/// Where a profile keeps its own merged map, when it needs one.
fn profile_fst_path(cache_dir: &Path, id: &str) -> PathBuf {
    cache_dir.join(format!("profile_{}.fst", refresh::sanitize_name(id)))
}

/// Drop a profile's own map and the sidecar describing it — whenever the profile
/// stops keeping one, or the file it should have kept never landed.
fn discard_profile_cache(path: &Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(meta_path(path));
}

/// Fingerprints of the lists `names` selects, as the profile's sidecar records
/// them. A list with no cached FST contributes nothing here, exactly as it
/// contributes nothing to the merge; a list whose FST can't be vouched for
/// yields `None`, which makes the caller merge rather than trust a match.
fn profile_fingerprint(cache_dir: &Path, names: &[String]) -> Option<Vec<(String, String)>> {
    let mut inputs = Vec::with_capacity(names.len());
    for name in names {
        let safe = refresh::sanitize_name(name);
        if !cache_dir.join(format!("{safe}.fst")).exists() {
            continue;
        }
        inputs.push((safe, refresh::list_digest(cache_dir, name)?));
    }
    inputs.sort();
    inputs.dedup();
    Some(inputs)
}

/// Read a sidecar written by [`save_fst_inputs`]. Synchronous: profile
/// compilation runs on the blocking pool and these files are tiny.
fn load_fst_inputs(fst_path: &Path) -> Option<FstInputs> {
    let bytes = std::fs::read(meta_path(fst_path)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn save_fst_inputs(fst_path: &Path, inputs: &[(String, String)]) {
    let path = meta_path(fst_path);
    let meta = FstInputs {
        inputs: inputs.to_vec(),
    };
    match serde_json::to_vec(&meta) {
        Ok(bytes) => {
            if let Err(e) = std::fs::write(&path, bytes) {
                tracing::warn!("could not write profile meta {}: {}", path.display(), e);
            }
        }
        Err(e) => tracing::warn!("could not serialise profile meta: {}", e),
    }
}

/// Merge a profile's per-list FSTs and mmap the result from a
/// `profile_<id>.fst` cache file under `cache_dir` (falling back to a RAM FST
/// if the write fails). Returns `None` when there's nothing to merge. Block
/// and allow subsets use distinct `cache_dir`s, so the cache file name can
/// stay the same for both.
///
/// The merge runs only when one of *this profile's* lists actually moved. Lists
/// churn at their own pace — one that rebuilds hourly would otherwise re-merge
/// every profile on the box, including the ones that never named it.
fn build_profile_fst(id: &str, names: &[String], cache_dir: &Path) -> Option<FstMap> {
    let path = profile_fst_path(cache_dir, id);
    let fingerprint = profile_fingerprint(cache_dir, names);

    if let Some(inputs) = &fingerprint
        && load_fst_inputs(&path).is_some_and(|recorded| recorded.inputs == *inputs)
        && let Ok(map) = loader::mmap_fst(&path)
    {
        return Some(map);
    }

    let maps = mmap_named_lists(cache_dir, id, names);
    // Nothing to merge, or a single list that is already its own map: either way
    // this profile keeps no file, so nothing on disk may claim it has one.
    if maps.len() < 2 {
        discard_profile_cache(&path);
        return maps.into_iter().next();
    }
    let tmp = path.with_extension("fst.tmp");
    let merged = loader::merge_fsts_file(&maps, &tmp)
        .map_err(|e| tracing::warn!("profile '{}': FST merge failed: {}", id, e))
        .ok()?;
    if let loader::BuiltFst::File(_) = merged
        && std::fs::rename(&tmp, &path).is_ok()
    {
        match &fingerprint {
            Some(inputs) => save_fst_inputs(&path, inputs),
            // Can't vouch for what went in, so nothing may claim to.
            None => {
                let _ = std::fs::remove_file(meta_path(&path));
            }
        }
        return loader::mmap_fst(&path).ok();
    }
    let _ = std::fs::remove_file(&tmp);
    // The map never reached the disk — whatever is there does not describe it.
    discard_profile_cache(&path);
    let bytes = match merged {
        loader::BuiltFst::Ram(bytes) => bytes,
        loader::BuiltFst::File(_) => loader::merge_fsts(&maps)
            .map_err(|e| tracing::warn!("profile '{}': FST merge failed: {}", id, e))
            .ok()?,
    };
    loader::ram_fst(bytes).ok()
}

/// mmap the per-list FSTs for `names` under `cache_dir`, skipping (with a debug
/// log) lists that have no cached FST yet. Shared by the block and allow subset
/// compilation in [`compile_profiles`].
fn mmap_named_lists(cache_dir: &Path, profile_id: &str, names: &[String]) -> Vec<FstMap> {
    let mut maps = Vec::new();
    for name in names {
        let path = cache_dir.join(format!("{}.fst", refresh::sanitize_name(name)));
        match loader::mmap_fst(&path) {
            Ok(m) => maps.push(m),
            Err(_) => tracing::debug!(
                "profile '{}': list '{}' has no cached FST yet, skipping",
                profile_id,
                name
            ),
        }
    }
    maps
}
