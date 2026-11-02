use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use arc_swap::ArcSwap;
use fst::Map;
use parking_lot::RwLock;
use regex::Regex;

use crate::cache::BlocklistCache;
use crate::loader::{self, FstMap, empty_fst};
use crate::names::{
    has_suffix, is_registrable_or_deeper, matched_key, normalise, wildcard_to_regex,
};
use crate::profiles::{CompiledProfile, compile_profiles};
use crate::{AdblockStats, ListPolarity, refresh};
use ferrite_core::config::{AllowlistConfig, BlocklistConfig, ListConfig};
use ferrite_core::error::{FeriteError, Result};
use ferrite_core::net::normalize_client_key;

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

/// A diagnostic explanation of why a domain is (or isn't) blocked — produced by
/// [`Blocklist::explain`] for the Tools UI. Built off the DNS hot path: it scans
/// each list's on-disk FST to attribute a match to its source list, which the
/// merged hot-path FST can't do.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BlockExplanation {
    pub domain: String,
    pub blocked: bool,
    pub whitelisted: bool,
    /// When whitelisted, the whitelist entry that exempted it (and where it matched).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub whitelist_match: Option<MatchInfo>,
    /// Every source that would block this domain (manual blacklist, wildcard
    /// rule, subscription list). Empty when nothing matches.
    pub sources: Vec<BlockSource>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MatchInfo {
    /// The configured entry that matched (exact key or wildcard pattern).
    pub entry: String,
    /// The label at which it matched: the domain itself or a parent of it.
    pub matched: String,
    /// When the exemption came from a subscribed allowlist, its name; `None`
    /// for manual allowlist entries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BlockSource {
    /// `"blacklist"` (manual exact), `"wildcard"` (manual or config wildcard), or
    /// `"list"` (a subscription).
    pub kind: String,
    /// Human label: the list name, `"manual blacklist"`, or the wildcard pattern.
    pub name: String,
    /// The key or pattern that produced the match (the domain or a matched parent).
    pub matched: String,
}

/// The hot-swappable core data: the merged subscription FST.
///
/// Manual block patterns are *not* here — they live in `blacklist` /
/// `blacklist_wildcards`, which the API can also remove from. Config-sourced
/// entries used to be compiled into a second, parallel wildcard set here, which
/// meant an entry written in the file could be matched but never listed or
/// deleted through the UI. One set, one lifecycle.
struct BlocklistData {
    fst: FstMap,
}

/// Thread-safe blocklist engine.
///
/// - FST map: atomically swappable, built from all enabled remote lists.
/// - Whitelist / blacklist: per-process overrides, take effect immediately.
/// - LRU decision cache: avoids re-querying the FST on every packet.
/// - Lists: the set of remote subscriptions, mutable at runtime.
pub struct Blocklist {
    enabled: AtomicBool,
    has_client_bypass: AtomicBool,
    has_profiles: AtomicBool,
    data: ArcSwap<BlocklistData>,
    /// Per-device profiles (each a subset-of-lists FST + private cache), compiled
    /// from `profiles_config` and the on-disk per-list FSTs. Rebuilt on refresh,
    /// on startup load, and when the profile set changes via the API.
    profiles: ArcSwap<Vec<Arc<CompiledProfile>>>,
    /// Source of truth for [`Self::rebuild_profiles`]; the compiled `profiles`
    /// above are derived from this plus the per-list disk caches.
    profiles_config: RwLock<Vec<ferrite_core::config::BlocklistProfileConfig>>,
    client_bypass: ArcSwap<HashSet<String>>,
    whitelist: RwLock<HashSet<String>>,
    /// Wildcard entries for the whitelist, e.g. `*.safe.example.com`.
    whitelist_wildcards: RwLock<Vec<(String, Regex)>>,
    blacklist: RwLock<HashSet<String>>,
    blacklist_wildcards: RwLock<Vec<(String, Regex)>>,
    cache: BlocklistCache,
    lists: RwLock<Vec<ListConfig>>,
    /// Domain count per list name, updated after each refresh.
    domain_counts: RwLock<HashMap<String, usize>>,
    /// Adblock parse breakdown per list name (only for Adblock-format lists),
    /// updated after each refresh. Explains the rules-vs-domains gap in the UI.
    adblock_stats: RwLock<HashMap<String, AdblockStats>>,
    /// Merged FST of all subscribed allowlists — the same decision tier as the
    /// manual whitelist, hot-swapped on refresh like `data`.
    allow_fst: ArcSwap<FstMap>,
    /// Remote allowlist subscriptions, mutable at runtime like `lists`.
    allow_lists: RwLock<Vec<ListConfig>>,
    /// Domain count per allowlist name, updated after each refresh.
    allow_domain_counts: RwLock<HashMap<String, usize>>,
    /// Adblock parse breakdown per allowlist name (Adblock-format lists only).
    allow_adblock_stats: RwLock<HashMap<String, AdblockStats>>,
    /// Configured `[[zones]]` suffixes (normalised), exempt from profile
    /// default-deny alongside the built-in local suffixes. Set once at startup
    /// via [`Self::set_local_zones`] (zones are restart-required config).
    local_zones: RwLock<Vec<String>>,
    /// Serialises [`Self::refresh`] so concurrent API-triggered refreshes don't
    /// race on `data`/`domain_counts` or pile up duplicate network fetches.
    refresh_lock: tokio::sync::Mutex<()>,
    fst_path: PathBuf,
    list_cache_dir: PathBuf,
    /// Merged allowlist FST on disk, sibling of `fst_path` (`allowlist.fst`).
    allow_fst_path: PathBuf,
    /// Per-allowlist cache dir, separate from `list_cache_dir` so a blocklist
    /// and an allowlist with the same name can't collide on a cache file.
    allow_cache_dir: PathBuf,
    /// `true` while the merged FST being served *is* the mmap of `fst_path`.
    /// Then a profile whose lists are exactly the enabled set can map that same
    /// file instead of merging the very same inputs a second time.
    merged_on_disk: AtomicBool,
    /// The allowlist half of `merged_on_disk`.
    allow_merged_on_disk: AtomicBool,
}

impl Blocklist {
    pub fn new(config: BlocklistConfig, allowlist: AllowlistConfig, fst_path: PathBuf) -> Self {
        let empty = empty_fst();

        let client_bypass: HashSet<String> = normalize_client_keys(&config.client_bypass)
            .into_iter()
            .collect();

        // Manual allowlist entries. `config.whitelist` is the deprecated
        // location — `Config::normalize` migrates it, but seed from both so a
        // directly-constructed BlocklistConfig keeps its old semantics.
        let manual_allow = || config.whitelist.iter().chain(allowlist.domains.iter());

        let whitelist: HashSet<String> = manual_allow()
            .filter(|s| !s.contains('*'))
            .map(|s| normalise(s))
            .collect();

        let whitelist_wildcards: Vec<(String, Regex)> = manual_allow()
            .filter(|s| s.contains('*'))
            .filter_map(|s| {
                let norm = normalise(s);
                wildcard_to_regex(&norm).ok().map(|re| (norm, re))
            })
            .collect();

        // Manual block entries. `config.wildcard_block` is the deprecated
        // location — `Config::normalize` migrates it into `domains`, but seed
        // from both so a directly-constructed BlocklistConfig keeps working.
        let manual_block = || config.domains.iter().chain(config.wildcard_block.iter());

        let blacklist: HashSet<String> = manual_block()
            .filter(|s| !s.contains('*'))
            .map(|s| normalise(s))
            .collect();

        let blacklist_wildcards: Vec<(String, Regex)> = manual_block()
            .filter(|s| s.contains('*'))
            .filter_map(|s| {
                let norm = normalise(s);
                wildcard_to_regex(&norm)
                    .map_err(|e| tracing::warn!("skipping invalid wildcard '{}': {}", s, e))
                    .ok()
                    .map(|re| (norm, re))
            })
            .collect();

        let list_cache_dir = fst_path
            .parent()
            .map(|p| p.join("lists"))
            .unwrap_or_else(|| PathBuf::from("lists"));
        let allow_cache_dir = fst_path
            .parent()
            .map(|p| p.join("allowlists"))
            .unwrap_or_else(|| PathBuf::from("allowlists"));
        let allow_fst_path = fst_path
            .parent()
            .map(|p| p.join("allowlist.fst"))
            .unwrap_or_else(|| PathBuf::from("allowlist.fst"));

        Self {
            enabled: AtomicBool::new(config.enabled),
            has_client_bypass: AtomicBool::new(!client_bypass.is_empty()),
            has_profiles: AtomicBool::new(!config.profiles.is_empty()),
            data: ArcSwap::from_pointee(BlocklistData { fst: empty }),
            profiles: ArcSwap::from_pointee(Vec::new()),
            profiles_config: RwLock::new(config.profiles),
            client_bypass: ArcSwap::from_pointee(client_bypass),
            whitelist: RwLock::new(whitelist),
            whitelist_wildcards: RwLock::new(whitelist_wildcards),
            blacklist: RwLock::new(blacklist),
            blacklist_wildcards: RwLock::new(blacklist_wildcards),
            cache: BlocklistCache::new(config.decision_cache_size),
            lists: RwLock::new(config.lists),
            domain_counts: RwLock::new(HashMap::new()),
            adblock_stats: RwLock::new(HashMap::new()),
            allow_fst: ArcSwap::from_pointee(empty_fst()),
            allow_lists: RwLock::new(allowlist.lists),
            allow_domain_counts: RwLock::new(HashMap::new()),
            allow_adblock_stats: RwLock::new(HashMap::new()),
            local_zones: RwLock::new(Vec::new()),
            refresh_lock: tokio::sync::Mutex::new(()),
            fst_path,
            list_cache_dir,
            allow_fst_path,
            allow_cache_dir,
            merged_on_disk: AtomicBool::new(false),
            allow_merged_on_disk: AtomicBool::new(false),
        }
    }

    /// Try to load the previously saved FSTs from disk. Serves them via mmap so
    /// the (potentially tens-of-MB) maps live in the page cache, not anonymous
    /// RSS. Returns `false` when anything that should be cached is missing or
    /// invalid — the caller then runs a refresh, which reuses whatever per-list
    /// caches are still fresh.
    pub fn load_from_disk(&self) -> bool {
        if !self.fst_path.exists() {
            return false; // first boot — nothing cached yet
        }
        match loader::mmap_fst(&self.fst_path) {
            Ok(fst) => {
                let count = fst.len();
                self.data.store(Arc::new(BlocklistData { fst }));
                self.merged_on_disk.store(true, Ordering::Relaxed);
                self.cache.clear();
                self.restore_list_stats_from_cache();
                // Settled before the profiles compile: both merged FSTs are then
                // known to be the files on disk, which is what lets a profile
                // covering every list map one instead of rebuilding it.
                let allow_ok = self.load_allow_from_disk();
                // Per-list FSTs are on disk too, so profiles can compile now
                // (before any network refresh) — a restart keeps device profiles
                // working immediately, like the global list.
                self.rebuild_profiles();
                tracing::info!("blocklist loaded from disk: {} domains", count);
                allow_ok
            }
            Err(e) => {
                tracing::warn!("cached FST on disk is invalid, will re-fetch: {}", e);
                false
            }
        }
    }

    /// Allowlist counterpart of the merged-FST load above. `true` when the
    /// subscribed-allowlist state needs no refresh: either no allowlists are
    /// configured, or the merged `allowlist.fst` loaded cleanly. `false` (e.g.
    /// first boot after allowlists were added to the config) makes
    /// [`Self::load_from_disk`] report a miss so startup triggers a refresh —
    /// which is cheap for the blocklists, whose per-list caches are still fresh.
    fn load_allow_from_disk(&self) -> bool {
        let configured = !self.allow_lists.read().is_empty();
        if !self.allow_fst_path.exists() {
            return !configured;
        }
        match loader::mmap_fst(&self.allow_fst_path) {
            Ok(fst) => {
                let count = fst.len();
                self.allow_fst.store(Arc::new(fst));
                self.allow_merged_on_disk.store(true, Ordering::Relaxed);
                self.restore_allow_stats_from_cache();
                if configured || count > 0 {
                    tracing::info!("allowlist loaded from disk: {} domains", count);
                }
                true
            }
            Err(e) => {
                tracing::warn!(
                    "cached allowlist FST on disk is invalid, will re-fetch: {}",
                    e
                );
                !configured
            }
        }
    }

    /// Restore per-list domain counts and Adblock parse stats from the on-disk
    /// caches the last refresh wrote (`<list>.fst` / `<list>.stats.json` under the
    /// list cache dir). `load_from_disk` only loads the merged FST, so without this
    /// the Lists page would show blank counts/stats after a restart until the next
    /// refresh repopulated them over the network. Read-only and synchronous —
    /// missing/garbage caches are simply skipped, and a later refresh overwrites
    /// these with authoritative values.
    fn restore_list_stats_from_cache(&self) {
        let lists: Vec<ListConfig> = self.lists.read().iter().cloned().collect();
        let mut counts: HashMap<String, usize> = HashMap::new();
        let mut stats: HashMap<String, AdblockStats> = HashMap::new();
        for list in &lists {
            let safe = refresh::sanitize_name(&list.name);
            // Count = entries in the per-list FST (exactly what a refresh records).
            if let Ok(map) = loader::mmap_fst(&self.list_cache_dir.join(format!("{safe}.fst"))) {
                counts.insert(list.name.clone(), map.len());
            }
            if let Ok(bytes) = std::fs::read(self.list_cache_dir.join(format!("{safe}.stats.json")))
                && let Ok(s) = serde_json::from_slice::<AdblockStats>(&bytes)
            {
                stats.insert(list.name.clone(), s);
            }
        }
        if !counts.is_empty() {
            *self.domain_counts.write() = counts;
        }
        if !stats.is_empty() {
            *self.adblock_stats.write() = stats;
        }
    }

    /// Allowlist counterpart of [`Self::restore_list_stats_from_cache`].
    fn restore_allow_stats_from_cache(&self) {
        let lists: Vec<ListConfig> = self.allow_lists.read().iter().cloned().collect();
        let mut counts: HashMap<String, usize> = HashMap::new();
        let mut stats: HashMap<String, AdblockStats> = HashMap::new();
        for list in &lists {
            let safe = refresh::sanitize_name(&list.name);
            if let Ok(map) = loader::mmap_fst(&self.allow_cache_dir.join(format!("{safe}.fst"))) {
                counts.insert(list.name.clone(), map.len());
            }
            if let Ok(bytes) =
                std::fs::read(self.allow_cache_dir.join(format!("{safe}.stats.json")))
                && let Ok(s) = serde_json::from_slice::<AdblockStats>(&bytes)
            {
                stats.insert(list.name.clone(), s);
            }
        }
        if !counts.is_empty() {
            *self.allow_domain_counts.write() = counts;
        }
        if !stats.is_empty() {
            *self.allow_adblock_stats.write() = stats;
        }
    }

    // ── Blocking checks ──────────────────────────────────────────────────────

    pub fn blocking_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn set_blocking_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn has_client_bypass(&self) -> bool {
        self.has_client_bypass.load(Ordering::Relaxed)
    }

    pub fn set_client_bypass(&self, entries: &[String]) {
        let normalized: HashSet<String> = normalize_client_keys(entries).into_iter().collect();
        let has_entries = !normalized.is_empty();
        self.client_bypass.store(Arc::new(normalized));
        self.has_client_bypass.store(has_entries, Ordering::Relaxed);
    }

    pub fn client_bypasses_blocking(&self, client_ip: &str, mac: Option<&str>) -> bool {
        if !self.has_client_bypass() {
            return false;
        }

        let entries = self.client_bypass.load();
        normalize_client_key(client_ip)
            .as_ref()
            .is_some_and(|key| entries.contains(key))
            || mac
                .and_then(normalize_client_key)
                .as_ref()
                .is_some_and(|key| entries.contains(key))
    }

    pub fn client_bypasses_blocking_normalized(&self, client_ip: &str, mac: Option<&str>) -> bool {
        if !self.has_client_bypass() {
            return false;
        }

        let entries = self.client_bypass.load();
        entries.contains(client_ip) || mac.is_some_and(|key| entries.contains(key))
    }

    /// Convenience wrapper that normalises first. The DNS hot path uses
    /// [`Self::is_blocked_normalized`]; the diagnostic API uses [`Self::explain`].
    /// Kept as a test helper.
    #[cfg(test)]
    pub fn is_blocked(&self, domain: &str) -> bool {
        let domain = normalise(domain);
        self.is_blocked_normalized(&domain)
    }

    /// Like [`Self::is_blocked`], but assumes `domain` is already lowercase
    /// and has no trailing root dot. Used by the DNS hot path.
    pub fn is_blocked_normalized(&self, domain: &str) -> bool {
        if let Some(cached) = self.cache.get(domain) {
            return cached;
        }
        let data = self.data.load();
        let result = self.check_blocked_in(domain, &data.fst);
        self.cache.insert(domain, result);
        result
    }

    /// Profile-aware block check for the DNS hot path. With `profile == None`
    /// this is exactly [`Self::is_blocked_normalized`] (the default, all-lists
    /// FST). With a profile it uses that profile's subset FST + private cache;
    /// the manual blacklist still applies (it is global).
    pub fn is_blocked_for_normalized(
        &self,
        domain: &str,
        profile: Option<&CompiledProfile>,
    ) -> bool {
        let Some(profile) = profile else {
            return self.is_blocked_normalized(domain);
        };
        if let Some(cached) = profile.cache.get(domain) {
            return cached;
        }
        // Only the subscription FST differs; the manual sets are global and
        // `check_blocked_in` reads them itself.
        let result = self.check_blocked_in(domain, &profile.fst);
        profile.cache.insert(domain, result);
        result
    }

    /// Is `domain` *explicitly* allowed for this client — a global whitelist
    /// entry or a profile allow? (Not the same as "not blocked": an ordinary
    /// unlisted domain is neither blocked nor explicitly allowed.) Used to decide
    /// whether to trust a CNAME chain wholesale.
    pub fn is_allowed_for(&self, domain: &str, profile: Option<&CompiledProfile>) -> bool {
        if let Some(p) = profile
            && p.allows(domain)
        {
            return true;
        }
        self.is_whitelisted_for_normalized(domain, profile)
    }

    /// The full block decision for the DNS hot path, including the global
    /// whitelist and any per-device profile overrides. Precedence, most-specific
    /// first:
    ///   1. profile `allow`  → allowed (overrides the global block AND the
    ///      profile's own lists — "let this device reach it no matter what"),
    ///   2. profile `block`  → blocked (overrides the global whitelist),
    ///   3. whitelist tier   → allowed: manual `[allowlist] domains` plus the
    ///      profile's allowlist subscriptions (or the global set when the
    ///      profile names none),
    ///   4. profile `default_deny` → blocked, except local-infrastructure names
    ///      ([`Self::is_local_infra`]) which fall through,
    ///   5. global blacklist (exact + wildcard) + the profile's (or global)
    ///      subscription FST → blocked,
    ///   6. otherwise allowed.
    ///
    /// The FST layer (step 5) is the cached part ([`Self::is_blocked_for_normalized`]);
    /// the override and whitelist checks around it are cheap set/regex lookups, so
    /// they run uncached on top.
    pub fn should_block_for(&self, domain: &str, profile: Option<&CompiledProfile>) -> bool {
        if let Some(p) = profile {
            if p.allows(domain) {
                return false;
            }
            if p.blocks(domain) {
                return true;
            }
        }
        if self.is_whitelisted_for_normalized(domain, profile) {
            return false;
        }
        // Default-deny: everything past the allow tiers is blocked. Local
        // infrastructure names fall through to the normal block sources
        // instead of being outright allowed, so a blacklisted local name
        // still blocks.
        if let Some(p) = profile
            && p.default_deny
            && !self.is_local_infra(domain)
        {
            return true;
        }
        self.is_blocked_for_normalized(domain, profile)
    }

    /// Names a default-deny profile must not touch: bare hostnames (no dot),
    /// reverse DNS and special-use local suffixes, and the configured
    /// `[[zones]]` suffixes. These resolve normally — and stay subject to the
    /// regular block sources — so LAN plumbing (PTR lookups, mDNS names,
    /// router zones) keeps working without any per-profile configuration.
    fn is_local_infra(&self, domain: &str) -> bool {
        if !domain.contains('.') {
            return true;
        }
        const LOCAL_SUFFIXES: &[&str] = &[
            "arpa",        // in-addr.arpa / ip6.arpa PTR + home.arpa (RFC 8375)
            "local",       // mDNS (RFC 6762)
            "localhost",   // RFC 6761
            "localdomain", // common resolver default
            "internal",    // ICANN-reserved private-use TLD
            "lan",         // common router default
            "home",        // common router default
        ];
        if LOCAL_SUFFIXES.iter().any(|s| has_suffix(domain, s)) {
            return true;
        }
        self.local_zones
            .read()
            .iter()
            .any(|z| has_suffix(domain, z))
    }

    /// Register the configured `[[zones]]` suffixes as default-deny-exempt
    /// local infrastructure. Called once at startup (zones are restart-required
    /// config); names are normalised like query names.
    pub fn set_local_zones(&self, zones: &[String]) {
        *self.local_zones.write() = zones.iter().map(|z| normalise(z)).collect();
    }

    /// The core block decision against a specific subscription FST. The manual
    /// blacklist (exact + wildcard) is always consulted first — it is global and
    /// overrides every profile — then the given FST with the hierarchy walk.
    /// Shared by the default path and every profile so their semantics can't
    /// drift.
    fn check_blocked_in(&self, domain: &str, fst: &FstMap) -> bool {
        {
            // Manual blacklist: exact match, then walk up the hierarchy so a
            // blacklist entry for `evil.com` also blocks `www.evil.com` —
            // symmetric with the FST walk below and the whitelist walk.
            let blacklist = self.blacklist.read();
            if blacklist.contains(domain) {
                return true;
            }
            let mut rest = domain;
            while let Some(dot) = rest.find('.') {
                rest = &rest[dot + 1..];
                if blacklist.contains(rest) && is_registrable_or_deeper(rest) {
                    return true;
                }
            }
        }
        if self
            .blacklist_wildcards
            .read()
            .iter()
            .any(|(_, re)| re.is_match(domain))
        {
            return true;
        }

        if fst.contains_key(domain.as_bytes()) {
            return true;
        }

        // Walk up the domain hierarchy: `www.evil.com` → check `evil.com`.
        // The public-suffix guard stops the walk at the registrable-domain
        // boundary so an entry for a multi-label suffix (e.g. `co.uk`) cannot
        // over-match every domain under that ccTLD.
        let mut rest = domain;
        while let Some(dot) = rest.find('.') {
            rest = &rest[dot + 1..];
            if fst.contains_key(rest.as_bytes()) && is_registrable_or_deeper(rest) {
                return true;
            }
        }
        false
    }

    // ── Per-device profiles ────────────────────────────────────────────────

    pub fn has_profiles(&self) -> bool {
        self.has_profiles.load(Ordering::Relaxed)
    }

    /// The profile that applies to this client, if any. Assumes `client_ip`/`mac`
    /// are already normalised (DNS hot path). First match wins (config order).
    pub fn profile_for(&self, client_ip: &str, mac: Option<&str>) -> Option<Arc<CompiledProfile>> {
        if !self.has_profiles() {
            return None;
        }
        self.profiles
            .load()
            .iter()
            .find(|p| p.matches_client(client_ip, mac))
            .cloned()
    }

    /// Replace the profile set and rebuild their FSTs from the on-disk per-list
    /// caches. Used by the API after a config change; persists nothing itself.
    pub fn set_profiles(&self, profiles: Vec<ferrite_core::config::BlocklistProfileConfig>) {
        self.has_profiles
            .store(!profiles.is_empty(), Ordering::Relaxed);
        *self.profiles_config.write() = profiles;
        self.rebuild_profiles();
    }

    /// Current profile configs (for the API to echo back / persist).
    pub fn get_profiles(&self) -> Vec<ferrite_core::config::BlocklistProfileConfig> {
        self.profiles_config.read().clone()
    }

    /// (Re)compile every profile's merged FST from the per-list `.fst` files the
    /// last refresh wrote, synchronously on the calling thread. A multi-list
    /// profile over big lists is a multi-second CPU+IO job — from async
    /// contexts use [`Self::rebuild_profiles_off_thread`] instead; this sync
    /// form is for startup ([`Self::load_from_disk`]) and tests.
    pub fn rebuild_profiles(&self) {
        let configs = self.profiles_config.read().clone();
        let compiled = compile_profiles(
            &configs,
            &self.list_cache_dir,
            &self.allow_cache_dir,
            self.merged_set().as_ref(),
            self.allow_merged_set().as_ref(),
        );
        self.profiles.store(Arc::new(compiled));
        if !configs.is_empty() {
            tracing::info!("blocklist: rebuilt {} profile(s)", configs.len());
        }
    }

    /// Like [`Self::rebuild_profiles`], but the FST merging runs on the
    /// blocking pool so a runtime worker (and whoever awaits us — the refresh
    /// path or an API handler) isn't stalled for seconds by a large profile.
    /// On a join error the previous compiled set stays in place.
    pub async fn rebuild_profiles_off_thread(&self) {
        let configs = self.profiles_config.read().clone();
        let list_dir = self.list_cache_dir.clone();
        let allow_dir = self.allow_cache_dir.clone();
        let merged = self.merged_set();
        let allow_merged = self.allow_merged_set();
        let compiled = tokio::task::spawn_blocking(move || {
            compile_profiles(
                &configs,
                &list_dir,
                &allow_dir,
                merged.as_ref(),
                allow_merged.as_ref(),
            )
        })
        .await;
        match compiled {
            Ok(compiled) => {
                let count = compiled.len();
                self.profiles.store(Arc::new(compiled));
                if count > 0 {
                    tracing::info!("blocklist: rebuilt {} profile(s)", count);
                }
            }
            Err(e) => tracing::error!("profile rebuild task panicked, keeping previous set: {}", e),
        }
    }

    /// The merged block FST as an input for profile compilation — `None` unless
    /// the file on disk is the map currently being served.
    fn merged_set(&self) -> Option<MergedSet> {
        self.merged_on_disk
            .load(Ordering::Relaxed)
            .then(|| MergedSet {
                path: self.fst_path.clone(),
                names: enabled_list_names(&self.lists.read()),
            })
    }

    /// Allowlist counterpart of [`Self::merged_set`].
    fn allow_merged_set(&self) -> Option<MergedSet> {
        self.allow_merged_on_disk
            .load(Ordering::Relaxed)
            .then(|| MergedSet {
                path: self.allow_fst_path.clone(),
                names: enabled_list_names(&self.allow_lists.read()),
            })
    }

    /// Returns `true` if `domain` is explicitly whitelisted (exact or wildcard
    /// match). Convenience wrapper that normalises first; the hot path uses
    /// [`Self::is_whitelisted_normalized`]. Kept as a test helper.
    #[cfg(any(test, feature = "testutil"))]
    pub fn is_whitelisted(&self, domain: &str) -> bool {
        let domain = normalise(domain);
        self.is_whitelisted_normalized(&domain)
    }

    /// Global-tier wrapper around [`Self::is_whitelisted_for_normalized`].
    /// Production callers are profile-aware; kept as a test helper.
    #[cfg(any(test, feature = "testutil"))]
    pub fn is_whitelisted_normalized(&self, domain: &str) -> bool {
        self.is_whitelisted_for_normalized(domain, None)
    }

    /// Profile-aware whitelist tier, assuming `domain` is already lowercase
    /// with no trailing root dot (the DNS hot path): the manual entries
    /// (always global, like the manual blacklist) plus the subscribed
    /// allowlists — the profile's named subset when it has one, else the
    /// global merged set.
    ///
    /// Matching walks up the domain hierarchy so that whitelisting `example.com`
    /// also exempts `www.example.com`, mirroring how [`Self::check_blocked_in`]
    /// matches a blocked parent against its subdomains. Without this the two
    /// checks are asymmetric: a blocklist entry for `example.com` blocks every
    /// subdomain, but a whitelist entry for `example.com` would only exempt the
    /// exact name — so a whitelisted domain's subdomains would stay blocked.
    pub fn is_whitelisted_for_normalized(
        &self,
        domain: &str,
        profile: Option<&CompiledProfile>,
    ) -> bool {
        {
            let whitelist = self.whitelist.read();
            if whitelist.contains(domain) {
                return true;
            }
            // Walk up the hierarchy: `www.example.com` → check `example.com`.
            // The public-suffix guard stops the walk at the registrable-domain
            // boundary, matching the guard in `check_blocked` (so whitelisting a
            // multi-label suffix like `co.uk` doesn't exempt an entire ccTLD).
            let mut rest = domain;
            while let Some(dot) = rest.find('.') {
                rest = &rest[dot + 1..];
                // Set lookup before the public-suffix guard: both must hold, and
                // this one is a hash (free on the empty set every unconfigured
                // install has) where the guard is a trie walk. This runs
                // uncached on every single query, unlike the FST tier below it.
                if whitelist.contains(rest) && is_registrable_or_deeper(rest) {
                    return true;
                }
            }
        }
        if self
            .whitelist_wildcards
            .read()
            .iter()
            .any(|(_, re)| re.is_match(domain))
        {
            return true;
        }
        // Subscribed allowlists: same exact + hierarchy walk against the merged
        // allow FST (mmap'd, so this is a page-cache probe, not a RAM scan).
        match profile.and_then(|p| p.allow_fst.as_ref()) {
            Some(fst) => matched_key(domain, |k| fst.contains_key(k.as_bytes())).is_some(),
            None => {
                let allow = self.allow_fst.load();
                !allow.is_empty()
                    && matched_key(domain, |k| allow.contains_key(k.as_bytes())).is_some()
            }
        }
    }

    /// Off-hot-path explanation of why `domain` is or isn't blocked, attributing
    /// each match to its source. Scans every enabled list's on-disk FST, so it is
    /// slower than [`Self::is_blocked`] — call it only from the diagnostic API,
    /// never the DNS path.
    pub fn explain(&self, domain: &str) -> BlockExplanation {
        let domain = normalise(domain);

        let whitelist_match = self.whitelist_match(&domain);
        let whitelisted = whitelist_match.is_some();

        let mut sources = Vec::new();

        // Manual blacklist (exact + hierarchy walk).
        {
            let blacklist = self.blacklist.read();
            if let Some(key) = matched_key(&domain, |k| blacklist.contains(k)) {
                sources.push(BlockSource {
                    kind: "blacklist".into(),
                    name: "manual blacklist".into(),
                    matched: key,
                });
            }
        }
        // Manual blacklist wildcards.
        for (pat, re) in self.blacklist_wildcards.read().iter() {
            if re.is_match(&domain) {
                sources.push(BlockSource {
                    kind: "wildcard".into(),
                    name: pat.clone(),
                    matched: domain.clone(),
                });
            }
        }
        // Subscription lists: scan each enabled list's own on-disk FST so the
        // match attributes to a specific list (the merged hot-path FST can't).
        let lists = self.lists.read().clone();
        let mut list_matched = false;
        for list in lists.iter().filter(|l| l.enabled) {
            let path = self
                .list_cache_dir
                .join(format!("{}.fst", refresh::sanitize_name(&list.name)));
            let Ok(map) = loader::mmap_fst(&path) else {
                continue;
            };
            if let Some(key) = matched_key(&domain, |k| map.contains_key(k.as_bytes())) {
                list_matched = true;
                sources.push(BlockSource {
                    kind: "list".into(),
                    name: list.name.clone(),
                    matched: key,
                });
            }
        }
        // Fallback: the merged FST matches but no per-list file attributed it
        // (e.g. a source file is missing) — still report the block.
        if !list_matched
            && let Some(key) =
                matched_key(&domain, |k| self.data.load().fst.contains_key(k.as_bytes()))
        {
            sources.push(BlockSource {
                kind: "list".into(),
                name: "subscription (source file unavailable)".into(),
                matched: key,
            });
        }

        let blocked = !whitelisted && !sources.is_empty();
        BlockExplanation {
            domain,
            blocked,
            whitelisted,
            whitelist_match,
            sources,
        }
    }

    /// The whitelist entry that exempts `domain`, if any (manual exact/hierarchy,
    /// manual wildcard, then subscribed allowlists) — mirrors
    /// [`Self::is_whitelisted_normalized`]. A subscription match is attributed to
    /// its source allowlist by scanning each enabled list's own on-disk FST (the
    /// merged hot-path FST can't), like the block-source attribution in
    /// [`Self::explain`].
    fn whitelist_match(&self, domain: &str) -> Option<MatchInfo> {
        {
            let whitelist = self.whitelist.read();
            if let Some(key) = matched_key(domain, |k| whitelist.contains(k)) {
                return Some(MatchInfo {
                    entry: key.clone(),
                    matched: key,
                    list: None,
                });
            }
        }
        for (pat, re) in self.whitelist_wildcards.read().iter() {
            if re.is_match(domain) {
                return Some(MatchInfo {
                    entry: pat.clone(),
                    matched: domain.to_string(),
                    list: None,
                });
            }
        }
        let allow_lists = self.allow_lists.read().clone();
        for list in allow_lists.iter().filter(|l| l.enabled) {
            let path = self
                .allow_cache_dir
                .join(format!("{}.fst", refresh::sanitize_name(&list.name)));
            let Ok(map) = loader::mmap_fst(&path) else {
                continue;
            };
            if let Some(key) = matched_key(domain, |k| map.contains_key(k.as_bytes())) {
                return Some(MatchInfo {
                    entry: key.clone(),
                    matched: key,
                    list: Some(list.name.clone()),
                });
            }
        }
        // Fallback: the merged allow FST matches but no per-list file attributed
        // it (e.g. a source file is missing) — still report the exemption.
        let allow = self.allow_fst.load();
        if let Some(key) = matched_key(domain, |k| allow.contains_key(k.as_bytes())) {
            return Some(MatchInfo {
                entry: key.clone(),
                matched: key,
                list: Some("allowlist subscription (source file unavailable)".into()),
            });
        }
        None
    }

    // ── Whitelist / blacklist CRUD ───────────────────────────────────────────

    /// Clear every decision cache: the global one AND each profile's private
    /// cache. Manual black/whitelist entries are global (they apply inside
    /// every profile's `check_blocked_in`), so a mutation must also drop the
    /// per-profile caches — otherwise a profiled client keeps serving the
    /// stale decision for up to the cache TTL.
    fn clear_decision_caches(&self) {
        self.cache.clear();
        for p in self.profiles.load().iter() {
            p.cache.clear();
        }
    }

    pub fn add_whitelist(&self, domain: &str) -> Result<()> {
        let d = normalise(domain);
        if d.contains('*') {
            let re = wildcard_to_regex(&d)?;
            self.whitelist_wildcards.write().push((d, re));
        } else {
            self.whitelist.write().insert(d);
        }
        // A whitelist/blacklist entry now matches subdomains via the hierarchy
        // walk, so an exact-key invalidation can't cover the cached block/allow
        // decisions it affects — clear the whole decision cache.
        self.clear_decision_caches();
        Ok(())
    }

    pub fn remove_whitelist(&self, domain: &str) {
        let d = normalise(domain);
        if d.contains('*') {
            self.whitelist_wildcards
                .write()
                .retain(|(pat, _)| pat != &d);
        } else {
            self.whitelist.write().remove(&d);
        }
        self.clear_decision_caches();
    }

    pub fn add_blacklist(&self, domain: &str) -> Result<()> {
        let d = normalise(domain);
        if d.contains('*') {
            let re = wildcard_to_regex(&d)?;
            self.blacklist_wildcards.write().push((d, re));
        } else {
            self.blacklist.write().insert(d);
        }
        self.clear_decision_caches();
        Ok(())
    }

    pub fn remove_blacklist(&self, domain: &str) {
        let d = normalise(domain);
        if d.contains('*') {
            self.blacklist_wildcards
                .write()
                .retain(|(pat, _)| pat != &d);
        } else {
            self.blacklist.write().remove(&d);
        }
        self.clear_decision_caches();
    }

    pub fn list_whitelist(&self) -> Vec<String> {
        let mut result: Vec<String> = self.whitelist.read().iter().cloned().collect();
        result.extend(
            self.whitelist_wildcards
                .read()
                .iter()
                .map(|(p, _)| p.clone()),
        );
        result
    }

    pub fn list_blacklist(&self) -> Vec<String> {
        let mut result: Vec<String> = self.blacklist.read().iter().cloned().collect();
        result.extend(
            self.blacklist_wildcards
                .read()
                .iter()
                .map(|(p, _)| p.clone()),
        );
        result
    }

    // ── Subscription list management ─────────────────────────────────────────

    pub fn get_lists(&self) -> Vec<ListConfig> {
        self.lists.read().clone()
    }

    pub fn domain_count(&self, name: &str) -> Option<usize> {
        self.domain_counts.read().get(name).copied()
    }

    /// Adblock parse breakdown for `name`, if it is an Adblock-format list and
    /// has been refreshed at least once. `None` for hosts/plain lists.
    pub fn parse_stats(&self, name: &str) -> Option<AdblockStats> {
        self.adblock_stats.read().get(name).copied()
    }

    pub fn add_list(&self, cfg: ListConfig) -> Result<()> {
        let mut lists = self.lists.write();
        if lists.iter().any(|l| l.name == cfg.name) {
            return Err(FeriteError::Config(format!(
                "list '{}' already exists",
                cfg.name
            )));
        }
        lists.push(cfg);
        Ok(())
    }

    pub fn remove_list(&self, name: &str) -> bool {
        let mut lists = self.lists.write();
        let before = lists.len();
        lists.retain(|l| l.name != name);
        lists.len() < before
    }

    pub fn set_list_enabled(&self, name: &str, enabled: bool) -> bool {
        let mut lists = self.lists.write();
        if let Some(l) = lists.iter_mut().find(|l| l.name == name) {
            l.enabled = enabled;
            true
        } else {
            false
        }
    }

    // ── Allowlist subscription management ────────────────────────────────────

    pub fn get_allow_lists(&self) -> Vec<ListConfig> {
        self.allow_lists.read().clone()
    }

    pub fn allow_domain_count(&self, name: &str) -> Option<usize> {
        self.allow_domain_counts.read().get(name).copied()
    }

    /// Adblock parse breakdown for allowlist `name` (Adblock-format lists only —
    /// there `kept` counts the `@@` exception domains harvested as allows).
    pub fn allow_parse_stats(&self, name: &str) -> Option<AdblockStats> {
        self.allow_adblock_stats.read().get(name).copied()
    }

    pub fn add_allow_list(&self, cfg: ListConfig) -> Result<()> {
        let mut lists = self.allow_lists.write();
        if lists.iter().any(|l| l.name == cfg.name) {
            return Err(FeriteError::Config(format!(
                "allowlist '{}' already exists",
                cfg.name
            )));
        }
        lists.push(cfg);
        Ok(())
    }

    pub fn remove_allow_list(&self, name: &str) -> bool {
        let mut lists = self.allow_lists.write();
        let before = lists.len();
        lists.retain(|l| l.name != name);
        lists.len() < before
    }

    pub fn set_allow_list_enabled(&self, name: &str, enabled: bool) -> bool {
        let mut lists = self.allow_lists.write();
        if let Some(l) = lists.iter_mut().find(|l| l.name == name) {
            l.enabled = enabled;
            true
        } else {
            false
        }
    }

    // ── FST refresh ──────────────────────────────────────────────────────────

    /// Fetch all enabled lists and atomically replace the global FSTs — the
    /// merged blocklist and the merged subscribed allowlist.
    ///
    /// `force` bypasses the per-list disk caches (both the built `.fst` and the
    /// parsed `.domains` text), forcing a network re-fetch and a fresh parse.
    /// Use it for operator-triggered refreshes so a parser/format change takes
    /// effect immediately; the periodic/startup refresh passes `false` and reuses
    /// the caches within their TTL.
    pub async fn refresh(&self, force: bool) -> Result<usize> {
        // Serialise refreshes: concurrent API actions (add/del/patch list) each
        // spawn a refresh, and overlapping runs would re-fetch every list and
        // interleave their `data`/`domain_counts` stores. One at a time.
        let _refresh_guard = self.refresh_lock.lock().await;

        let lists: Vec<ListConfig> = self
            .lists
            .read()
            .iter()
            .filter(|l| l.enabled)
            .cloned()
            .collect();

        let set = refresh_list_set(
            &lists,
            &self.list_cache_dir,
            &self.fst_path,
            force,
            ListPolarity::Block,
        )
        .await?;
        let unique_count = set.unique_count;

        // Install the new FST and its domain counts together so a reader never
        // sees counts from one refresh paired with the FST of another.
        self.data.store(Arc::new(BlocklistData { fst: set.fst }));
        *self.domain_counts.write() = set.counts;
        *self.adblock_stats.write() = set.stats;
        self.merged_on_disk.store(set.persisted, Ordering::Relaxed);

        let allow_changed = self.refresh_allowlists(force).await;

        // Nothing moved: the decision cache is still answering off the same sets,
        // and the compiled profiles off the same per-list FSTs. Clearing and
        // recompiling them here would cost seconds of CPU and a cold cache to
        // arrive at exactly what is already in place.
        if set.changed || allow_changed {
            self.cache.clear();
            // The per-list FSTs just refreshed — recompile profiles off the fresh
            // subset caches so device profiles track list updates.
            self.rebuild_profiles_off_thread().await;
            tracing::info!("blocklist refreshed: {} unique domains", unique_count);
        } else {
            tracing::info!(
                "blocklist unchanged: {} unique domains, nothing rebuilt",
                unique_count
            );
        }
        Ok(unique_count)
    }

    /// Allowlist half of [`Self::refresh`] — same pipeline, opposite polarity.
    /// A total failure keeps the previous allow set and never fails the whole
    /// refresh: serving stale allows beats suddenly re-blocking domains the
    /// user explicitly exempted.
    ///
    /// Returns `true` when the allow set actually moved.
    async fn refresh_allowlists(&self, force: bool) -> bool {
        let lists: Vec<ListConfig> = self
            .allow_lists
            .read()
            .iter()
            .filter(|l| l.enabled)
            .cloned()
            .collect();

        // Nothing subscribed and nothing persisted → keep the in-memory empty
        // FST and don't create cache dirs/files for an unused feature. (With a
        // stale merged file still on disk the rebuild below runs and overwrites
        // it with an empty FST, so removing the last allowlist takes effect.)
        if lists.is_empty() && !self.allow_fst_path.exists() {
            return false;
        }

        match refresh_list_set(
            &lists,
            &self.allow_cache_dir,
            &self.allow_fst_path,
            force,
            ListPolarity::Allow,
        )
        .await
        {
            Ok(set) => {
                let changed = set.changed;
                self.allow_fst.store(Arc::new(set.fst));
                *self.allow_domain_counts.write() = set.counts;
                *self.allow_adblock_stats.write() = set.stats;
                self.allow_merged_on_disk
                    .store(set.persisted, Ordering::Relaxed);
                if !lists.is_empty() && changed {
                    tracing::info!("allowlist refreshed: {} unique domains", set.unique_count);
                }
                changed
            }
            Err(e) => {
                tracing::error!(
                    "allowlist refresh failed, keeping previous allow set: {}",
                    e
                );
                false
            }
        }
    }

    pub fn blocked_count(&self) -> u64 {
        self.data.load().fst.len() as u64
    }

    /// Decision-cache entry count (memory introspection).
    pub fn decision_cache_entries(&self) -> usize {
        self.cache.entries()
    }

    #[allow(dead_code)]
    pub fn invalidate(&self, domain: &str) {
        self.cache.invalidate(domain);
    }
}

/// Fetch every enabled list in `lists` (at most [`MAX_CONCURRENT_LIST_REFRESHES`]
/// at a time), resolve each to a per-list FST under `cache_dir`, k-way-merge
/// them, and atomically persist + mmap the merged FST at `merged_path`. Shared
/// by the blocklist and allowlist halves of [`Blocklist::refresh`]; `polarity`
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
        let label = match polarity {
            ListPolarity::Block => "blocklists",
            ListPolarity::Allow => "allowlists",
        };
        return Err(FeriteError::Fst(format!(
            "all enabled {label} failed and no cached domains are available"
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

pub(crate) fn normalize_client_keys(entries: &[String]) -> Vec<String> {
    let normalized: BTreeSet<String> = entries
        .iter()
        .filter_map(|key| normalize_client_key(key))
        .collect();
    normalized.into_iter().collect()
}

#[cfg(test)]
mod tests;
