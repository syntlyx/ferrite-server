use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use arc_swap::ArcSwap;
use fst::{Map, MapBuilder};
use parking_lot::RwLock;
use regex::Regex;

use crate::blocklist::cache::BlocklistCache;
use crate::blocklist::loader::{self, FstMap};
use crate::blocklist::{AdblockStats, ListPolarity, refresh};
use crate::clients::normalize_client_key;
use crate::config::{AllowlistConfig, BlocklistConfig, ListConfig};
use crate::error::{FeriteError, Result};

/// What [`refresh_list_set`] hands back: the merged FST, per-list domain
/// counts, per-list Adblock parse stats, and the merged unique-domain count.
type ListSetRefresh = (
    FstMap,
    HashMap<String, usize>,
    HashMap<String, AdblockStats>,
    usize,
);
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

/// Exact match on `domain`, else the first parent in the hierarchy that matches
/// (stopping at the registrable-domain boundary) — the same walk as
/// [`Blocklist::check_blocked`]. Returns the key that matched.
fn matched_key(domain: &str, contains: impl Fn(&str) -> bool) -> Option<String> {
    if contains(domain) {
        return Some(domain.to_string());
    }
    let mut rest = domain;
    while let Some(dot) = rest.find('.') {
        rest = &rest[dot + 1..];
        if is_registrable_or_deeper(rest) && contains(rest) {
            return Some(rest.to_string());
        }
    }
    None
}

/// The hot-swappable core data (FST + wildcards).
struct BlocklistData {
    fst: FstMap,
    wildcards: Vec<Regex>,
}

/// Decision-cache size for a per-device profile. Smaller than the global cache
/// (there are usually only a handful of profiles, each seeing one device's
/// traffic) so N profiles don't multiply the global figure.
const PROFILE_DECISION_CACHE: usize = 8_192;

/// A compiled per-device blocking profile: its own merged FST (a subset of the
/// subscription lists) plus a private decision cache. The manual black/whitelist
/// and `wildcard_block` are shared from the parent [`Blocklist`], so a profile
/// only changes *which subscription lists* apply to its clients.
pub struct CompiledProfile {
    /// Normalised client keys (IP/MAC) this profile applies to.
    clients: HashSet<String>,
    fst: FstMap,
    cache: BlocklistCache,
    /// Per-profile manual overrides (exact + wildcard), applied *before* the
    /// global rules for this profile's clients: `allow` beats everything
    /// (including a global block), `block` beats the global whitelist.
    allow_exact: HashSet<String>,
    allow_wild: Vec<Regex>,
    block_exact: HashSet<String>,
    block_wild: Vec<Regex>,
    /// Merged FST of this profile's named allowlist subscriptions; `None` when
    /// the profile names none and inherits the global allow set.
    allow_fst: Option<FstMap>,
    /// Default-deny: block everything not explicitly allowed for this profile
    /// (except local-infrastructure names — see [`Blocklist::is_local_infra`]).
    default_deny: bool,
}

impl CompiledProfile {
    /// Does this profile apply to the querying client? Assumes the client keys
    /// are already normalised (the DNS hot path).
    fn matches_client(&self, client_ip: &str, mac: Option<&str>) -> bool {
        self.clients.contains(client_ip) || mac.is_some_and(|m| self.clients.contains(m))
    }

    /// Is `domain` explicitly allowed for this profile (exact/hierarchy or
    /// wildcard)? An allow overrides the global block and the profile's lists.
    fn allows(&self, domain: &str) -> bool {
        domain_in_set(domain, &self.allow_exact)
            || self.allow_wild.iter().any(|re| re.is_match(domain))
    }

    /// Is `domain` explicitly blocked for this profile (exact/hierarchy or
    /// wildcard)? A profile block overrides the global whitelist.
    fn blocks(&self, domain: &str) -> bool {
        domain_in_set(domain, &self.block_exact)
            || self.block_wild.iter().any(|re| re.is_match(domain))
    }
}

/// Exact match on `domain`, else a parent in the hierarchy (stopping at the
/// registrable boundary) — the shared walk used by the blacklist, whitelist, and
/// profile overrides so a rule for `evil.com` also matches `www.evil.com`.
fn domain_in_set(domain: &str, set: &HashSet<String>) -> bool {
    if set.contains(domain) {
        return true;
    }
    let mut rest = domain;
    while let Some(dot) = rest.find('.') {
        rest = &rest[dot + 1..];
        if is_registrable_or_deeper(rest) && set.contains(rest) {
            return true;
        }
    }
    false
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
    profiles_config: RwLock<Vec<crate::config::BlocklistProfileConfig>>,
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

        let wildcards = compile_wildcards(&config.wildcard_block);

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
            data: ArcSwap::from_pointee(BlocklistData {
                fst: empty,
                wildcards,
            }),
            profiles: ArcSwap::from_pointee(Vec::new()),
            profiles_config: RwLock::new(config.profiles),
            client_bypass: ArcSwap::from_pointee(client_bypass),
            whitelist: RwLock::new(whitelist),
            whitelist_wildcards: RwLock::new(whitelist_wildcards),
            blacklist: RwLock::new(HashSet::new()),
            blacklist_wildcards: RwLock::new(Vec::new()),
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
                let wildcards: Vec<Regex> = self
                    .data
                    .load()
                    .wildcards
                    .iter()
                    .map(|re| Regex::new(re.as_str()).expect("previously compiled"))
                    .collect();
                self.data.store(Arc::new(BlocklistData { fst, wildcards }));
                self.cache.clear();
                self.restore_list_stats_from_cache();
                // Per-list FSTs are on disk too, so profiles can compile now
                // (before any network refresh) — a restart keeps device profiles
                // working immediately, like the global list.
                self.rebuild_profiles();
                tracing::info!("blocklist loaded from disk: {} domains", count);
                self.load_allow_from_disk()
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
        let result = self.check_blocked_in(domain, &data.fst, &data.wildcards);
        self.cache.insert(domain, result);
        result
    }

    /// Profile-aware block check for the DNS hot path. With `profile == None`
    /// this is exactly [`Self::is_blocked_normalized`] (the default, all-lists
    /// FST). With a profile it uses that profile's subset FST + private cache;
    /// the manual blacklist and `wildcard_block` still apply (they're global).
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
        // Profiles share the global compiled wildcards (config.wildcard_block);
        // only the subscription FST differs.
        let wildcards = self.data.load().wildcards.clone();
        let result = self.check_blocked_in(domain, &profile.fst, &wildcards);
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
    ///   5. global blacklist + the profile's (or global) subscription FST +
    ///      wildcards → blocked,
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

    /// The core block decision against a specific FST + wildcard set. The manual
    /// blacklist (exact + wildcard) is always consulted first — it is global and
    /// overrides every profile — then the given FST/wildcards with the hierarchy
    /// walk. Shared by the default path and every profile so their semantics
    /// can't drift.
    fn check_blocked_in(&self, domain: &str, fst: &FstMap, wildcards: &[Regex]) -> bool {
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
                if is_registrable_or_deeper(rest) && blacklist.contains(rest) {
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
        for re in wildcards {
            if re.is_match(domain) {
                return true;
            }
        }

        // Walk up the domain hierarchy: `www.evil.com` → check `evil.com`.
        // The public-suffix guard stops the walk at the registrable-domain
        // boundary so an entry for a multi-label suffix (e.g. `co.uk`) cannot
        // over-match every domain under that ccTLD.
        let mut rest = domain;
        while let Some(dot) = rest.find('.') {
            rest = &rest[dot + 1..];
            if is_registrable_or_deeper(rest) && fst.contains_key(rest.as_bytes()) {
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
    pub fn set_profiles(&self, profiles: Vec<crate::config::BlocklistProfileConfig>) {
        self.has_profiles
            .store(!profiles.is_empty(), Ordering::Relaxed);
        *self.profiles_config.write() = profiles;
        self.rebuild_profiles();
    }

    /// Current profile configs (for the API to echo back / persist).
    pub fn get_profiles(&self) -> Vec<crate::config::BlocklistProfileConfig> {
        self.profiles_config.read().clone()
    }

    /// (Re)compile every profile's merged FST from the per-list `.fst` files the
    /// last refresh wrote, synchronously on the calling thread. A multi-list
    /// profile over big lists is a multi-second CPU+IO job — from async
    /// contexts use [`Self::rebuild_profiles_off_thread`] instead; this sync
    /// form is for startup ([`Self::load_from_disk`]) and tests.
    pub fn rebuild_profiles(&self) {
        let configs = self.profiles_config.read().clone();
        let compiled = compile_profiles(&configs, &self.list_cache_dir, &self.allow_cache_dir);
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
        let compiled =
            tokio::task::spawn_blocking(move || compile_profiles(&configs, &list_dir, &allow_dir))
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

    /// Returns `true` if `domain` is explicitly whitelisted (exact or wildcard
    /// match). Convenience wrapper that normalises first; the hot path uses
    /// [`Self::is_whitelisted_normalized`]. Kept as a test helper.
    #[cfg(test)]
    pub fn is_whitelisted(&self, domain: &str) -> bool {
        let domain = normalise(domain);
        self.is_whitelisted_normalized(&domain)
    }

    /// Global-tier wrapper around [`Self::is_whitelisted_for_normalized`].
    /// Production callers are profile-aware; kept as a test helper.
    #[cfg(test)]
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
                if is_registrable_or_deeper(rest) && whitelist.contains(rest) {
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
        // Config `wildcard_block` (compiled into the hot-path data; only the
        // anchored regex survives there, so report that as the pattern).
        for re in &self.data.load().wildcards {
            if re.is_match(&domain) {
                sources.push(BlockSource {
                    kind: "wildcard".into(),
                    name: re.as_str().to_string(),
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

        let (fst, counts, stats, unique_count) = refresh_list_set(
            &lists,
            &self.list_cache_dir,
            &self.fst_path,
            force,
            ListPolarity::Block,
        )
        .await?;

        let wildcards = self.data.load().wildcards.clone();
        // Install the new FST and its domain counts together so a reader never
        // sees counts from one refresh paired with the FST of another.
        self.data.store(Arc::new(BlocklistData { fst, wildcards }));
        *self.domain_counts.write() = counts;
        *self.adblock_stats.write() = stats;

        self.refresh_allowlists(force).await;

        self.cache.clear();
        // The per-list FSTs just refreshed — recompile profiles off the fresh
        // subset caches so device profiles track list updates.
        self.rebuild_profiles_off_thread().await;

        tracing::info!("blocklist refreshed: {} unique domains", unique_count);
        Ok(unique_count)
    }

    /// Allowlist half of [`Self::refresh`] — same pipeline, opposite polarity.
    /// A total failure keeps the previous allow set and never fails the whole
    /// refresh: serving stale allows beats suddenly re-blocking domains the
    /// user explicitly exempted.
    async fn refresh_allowlists(&self, force: bool) {
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
            return;
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
            Ok((fst, counts, stats, unique_count)) => {
                self.allow_fst.store(Arc::new(fst));
                *self.allow_domain_counts.write() = counts;
                *self.allow_adblock_stats.write() = stats;
                if !lists.is_empty() {
                    tracing::info!("allowlist refreshed: {} unique domains", unique_count);
                }
            }
            Err(e) => tracing::error!(
                "allowlist refresh failed, keeping previous allow set: {}",
                e
            ),
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
            let safe = refresh::sanitize_name(&list.name);
            let fst_cache = cache_dir.join(format!("{safe}.fst"));
            let domains_cache = cache_dir.join(format!("{safe}.domains"));
            let stats_cache = cache_dir.join(format!("{safe}.stats.json"));
            tokio::spawn(async move {
                let Ok(_permit) = permits.acquire_owned().await else {
                    return (String::new(), refresh::ListFst::Ram(Vec::new()), 0, None);
                };
                refresh::load_or_build_list_fst(
                    name,
                    url,
                    fst_cache,
                    domains_cache,
                    stats_cache,
                    force,
                    polarity,
                )
                .await
            })
        })
        .collect();

    let mut per_list_fsts: Vec<refresh::ListFst> = Vec::with_capacity(lists.len());
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut stats: HashMap<String, AdblockStats> = HashMap::new();

    for task in tasks {
        let (name, fst_src, count, list_stats) = task.await.unwrap_or_else(|e| {
            tracing::error!("list task panicked: {}", e);
            (String::new(), refresh::ListFst::Ram(Vec::new()), 0, None)
        });
        if !name.is_empty() {
            if let Some(s) = list_stats {
                stats.insert(name.clone(), s);
            }
            counts.insert(name, count);
            per_list_fsts.push(fst_src);
        }
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

    let merged_path = merged_path.to_path_buf();
    let (fst, unique_count) = tokio::task::spawn_blocking(move || -> Result<(FstMap, usize)> {
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
        let fst_bytes = loader::merge_fsts(&maps)?;
        let unique_count = Map::new(fst_bytes.as_slice())
            .map_err(|e| FeriteError::Fst(e.to_string()))?
            .len();

        if let Some(parent) = merged_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let tmp = merged_path.with_extension("fst.tmp");
        let persisted =
            std::fs::write(&tmp, &fst_bytes).is_ok() && std::fs::rename(&tmp, &merged_path).is_ok();
        let fst = if persisted {
            tracing::info!("merged FST saved to {}", merged_path.display());
            // Serve from the mmap'd file: the merged map then sits in the
            // page cache (evictable) instead of RSS-pinned RAM.
            loader::mmap_fst(&merged_path).or_else(|_| loader::ram_fst(fst_bytes))?
        } else {
            loader::ram_fst(fst_bytes)?
        };
        Ok((fst, unique_count))
    })
    .await
    .map_err(|e| FeriteError::Internal(e.to_string()))??;

    Ok((fst, counts, stats, unique_count))
}

/// Compile every profile from its config and the per-list `.fst` caches on
/// disk. Free function taking owned-by-reference inputs so the (potentially
/// multi-second) FST merging can run on the blocking pool — see
/// [`Blocklist::rebuild_profiles_off_thread`]. The per-list FSTs are mmap'd,
/// so merges stream from the page cache and the compiled profile FSTs are
/// themselves mmap'd from `profile_<id>.fst` files (kept off anonymous RSS,
/// like the global FST).
fn compile_profiles(
    configs: &[crate::config::BlocklistProfileConfig],
    list_cache_dir: &Path,
    allow_cache_dir: &Path,
) -> Vec<Arc<CompiledProfile>> {
    let mut compiled: Vec<Arc<CompiledProfile>> = Vec::with_capacity(configs.len());
    for cfg in configs {
        let maps = mmap_named_lists(list_cache_dir, &cfg.id, &cfg.lists);
        let fst = build_profile_fst(&cfg.id, maps, list_cache_dir).unwrap_or_else(empty_fst);
        // Allowlist subset: named lists compile to the profile's own allow
        // FST; an empty selection means "inherit the global allow set"
        // (`None`), so existing profiles keep their exemptions.
        let allow_fst = if cfg.allowlists.is_empty() {
            None
        } else {
            let maps = mmap_named_lists(allow_cache_dir, &cfg.id, &cfg.allowlists);
            Some(build_profile_fst(&cfg.id, maps, allow_cache_dir).unwrap_or_else(empty_fst))
        };
        let clients: HashSet<String> = normalize_client_keys(&cfg.clients).into_iter().collect();
        let (allow_exact, allow_wild) = split_patterns(&cfg.allow);
        let (block_exact, block_wild) = split_patterns(&cfg.block);
        compiled.push(Arc::new(CompiledProfile {
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
    compiled
}

/// Merge a profile's per-list FSTs and mmap the result from a
/// `profile_<id>.fst` cache file under `cache_dir` (falling back to a RAM FST
/// if the write fails). Returns `None` when there's nothing to merge. Block
/// and allow subsets use distinct `cache_dir`s, so the cache file name can
/// stay the same for both.
fn build_profile_fst(id: &str, maps: Vec<FstMap>, cache_dir: &Path) -> Option<FstMap> {
    if maps.is_empty() {
        return None;
    }
    // Single-list subset: no merge needed — serve the (already mmap'd)
    // per-list FST directly instead of copying + rewriting tens of MB.
    if maps.len() == 1 {
        return maps.into_iter().next();
    }
    let bytes = loader::merge_fsts(&maps)
        .map_err(|e| tracing::warn!("profile '{}': FST merge failed: {}", id, e))
        .ok()?;
    let path = cache_dir.join(format!("profile_{}.fst", refresh::sanitize_name(id)));
    let tmp = path.with_extension("fst.tmp");
    let persisted = std::fs::write(&tmp, &bytes).is_ok() && std::fs::rename(&tmp, &path).is_ok();
    if persisted {
        loader::mmap_fst(&path)
            .or_else(|_| loader::ram_fst(bytes))
            .ok()
    } else {
        loader::ram_fst(bytes).ok()
    }
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

fn normalize_client_keys(entries: &[String]) -> Vec<String> {
    let normalized: BTreeSet<String> = entries
        .iter()
        .filter_map(|key| normalize_client_key(key))
        .collect();
    normalized.into_iter().collect()
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn normalise(domain: &str) -> String {
    domain
        .to_ascii_lowercase()
        .trim_end_matches('.')
        .to_string()
}

/// Canonical domain key used by the blocklist engine and the DNS hot path:
/// lowercase, trailing root dot stripped. Exposed so the API layer can store
/// and look up entries under the exact same key the engine uses (otherwise a
/// UI-listed value can't delete its persisted row).
pub fn normalise_domain(domain: &str) -> String {
    normalise(domain)
}

/// `true` if `name` equals `suffix` or ends with `.suffix` (label boundary —
/// `mylan` must not match suffix `lan`).
fn has_suffix(name: &str, suffix: &str) -> bool {
    name == suffix
        || (name.len() > suffix.len()
            && name.ends_with(suffix)
            && name.as_bytes()[name.len() - suffix.len() - 1] == b'.')
}

/// Returns `true` if `name` is a registrable domain or a subdomain of one —
/// i.e. it extends beyond its own public suffix. Used to stop the hierarchy
/// walk at the registrable boundary so an entry for a public suffix
/// (`com`, `co.uk`, `com.au`, …) never matches every domain beneath it.
///
/// Unknown suffixes are treated as registrable (fail open to the previous
/// single-dot behaviour) rather than silently dropping the check.
fn is_registrable_or_deeper(name: &str) -> bool {
    match psl::suffix(name.as_bytes()) {
        Some(suffix) => name.len() > suffix.as_bytes().len(),
        None => true,
    }
}

fn empty_fst() -> FstMap {
    let bytes = MapBuilder::memory().into_inner().expect("empty FST build");
    loader::ram_fst(bytes).expect("empty FST map")
}

fn compile_wildcards(patterns: &[String]) -> Vec<Regex> {
    patterns
        .iter()
        .filter_map(|p| {
            let pattern = normalise(p);
            wildcard_to_regex(&pattern)
                .map_err(|e| tracing::warn!("skipping invalid wildcard '{}': {}", p, e))
                .ok()
        })
        .collect()
}

/// Compile a domain wildcard pattern (`*.example.com`) into an anchored regex.
/// Exposed to the crate so the proxy routing engine can reuse the exact same
/// wildcard semantics as the blocklist (`\*` → `.*`, anchored `^…$`).
pub(crate) fn wildcard_to_regex(pattern: &str) -> Result<Regex> {
    if pattern == "*" || pattern.trim_matches('*').is_empty() {
        return Err(FeriteError::Config(
            "wildcard pattern cannot match everything".into(),
        ));
    }
    let escaped = regex::escape(pattern);
    Regex::new(&format!("^{}$", escaped.replace("\\*", ".*")))
        .map_err(|e| FeriteError::Config(format!("invalid wildcard '{}': {}", pattern, e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_fst_path(name: &str) -> PathBuf {
        let unique = format!(
            "{}-{}-{}",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        std::env::temp_dir().join(unique).join("blocklist.fst")
    }

    #[tokio::test]
    async fn refresh_preserves_wildcard_block_rules() {
        let blocklist = Blocklist::new(
            BlocklistConfig {
                enabled: true,
                decision_cache_size: 50_000,
                lists: vec![],
                wildcard_block: vec!["*.ads.test".to_string()],
                whitelist: vec![],
                client_bypass: vec![],
                profiles: vec![],
            },
            AllowlistConfig::default(),
            temp_fst_path("ferrite-blocklist-wildcard"),
        );

        assert!(blocklist.is_blocked("tracker.ads.test"));
        blocklist.refresh(false).await.unwrap();
        assert!(blocklist.is_blocked("tracker.ads.test"));
    }

    #[test]
    fn load_from_disk_restores_per_list_counts_and_stats_from_cache() {
        let fst_path = temp_fst_path("ferrite-blocklist-restore-stats");
        let cache_dir = fst_path.parent().unwrap().join("lists");
        std::fs::create_dir_all(&cache_dir).unwrap();

        // Merged FST (what load_from_disk loads) plus the per-list caches a refresh
        // would have written: a `<list>.fst` and a `<list>.stats.json` sidecar.
        let domains = vec!["a.ads.test".to_string(), "b.ads.test".to_string()];
        std::fs::write(
            &fst_path,
            crate::blocklist::loader::build_fst(domains.clone()).unwrap(),
        )
        .unwrap();

        let safe = refresh::sanitize_name("My List");
        std::fs::write(
            cache_dir.join(format!("{safe}.fst")),
            crate::blocklist::loader::build_fst(domains).unwrap(),
        )
        .unwrap();
        let stats = AdblockStats {
            kept: 2,
            exceptions: 1,
            ..Default::default()
        };
        std::fs::write(
            cache_dir.join(format!("{safe}.stats.json")),
            serde_json::to_vec(&stats).unwrap(),
        )
        .unwrap();

        let blocklist = Blocklist::new(
            BlocklistConfig {
                enabled: true,
                decision_cache_size: 1000,
                lists: vec![ListConfig {
                    name: "My List".to_string(),
                    url: "https://example.test/list.txt".to_string(),
                    enabled: true,
                }],
                wildcard_block: vec![],
                whitelist: vec![],
                client_bypass: vec![],
                profiles: vec![],
            },
            AllowlistConfig::default(),
            fst_path,
        );

        assert!(blocklist.load_from_disk());
        // Per-list count + Adblock stats restored from cache — no network refresh.
        assert_eq!(blocklist.domain_count("My List"), Some(2));
        let restored = blocklist.parse_stats("My List").expect("stats restored");
        assert_eq!(restored.kept, 2);
        assert_eq!(restored.exceptions, 1);
    }

    #[test]
    fn per_device_profile_applies_a_list_subset_to_matched_clients() {
        use crate::config::BlocklistProfileConfig;

        let fst_path = temp_fst_path("ferrite-blocklist-profiles");
        let cache_dir = fst_path.parent().unwrap().join("lists");
        std::fs::create_dir_all(&cache_dir).unwrap();

        // Two per-list FSTs on disk, as a refresh would have written them.
        let ads = refresh::sanitize_name("Ads");
        std::fs::write(
            cache_dir.join(format!("{ads}.fst")),
            loader::build_fst(vec!["ads.test".to_string()]).unwrap(),
        )
        .unwrap();
        let porn = refresh::sanitize_name("Adult");
        std::fs::write(
            cache_dir.join(format!("{porn}.fst")),
            loader::build_fst(vec!["adult.test".to_string()]).unwrap(),
        )
        .unwrap();
        // The global merged FST contains both (default = everything).
        std::fs::write(
            &fst_path,
            loader::build_fst(vec!["ads.test".to_string(), "adult.test".to_string()]).unwrap(),
        )
        .unwrap();

        // "kids" profile applies BOTH lists to 10.0.0.5; everyone else gets the
        // default all-lists FST.
        let blocklist = Blocklist::new(
            BlocklistConfig {
                enabled: true,
                decision_cache_size: 1000,
                lists: vec![
                    ListConfig {
                        name: "Ads".into(),
                        url: "https://x.test/ads".into(),
                        enabled: true,
                    },
                    ListConfig {
                        name: "Adult".into(),
                        url: "https://x.test/adult".into(),
                        enabled: true,
                    },
                ],
                wildcard_block: vec![],
                whitelist: vec![],
                client_bypass: vec![],
                profiles: vec![BlocklistProfileConfig {
                    id: "kids".into(),
                    name: "Kids".into(),
                    lists: vec!["Ads".into(), "Adult".into()],
                    clients: vec!["10.0.0.5".into()],
                    block: Vec::new(),
                    allow: Vec::new(),
                    allowlists: Vec::new(),
                    default_deny: false,
                }],
            },
            AllowlistConfig::default(),
            fst_path,
        );
        assert!(blocklist.load_from_disk());

        let kids = blocklist.profile_for("10.0.0.5", None);
        assert!(kids.is_some(), "profile must match its listed client");
        // The kids device: both categories blocked via its own subset FST.
        assert!(blocklist.is_blocked_for_normalized("ads.test", kids.as_deref()));
        assert!(blocklist.is_blocked_for_normalized("adult.test", kids.as_deref()));

        // An unmatched client gets no profile → the default FST (also both, here).
        assert!(blocklist.profile_for("10.0.0.9", None).is_none());

        // A profile with only the Ads list blocks ads but NOT adult content.
        blocklist.set_profiles(vec![BlocklistProfileConfig {
            id: "lite".into(),
            name: "Lite".into(),
            lists: vec!["Ads".into()],
            clients: vec!["aa:bb:cc:dd:ee:ff".into()],
            block: Vec::new(),
            allow: Vec::new(),
            allowlists: Vec::new(),
            default_deny: false,
        }]);
        let lite = blocklist.profile_for("10.0.0.9", Some("aa:bb:cc:dd:ee:ff"));
        assert!(lite.is_some(), "profile must match by MAC");
        assert!(blocklist.is_blocked_for_normalized("ads.test", lite.as_deref()));
        assert!(
            !blocklist.is_blocked_for_normalized("adult.test", lite.as_deref()),
            "a list the profile excludes must not block"
        );

        // Subdomains of a profile-blocked domain are caught by the hierarchy walk.
        assert!(blocklist.is_blocked_for_normalized("track.ads.test", lite.as_deref()));
    }

    #[test]
    fn per_profile_manual_rules_override_global() {
        use crate::config::BlocklistProfileConfig;

        let fst_path = temp_fst_path("ferrite-blocklist-profile-overrides");
        let cache_dir = fst_path.parent().unwrap().join("lists");
        std::fs::create_dir_all(&cache_dir).unwrap();
        // A single "Ads" list containing social.example so it's globally blocked.
        let ads = refresh::sanitize_name("Ads");
        std::fs::write(
            cache_dir.join(format!("{ads}.fst")),
            loader::build_fst(vec!["social.example".to_string()]).unwrap(),
        )
        .unwrap();
        std::fs::write(
            &fst_path,
            loader::build_fst(vec!["social.example".to_string()]).unwrap(),
        )
        .unwrap();

        let blocklist = Blocklist::new(
            BlocklistConfig {
                enabled: true,
                decision_cache_size: 1000,
                lists: vec![ListConfig {
                    name: "Ads".into(),
                    url: "https://x.test/ads".into(),
                    enabled: true,
                }],
                // Globally whitelist news.example (allowed for everyone by default).
                whitelist: vec!["news.example".into()],
                wildcard_block: vec![],
                client_bypass: vec![],
                profiles: vec![
                    // "me": allow social.example (override the global block) for one device.
                    BlocklistProfileConfig {
                        id: "me".into(),
                        name: "Me".into(),
                        lists: vec!["Ads".into()],
                        clients: vec!["10.0.0.1".into()],
                        block: vec![],
                        allow: vec!["social.example".into()],
                        allowlists: Vec::new(),
                        default_deny: false,
                    },
                    // "kids": block news.example (override the global whitelist) + games.
                    BlocklistProfileConfig {
                        id: "kids".into(),
                        name: "Kids".into(),
                        lists: vec!["Ads".into()],
                        clients: vec!["10.0.0.2".into()],
                        block: vec!["news.example".into(), "*.games.example".into()],
                        allow: vec![],
                        allowlists: Vec::new(),
                        default_deny: false,
                    },
                ],
            },
            AllowlistConfig::default(),
            fst_path,
        );
        assert!(blocklist.load_from_disk());

        let me = blocklist.profile_for("10.0.0.1", None);
        let kids = blocklist.profile_for("10.0.0.2", None);
        assert!(me.is_some() && kids.is_some());

        // "me": profile allow beats the global block on social.example…
        assert!(!blocklist.should_block_for("social.example", me.as_deref()));
        // …and a subdomain of the allowed domain is freed too (hierarchy walk).
        assert!(!blocklist.should_block_for("cdn.social.example", me.as_deref()));

        // "kids": profile block beats the global whitelist on news.example…
        assert!(blocklist.should_block_for("news.example", kids.as_deref()));
        // …wildcard profile block works…
        assert!(blocklist.should_block_for("play.games.example", kids.as_deref()));
        // …and the global block still applies to kids (social is on its list).
        assert!(blocklist.should_block_for("social.example", kids.as_deref()));

        // No profile (some other device): global rules only — social blocked,
        // news whitelisted, games untouched.
        assert!(blocklist.should_block_for("social.example", None));
        assert!(!blocklist.should_block_for("news.example", None));
        assert!(!blocklist.should_block_for("play.games.example", None));
    }

    #[tokio::test]
    async fn refresh_keeps_existing_fst_when_enabled_lists_all_fail() {
        let fst_path = temp_fst_path("ferrite-blocklist-all-fail");
        std::fs::create_dir_all(fst_path.parent().unwrap()).unwrap();
        let original =
            crate::blocklist::loader::build_fst(vec!["blocked.test".to_string()]).unwrap();
        std::fs::write(&fst_path, original).unwrap();

        let blocklist = Blocklist::new(
            BlocklistConfig {
                enabled: true,
                decision_cache_size: 50_000,
                lists: vec![ListConfig {
                    name: "Missing".to_string(),
                    url: "file:///this/path/does/not/exist".to_string(),
                    enabled: true,
                }],
                wildcard_block: vec![],
                whitelist: vec![],
                client_bypass: vec![],
                profiles: vec![],
            },
            AllowlistConfig::default(),
            fst_path.clone(),
        );

        assert!(blocklist.load_from_disk());
        assert!(blocklist.is_blocked("blocked.test"));

        let err = blocklist.refresh(false).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("all enabled blocklists failed and no cached domains are available")
        );
        assert!(blocklist.is_blocked("blocked.test"));

        let persisted = std::fs::read(fst_path).unwrap();
        let map = Map::new(persisted).unwrap();
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("blocked.test".as_bytes()));
    }

    #[test]
    fn config_entries_are_normalized_once_for_hot_path_lookups() {
        let blocklist = Blocklist::new(
            BlocklistConfig {
                enabled: true,
                decision_cache_size: 128,
                lists: vec![],
                wildcard_block: vec!["*.Ads.Test.".to_string()],
                whitelist: vec!["Safe.Test.".to_string(), "*.Trusted.Test.".to_string()],
                client_bypass: vec![],
                profiles: vec![],
            },
            AllowlistConfig::default(),
            temp_fst_path("ferrite-blocklist-normalized"),
        );

        assert!(blocklist.is_whitelisted("SAFE.TEST."));
        assert!(blocklist.is_whitelisted_normalized("app.trusted.test"));
        assert!(blocklist.is_blocked("Tracker.Ads.Test."));
        assert!(blocklist.is_blocked_normalized("tracker.ads.test"));
    }

    #[test]
    fn explain_attributes_sources_and_whitelist() {
        let blocklist = Blocklist::new(
            BlocklistConfig {
                enabled: true,
                decision_cache_size: 128,
                lists: vec![],
                wildcard_block: vec!["*.ads.test".to_string()],
                whitelist: vec!["safe.test".to_string()],
                client_bypass: vec![],
                profiles: vec![],
            },
            AllowlistConfig::default(),
            temp_fst_path("ferrite-blocklist-explain"),
        );
        blocklist.add_blacklist("evil.test").unwrap();

        // Manual blacklist match attributes to the parent (hierarchy walk).
        let e = blocklist.explain("www.evil.test");
        assert!(e.blocked);
        assert!(!e.whitelisted);
        assert!(
            e.sources
                .iter()
                .any(|s| s.kind == "blacklist" && s.matched == "evil.test")
        );

        // Config wildcard_block match is reported as a wildcard source.
        let w = blocklist.explain("x.ads.test");
        assert!(w.blocked);
        assert!(w.sources.iter().any(|s| s.kind == "wildcard"));

        // A whitelisted domain reports the exempting entry and is not blocked.
        let s = blocklist.explain("safe.test");
        assert!(!s.blocked);
        assert!(s.whitelisted);
        assert_eq!(s.whitelist_match.as_ref().unwrap().entry, "safe.test");

        // Whitelist beats a block: still report the source, but blocked = false.
        blocklist.add_whitelist("evil.test").unwrap();
        let ww = blocklist.explain("evil.test");
        assert!(ww.whitelisted);
        assert!(!ww.blocked);
        assert!(!ww.sources.is_empty());
    }

    #[test]
    fn whitelisting_parent_domain_exempts_subdomains() {
        let blocklist = Blocklist::new(
            BlocklistConfig {
                enabled: true,
                decision_cache_size: 128,
                lists: vec![],
                wildcard_block: vec![],
                whitelist: vec!["google.com".to_string()],
                client_bypass: vec![],
                profiles: vec![],
            },
            AllowlistConfig::default(),
            temp_fst_path("ferrite-blocklist-wl-hierarchy"),
        );

        // Exact and subdomains are all whitelisted, symmetric with is_blocked.
        assert!(blocklist.is_whitelisted_normalized("google.com"));
        assert!(blocklist.is_whitelisted_normalized("www.google.com"));
        assert!(blocklist.is_whitelisted_normalized("adservice.google.com"));
        // Sibling / bare-TLD parents must not be matched.
        assert!(!blocklist.is_whitelisted_normalized("notgoogle.com"));
        assert!(!blocklist.is_whitelisted_normalized("google.com.evil.com"));
    }

    #[test]
    fn blacklisting_parent_domain_blocks_subdomains() {
        let blocklist = Blocklist::new(
            BlocklistConfig {
                enabled: true,
                decision_cache_size: 128,
                lists: vec![],
                wildcard_block: vec![],
                whitelist: vec![],
                client_bypass: vec![],
                profiles: vec![],
            },
            AllowlistConfig::default(),
            temp_fst_path("ferrite-blocklist-bl-hierarchy"),
        );

        blocklist.add_blacklist("evil.com").unwrap();
        assert!(blocklist.is_blocked_normalized("evil.com"));
        // Subdomains are blocked via the hierarchy walk, symmetric with the FST.
        assert!(blocklist.is_blocked_normalized("www.evil.com"));
        assert!(blocklist.is_blocked_normalized("ads.tracking.evil.com"));
        // Sibling / unrelated domains are not.
        assert!(!blocklist.is_blocked_normalized("notevil.com"));
        assert!(!blocklist.is_blocked_normalized("evil.com.good.org"));
    }

    #[test]
    fn blacklisting_parent_clears_stale_allow_for_subdomain() {
        // A cached ALLOW decision for a subdomain must not survive blacklisting
        // its parent — add_blacklist clears the whole decision cache because the
        // hierarchy walk now makes the parent affect every subdomain.
        let blocklist = Blocklist::new(
            BlocklistConfig {
                enabled: true,
                decision_cache_size: 128,
                lists: vec![],
                wildcard_block: vec![],
                whitelist: vec![],
                client_bypass: vec![],
                profiles: vec![],
            },
            AllowlistConfig::default(),
            temp_fst_path("ferrite-blocklist-stale-allow"),
        );

        // First lookup caches an ALLOW (300s TTL) for the subdomain.
        assert!(!blocklist.is_blocked_normalized("www.ads.test"));
        blocklist.add_blacklist("ads.test").unwrap();
        // The stale cached ALLOW must be gone.
        assert!(blocklist.is_blocked_normalized("www.ads.test"));
    }

    #[test]
    fn public_suffix_entry_does_not_overmatch_ccsld() {
        // An entry for a multi-label public suffix (co.uk) must not match every
        // domain under it — only the exact name.
        let blocklist = Blocklist::new(
            BlocklistConfig {
                enabled: true,
                decision_cache_size: 128,
                lists: vec![],
                wildcard_block: vec![],
                whitelist: vec![],
                client_bypass: vec![],
                profiles: vec![],
            },
            AllowlistConfig::default(),
            temp_fst_path("ferrite-blocklist-psl"),
        );

        blocklist.add_blacklist("co.uk").unwrap();
        assert!(!blocklist.is_blocked_normalized("victim.co.uk"));
        assert!(!blocklist.is_blocked_normalized("www.bbc.co.uk"));
        // But a normal registrable domain still covers its subdomains.
        blocklist.add_blacklist("bad.co.uk").unwrap();
        assert!(blocklist.is_blocked_normalized("bad.co.uk"));
        assert!(blocklist.is_blocked_normalized("tracker.bad.co.uk"));
    }

    #[tokio::test]
    async fn subscribed_allowlist_exempts_blocked_domains() {
        let fst_path = temp_fst_path("ferrite-allowlist-exempt");
        let dir = fst_path.parent().unwrap().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        let block_src = dir.join("block.txt");
        std::fs::write(&block_src, "cdn.example\ntracker.example\n").unwrap();
        let allow_src = dir.join("allow.txt");
        std::fs::write(&allow_src, "cdn.example\n").unwrap();

        let blocklist = Blocklist::new(
            BlocklistConfig {
                enabled: true,
                decision_cache_size: 1000,
                lists: vec![ListConfig {
                    name: "Block".into(),
                    url: format!("file://{}", block_src.display()),
                    enabled: true,
                }],
                wildcard_block: vec![],
                whitelist: vec![],
                client_bypass: vec![],
                profiles: vec![],
            },
            AllowlistConfig {
                domains: vec![],
                lists: vec![ListConfig {
                    name: "Allow".into(),
                    url: format!("file://{}", allow_src.display()),
                    enabled: true,
                }],
            },
            fst_path,
        );
        blocklist.refresh(false).await.unwrap();

        // Blocked by the subscription…
        assert!(blocklist.should_block_for("tracker.example", None));
        // …but the subscribed allowlist exempts cdn.example and its subdomains
        // (the whitelist tier walks the hierarchy, symmetric with blocks).
        assert!(!blocklist.should_block_for("cdn.example", None));
        assert!(!blocklist.should_block_for("static.cdn.example", None));
        assert!(blocklist.is_whitelisted_normalized("cdn.example"));
        assert_eq!(blocklist.allow_domain_count("Allow"), Some(1));

        // Explain attributes the exemption to its source allowlist by name and
        // still reports the (overridden) block source.
        let e = blocklist.explain("cdn.example");
        assert!(e.whitelisted && !e.blocked);
        assert_eq!(
            e.whitelist_match.as_ref().unwrap().list.as_deref(),
            Some("Allow")
        );
        assert!(!e.sources.is_empty());

        // Removing the allowlist takes effect on the next refresh.
        assert!(blocklist.remove_allow_list("Allow"));
        blocklist.refresh(false).await.unwrap();
        assert!(blocklist.should_block_for("cdn.example", None));
    }

    #[tokio::test]
    async fn profile_block_overrides_subscribed_allowlist() {
        use crate::config::BlocklistProfileConfig;

        let fst_path = temp_fst_path("ferrite-allowlist-profile-block");
        let dir = fst_path.parent().unwrap().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        let allow_src = dir.join("allow.txt");
        std::fs::write(&allow_src, "social.example\n").unwrap();

        let blocklist = Blocklist::new(
            BlocklistConfig {
                enabled: true,
                decision_cache_size: 1000,
                lists: vec![],
                wildcard_block: vec![],
                whitelist: vec![],
                client_bypass: vec![],
                profiles: vec![BlocklistProfileConfig {
                    id: "kids".into(),
                    name: "Kids".into(),
                    lists: vec![],
                    clients: vec!["10.0.0.2".into()],
                    block: vec!["social.example".into()],
                    allow: vec![],
                    allowlists: Vec::new(),
                    default_deny: false,
                }],
            },
            AllowlistConfig {
                domains: vec![],
                lists: vec![ListConfig {
                    name: "Allow".into(),
                    url: format!("file://{}", allow_src.display()),
                    enabled: true,
                }],
            },
            fst_path,
        );
        blocklist.refresh(false).await.unwrap();

        // Default clients: subscribed allow entry, nothing blocks it.
        assert!(!blocklist.should_block_for("social.example", None));
        assert!(blocklist.is_whitelisted_normalized("social.example"));
        // A per-device profile block still wins over the allow tier (same
        // precedence as over the manual whitelist).
        let kids = blocklist.profile_for("10.0.0.2", None);
        assert!(kids.is_some());
        assert!(blocklist.should_block_for("social.example", kids.as_deref()));
    }

    #[test]
    fn load_from_disk_restores_allowlist_fst_and_counts() {
        let fst_path = temp_fst_path("ferrite-allowlist-restore");
        let dir = fst_path.parent().unwrap().to_path_buf();
        let allow_dir = dir.join("allowlists");
        std::fs::create_dir_all(&allow_dir).unwrap();

        let allow_fst = || loader::build_fst(vec!["cdn.example".to_string()]).unwrap();
        std::fs::write(&fst_path, allow_fst()).unwrap();
        std::fs::write(dir.join("allowlist.fst"), allow_fst()).unwrap();
        let safe = refresh::sanitize_name("Allow");
        std::fs::write(allow_dir.join(format!("{safe}.fst")), allow_fst()).unwrap();

        let blocklist = Blocklist::new(
            BlocklistConfig {
                enabled: true,
                decision_cache_size: 1000,
                lists: vec![],
                wildcard_block: vec![],
                whitelist: vec![],
                client_bypass: vec![],
                profiles: vec![],
            },
            AllowlistConfig {
                domains: vec![],
                lists: vec![ListConfig {
                    name: "Allow".into(),
                    url: "https://x.test/allow".into(),
                    enabled: true,
                }],
            },
            fst_path,
        );
        assert!(blocklist.load_from_disk());
        // cdn.example is in the merged block FST *and* the allow FST — the
        // allow tier wins, straight from the disk caches (no refresh).
        assert!(blocklist.is_whitelisted_normalized("cdn.example"));
        assert!(!blocklist.should_block_for("cdn.example", None));
        assert_eq!(blocklist.allow_domain_count("Allow"), Some(1));
    }

    #[test]
    fn load_from_disk_misses_when_allowlists_configured_but_not_cached() {
        let fst_path = temp_fst_path("ferrite-allowlist-miss");
        std::fs::create_dir_all(fst_path.parent().unwrap()).unwrap();
        std::fs::write(
            &fst_path,
            loader::build_fst(vec!["ads.example".to_string()]).unwrap(),
        )
        .unwrap();

        let blocklist = Blocklist::new(
            BlocklistConfig {
                enabled: true,
                decision_cache_size: 1000,
                lists: vec![],
                wildcard_block: vec![],
                whitelist: vec![],
                client_bypass: vec![],
                profiles: vec![],
            },
            AllowlistConfig {
                domains: vec![],
                lists: vec![ListConfig {
                    name: "Allow".into(),
                    url: "https://x.test/allow".into(),
                    enabled: true,
                }],
            },
            fst_path,
        );
        // The merged blocklist FST is cached but the allowlist isn't (first
        // boot after allowlists were added) — report a miss so startup runs a
        // refresh that fetches them.
        assert!(!blocklist.load_from_disk());
    }

    #[test]
    fn allow_list_crud_mirrors_blocklist_semantics() {
        let blocklist = Blocklist::new(
            BlocklistConfig {
                enabled: true,
                decision_cache_size: 128,
                lists: vec![],
                wildcard_block: vec![],
                whitelist: vec![],
                client_bypass: vec![],
                profiles: vec![],
            },
            AllowlistConfig::default(),
            temp_fst_path("ferrite-allowlist-crud"),
        );

        let cfg = ListConfig {
            name: "Allow".into(),
            url: "https://x.test/allow".into(),
            enabled: true,
        };
        blocklist.add_allow_list(cfg.clone()).unwrap();
        assert!(
            blocklist.add_allow_list(cfg).is_err(),
            "duplicate name must be rejected"
        );
        assert!(blocklist.set_allow_list_enabled("Allow", false));
        assert!(!blocklist.get_allow_lists()[0].enabled);
        assert!(!blocklist.set_allow_list_enabled("Ghost", false));
        assert!(blocklist.remove_allow_list("Allow"));
        assert!(!blocklist.remove_allow_list("Allow"));
        assert!(blocklist.get_allow_lists().is_empty());
    }

    #[tokio::test]
    async fn default_deny_blocks_everything_except_allow_tiers() {
        use crate::config::BlocklistProfileConfig;

        let fst_path = temp_fst_path("ferrite-default-deny");
        let dir = fst_path.parent().unwrap().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        let feed_src = dir.join("feed.txt");
        std::fs::write(&feed_src, "feed.example\n").unwrap();

        let blocklist = Blocklist::new(
            BlocklistConfig {
                enabled: true,
                decision_cache_size: 1000,
                lists: vec![],
                wildcard_block: vec![],
                whitelist: vec![],
                client_bypass: vec![],
                profiles: vec![BlocklistProfileConfig {
                    id: "kid".into(),
                    name: "Kid".into(),
                    lists: vec![],
                    clients: vec!["10.0.0.2".into()],
                    block: vec![],
                    allow: vec!["app.example".into()],
                    allowlists: vec![],
                    default_deny: true,
                }],
            },
            AllowlistConfig {
                domains: vec!["manual.example".into()],
                lists: vec![ListConfig {
                    name: "Feed".into(),
                    url: format!("file://{}", feed_src.display()),
                    enabled: true,
                }],
            },
            fst_path,
        );
        blocklist.refresh(false).await.unwrap();

        let kid = blocklist.profile_for("10.0.0.2", None);
        assert!(kid.is_some());
        let kid = kid.as_deref();

        // Everything unknown is blocked for the default-deny profile…
        assert!(blocklist.should_block_for("random.example", kid));
        assert!(blocklist.should_block_for("www.google.com", kid));
        // …every allow tier exempts, with the hierarchy walk:
        assert!(!blocklist.should_block_for("app.example", kid)); // profile allow
        assert!(!blocklist.should_block_for("sub.app.example", kid));
        assert!(!blocklist.should_block_for("manual.example", kid)); // manual domains
        assert!(!blocklist.should_block_for("www.manual.example", kid));
        assert!(!blocklist.should_block_for("feed.example", kid)); // inherited allowlist
        assert!(!blocklist.should_block_for("cdn.feed.example", kid));

        // Other clients are untouched (no block sources configured).
        assert!(!blocklist.should_block_for("random.example", None));
    }

    #[tokio::test]
    async fn default_deny_exempts_local_infra_but_not_from_blacklist() {
        use crate::config::BlocklistProfileConfig;

        let blocklist = Blocklist::new(
            BlocklistConfig {
                enabled: true,
                decision_cache_size: 1000,
                lists: vec![],
                wildcard_block: vec![],
                whitelist: vec![],
                client_bypass: vec![],
                profiles: vec![BlocklistProfileConfig {
                    id: "kiosk".into(),
                    name: "Kiosk".into(),
                    lists: vec![],
                    clients: vec!["10.0.0.3".into()],
                    block: vec![],
                    allow: vec![],
                    allowlists: vec![],
                    default_deny: true,
                }],
            },
            AllowlistConfig::default(),
            temp_fst_path("ferrite-default-deny-infra"),
        );
        blocklist.rebuild_profiles();
        blocklist.set_local_zones(&["corp.example".to_string()]);

        let kiosk = blocklist.profile_for("10.0.0.3", None);
        assert!(kiosk.is_some());
        let kiosk = kiosk.as_deref();

        // Local infrastructure resolves without any per-profile configuration:
        // reverse DNS, bare hostnames, well-known local suffixes, configured zones.
        assert!(!blocklist.should_block_for("1.1.168.192.in-addr.arpa", kiosk));
        assert!(!blocklist.should_block_for("nas", kiosk));
        assert!(!blocklist.should_block_for("printer.lan", kiosk));
        assert!(!blocklist.should_block_for("tv.local", kiosk));
        assert!(!blocklist.should_block_for("host.localdomain", kiosk));
        assert!(!blocklist.should_block_for("router.home", kiosk));
        assert!(!blocklist.should_block_for("api.corp.example", kiosk));
        // Ordinary internet names stay denied.
        assert!(blocklist.should_block_for("example.com", kiosk));

        // The exemption falls through to the normal sources, it doesn't
        // outright allow: a blacklisted local name still blocks.
        blocklist.add_blacklist("bad.lan").unwrap();
        assert!(blocklist.should_block_for("bad.lan", kiosk));
    }

    #[test]
    fn has_suffix_respects_label_boundaries() {
        assert!(has_suffix("printer.lan", "lan"));
        assert!(has_suffix("lan", "lan"));
        assert!(has_suffix("a.b.corp.example", "corp.example"));
        assert!(!has_suffix("mylan.com", "lan"));
        assert!(!has_suffix("foolan", "lan"));
        assert!(!has_suffix("lan.example.com", "lan"));
    }

    #[tokio::test]
    async fn profile_allowlist_subset_overrides_the_global_allow_set() {
        use crate::config::BlocklistProfileConfig;

        let fst_path = temp_fst_path("ferrite-profile-allowlist-subset");
        let dir = fst_path.parent().unwrap().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        let kid_src = dir.join("kidsafe.txt");
        std::fs::write(&kid_src, "kid.example\n").unwrap();
        let gen_src = dir.join("general.txt");
        std::fs::write(&gen_src, "gen.example\n").unwrap();

        let blocklist = Blocklist::new(
            BlocklistConfig {
                enabled: true,
                decision_cache_size: 1000,
                lists: vec![],
                wildcard_block: vec![],
                whitelist: vec![],
                client_bypass: vec![],
                profiles: vec![BlocklistProfileConfig {
                    id: "kid".into(),
                    name: "Kid".into(),
                    lists: vec![],
                    clients: vec!["10.0.0.2".into()],
                    block: vec![],
                    allow: vec![],
                    allowlists: vec!["KidSafe".into()],
                    default_deny: true,
                }],
            },
            AllowlistConfig {
                domains: vec![],
                lists: vec![
                    ListConfig {
                        name: "KidSafe".into(),
                        url: format!("file://{}", kid_src.display()),
                        enabled: true,
                    },
                    ListConfig {
                        name: "General".into(),
                        url: format!("file://{}", gen_src.display()),
                        enabled: true,
                    },
                ],
            },
            fst_path,
        );
        blocklist.refresh(false).await.unwrap();

        let kid = blocklist.profile_for("10.0.0.2", None);
        assert!(kid.is_some());
        let kid = kid.as_deref();

        // The named subset applies — the other allowlist does NOT leak in.
        assert!(!blocklist.should_block_for("kid.example", kid));
        assert!(blocklist.should_block_for("gen.example", kid));

        // The subset also scopes ordinary (non-default-deny) exemptions: a
        // global block that only "General" would exempt stays blocked for the
        // profile, while unprofiled clients keep the global exemption.
        blocklist.add_blacklist("gen.example").unwrap();
        assert!(blocklist.should_block_for("gen.example", kid));
        assert!(!blocklist.should_block_for("gen.example", None));
    }

    #[test]
    fn whitelisted_parent_overrides_blocked_subdomain() {
        // Reproduces the reported "domain is whitelisted but its subdomain is
        // still blocked" bug: a blocklist (FST) entry for `google.com` blocks
        // every subdomain via the hierarchy walk, so whitelisting the parent
        // must exempt them too.
        let fst_path = temp_fst_path("ferrite-blocklist-wl-over-block");
        std::fs::create_dir_all(fst_path.parent().unwrap()).unwrap();
        let fst_bytes =
            crate::blocklist::loader::build_fst(vec!["google.com".to_string()]).unwrap();
        std::fs::write(&fst_path, fst_bytes).unwrap();

        let blocklist = Blocklist::new(
            BlocklistConfig {
                enabled: true,
                decision_cache_size: 128,
                lists: vec![],
                wildcard_block: vec![],
                whitelist: vec![],
                client_bypass: vec![],
                profiles: vec![],
            },
            AllowlistConfig::default(),
            fst_path,
        );
        assert!(blocklist.load_from_disk());

        assert!(blocklist.is_blocked_normalized("www.google.com"));
        assert!(!blocklist.is_whitelisted_normalized("www.google.com"));

        blocklist.add_whitelist("google.com").unwrap();
        // The handler gates blocking on `!is_whitelisted`, so this is what makes
        // www.google.com resolve again.
        assert!(blocklist.is_whitelisted_normalized("www.google.com"));
    }
}
