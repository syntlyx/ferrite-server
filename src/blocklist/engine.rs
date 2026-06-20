use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use arc_swap::ArcSwap;
use fst::{Map, MapBuilder};
use parking_lot::RwLock;
use regex::Regex;

use crate::blocklist::cache::BlocklistCache;
use crate::blocklist::{AdblockStats, refresh};
use crate::clients::normalize_client_key;
use crate::config::{BlocklistConfig, ListConfig};
use crate::error::{FeriteError, Result};

type FstBuildResult = (Map<Vec<u8>>, Vec<Regex>, usize);
const MAX_CONCURRENT_LIST_REFRESHES: usize = 2;

/// The hot-swappable core data (FST + wildcards).
struct BlocklistData {
    fst: Map<Vec<u8>>,
    wildcards: Vec<Regex>,
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
    data: ArcSwap<BlocklistData>,
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
    /// Serialises [`Self::refresh`] so concurrent API-triggered refreshes don't
    /// race on `data`/`domain_counts` or pile up duplicate network fetches.
    refresh_lock: tokio::sync::Mutex<()>,
    fst_path: PathBuf,
    list_cache_dir: PathBuf,
}

impl Blocklist {
    pub fn new(config: BlocklistConfig, fst_path: PathBuf) -> Self {
        let empty_fst = empty_fst();

        let client_bypass: HashSet<String> = normalize_client_keys(&config.client_bypass)
            .into_iter()
            .collect();

        let whitelist: HashSet<String> = config
            .whitelist
            .iter()
            .filter(|s| !s.contains('*'))
            .map(|s| normalise(s))
            .collect();

        let whitelist_wildcards: Vec<(String, Regex)> = config
            .whitelist
            .iter()
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

        Self {
            enabled: AtomicBool::new(config.enabled),
            has_client_bypass: AtomicBool::new(!client_bypass.is_empty()),
            data: ArcSwap::from_pointee(BlocklistData {
                fst: empty_fst,
                wildcards,
            }),
            client_bypass: ArcSwap::from_pointee(client_bypass),
            whitelist: RwLock::new(whitelist),
            whitelist_wildcards: RwLock::new(whitelist_wildcards),
            blacklist: RwLock::new(HashSet::new()),
            blacklist_wildcards: RwLock::new(Vec::new()),
            cache: BlocklistCache::new(config.decision_cache_size),
            lists: RwLock::new(config.lists),
            domain_counts: RwLock::new(HashMap::new()),
            adblock_stats: RwLock::new(HashMap::new()),
            refresh_lock: tokio::sync::Mutex::new(()),
            fst_path,
            list_cache_dir,
        }
    }

    /// Try to load a previously saved FST from disk.
    pub fn load_from_disk(&self) -> bool {
        let bytes = match std::fs::read(&self.fst_path) {
            Ok(b) => b,
            Err(_) => return false,
        };
        match Map::new(bytes) {
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
                tracing::info!("blocklist loaded from disk: {} domains", count);
                true
            }
            Err(e) => {
                tracing::warn!("cached FST on disk is invalid, will re-fetch: {}", e);
                false
            }
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
        let result = self.check_blocked(domain);
        self.cache.insert(domain, result);
        result
    }

    fn check_blocked(&self, domain: &str) -> bool {
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

        let data = self.data.load();

        if data.fst.contains_key(domain.as_bytes()) {
            return true;
        }
        for re in &data.wildcards {
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
            if is_registrable_or_deeper(rest) && data.fst.contains_key(rest.as_bytes()) {
                return true;
            }
        }
        false
    }

    /// Returns `true` if `domain` is explicitly whitelisted (exact or wildcard match).
    pub fn is_whitelisted(&self, domain: &str) -> bool {
        let domain = normalise(domain);
        self.is_whitelisted_normalized(&domain)
    }

    /// Like [`Self::is_whitelisted`], but assumes `domain` is already lowercase
    /// and has no trailing root dot. Used by the DNS hot path.
    ///
    /// Matching walks up the domain hierarchy so that whitelisting `example.com`
    /// also exempts `www.example.com`, mirroring how [`Self::check_blocked`]
    /// matches a blocked parent against its subdomains. Without this the two
    /// checks are asymmetric: a blocklist entry for `example.com` blocks every
    /// subdomain, but a whitelist entry for `example.com` would only exempt the
    /// exact name — so a whitelisted domain's subdomains would stay blocked.
    pub fn is_whitelisted_normalized(&self, domain: &str) -> bool {
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
        self.whitelist_wildcards
            .read()
            .iter()
            .any(|(_, re)| re.is_match(domain))
    }

    // ── Whitelist / blacklist CRUD ───────────────────────────────────────────

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
        self.cache.clear();
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
        self.cache.clear();
    }

    pub fn add_blacklist(&self, domain: &str) -> Result<()> {
        let d = normalise(domain);
        if d.contains('*') {
            let re = wildcard_to_regex(&d)?;
            self.blacklist_wildcards.write().push((d, re));
        } else {
            self.blacklist.write().insert(d);
        }
        self.cache.clear();
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
        self.cache.clear();
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

    // ── FST refresh ──────────────────────────────────────────────────────────

    /// Fetch all enabled lists and atomically replace the global FST.
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

        let _ = tokio::fs::create_dir_all(&self.list_cache_dir).await;
        let refresh_permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_LIST_REFRESHES));

        let tasks: Vec<_> = lists
            .iter()
            .map(|list| {
                let name = list.name.clone();
                let url = list.url.clone();
                let permits = Arc::clone(&refresh_permits);
                let fst_cache = self
                    .list_cache_dir
                    .join(format!("{}.fst", refresh::sanitize_name(&list.name)));
                let domains_cache = self
                    .list_cache_dir
                    .join(format!("{}.domains", refresh::sanitize_name(&list.name)));
                let stats_cache = self
                    .list_cache_dir
                    .join(format!("{}.stats.json", refresh::sanitize_name(&list.name)));
                tokio::spawn(async move {
                    let Ok(_permit) = permits.acquire_owned().await else {
                        return (String::new(), vec![], 0, None);
                    };
                    refresh::load_or_build_list_fst(
                        name,
                        url,
                        fst_cache,
                        domains_cache,
                        stats_cache,
                        force,
                    )
                    .await
                })
            })
            .collect();

        let mut per_list_fsts: Vec<Vec<u8>> = Vec::with_capacity(lists.len());
        let mut counts: HashMap<String, usize> = HashMap::new();
        let mut stats: HashMap<String, AdblockStats> = HashMap::new();

        for task in tasks {
            let (name, fst_bytes, count, list_stats) = task.await.unwrap_or_else(|e| {
                tracing::error!("list task panicked: {}", e);
                (String::new(), vec![], 0, None)
            });
            if !name.is_empty() {
                if let Some(s) = list_stats {
                    stats.insert(name.clone(), s);
                }
                counts.insert(name, count);
                per_list_fsts.push(fst_bytes);
            }
        }

        if !lists.is_empty() && per_list_fsts.is_empty() {
            return Err(FeriteError::Fst(
                "all enabled blocklists failed and no cached domains are available".to_string(),
            ));
        }

        let fst_path = self.fst_path.clone();
        let wildcards = self.data.load().wildcards.clone();

        let (fst, wildcards, unique_count) =
            tokio::task::spawn_blocking(move || -> Result<FstBuildResult> {
                use crate::blocklist::loader;
                let fst_bytes = loader::merge_fsts(&per_list_fsts)?;
                let unique_count = Map::new(fst_bytes.as_slice())
                    .map_err(|e| FeriteError::Fst(e.to_string()))?
                    .len();

                if let Some(parent) = fst_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let tmp = fst_path.with_extension("fst.tmp");
                if std::fs::write(&tmp, &fst_bytes).is_ok() {
                    let _ = std::fs::rename(&tmp, &fst_path);
                    tracing::info!("blocklist FST saved to disk");
                }

                let fst = Map::new(fst_bytes).map_err(|e| FeriteError::Fst(e.to_string()))?;
                Ok((fst, wildcards, unique_count))
            })
            .await
            .map_err(|e| FeriteError::Internal(e.to_string()))??;

        // Install the new FST and its domain counts together so a reader never
        // sees counts from one refresh paired with the FST of another.
        self.data.store(Arc::new(BlocklistData { fst, wildcards }));
        *self.domain_counts.write() = counts;
        *self.adblock_stats.write() = stats;
        self.cache.clear();

        tracing::info!("blocklist refreshed: {} unique domains", unique_count);
        Ok(unique_count)
    }

    pub fn blocked_count(&self) -> u64 {
        self.data.load().fst.len() as u64
    }

    #[allow(dead_code)]
    pub fn invalidate(&self, domain: &str) {
        self.cache.invalidate(domain);
    }
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

fn empty_fst() -> Map<Vec<u8>> {
    let bytes = MapBuilder::memory().into_inner().expect("empty FST build");
    Map::new(bytes).expect("empty FST map")
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
            },
            temp_fst_path("ferrite-blocklist-wildcard"),
        );

        assert!(blocklist.is_blocked("tracker.ads.test"));
        blocklist.refresh(false).await.unwrap();
        assert!(blocklist.is_blocked("tracker.ads.test"));
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
            },
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
            },
            temp_fst_path("ferrite-blocklist-normalized"),
        );

        assert!(blocklist.is_whitelisted("SAFE.TEST."));
        assert!(blocklist.is_whitelisted_normalized("app.trusted.test"));
        assert!(blocklist.is_blocked("Tracker.Ads.Test."));
        assert!(blocklist.is_blocked_normalized("tracker.ads.test"));
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
            },
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
            },
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
            },
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
            },
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
            },
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
