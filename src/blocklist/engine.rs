use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use fst::{Map, MapBuilder};
use parking_lot::RwLock;
use regex::Regex;

use crate::blocklist::cache::BlocklistCache;
use crate::blocklist::refresh;
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
    data: ArcSwap<BlocklistData>,
    whitelist: RwLock<HashSet<String>>,
    /// Wildcard entries for the whitelist, e.g. `*.safe.example.com`.
    whitelist_wildcards: RwLock<Vec<(String, Regex)>>,
    blacklist: RwLock<HashSet<String>>,
    blacklist_wildcards: RwLock<Vec<(String, Regex)>>,
    cache: BlocklistCache,
    lists: RwLock<Vec<ListConfig>>,
    /// Domain count per list name, updated after each refresh.
    domain_counts: RwLock<HashMap<String, usize>>,
    fst_path: PathBuf,
    list_cache_dir: PathBuf,
}

impl Blocklist {
    pub fn new(config: BlocklistConfig, fst_path: PathBuf) -> Self {
        let empty_fst = empty_fst();

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
            data: ArcSwap::from_pointee(BlocklistData {
                fst: empty_fst,
                wildcards,
            }),
            whitelist: RwLock::new(whitelist),
            whitelist_wildcards: RwLock::new(whitelist_wildcards),
            blacklist: RwLock::new(HashSet::new()),
            blacklist_wildcards: RwLock::new(Vec::new()),
            cache: BlocklistCache::new(config.decision_cache_size),
            lists: RwLock::new(config.lists),
            domain_counts: RwLock::new(HashMap::new()),
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
        if self.blacklist.read().contains(domain) {
            return true;
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
        let mut rest = domain;
        while let Some(dot) = rest.find('.') {
            rest = &rest[dot + 1..];
            if rest.contains('.') && data.fst.contains_key(rest.as_bytes()) {
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
    pub fn is_whitelisted_normalized(&self, domain: &str) -> bool {
        if self.whitelist.read().contains(domain) {
            return true;
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
            self.cache.clear();
        } else {
            self.cache.invalidate(&d);
            self.whitelist.write().insert(d);
        }
        Ok(())
    }

    pub fn remove_whitelist(&self, domain: &str) {
        let d = normalise(domain);
        if d.contains('*') {
            self.whitelist_wildcards
                .write()
                .retain(|(pat, _)| pat != &d);
            self.cache.clear();
        } else {
            self.cache.invalidate(&d);
            self.whitelist.write().remove(&d);
        }
    }

    pub fn add_blacklist(&self, domain: &str) -> Result<()> {
        let d = normalise(domain);
        if d.contains('*') {
            let re = wildcard_to_regex(&d)?;
            self.blacklist_wildcards.write().push((d, re));
            self.cache.clear();
        } else {
            self.cache.invalidate(&d);
            self.blacklist.write().insert(d);
        }
        Ok(())
    }

    pub fn remove_blacklist(&self, domain: &str) {
        let d = normalise(domain);
        if d.contains('*') {
            self.blacklist_wildcards
                .write()
                .retain(|(pat, _)| pat != &d);
            self.cache.clear();
        } else {
            self.cache.invalidate(&d);
            self.blacklist.write().remove(&d);
        }
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
    pub async fn refresh(&self) -> Result<usize> {
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
                tokio::spawn(async move {
                    let Ok(_permit) = permits.acquire_owned().await else {
                        return (String::new(), vec![], 0);
                    };
                    refresh::load_or_build_list_fst(name, url, fst_cache, domains_cache).await
                })
            })
            .collect();

        let mut per_list_fsts: Vec<Vec<u8>> = Vec::with_capacity(lists.len());
        let mut counts: HashMap<String, usize> = HashMap::new();

        for task in tasks {
            let (name, fst_bytes, count) = task.await.unwrap_or_else(|e| {
                tracing::error!("list task panicked: {}", e);
                (String::new(), vec![], 0)
            });
            if !name.is_empty() {
                counts.insert(name, count);
                per_list_fsts.push(fst_bytes);
            }
        }

        *self.domain_counts.write() = counts;

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

        self.data.store(Arc::new(BlocklistData { fst, wildcards }));
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

// ── Internal helpers ──────────────────────────────────────────────────────────

fn normalise(domain: &str) -> String {
    domain
        .to_ascii_lowercase()
        .trim_end_matches('.')
        .to_string()
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

fn wildcard_to_regex(pattern: &str) -> Result<Regex> {
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
                decision_cache_size: 50_000,
                lists: vec![],
                wildcard_block: vec!["*.ads.test".to_string()],
                whitelist: vec![],
            },
            temp_fst_path("ferrite-blocklist-wildcard"),
        );

        assert!(blocklist.is_blocked("tracker.ads.test"));
        blocklist.refresh().await.unwrap();
        assert!(blocklist.is_blocked("tracker.ads.test"));
    }

    #[test]
    fn config_entries_are_normalized_once_for_hot_path_lookups() {
        let blocklist = Blocklist::new(
            BlocklistConfig {
                decision_cache_size: 128,
                lists: vec![],
                wildcard_block: vec!["*.Ads.Test.".to_string()],
                whitelist: vec!["Safe.Test.".to_string(), "*.Trusted.Test.".to_string()],
            },
            temp_fst_path("ferrite-blocklist-normalized"),
        );

        assert!(blocklist.is_whitelisted("SAFE.TEST."));
        assert!(blocklist.is_whitelisted_normalized("app.trusted.test"));
        assert!(blocklist.is_blocked("Tracker.Ads.Test."));
        assert!(blocklist.is_blocked_normalized("tracker.ads.test"));
    }
}
