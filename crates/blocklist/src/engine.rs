use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use arc_swap::ArcSwap;
use parking_lot::RwLock;

use crate::ListPolarity;
use crate::cache::BlocklistCache;
use crate::loader::FstMap;
use crate::manual::ManualList;
use crate::names::{has_suffix, is_registrable_or_deeper, matched_key, normalise};
use crate::profiles::{CompiledProfile, compile_profiles};
use crate::subscriptions::Subscriptions;
use ferrite_core::config::{AllowlistConfig, BlocklistConfig};
use ferrite_core::error::Result;
use ferrite_core::net::normalize_client_key;

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
    /// Subscribed blocklists and their merged FST — the subscription tier of
    /// the block decision.
    ///
    /// Manual block patterns are *not* here — they live in `blacklist` /
    /// `blacklist_wildcards`, which the API can also remove from. Config-sourced
    /// entries used to be compiled into a second, parallel wildcard set, which
    /// meant an entry written in the file could be matched but never listed or
    /// deleted through the UI. One set, one lifecycle.
    block: Subscriptions,
    /// Subscribed allowlists — the same decision tier as the manual whitelist.
    allow: Subscriptions,
    /// Per-device profiles (each a subset-of-lists FST + private cache), compiled
    /// from `profiles_config` and the on-disk per-list FSTs. Rebuilt on refresh,
    /// on startup load, and when the profile set changes via the API.
    profiles: ArcSwap<Vec<Arc<CompiledProfile>>>,
    /// Source of truth for [`Self::rebuild_profiles`]; the compiled `profiles`
    /// above are derived from this plus the per-list disk caches.
    profiles_config: RwLock<Vec<ferrite_core::config::BlocklistProfileConfig>>,
    client_bypass: ArcSwap<HashSet<String>>,
    /// Manual allow entries — the `[allowlist] domains` tier.
    whitelist: ManualList,
    /// Manual block entries — `[blocklist] domains`.
    blacklist: ManualList,
    cache: BlocklistCache,
    /// Configured `[[zones]]` suffixes (normalised), exempt from profile
    /// default-deny alongside the built-in local suffixes. Set once at startup
    /// via [`Self::set_local_zones`] (zones are restart-required config).
    local_zones: RwLock<Vec<String>>,
    /// Serialises [`Self::refresh`] so concurrent API-triggered refreshes don't
    /// race on the swapped FSTs and counts or pile up duplicate network fetches.
    refresh_lock: tokio::sync::Mutex<()>,
}

impl Blocklist {
    pub fn new(config: BlocklistConfig, allowlist: AllowlistConfig, fst_path: PathBuf) -> Self {
        let client_bypass: HashSet<String> = normalize_client_keys(&config.client_bypass)
            .into_iter()
            .collect();

        // Manual allowlist entries. `config.whitelist` is the deprecated
        // location — `Config::normalize` migrates it, but seed from both so a
        // directly-constructed BlocklistConfig keeps its old semantics.
        let whitelist = ManualList::from_entries(config.whitelist.iter().chain(&allowlist.domains));
        // Manual block entries. `config.wildcard_block` is the deprecated
        // location — `Config::normalize` migrates it into `domains`, but seed
        // from both so a directly-constructed BlocklistConfig keeps working.
        let blacklist =
            ManualList::from_entries(config.domains.iter().chain(&config.wildcard_block));

        // Per-list caches and the merged allowlist sit beside the merged blocklist.
        let dir = fst_path.parent().unwrap_or(Path::new("")).to_path_buf();
        let block = Subscriptions::new(
            ListPolarity::Block,
            config.lists,
            fst_path,
            dir.join("lists"),
        );
        let allow = Subscriptions::new(
            ListPolarity::Allow,
            allowlist.lists,
            dir.join("allowlist.fst"),
            dir.join("allowlists"),
        );

        Self {
            enabled: AtomicBool::new(config.enabled),
            has_client_bypass: AtomicBool::new(!client_bypass.is_empty()),
            has_profiles: AtomicBool::new(!config.profiles.is_empty()),
            block,
            allow,
            profiles: ArcSwap::from_pointee(Vec::new()),
            profiles_config: RwLock::new(config.profiles),
            client_bypass: ArcSwap::from_pointee(client_bypass),
            whitelist,
            blacklist,
            cache: BlocklistCache::new(config.decision_cache_size),
            local_zones: RwLock::new(Vec::new()),
            refresh_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Try to load the previously saved FSTs from disk. Serves them via mmap so
    /// the (potentially tens-of-MB) maps live in the page cache, not anonymous
    /// RSS. Returns `false` when anything that should be cached is missing or
    /// invalid — the caller then runs a refresh, which reuses whatever per-list
    /// caches are still fresh.
    pub fn load_from_disk(&self) -> bool {
        match self.block.load_merged() {
            Ok(Some(count)) => {
                self.cache.clear();
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
            Ok(None) => false, // first boot — nothing cached yet
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
        let configured = self.allow.is_configured();
        match self.allow.load_merged() {
            Ok(Some(count)) => {
                if configured || count > 0 {
                    tracing::info!("allowlist loaded from disk: {} domains", count);
                }
                true
            }
            Ok(None) => !configured,
            Err(e) => {
                tracing::warn!(
                    "cached allowlist FST on disk is invalid, will re-fetch: {}",
                    e
                );
                !configured
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
        let result = self.check_blocked_in(domain, &self.block.fst());
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
        // Manual blacklist: exact match, then walk up the hierarchy so a
        // blacklist entry for `evil.com` also blocks `www.evil.com` —
        // symmetric with the FST walk below and the whitelist walk.
        if self.blacklist.contains(domain) {
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
            self.block.cache_dir(),
            self.allow.cache_dir(),
            self.block.merged_set().as_ref(),
            self.allow.merged_set().as_ref(),
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
        let list_dir = self.block.cache_dir().to_path_buf();
        let allow_dir = self.allow.cache_dir().to_path_buf();
        let merged = self.block.merged_set();
        let allow_merged = self.allow.merged_set();
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
        if self.whitelist.contains(domain) {
            return true;
        }
        // Subscribed allowlists: same exact + hierarchy walk against the merged
        // allow FST (mmap'd, so this is a page-cache probe, not a RAM scan).
        match profile.and_then(|p| p.allow_fst.as_ref()) {
            Some(fst) => matched_key(domain, |k| fst.contains_key(k.as_bytes())).is_some(),
            None => {
                let allow = self.allow.fst();
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
        if let Some(key) = self.blacklist.exact_match(&domain) {
            sources.push(BlockSource {
                kind: "blacklist".into(),
                name: "manual blacklist".into(),
                matched: key,
            });
        }
        // Manual blacklist wildcards.
        for pat in self.blacklist.matching_patterns(&domain) {
            sources.push(BlockSource {
                kind: "wildcard".into(),
                name: pat,
                matched: domain.clone(),
            });
        }
        // Subscription lists: scan each enabled list's own on-disk FST so the
        // match attributes to a specific list (the merged hot-path FST can't).
        let mut list_matched = false;
        for (name, key) in self.block.attribute(&domain) {
            list_matched = true;
            sources.push(BlockSource {
                kind: "list".into(),
                name,
                matched: key,
            });
        }
        // Fallback: the merged FST matches but no per-list file attributed it
        // (e.g. a source file is missing) — still report the block.
        if !list_matched && let Some(key) = self.block.merged_match(&domain) {
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
        if let Some(key) = self.whitelist.exact_match(domain) {
            return Some(MatchInfo {
                entry: key.clone(),
                matched: key,
                list: None,
            });
        }
        if let Some(pat) = self.whitelist.matching_patterns(domain).into_iter().next() {
            return Some(MatchInfo {
                entry: pat,
                matched: domain.to_string(),
                list: None,
            });
        }
        if let Some((name, key)) = self.allow.attribute(domain).next() {
            return Some(MatchInfo {
                entry: key.clone(),
                matched: key,
                list: Some(name),
            });
        }
        // Fallback: the merged allow FST matches but no per-list file attributed
        // it (e.g. a source file is missing) — still report the exemption.
        if let Some(key) = self.allow.merged_match(domain) {
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
        self.whitelist.add(domain)?;
        // A whitelist/blacklist entry matches subdomains via the hierarchy
        // walk, so an exact-key invalidation can't cover the cached block/allow
        // decisions it affects — clear the whole decision cache.
        self.clear_decision_caches();
        Ok(())
    }

    pub fn remove_whitelist(&self, domain: &str) {
        self.whitelist.remove(domain);
        self.clear_decision_caches();
    }

    pub fn add_blacklist(&self, domain: &str) -> Result<()> {
        self.blacklist.add(domain)?;
        self.clear_decision_caches();
        Ok(())
    }

    pub fn remove_blacklist(&self, domain: &str) {
        self.blacklist.remove(domain);
        self.clear_decision_caches();
    }

    pub fn list_whitelist(&self) -> Vec<String> {
        self.whitelist.entries()
    }

    pub fn list_blacklist(&self) -> Vec<String> {
        self.blacklist.entries()
    }

    // ── Subscriptions ────────────────────────────────────────────────────────

    /// The subscription set of `polarity` — the blocklists or the allowlists.
    pub fn subscriptions(&self, polarity: ListPolarity) -> &Subscriptions {
        match polarity {
            ListPolarity::Block => &self.block,
            ListPolarity::Allow => &self.allow,
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

        let block = self.block.refresh(force).await?;
        let allow_changed = self.refresh_allowlists(force).await;

        // Nothing moved: the decision cache is still answering off the same sets,
        // and the compiled profiles off the same per-list FSTs. Clearing and
        // recompiling them here would cost seconds of CPU and a cold cache to
        // arrive at exactly what is already in place.
        if block.changed || allow_changed {
            self.cache.clear();
            // The per-list FSTs just refreshed — recompile profiles off the fresh
            // subset caches so device profiles track list updates.
            self.rebuild_profiles_off_thread().await;
            tracing::info!("blocklist refreshed: {} unique domains", block.unique_count);
        } else {
            tracing::info!(
                "blocklist unchanged: {} unique domains, nothing rebuilt",
                block.unique_count
            );
        }
        Ok(block.unique_count)
    }

    /// Allowlist half of [`Self::refresh`] — same pipeline, opposite polarity.
    /// A total failure keeps the previous allow set and never fails the whole
    /// refresh: serving stale allows beats suddenly re-blocking domains the
    /// user explicitly exempted.
    ///
    /// Returns `true` when the allow set actually moved.
    async fn refresh_allowlists(&self, force: bool) -> bool {
        let has_enabled = self.allow.has_enabled();
        // Nothing subscribed and nothing persisted → keep the in-memory empty
        // FST and don't create cache dirs/files for an unused feature. (With a
        // stale merged file still on disk the rebuild below runs and overwrites
        // it with an empty FST, so removing the last allowlist takes effect.)
        if !has_enabled && !self.allow.merged_path().exists() {
            return false;
        }
        match self.allow.refresh(force).await {
            Ok(set) => {
                if has_enabled && set.changed {
                    tracing::info!("allowlist refreshed: {} unique domains", set.unique_count);
                }
                set.changed
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

    /// Unique domains in the merged blocklist FST.
    pub fn blocked_count(&self) -> u64 {
        self.block.fst().len() as u64
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

pub(crate) fn normalize_client_keys(entries: &[String]) -> Vec<String> {
    let normalized: BTreeSet<String> = entries
        .iter()
        .filter_map(|key| normalize_client_key(key))
        .collect();
    normalized.into_iter().collect()
}

#[cfg(test)]
mod tests;
