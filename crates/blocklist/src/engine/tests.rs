use super::*;
use crate::{AdblockStats, loader, refresh};
use ferrite_core::config::ListConfig;
use fst::Map;

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
            domains: vec![],
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
        crate::loader::build_fst(domains.clone()).unwrap(),
    )
    .unwrap();

    let safe = refresh::sanitize_name("My List");
    std::fs::write(
        cache_dir.join(format!("{safe}.fst")),
        crate::loader::build_fst(domains).unwrap(),
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
            domains: vec![],
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
    assert_eq!(
        blocklist
            .subscriptions(ListPolarity::Block)
            .domain_count("My List"),
        Some(2)
    );
    let restored = blocklist
        .subscriptions(ListPolarity::Block)
        .parse_stats("My List")
        .expect("stats restored");
    assert_eq!(restored.kept, 2);
    assert_eq!(restored.exceptions, 1);
}

#[test]
fn per_device_profile_applies_a_list_subset_to_matched_clients() {
    use ferrite_core::config::BlocklistProfileConfig;

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
            domains: vec![],
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
    use ferrite_core::config::BlocklistProfileConfig;

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
            domains: vec![],
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
    let original = crate::loader::build_fst(vec!["blocked.test".to_string()]).unwrap();
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
            domains: vec![],
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
            domains: vec![],
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
            domains: vec![],
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
            domains: vec![],
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
            domains: vec![],
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
            domains: vec![],
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
            domains: vec![],
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
            domains: vec![],
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
    assert_eq!(
        blocklist
            .subscriptions(ListPolarity::Allow)
            .domain_count("Allow"),
        Some(1)
    );

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
    assert!(blocklist.subscriptions(ListPolarity::Allow).remove("Allow"));
    blocklist.refresh(false).await.unwrap();
    assert!(blocklist.should_block_for("cdn.example", None));
}

#[tokio::test]
async fn profile_block_overrides_subscribed_allowlist() {
    use ferrite_core::config::BlocklistProfileConfig;

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
            domains: vec![],
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
            domains: vec![],
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
    assert_eq!(
        blocklist
            .subscriptions(ListPolarity::Allow)
            .domain_count("Allow"),
        Some(1)
    );
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
            domains: vec![],
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
            domains: vec![],
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
    blocklist
        .subscriptions(ListPolarity::Allow)
        .add(cfg.clone())
        .unwrap();
    assert!(
        blocklist
            .subscriptions(ListPolarity::Allow)
            .add(cfg)
            .is_err(),
        "duplicate name must be rejected"
    );
    assert!(
        blocklist
            .subscriptions(ListPolarity::Allow)
            .set_enabled("Allow", false)
    );
    assert!(!blocklist.subscriptions(ListPolarity::Allow).lists()[0].enabled);
    assert!(
        !blocklist
            .subscriptions(ListPolarity::Allow)
            .set_enabled("Ghost", false)
    );
    assert!(blocklist.subscriptions(ListPolarity::Allow).remove("Allow"));
    assert!(!blocklist.subscriptions(ListPolarity::Allow).remove("Allow"));
    assert!(
        blocklist
            .subscriptions(ListPolarity::Allow)
            .lists()
            .is_empty()
    );
}

#[tokio::test]
async fn default_deny_blocks_everything_except_allow_tiers() {
    use ferrite_core::config::BlocklistProfileConfig;

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
            domains: vec![],
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
    use ferrite_core::config::BlocklistProfileConfig;

    let blocklist = Blocklist::new(
        BlocklistConfig {
            enabled: true,
            decision_cache_size: 1000,
            lists: vec![],
            domains: vec![],
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
    use ferrite_core::config::BlocklistProfileConfig;

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
            domains: vec![],
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

/// Two refreshes over the same content must not rebuild the merged FST: the
/// union would reproduce the file byte for byte, and on a Pi-class box that
/// is tens of seconds of CPU per refresh. The inode is the proof — a rebuild
/// renames a new file into place.
#[cfg(unix)]
#[tokio::test]
async fn unchanged_lists_reuse_the_merged_fst() {
    use std::os::unix::fs::MetadataExt;

    let fst_path = temp_fst_path("ferrite-merge-skip");
    let dir = fst_path.parent().unwrap().to_path_buf();
    std::fs::create_dir_all(&dir).unwrap();
    let ads = dir.join("ads.txt");
    std::fs::write(&ads, "ads.example\n").unwrap();
    let track = dir.join("track.txt");
    std::fs::write(&track, "track.example\n").unwrap();

    let blocklist = Blocklist::new(
        BlocklistConfig {
            enabled: true,
            decision_cache_size: 1000,
            lists: vec![
                ListConfig {
                    name: "Ads".into(),
                    url: format!("file://{}", ads.display()),
                    enabled: true,
                },
                ListConfig {
                    name: "Track".into(),
                    url: format!("file://{}", track.display()),
                    enabled: true,
                },
            ],
            domains: vec![],
            wildcard_block: vec![],
            whitelist: vec![],
            client_bypass: vec![],
            profiles: vec![],
        },
        AllowlistConfig::default(),
        fst_path.clone(),
    );

    blocklist.refresh(false).await.unwrap();
    assert!(blocklist.is_blocked("ads.example"));
    let first = std::fs::metadata(&fst_path).unwrap().ino();

    // Forced: both sources are read again in full, and both still hash to
    // what the merged FST was built from — so the file stays as it is.
    blocklist.refresh(true).await.unwrap();
    assert_eq!(
        std::fs::metadata(&fst_path).unwrap().ino(),
        first,
        "identical content must not rebuild the merged FST"
    );
    assert!(blocklist.is_blocked("track.example"));

    // A changed source is a changed fingerprint: merged again, and the new
    // domain blocks.
    std::fs::write(&track, "track.example\nnew.example\n").unwrap();
    blocklist.refresh(true).await.unwrap();
    assert_ne!(
        std::fs::metadata(&fst_path).unwrap().ino(),
        first,
        "a changed list must rebuild the merged FST"
    );
    assert!(blocklist.is_blocked("new.example"));

    std::fs::remove_dir_all(&dir).ok();
}

/// A profile recompiles only when its *own* lists move. Lists churn at their
/// own pace — easylist rebuilds upstream every hour — and without this one
/// such list re-merges every profile on the box, including those that never
/// named it.
#[cfg(unix)]
#[tokio::test]
async fn a_profile_recompiles_only_when_its_own_lists_move() {
    use ferrite_core::config::BlocklistProfileConfig;
    use std::os::unix::fs::MetadataExt;

    let fst_path = temp_fst_path("ferrite-profile-fingerprint");
    let dir = fst_path.parent().unwrap().to_path_buf();
    std::fs::create_dir_all(&dir).unwrap();
    let source = |name: &str, body: &str| {
        let path = dir.join(format!("{name}.txt"));
        std::fs::write(&path, body).unwrap();
        path
    };
    let ads = source("ads", "ads.example\n");
    let track = source("track", "track.example\n");
    let noisy = source("noisy", "noisy.example\n");

    let list = |name: &str, path: &PathBuf| ListConfig {
        name: name.into(),
        url: format!("file://{}", path.display()),
        enabled: true,
    };

    let blocklist = Blocklist::new(
        BlocklistConfig {
            enabled: true,
            decision_cache_size: 1000,
            lists: vec![
                list("Ads", &ads),
                list("Track", &track),
                list("Noisy", &noisy),
            ],
            domains: vec![],
            wildcard_block: vec![],
            whitelist: vec![],
            client_bypass: vec![],
            // Two of the three, so the profile keeps a map of its own rather
            // than mapping the merged one.
            profiles: vec![BlocklistProfileConfig {
                id: "kid".into(),
                name: "Kid".into(),
                lists: vec!["Ads".into(), "Track".into()],
                clients: vec!["10.0.0.2".into()],
                block: vec![],
                allow: vec![],
                allowlists: vec![],
                default_deny: false,
            }],
        },
        AllowlistConfig::default(),
        fst_path,
    );
    blocklist.refresh(false).await.unwrap();

    let profile_fst = dir.join("lists").join("profile_kid.fst");
    let compiled_at = std::fs::metadata(&profile_fst).unwrap().ino();

    // The list the profile never named changes: the global set is merged
    // again, the profile is not.
    std::fs::write(&noisy, "noisy.example\nmore.example\n").unwrap();
    blocklist.refresh(true).await.unwrap();
    assert!(blocklist.is_blocked("more.example"), "the global set moved");
    assert_eq!(
        std::fs::metadata(&profile_fst).unwrap().ino(),
        compiled_at,
        "a list this profile doesn't use must not re-merge it"
    );

    // One of its own lists changes: now it must.
    std::fs::write(&ads, "ads.example\nnew.example\n").unwrap();
    blocklist.refresh(true).await.unwrap();
    assert_ne!(
        std::fs::metadata(&profile_fst).unwrap().ino(),
        compiled_at,
        "its own list moved, so the profile must compile again"
    );
    let kid = blocklist.profile_for("10.0.0.2", None);
    assert!(blocklist.should_block_for("new.example", kid.as_deref()));

    std::fs::remove_dir_all(&dir).ok();
}

/// What a refresh actually costs, and what the fingerprint saves. Ignored —
/// run it deliberately:
///
/// ```text
/// cargo test -p ferrite-blocklist --release refresh_cost -- --ignored --nocapture
/// ```
///
/// Numbers on a dev machine are a fraction of a router's; the ratio between
/// the two refreshes is the point. On the real box (11 lists, 1.78M domains)
/// the cold pass was ~49 s, of which ~44 s was FST building and merging.
#[tokio::test]
#[ignore = "benchmark, not a correctness test"]
async fn refresh_cost_cold_vs_unchanged() {
    let fst_path = temp_fst_path("ferrite-refresh-cost");
    let dir = fst_path.parent().unwrap().to_path_buf();
    std::fs::create_dir_all(&dir).unwrap();

    // Three lists roughly the size of the ones a real box subscribes to —
    // the merge is what dominates, and it scales with the total key count.
    let lists: Vec<ListConfig> = [("Big", 1_200_000), ("Medium", 300_000), ("Small", 50_000)]
        .iter()
        .map(|(name, count)| {
            let path = dir.join(format!("{}.txt", name.to_lowercase()));
            let mut text = String::with_capacity(count * 28);
            for i in 0..*count {
                text.push_str(&format!("host{:07}.{}.example\n", i, name.to_lowercase()));
            }
            std::fs::write(&path, text).unwrap();
            ListConfig {
                name: name.to_string(),
                url: format!("file://{}", path.display()),
                enabled: true,
            }
        })
        .collect();

    let blocklist = Blocklist::new(
        BlocklistConfig {
            enabled: true,
            decision_cache_size: 1000,
            lists,
            domains: vec![],
            wildcard_block: vec![],
            whitelist: vec![],
            client_bypass: vec![],
            profiles: vec![],
        },
        AllowlistConfig::default(),
        fst_path,
    );

    let start = std::time::Instant::now();
    let count = blocklist.refresh(true).await.unwrap();
    let cold = start.elapsed();

    let start = std::time::Instant::now();
    blocklist.refresh(true).await.unwrap();
    let unchanged = start.elapsed();

    println!("refresh over {count} unique domains: cold {cold:.2?}, unchanged {unchanged:.2?}");
    std::fs::remove_dir_all(&dir).ok();
}

/// A profile that selects every enabled list is the merged FST — it must map
/// that file rather than merge the same inputs into a private copy of it.
#[tokio::test]
async fn profile_covering_every_list_serves_the_merged_fst() {
    use ferrite_core::config::BlocklistProfileConfig;

    let fst_path = temp_fst_path("ferrite-profile-merge-reuse");
    let dir = fst_path.parent().unwrap().to_path_buf();
    std::fs::create_dir_all(&dir).unwrap();
    let sources: Vec<(String, PathBuf)> = ["Ads", "Track", "Malware"]
        .iter()
        .map(|name| {
            let path = dir.join(format!("{}.txt", name.to_lowercase()));
            std::fs::write(&path, format!("{}.example\n", name.to_lowercase())).unwrap();
            (name.to_string(), path)
        })
        .collect();

    let lists: Vec<ListConfig> = sources
        .iter()
        .map(|(name, path)| ListConfig {
            name: name.clone(),
            url: format!("file://{}", path.display()),
            enabled: true,
        })
        .collect();

    // A leftover compile from an earlier run: taking the shortcut must clear
    // it, not leave a duplicate of the whole blocklist on the card.
    let list_cache_dir = dir.join("lists");
    std::fs::create_dir_all(&list_cache_dir).unwrap();
    let stale = list_cache_dir.join("profile_all.fst");
    std::fs::write(&stale, b"stale").unwrap();

    let blocklist = Blocklist::new(
        BlocklistConfig {
            enabled: true,
            decision_cache_size: 1000,
            lists: lists.clone(),
            domains: vec![],
            wildcard_block: vec![],
            whitelist: vec![],
            client_bypass: vec![],
            profiles: vec![
                BlocklistProfileConfig {
                    id: "all".into(),
                    name: "Everything".into(),
                    lists: lists.iter().map(|l| l.name.clone()).collect(),
                    clients: vec!["10.0.0.2".into()],
                    block: vec![],
                    allow: vec![],
                    allowlists: vec![],
                    default_deny: false,
                },
                BlocklistProfileConfig {
                    id: "some".into(),
                    name: "Two of them".into(),
                    lists: vec!["Ads".into(), "Track".into()],
                    clients: vec!["10.0.0.3".into()],
                    block: vec![],
                    allow: vec![],
                    allowlists: vec![],
                    default_deny: false,
                },
            ],
        },
        AllowlistConfig::default(),
        fst_path,
    );
    blocklist.refresh(false).await.unwrap();

    let all = blocklist.profile_for("10.0.0.2", None);
    let all = all.as_deref();
    assert!(blocklist.should_block_for("ads.example", all));
    assert!(blocklist.should_block_for("malware.example", all));
    assert!(
        !stale.exists(),
        "the profile's own FST is redundant once it maps the merged one"
    );

    // A genuine subset still compiles its own map.
    let some = blocklist.profile_for("10.0.0.3", None);
    let some = some.as_deref();
    assert!(blocklist.should_block_for("track.example", some));
    assert!(!blocklist.should_block_for("malware.example", some));
    assert!(list_cache_dir.join("profile_some.fst").exists());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn whitelisted_parent_overrides_blocked_subdomain() {
    // Reproduces the reported "domain is whitelisted but its subdomain is
    // still blocked" bug: a blocklist (FST) entry for `google.com` blocks
    // every subdomain via the hierarchy walk, so whitelisting the parent
    // must exempt them too.
    let fst_path = temp_fst_path("ferrite-blocklist-wl-over-block");
    std::fs::create_dir_all(fst_path.parent().unwrap()).unwrap();
    let fst_bytes = crate::loader::build_fst(vec!["google.com".to_string()]).unwrap();
    std::fs::write(&fst_path, fst_bytes).unwrap();

    let blocklist = Blocklist::new(
        BlocklistConfig {
            enabled: true,
            decision_cache_size: 128,
            lists: vec![],
            domains: vec![],
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

#[test]
fn a_pause_lifts_filtering_box_wide_or_for_one_device() {
    let bl = Blocklist::new(
        BlocklistConfig::default(),
        AllowlistConfig::default(),
        temp_fst_path("pause"),
    );
    assert!(bl.blocking_enabled());
    assert!(!bl.has_client_exceptions());

    bl.pauses().pause_global(i64::MAX);
    assert!(!bl.blocking_enabled());
    bl.pauses().resume_global();
    assert!(bl.blocking_enabled());

    // A device pause is a client exception like a configured bypass, and is
    // matched by IP or MAC; the configured bypass itself is untouched.
    bl.pauses()
        .pause_clients(&["aa:bb:cc:dd:ee:ff".into()], i64::MAX);
    assert!(bl.has_client_exceptions());
    assert!(!bl.has_client_bypass());
    assert!(bl.client_filtering_off_normalized("10.0.0.2", Some("aa:bb:cc:dd:ee:ff")));
    assert!(!bl.client_filtering_off_normalized("10.0.0.2", None));
    assert!(!bl.client_bypasses_blocking("10.0.0.2", Some("aa:bb:cc:dd:ee:ff")));
}
