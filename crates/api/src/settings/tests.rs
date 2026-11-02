use super::*;
use ferrite_app::test_support;
use ferrite_core::config::Config;

#[tokio::test]
async fn get_settings_masks_secret_fields_but_keeps_shape_stable() {
    let (state, db_path) = test_support::app_state("settings-mask").await;
    {
        let mut cfg = state.live_config.write();
        cfg.api.api_key = Some("secret-api-key".to_string());
        cfg.api.password_hash = Some("$argon2id$secret-hash".to_string());
    }

    let Json(value) = get_settings(State(state.clone())).await.unwrap();

    assert_eq!(value["api"]["api_key"], "***");
    assert_eq!(value["api"]["password_hash"], "***");

    state.live_config.write().api.api_key = None;
    state.live_config.write().api.password_hash = None;
    let Json(value) = get_settings(State(state.clone())).await.unwrap();
    assert!(value["api"]["api_key"].is_null());
    assert!(value["api"]["password_hash"].is_null());

    drop(state);
    test_support::cleanup_sqlite(&db_path);
}

#[tokio::test]
async fn get_settings_treats_blank_secret_fields_as_unset() {
    let (state, db_path) = test_support::app_state("settings-mask-empty").await;
    {
        let mut cfg = state.live_config.write();
        cfg.api.api_key = Some("   ".to_string());
        cfg.api.password_hash = Some("".to_string());
    }

    let Json(value) = get_settings(State(state.clone())).await.unwrap();

    assert!(value["api"]["api_key"].is_null());
    assert!(value["api"]["password_hash"].is_null());

    drop(state);
    test_support::cleanup_sqlite(&db_path);
}

#[tokio::test]
async fn hot_settings_patch_updates_runtime_state_and_persists_config() {
    let (state, db_path, config_path) =
        test_support::app_state_with_config_path("settings-hot-patch").await;
    let web_dir = test_support::temp_path("settings-web-dir", "dist");
    let log_ignore = vec!["*.lan".to_string(), "fe.te".to_string()];

    let Json(value) = update_settings(
        State(state.clone()),
        axum::http::HeaderMap::new(),
        Json(SettingsPatch {
            api_key: Some(Some("new-key".to_string())),
            dns_min_ttl: Some(120),
            dns_max_ttl: Some(240),
            dns_log_ignore: Some(log_ignore.clone()),
            web_dir: Some(Some(web_dir.clone())),
            log_retention_days: Some(14),
            log_max_mb: Some(64),
            blocklist_enabled: Some(false),
            blocklist_client_bypass: Some(vec![
                "::ffff:192.0.2.10".to_string(),
                "AA-BB-CC-DD-EE-FF".to_string(),
            ]),
            ..Default::default()
        }),
    )
    .await
    .unwrap();

    assert_eq!(value["status"], "ok");
    assert_eq!(value["restart_required"], false);
    assert_eq!(state.inner.dns_cache.min_ttl_secs(), 120);
    assert_eq!(*state.inner.log_ignore.read(), log_ignore);

    let cfg = state.live_config.read().clone();
    assert_eq!(cfg.api.api_key.as_deref(), Some("new-key"));
    assert_eq!(cfg.dns.min_ttl, 120);
    assert_eq!(cfg.dns.max_ttl, 240);
    assert_eq!(cfg.storage.log_retention_days, 14);
    assert_eq!(cfg.storage.log_max_mb, 64);
    assert_eq!(cfg.web_dir.as_ref(), Some(&web_dir));
    assert!(!cfg.blocklist.enabled);
    assert_eq!(
        cfg.blocklist.client_bypass,
        vec!["192.0.2.10".to_string(), "aa:bb:cc:dd:ee:ff".to_string()]
    );
    assert!(!state.inner.blocklist.blocking_enabled());
    assert!(
        state
            .inner
            .blocklist
            .client_bypasses_blocking("192.0.2.10", None)
    );
    assert!(
        state
            .inner
            .blocklist
            .client_bypasses_blocking("192.0.2.99", Some("aa:bb:cc:dd:ee:ff"))
    );

    let saved: Config = toml::from_str(&std::fs::read_to_string(&config_path).unwrap())
        .expect("persisted config should parse");
    assert_eq!(saved.api.api_key.as_deref(), Some("new-key"));
    assert_eq!(saved.storage.log_max_mb, 64);
    assert_eq!(saved.dns.log_ignore, log_ignore);
    assert_eq!(saved.web_dir.as_ref(), Some(&web_dir));
    assert!(!saved.blocklist.enabled);
    assert_eq!(saved.blocklist.client_bypass, cfg.blocklist.client_bypass);

    drop(state);
    test_support::cleanup_sqlite(&db_path);
    let _ = std::fs::remove_file(config_path);
}

/// A bad `storage_path` has to be refused *here*. Accepting it would write
/// it to the config and then restart into a box that cannot open its
/// database, with the panel gone — recoverable only with a text editor on
/// the device.
#[tokio::test]
async fn an_unusable_storage_path_is_refused_before_it_is_saved() {
    let (state, db_path, config_path) =
        test_support::app_state_with_config_path("api-storage-path-bad").await;
    let original = state.live_config.read().storage.path.clone();

    for bad in [
        "",                                   // empty
        "relative/ferrite.db",                // not absolute
        "/ferrite-nonexistent-root/x/db.sq3", // nothing along it exists
    ] {
        let err = update_settings(
            State(state.clone()),
            axum::http::HeaderMap::new(),
            Json(SettingsPatch {
                storage_path: Some(PathBuf::from(bad)),
                ..Default::default()
            }),
        )
        .await;
        assert!(err.is_err(), "'{bad}' should have been refused");
    }

    // A directory is not a database file.
    let dir = std::env::temp_dir();
    assert!(
        update_settings(
            State(state.clone()),
            axum::http::HeaderMap::new(),
            Json(SettingsPatch {
                storage_path: Some(dir.clone()),
                ..Default::default()
            }),
        )
        .await
        .is_err()
    );

    // Nothing stuck to the live config through any of that.
    assert_eq!(state.live_config.read().storage.path, original);

    drop(state);
    test_support::cleanup_sqlite(&db_path);
    let _ = std::fs::remove_file(config_path);
}

/// A usable path is accepted, marked restart-required, and persisted — the
/// setting was previously reachable only by editing the file by hand.
#[tokio::test]
async fn a_usable_storage_path_is_saved_and_asks_for_a_restart() {
    let (state, db_path, config_path) =
        test_support::app_state_with_config_path("api-storage-path-good").await;

    // A directory that does not exist yet: startup creates it, so this has
    // to be accepted rather than refused for not being there.
    let target = std::env::temp_dir()
        .join(format!("ferrite-relocate-{}", std::process::id()))
        .join("ferrite.db");

    let Json(value) = update_settings(
        State(state.clone()),
        axum::http::HeaderMap::new(),
        Json(SettingsPatch {
            storage_path: Some(target.clone()),
            ..Default::default()
        }),
    )
    .await
    .unwrap();

    assert_eq!(value["restart_required"], true);
    assert!(
        value["restart_changed"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f == "storage_path")
    );
    assert_eq!(state.live_config.read().storage.path, target);

    let saved: Config = toml::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
    assert_eq!(saved.storage.path, target);

    drop(state);
    test_support::cleanup_sqlite(&db_path);
    let _ = std::fs::remove_file(config_path);
}

/// The blocklist cache directory: a file or a relative path is refused, a
/// directory that does not exist yet is accepted and persisted.
#[tokio::test]
async fn blocklist_cache_dir_is_validated_then_saved() {
    let (state, db_path, config_path) =
        test_support::app_state_with_config_path("api-blocklist-cache-dir").await;
    let original = state.live_config.read().storage.blocklist_cache_dir.clone();

    let file = std::env::temp_dir().join(format!("ferrite-cache-file-{}", std::process::id()));
    std::fs::write(&file, b"").unwrap();
    for bad in [PathBuf::from("relative/cache"), file.clone()] {
        let err = update_settings(
            State(state.clone()),
            axum::http::HeaderMap::new(),
            Json(SettingsPatch {
                blocklist_cache_dir: Some(bad.clone()),
                ..Default::default()
            }),
        )
        .await;
        assert!(err.is_err(), "'{}' should have been refused", bad.display());
    }
    let _ = std::fs::remove_file(&file);
    assert_eq!(
        state.live_config.read().storage.blocklist_cache_dir,
        original
    );

    let target = std::env::temp_dir().join(format!("ferrite-cache-dir-{}", std::process::id()));
    let Json(value) = update_settings(
        State(state.clone()),
        axum::http::HeaderMap::new(),
        Json(SettingsPatch {
            blocklist_cache_dir: Some(target.clone()),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    assert!(
        value["restart_changed"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f == "blocklist_cache_dir")
    );
    let saved: Config = toml::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
    assert_eq!(saved.storage.blocklist_cache_dir, target);
    assert_eq!(
        saved.storage.blocklist_fst_path(),
        target.join("blocklist.fst")
    );

    drop(state);
    test_support::cleanup_sqlite(&db_path);
    let _ = std::fs::remove_file(config_path);
}

#[tokio::test]
async fn privacy_switches_stop_recording_and_drop_what_is_in_memory() {
    let (state, db_path, config_path) =
        test_support::app_state_with_config_path("settings-privacy").await;

    // Something already recorded, as if the box had been running.
    let entry = ferrite_core::types::QueryEntry {
        id: 1,
        timestamp: chrono::Utc::now(),
        domain: "private.example".to_string(),
        query_type: 1,
        client_ip: "192.0.2.10".to_string(),
        device: "192.0.2.10".to_string(),
        status: ferrite_core::types::QueryStatus::Blocked,
        latency_ms: 1,
        upstream: None,
        rcode: 0,
    };
    state.inner.live_stats.record_query(entry.status);
    state
        .inner
        .live_stats
        .push_entry(&entry, &state.inner.record_switches);
    assert_eq!(state.inner.live_stats.top_domains.top(10).len(), 1);
    assert_eq!(state.inner.live_stats.recent_queries.recent(10).len(), 1);

    let Json(value) = update_settings(
        State(state.clone()),
        axum::http::HeaderMap::new(),
        Json(SettingsPatch {
            log_queries: Some(false),
            keep_stats: Some(false),
            ..Default::default()
        }),
    )
    .await
    .unwrap();

    assert_eq!(value["status"], "ok");
    assert_eq!(value["restart_required"], false);

    // Switches are live…
    assert!(!state.inner.record_switches.scope().records_anything());
    // …the history already in RAM is gone…
    assert!(state.inner.live_stats.top_domains.top(10).is_empty());
    assert!(state.inner.live_stats.recent_queries.recent(10).is_empty());
    // …but the anonymous lifetime counters stay, so the dashboard still has
    // something honest to show.
    assert_eq!(state.inner.live_stats.total(), 1);
    assert_eq!(state.inner.live_stats.blocked(), 1);

    let cfg = state.live_config.read().clone();
    assert!(!cfg.storage.log_queries);
    assert!(!cfg.storage.keep_stats);

    let saved: Config = toml::from_str(&std::fs::read_to_string(&config_path).unwrap())
        .expect("persisted config should parse");
    assert!(!saved.storage.log_queries);
    assert!(!saved.storage.keep_stats);

    // And back on again without a restart.
    let _ = update_settings(
        State(state.clone()),
        axum::http::HeaderMap::new(),
        Json(SettingsPatch {
            log_queries: Some(true),
            keep_stats: Some(true),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    assert_eq!(
        state.inner.record_switches.scope(),
        ferrite_core::recording::RecordScope::ALL
    );

    drop(state);
    test_support::cleanup_sqlite(&db_path);
    let _ = std::fs::remove_file(config_path);
}

#[tokio::test]
async fn switching_recording_off_scrubs_the_snapshot_already_on_disk() {
    let (state, db_path, config_path) =
        test_support::app_state_with_config_path("settings-privacy-snapshot").await;
    let snapshot_path = state.snapshot_path.as_ref().clone();

    // A snapshot written while recording was still on: it carries the DNS
    // cache, which is a list of recently resolved names.
    state.inner.dns_cache.insert(
        "private.example",
        1,
        false,
        ferrite_dns::types::DnsResponse {
            bytes: bytes::Bytes::from_static(b"\x00\x01wire"),
            ttl: 300,
        },
    );
    ferrite_app::snapshot::save::save(
        &state.inner.dns_cache,
        &state.inner.live_stats,
        &snapshot_path,
        ferrite_core::recording::RecordScope::ALL,
    )
    .unwrap();
    let before = ferrite_app::snapshot::restore::load_snapshot(&snapshot_path)
        .unwrap()
        .expect("snapshot written");
    assert_eq!(before.dns_cache.len(), 1);

    let _ = update_settings(
        State(state.clone()),
        axum::http::HeaderMap::new(),
        Json(SettingsPatch {
            log_queries: Some(false),
            keep_stats: Some(false),
            ..Default::default()
        }),
    )
    .await
    .unwrap();

    // Rewritten before the request returned, not five minutes later: a
    // power cut in that window would otherwise leave the domains on disk
    // and restore them into the cache on the next start.
    let after = ferrite_app::snapshot::restore::load_snapshot(&snapshot_path)
        .unwrap()
        .expect("snapshot still present");
    assert!(after.dns_cache.is_empty());

    drop(state);
    test_support::cleanup_sqlite(&db_path);
    let _ = std::fs::remove_file(config_path);
    let _ = std::fs::remove_file(snapshot_path);
}

#[tokio::test]
async fn nullable_api_key_patch_clears_secret() {
    let (state, db_path, config_path) =
        test_support::app_state_with_config_path("settings-null-api-key").await;
    state.live_config.write().api.api_key = Some("old-key".to_string());

    let Json(value) = update_settings(
        State(state.clone()),
        axum::http::HeaderMap::new(),
        Json(SettingsPatch {
            api_key: Some(None),
            ..Default::default()
        }),
    )
    .await
    .unwrap();

    assert_eq!(value["status"], "ok");
    assert!(state.live_config.read().api.api_key.is_none());

    let saved: Config = toml::from_str(&std::fs::read_to_string(&config_path).unwrap())
        .expect("persisted config should parse");
    assert!(saved.api.api_key.is_none());

    drop(state);
    test_support::cleanup_sqlite(&db_path);
    let _ = std::fs::remove_file(config_path);
}

#[tokio::test]
async fn invalid_ttl_patch_is_rejected_without_mutating_runtime_config() {
    let (state, db_path, config_path) =
        test_support::app_state_with_config_path("settings-invalid-ttl").await;

    // max is a real (non-zero) ceiling here — 0 would mean "no ceiling"
    // and make the patch valid.
    let err = update_settings(
        State(state.clone()),
        axum::http::HeaderMap::new(),
        Json(SettingsPatch {
            dns_min_ttl: Some(MAX_TTL),
            dns_max_ttl: Some(120),
            ..Default::default()
        }),
    )
    .await
    .unwrap_err();

    assert!(err.0.to_string().contains("cannot be greater"));
    let cfg = state.live_config.read();
    assert_eq!(cfg.dns.min_ttl, 60);
    assert_eq!(cfg.dns.max_ttl, 3600);
    assert_eq!(state.inner.dns_cache.min_ttl_secs(), 60);
    assert!(!config_path.exists());

    drop(cfg);
    drop(state);
    test_support::cleanup_sqlite(&db_path);
}

/// `dns_max_ttl = 0` means "no ceiling": it must pass validation even with
/// a non-zero floor (the ordering check compares against the effective
/// ceiling, not the literal 0) and land in the cache as MAX_TTL — not as a
/// cache whose every insert expires instantly.
#[tokio::test]
async fn zero_max_ttl_patch_means_no_ceiling() {
    let (state, db_path, config_path) =
        test_support::app_state_with_config_path("settings-zero-max-ttl").await;

    let Json(value) = update_settings(
        State(state.clone()),
        axum::http::HeaderMap::new(),
        Json(SettingsPatch {
            dns_min_ttl: Some(120),
            dns_max_ttl: Some(0),
            ..Default::default()
        }),
    )
    .await
    .unwrap();

    assert_eq!(value["status"], "ok");
    assert_eq!(state.inner.dns_cache.min_ttl_secs(), 120);
    assert_eq!(
        state.inner.dns_cache.max_ttl_secs(),
        MAX_TTL,
        "0 must normalize to the hard ceiling, not a dead cache"
    );
    // The config keeps the literal 0 — it's the documented spelling of
    // "no ceiling", not a value to be rewritten behind the operator's back.
    let cfg = state.live_config.read().clone();
    assert_eq!(cfg.dns.min_ttl, 120);
    assert_eq!(cfg.dns.max_ttl, 0);

    drop(state);
    test_support::cleanup_sqlite(&db_path);
    let _ = std::fs::remove_file(config_path);
}

#[tokio::test]
async fn blank_api_key_patch_is_rejected_without_persisting() {
    let (state, db_path, config_path) =
        test_support::app_state_with_config_path("settings-empty-api-key").await;

    let err = update_settings(
        State(state.clone()),
        axum::http::HeaderMap::new(),
        Json(SettingsPatch {
            api_key: Some(Some("  ".to_string())),
            ..Default::default()
        }),
    )
    .await
    .unwrap_err();

    assert!(err.0.to_string().contains("api_key cannot be empty"));
    assert!(state.live_config.read().api.api_key.is_none());
    assert!(!config_path.exists());

    drop(state);
    test_support::cleanup_sqlite(&db_path);
}

#[tokio::test]
async fn invalid_client_bypass_patch_is_rejected_without_mutating_config() {
    let (state, db_path, config_path) =
        test_support::app_state_with_config_path("settings-invalid-client-bypass").await;

    let err = update_settings(
        State(state.clone()),
        axum::http::HeaderMap::new(),
        Json(SettingsPatch {
            blocklist_client_bypass: Some(vec!["not-an-ip-or-mac".to_string()]),
            ..Default::default()
        }),
    )
    .await
    .unwrap_err();

    assert!(
        err.0
            .to_string()
            .contains("invalid blocklist_client_bypass")
    );
    assert!(state.live_config.read().blocklist.client_bypass.is_empty());
    assert!(
        !state
            .inner
            .blocklist
            .client_bypasses_blocking("192.0.2.10", None)
    );
    assert!(!config_path.exists());

    drop(state);
    test_support::cleanup_sqlite(&db_path);
}

#[tokio::test]
async fn changing_the_password_keeps_the_caller_signed_in_and_no_one_else() {
    use axum::http::{HeaderMap, HeaderValue};

    let (state, db_path) = test_support::app_state("settings-password-sessions").await;
    state.live_config.write().api.password_hash =
        Some(crate::auth::hash_password("old secret").unwrap());
    let login = |state: AppState| async move {
        let Json(v) = crate::auth::login(
            State(state),
            axum::http::HeaderMap::new(),
            None,
            Json(crate::auth::LoginRequest {
                password: "old secret".into(),
            }),
        )
        .await
        .unwrap();
        let mut h = HeaderMap::new();
        h.insert(
            "x-session-token",
            HeaderValue::from_str(v["token"].as_str().unwrap()).unwrap(),
        );
        h
    };
    let mine = login(state.clone()).await;
    let theirs = login(state.clone()).await;

    let Json(_) = update_settings(
        State(state.clone()),
        mine.clone(),
        Json(SettingsPatch {
            password: Some(Some("new secret".into())),
            ..Default::default()
        }),
    )
    .await
    .unwrap();

    assert!(crate::auth::is_authenticated(&state, &mine));
    assert!(!crate::auth::is_authenticated(&state, &theirs));

    drop(state);
    test_support::cleanup_sqlite(&db_path);
}

#[tokio::test]
async fn block_response_applies_live_and_custom_ip_needs_an_address() {
    use ferrite_core::config::BlockResponse;
    use std::net::Ipv4Addr;

    let (state, db_path, _config_path) =
        test_support::app_state_with_config_path("settings-block-response").await;

    let err = update_settings(
        State(state.clone()),
        axum::http::HeaderMap::new(),
        Json(SettingsPatch {
            blocklist_block_response: Some(BlockResponse::CustomIp),
            ..Default::default()
        }),
    )
    .await
    .unwrap_err();
    assert!(err.0.to_string().contains("custom_ip needs"));
    assert_eq!(
        state.inner.blocklist.block_answer().response,
        BlockResponse::Nxdomain
    );

    let Json(v) = update_settings(
        State(state.clone()),
        axum::http::HeaderMap::new(),
        Json(SettingsPatch {
            blocklist_block_response: Some(BlockResponse::CustomIp),
            blocklist_block_ipv4: Some(Some(Ipv4Addr::new(192, 168, 1, 5))),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    assert_eq!(v["restart_required"], false);
    let live = state.inner.blocklist.block_answer();
    assert_eq!(live.response, BlockResponse::CustomIp);
    assert_eq!(live.ipv4, Some(Ipv4Addr::new(192, 168, 1, 5)));
    assert_eq!(
        state.live_config.read().blocklist.block_response,
        BlockResponse::CustomIp
    );

    // Clearing the only address of custom_ip is refused too.
    assert!(
        update_settings(
            State(state.clone()),
            axum::http::HeaderMap::new(),
            Json(SettingsPatch {
                blocklist_block_ipv4: Some(None),
                ..Default::default()
            }),
        )
        .await
        .is_err()
    );

    drop(state);
    test_support::cleanup_sqlite(&db_path);
}
