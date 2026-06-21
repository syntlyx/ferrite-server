use std::{net::Ipv4Addr, path::PathBuf};

use axum::{Json, extract::State};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;

use crate::api::ApiError;
use crate::api::auth::hash_password;
use crate::app::AppState;
use crate::clients::normalize_client_key;
use crate::config::{UpstreamConfig, ZoneConfig};
use crate::dns::cache::{MAX_TTL, MIN_TTL};
use crate::error::FeriteError;

/// GET /api/settings — return the current live configuration.
/// `api_key` and `password_hash`: `"***"` if non-empty, `null` if not — always present.
pub async fn get_settings(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let cfg = state.live_config.read().clone();
    let has_api_key = cfg.api.has_api_key();
    let has_password = cfg.api.has_password();

    let mut val = serde_json::to_value(&cfg).map_err(|e| {
        ApiError(FeriteError::Internal(format!(
            "failed to serialize settings: {}",
            e
        )))
    })?;

    // Always emit these fields (never rely on skip_serializing_if omitting them),
    // so the web UI can distinguish "not set" (null) from "set" (masked).
    if let Some(api) = val.get_mut("api") {
        api["api_key"] = if has_api_key {
            json!("***")
        } else {
            json!(null)
        };
        api["password_hash"] = if has_password {
            json!("***")
        } else {
            json!(null)
        };
    }

    Ok(Json(val))
}

// Serde helper: distinguishes three states for nullable patch fields —
//   field absent → None          (leave setting untouched)
//   field = null → Some(None)    (clear the setting)
//   field = T   → Some(Some(T)) (set to a new value)
// Use together with #[serde(default)] so absent fields produce None.
mod nullable {
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D, T>(d: D) -> Result<Option<Option<T>>, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de>,
    {
        Option::<T>::deserialize(d).map(Some)
    }
}

/// All fields that can be changed via PATCH /api/settings.
///
/// Hot-patchable (no restart): `api_key`, `password`, `dns_min_ttl`, `dns_max_ttl`,
///                             `dns_log_ignore`, `web_dir`, `log_retention_days`,
///                             `blocklist_enabled`, `blocklist_client_bypass`,
///                             `debug_logging`.
/// Restart-required:           `dns_bind_addr`, `dns_cache_size`, `dns_strip_ecs`,
///                             `dns_dnssec`, `api_bind_addr`,
///                             `blocklist_decision_cache_size`, `upstream`, `zones`,
///                             `panel_enabled`, `panel_domain`, `panel_ipv4`, `panel_url`.
#[derive(Debug, Deserialize, Default)]
pub struct SettingsPatch {
    // ── Hot-patchable ────────────────────────────────────────────────────────
    #[serde(default, deserialize_with = "nullable::deserialize")]
    pub api_key: Option<Option<String>>,
    #[serde(default, deserialize_with = "nullable::deserialize")]
    pub password: Option<Option<String>>,
    pub dns_min_ttl: Option<u64>,
    pub dns_max_ttl: Option<u64>,
    pub dns_log_ignore: Option<Vec<String>>,
    #[serde(default, deserialize_with = "nullable::deserialize")]
    pub web_dir: Option<Option<PathBuf>>,
    pub log_retention_days: Option<u32>,
    pub blocklist_enabled: Option<bool>,
    pub blocklist_client_bypass: Option<Vec<String>>,
    pub debug_logging: Option<bool>,

    // ── Restart-required ─────────────────────────────────────────────────────
    pub dns_bind_addr: Option<String>,
    pub dns_cache_size: Option<usize>,
    pub dns_strip_ecs: Option<bool>,
    pub dns_dnssec: Option<bool>,
    pub blocklist_decision_cache_size: Option<usize>,
    pub api_bind_addr: Option<String>,
    pub upstream: Option<Vec<UpstreamConfig>>,
    pub zones: Option<Vec<ZoneConfig>>,
    pub panel_enabled: Option<bool>,
    pub panel_domain: Option<String>,
    #[serde(default, deserialize_with = "nullable::deserialize")]
    pub panel_ipv4: Option<Option<Ipv4Addr>>,
    #[serde(default, deserialize_with = "nullable::deserialize")]
    pub panel_url: Option<Option<String>>,
}

/// PATCH /api/settings — apply a partial settings update.
///
/// Hot-patchable fields take effect immediately.
/// Restart-required fields are saved to disk; the server exits with code 0
/// so a process supervisor (systemd, launchd, etc.) can restart it cleanly.
pub async fn update_settings(
    State(state): State<AppState>,
    Json(patch): Json<SettingsPatch>,
) -> Result<Json<Value>, ApiError> {
    // Pre-compute password hash outside the write lock — Argon2id is deliberately slow
    // (100–500 ms) and holding a write lock during that time stalls all API readers.
    let pre_hashed_password: Option<Option<String>> = match patch.password {
        None => None,
        Some(None) => Some(None),
        Some(Some(pw)) => {
            if pw.is_empty() {
                return Err(ApiError(FeriteError::Config(
                    "password cannot be empty; use null to disable password auth".into(),
                )));
            }
            let hash = hash_password(&pw).map_err(|e| {
                ApiError(FeriteError::Config(format!("password hash failed: {}", e)))
            })?;
            Some(Some(hash))
        }
    };

    let mut hot_changed: Vec<&'static str> = Vec::new();
    let mut restart_changed: Vec<&'static str> = Vec::new();
    let mut ttl_bounds_to_apply: Option<(u64, u64)> = None;
    let mut blocklist_enabled_to_apply: Option<bool> = None;
    let mut blocklist_client_bypass_to_apply: Option<Vec<String>> = None;
    let mut debug_logging_to_apply: Option<bool> = None;

    {
        let mut cfg = state.live_config.write();

        // ── Hot-patchable ────────────────────────────────────────────────────

        if let Some(key) = patch.api_key {
            cfg.api.api_key = match key {
                Some(k) => {
                    let key = k.trim().to_string();
                    if key.is_empty() {
                        return Err(ApiError(FeriteError::Config(
                            "api_key cannot be empty; use null to disable key auth".into(),
                        )));
                    }
                    Some(key)
                }
                None => None,
            };
            hot_changed.push("api_key");
        }

        if let Some(hash_opt) = pre_hashed_password {
            cfg.api.password_hash = hash_opt;
            hot_changed.push("password");
        }

        let ttl_changed = patch.dns_min_ttl.is_some() || patch.dns_max_ttl.is_some();
        if ttl_changed {
            let min = patch.dns_min_ttl.unwrap_or(cfg.dns.min_ttl);
            let max = patch.dns_max_ttl.unwrap_or(cfg.dns.max_ttl);
            if !(MIN_TTL..=MAX_TTL).contains(&min) {
                return Err(ApiError(FeriteError::Config(format!(
                    "dns_min_ttl must be between {} and {} seconds",
                    MIN_TTL, MAX_TTL
                ))));
            }
            if !(MIN_TTL..=MAX_TTL).contains(&max) {
                return Err(ApiError(FeriteError::Config(format!(
                    "dns_max_ttl must be between {} and {} seconds",
                    MIN_TTL, MAX_TTL
                ))));
            }
            if min > max {
                return Err(ApiError(FeriteError::Config(format!(
                    "dns_min_ttl ({}) cannot be greater than dns_max_ttl ({})",
                    min, max
                ))));
            }
        }

        if let Some(min) = patch.dns_min_ttl {
            cfg.dns.min_ttl = min;
            hot_changed.push("dns_min_ttl");
        }

        if let Some(max) = patch.dns_max_ttl {
            cfg.dns.max_ttl = max;
            hot_changed.push("dns_max_ttl");
        }

        if ttl_changed {
            ttl_bounds_to_apply = Some((cfg.dns.min_ttl, cfg.dns.max_ttl));
        }

        if let Some(ref patterns) = patch.dns_log_ignore {
            cfg.dns.log_ignore = patterns.clone();
            hot_changed.push("dns_log_ignore");
        }

        if let Some(dir) = patch.web_dir {
            cfg.web_dir = dir;
            hot_changed.push("web_dir");
        }

        if let Some(days) = patch.log_retention_days {
            cfg.storage.log_retention_days = days;
            hot_changed.push("log_retention_days");
        }

        if let Some(enabled) = patch.blocklist_enabled {
            cfg.blocklist.enabled = enabled;
            blocklist_enabled_to_apply = Some(enabled);
            hot_changed.push("blocklist_enabled");
        }

        if let Some(ref entries) = patch.blocklist_client_bypass {
            let normalized = normalize_client_bypass(entries)?;
            cfg.blocklist.client_bypass = normalized.clone();
            blocklist_client_bypass_to_apply = Some(normalized);
            hot_changed.push("blocklist_client_bypass");
        }

        if let Some(debug) = patch.debug_logging {
            cfg.debug_logging = debug;
            debug_logging_to_apply = Some(debug);
            hot_changed.push("debug_logging");
        }

        // ── Restart-required ─────────────────────────────────────────────────

        if let Some(ref addr) = patch.dns_bind_addr {
            cfg.dns.bind_addr = addr.parse().map_err(|_| {
                ApiError(FeriteError::Config(format!(
                    "invalid dns_bind_addr: {}",
                    addr
                )))
            })?;
            restart_changed.push("dns_bind_addr");
        }

        if let Some(size) = patch.dns_cache_size {
            cfg.dns.cache_size = size;
            restart_changed.push("dns_cache_size");
        }

        if let Some(v) = patch.dns_strip_ecs {
            cfg.dns.strip_ecs = v;
            restart_changed.push("dns_strip_ecs");
        }

        if let Some(v) = patch.dns_dnssec {
            cfg.dns.dnssec = v;
            restart_changed.push("dns_dnssec");
        }

        if let Some(size) = patch.blocklist_decision_cache_size {
            if size == 0 {
                return Err(ApiError(FeriteError::Config(
                    "blocklist_decision_cache_size must be greater than 0".into(),
                )));
            }
            cfg.blocklist.decision_cache_size = size;
            restart_changed.push("blocklist_decision_cache_size");
        }

        if let Some(ref addr) = patch.api_bind_addr {
            cfg.api.bind_addr = addr.parse().map_err(|_| {
                ApiError(FeriteError::Config(format!(
                    "invalid api_bind_addr: {}",
                    addr
                )))
            })?;
            restart_changed.push("api_bind_addr");
        }

        if let Some(upstreams) = patch.upstream {
            if upstreams.is_empty() {
                return Err(ApiError(FeriteError::Config(
                    "upstream list cannot be empty".into(),
                )));
            }
            cfg.upstream = upstreams;
            restart_changed.push("upstream");
        }

        if let Some(zones) = patch.zones {
            cfg.zones = zones;
            restart_changed.push("zones");
        }

        if let Some(enabled) = patch.panel_enabled {
            cfg.panel.enabled = enabled;
            restart_changed.push("panel_enabled");
        }

        if let Some(ref domain) = patch.panel_domain {
            let domain = domain.trim().trim_end_matches('.');
            if domain.is_empty() {
                return Err(ApiError(FeriteError::Config(
                    "panel_domain cannot be empty".into(),
                )));
            }
            cfg.panel.domain = domain.to_ascii_lowercase();
            restart_changed.push("panel_domain");
        }

        if let Some(ipv4) = patch.panel_ipv4 {
            cfg.panel.ipv4 = ipv4;
            restart_changed.push("panel_ipv4");
        }

        if let Some(url) = patch.panel_url {
            cfg.panel.url = match url {
                Some(raw) => {
                    let trimmed = raw.trim();
                    if trimmed.is_empty() {
                        return Err(ApiError(FeriteError::Config(
                            "panel_url cannot be empty; use null to reset".into(),
                        )));
                    }
                    Some(trimmed.to_string())
                }
                None => None,
            };
            restart_changed.push("panel_url");
        }
    }

    if let Some(patterns) = patch.dns_log_ignore {
        *state.inner.log_ignore.write() = patterns;
    }

    if let Some((min, max)) = ttl_bounds_to_apply {
        state.inner.dns_cache.set_ttl_bounds(min, max);
    }

    if let Some(enabled) = blocklist_enabled_to_apply {
        state.inner.blocklist.set_blocking_enabled(enabled);
    }

    if let Some(entries) = blocklist_client_bypass_to_apply {
        state.inner.blocklist.set_client_bypass(&entries);
    }

    // RUST_LOG, when set, owns the filter — don't let the toggle fight it.
    if let Some(debug) = debug_logging_to_apply
        && std::env::var_os("RUST_LOG").is_none()
    {
        crate::logbuf::set_debug(debug);
    }

    let all_changed = hot_changed.len() + restart_changed.len();
    if all_changed == 0 {
        return Ok(Json(json!({
            "status": "no_changes",
            "note": "no known fields provided"
        })));
    }

    let saved_path = persist_config(&state).await;
    let needs_restart = !restart_changed.is_empty();

    tracing::info!(
        "settings updated — hot: {:?}, restart-required: {:?}",
        hot_changed,
        restart_changed
    );

    if needs_restart {
        tracing::info!("restart-required settings changed, saving snapshot and exiting");
        let snap_state = state.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            let path = snap_state.inner.snapshot_path.clone();
            if let Err(e) = crate::snapshot::save::save(&snap_state, &path) {
                tracing::error!("snapshot save before restart failed: {}", e);
            }
            std::process::exit(0);
        });
    }

    Ok(Json(json!({
        "status": "ok",
        "changed": hot_changed.iter().chain(restart_changed.iter()).collect::<Vec<_>>(),
        "hot_changed": hot_changed,
        "restart_changed": restart_changed,
        "restart_required": needs_restart,
        "persisted": saved_path.is_some(),
        "saved_to": saved_path,
    })))
}

fn normalize_client_bypass(entries: &[String]) -> Result<Vec<String>, ApiError> {
    let mut normalized = BTreeSet::new();
    for entry in entries {
        let key = normalize_client_key(entry).ok_or_else(|| {
            ApiError(FeriteError::Config(format!(
                "invalid blocklist_client_bypass entry: {}",
                entry
            )))
        })?;
        normalized.insert(key);
    }
    Ok(normalized.into_iter().collect())
}

async fn persist_config(state: &AppState) -> Option<String> {
    let cfg = state.live_config.read().clone();

    let path = state.config_path.as_ref().clone().or_else(|| {
        crate::config::Config::config_candidates()
            .into_iter()
            .next()
    })?;

    let path_clone = path.clone();
    match tokio::task::spawn_blocking(move || cfg.save(&path_clone)).await {
        Ok(Ok(())) => {
            tracing::info!("config saved to {}", path.display());
            Some(path.display().to_string())
        }
        Ok(Err(e)) => {
            tracing::error!("failed to save config to {}: {}", path.display(), e);
            None
        }
        Err(e) => {
            tracing::error!("config save task panicked: {}", e);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::test_support;

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
            Json(SettingsPatch {
                api_key: Some(Some("new-key".to_string())),
                dns_min_ttl: Some(120),
                dns_max_ttl: Some(240),
                dns_log_ignore: Some(log_ignore.clone()),
                web_dir: Some(Some(web_dir.clone())),
                log_retention_days: Some(14),
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
        assert_eq!(saved.dns.log_ignore, log_ignore);
        assert_eq!(saved.web_dir.as_ref(), Some(&web_dir));
        assert!(!saved.blocklist.enabled);
        assert_eq!(saved.blocklist.client_bypass, cfg.blocklist.client_bypass);

        drop(state);
        test_support::cleanup_sqlite(&db_path);
        let _ = std::fs::remove_file(config_path);
    }

    #[tokio::test]
    async fn nullable_api_key_patch_clears_secret() {
        let (state, db_path, config_path) =
            test_support::app_state_with_config_path("settings-null-api-key").await;
        state.live_config.write().api.api_key = Some("old-key".to_string());

        let Json(value) = update_settings(
            State(state.clone()),
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

        let err = update_settings(
            State(state.clone()),
            Json(SettingsPatch {
                dns_min_ttl: Some(MAX_TTL),
                dns_max_ttl: Some(MIN_TTL),
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

    #[tokio::test]
    async fn blank_api_key_patch_is_rejected_without_persisting() {
        let (state, db_path, config_path) =
            test_support::app_state_with_config_path("settings-empty-api-key").await;

        let err = update_settings(
            State(state.clone()),
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
}
