use std::{
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
};

use axum::{Json, extract::State, http::HeaderMap};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;

use crate::ApiError;
use crate::auth::hash_password;
use ferrite_app::AppState;
use ferrite_core::config::{BlockAnswer, BlockResponse, UpstreamConfig, ZoneConfig};
use ferrite_core::error::FeriteError;
use ferrite_core::fsinfo;
use ferrite_core::net::normalize_client_key;
use ferrite_dns::cache::{MAX_TTL, MIN_TTL};

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
///                             `dns_client_ttl`,
///                             `dns_log_ignore`, `web_dir`, `log_retention_days`,
///                             `log_max_mb`,
///                             `log_queries`, `keep_stats`,
///                             `blocklist_enabled`, `blocklist_client_bypass`,
///                             `blocklist_block_response`, `blocklist_block_ipv4`,
///                             `blocklist_block_ipv6`, `debug_logging`.
/// Restart-required:           `storage_backend`, `storage_path`,
///                             `blocklist_cache_dir`,
///                             `dns_bind_addr`, `dns_cache_size`, `dns_cache_max_mb`,
///                             `dns_strip_ecs`, `dns_dnssec`, `api_bind_addr`,
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
    pub dns_client_ttl: Option<u32>,
    pub dns_log_ignore: Option<Vec<String>>,
    #[serde(default, deserialize_with = "nullable::deserialize")]
    pub web_dir: Option<Option<PathBuf>>,
    pub log_retention_days: Option<u32>,
    /// Cap the query log at this many megabytes (0 = no cap). Enforced within
    /// a minute of being set; see `StorageConfig::log_max_mb`.
    pub log_max_mb: Option<u32>,
    /// Privacy switch: record one row per query (the query log). Turning it off
    /// only stops new records — use `DELETE /api/queries` to drop what is
    /// already stored.
    pub log_queries: Option<bool>,
    /// Privacy switch: keep aggregate statistics (top lists, 24-hour graph,
    /// per-device counters). Same note about existing data.
    pub keep_stats: Option<bool>,
    pub blocklist_enabled: Option<bool>,
    pub blocklist_client_bypass: Option<Vec<String>>,
    /// What blocked names are answered with — see `BlockResponse`.
    pub blocklist_block_response: Option<BlockResponse>,
    /// The addresses `custom_ip` answers with; `null` clears one.
    #[serde(default, deserialize_with = "nullable::deserialize")]
    pub blocklist_block_ipv4: Option<Option<Ipv4Addr>>,
    #[serde(default, deserialize_with = "nullable::deserialize")]
    pub blocklist_block_ipv6: Option<Option<Ipv6Addr>>,
    pub debug_logging: Option<bool>,

    // ── Restart-required ─────────────────────────────────────────────────────
    /// `"sqlite"` or `"memory"` — which store holds the query log. Restart
    /// required: the store is built once, at startup.
    pub storage_backend: Option<String>,
    /// Where the SQLite database file lives. Restart required, and validated
    /// before it is written: a path that can't be opened would otherwise fail
    /// the *next* startup rather than this request. See
    /// `GET /api/storage/locations` for what this box offers.
    pub storage_path: Option<PathBuf>,
    /// Directory for the compiled blocklist cache. Restart required — the
    /// engine maps its files at startup — and validated the same way as
    /// `storage_path`, for the same reason.
    pub blocklist_cache_dir: Option<PathBuf>,
    pub dns_bind_addr: Option<String>,
    pub dns_cache_size: Option<usize>,
    pub dns_cache_max_mb: Option<usize>,
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
    headers: HeaderMap,
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
    let mut client_ttl_to_apply: Option<u32> = None;
    let mut blocklist_enabled_to_apply: Option<bool> = None;
    let mut blocklist_client_bypass_to_apply: Option<Vec<String>> = None;
    let mut debug_logging_to_apply: Option<bool> = None;
    let mut log_queries_to_apply: Option<bool> = None;
    let mut keep_stats_to_apply: Option<bool> = None;
    let mut block_answer_to_apply: Option<BlockAnswer> = None;

    {
        let mut cfg = state.live_config.write();

        // Checked before anything is written: `custom_ip` with no address
        // would answer every blocked A and AAAA with nothing at all, which is
        // `nodata` under another name — say so instead.
        let block_answer = (patch.blocklist_block_response.is_some()
            || patch.blocklist_block_ipv4.is_some()
            || patch.blocklist_block_ipv6.is_some())
        .then(|| BlockAnswer {
            response: patch
                .blocklist_block_response
                .unwrap_or(cfg.blocklist.block_response),
            ipv4: patch
                .blocklist_block_ipv4
                .unwrap_or(cfg.blocklist.block_ipv4),
            ipv6: patch
                .blocklist_block_ipv6
                .unwrap_or(cfg.blocklist.block_ipv6),
        });
        if let Some(answer) = block_answer
            && answer.response == BlockResponse::CustomIp
            && answer.ipv4.is_none()
            && answer.ipv6.is_none()
        {
            return Err(ApiError(FeriteError::Config(
                "custom_ip needs blocklist_block_ipv4 or blocklist_block_ipv6".into(),
            )));
        }

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
            // Keep the caller signed in under the new password; every other
            // session was issued under the old one and lapses with it.
            if let Some(hash) = hash_opt.as_deref() {
                crate::auth::rebind_session(&state, &headers, hash);
            }
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
            // A max of 0 means "no ceiling" (normalized to MAX_TTL by the
            // cache), so the ordering check must compare against what it will
            // actually become — otherwise min=120,max=0 is falsely rejected.
            let effective_max = if max == 0 { MAX_TTL } else { max };
            if min > effective_max {
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

        if let Some(ttl) = patch.dns_client_ttl {
            // 0 is meaningful ("clients must not cache"), so only the upper end
            // is bounded — and by the same ceiling as the cache TTLs.
            if ttl as u64 > MAX_TTL {
                return Err(ApiError(FeriteError::Config(format!(
                    "dns_client_ttl must be between 0 and {} seconds",
                    MAX_TTL
                ))));
            }
            cfg.dns.client_ttl = ttl;
            client_ttl_to_apply = Some(ttl);
            hot_changed.push("dns_client_ttl");
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
        if let Some(mb) = patch.log_max_mb {
            cfg.storage.log_max_mb = mb;
            hot_changed.push("log_max_mb");
        }

        if let Some(on) = patch.log_queries {
            cfg.storage.log_queries = on;
            log_queries_to_apply = Some(on);
            hot_changed.push("log_queries");
        }

        if let Some(on) = patch.keep_stats {
            cfg.storage.keep_stats = on;
            keep_stats_to_apply = Some(on);
            hot_changed.push("keep_stats");
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

        if let Some(answer) = block_answer {
            cfg.blocklist.block_response = answer.response;
            cfg.blocklist.block_ipv4 = answer.ipv4;
            cfg.blocklist.block_ipv6 = answer.ipv6;
            block_answer_to_apply = Some(answer);
            hot_changed.push("blocklist_block_response");
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

        if let Some(backend) = patch.storage_backend.as_deref() {
            // Parsed here rather than trusted: an unknown name would otherwise
            // be written to the config and fail the *next* startup, long after
            // the request that caused it.
            cfg.storage.backend = match backend.trim().to_ascii_lowercase().as_str() {
                "sqlite" => ferrite_core::config::StorageBackend::Sqlite,
                "memory" => ferrite_core::config::StorageBackend::Memory,
                other => {
                    return Err(ApiError(FeriteError::Config(format!(
                        "unknown storage_backend '{}' (expected 'sqlite' or 'memory')",
                        other
                    ))));
                }
            };
            restart_changed.push("storage_backend");
        }

        if let Some(path) = patch.storage_path.as_ref() {
            let path = validate_storage_path(path)?;
            if path != cfg.storage.path {
                cfg.storage.path = path;
                restart_changed.push("storage_path");
            }
        }

        if let Some(dir) = patch.blocklist_cache_dir.as_ref() {
            let dir = validate_blocklist_cache_dir(dir)?;
            if dir != cfg.storage.blocklist_cache_dir {
                cfg.storage.blocklist_cache_dir = dir;
                restart_changed.push("blocklist_cache_dir");
            }
        }

        if let Some(size) = patch.dns_cache_size {
            cfg.dns.cache_size = size;
            restart_changed.push("dns_cache_size");
        }

        if let Some(mb) = patch.dns_cache_max_mb {
            cfg.dns.cache_max_mb = mb;
            restart_changed.push("dns_cache_max_mb");
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

    if let Some(ttl) = client_ttl_to_apply {
        state
            .inner
            .client_ttl
            .store(ttl, std::sync::atomic::Ordering::Relaxed);
    }

    // Applied before the config is persisted: the switches decide what the very
    // next query records, and a crash between the two should leave ferrite
    // recording less than the operator asked for, never more.
    if let Some(on) = log_queries_to_apply {
        state.inner.record_switches.set_queries(on);
        // Query log off: drop the recent-queries buffer the live view reads
        // from, so the UI stops showing history that is no longer being kept.
        if !on {
            state.inner.live_stats.forget_recent();
        }
    }

    if let Some(on) = keep_stats_to_apply {
        state.inner.record_switches.set_stats(on);
        // Statistics off: drop what the in-memory top-N counters and the
        // 24-hour timeseries already hold, for the same reason — and the
        // proxy's per-egress routed-domain tables, which are the same kind of
        // history for anything that went through a tunnel.
        if !on {
            state.inner.live_stats.forget_history();
            state.inner.proxy.stats().forget_domains();
        }
    }

    // Nothing is recorded any more, but the snapshot written before the switch
    // still holds the DNS cache — a list of recently resolved domains that
    // would survive a power cut and be restored into the cache on the next
    // start. Rewrite it now (counters only) rather than waiting up to five
    // minutes for the periodic saver, which a hard reset may never reach.
    if (log_queries_to_apply.is_some() || keep_stats_to_apply.is_some())
        && !state.inner.record_switches.scope().records_anything()
    {
        match state.save_snapshot().await {
            Ok(()) => tracing::info!("recording disabled, snapshot rewritten without the cache"),
            Err(e) => tracing::warn!("recording disabled, but rewriting the snapshot failed: {e}"),
        }
        // The same reasoning covers the learned device inventory: the query log
        // is gone, the aggregates are gone, and a table of every MAC on the
        // network with the name it answers to would be the last thing left
        // describing the household. Manual aliases are configuration and stay.
        match state.inner.client_registry.forget_learned_devices().await {
            Ok(()) => tracing::info!("recording disabled, learned device inventory dropped"),
            Err(e) => {
                tracing::warn!("recording disabled, but dropping the device inventory failed: {e}")
            }
        }
    }

    if let Some(enabled) = blocklist_enabled_to_apply {
        state.inner.blocklist.set_blocking_enabled(enabled);
    }

    if let Some(entries) = blocklist_client_bypass_to_apply {
        state.inner.blocklist.set_client_bypass(&entries);
    }

    if let Some(answer) = block_answer_to_apply {
        state.inner.blocklist.set_block_answer(answer);
    }

    // RUST_LOG, when set, owns the filter — don't let the toggle fight it.
    if let Some(debug) = debug_logging_to_apply
        && std::env::var_os("RUST_LOG").is_none()
    {
        ferrite_core::logbuf::set_debug(debug);
    }

    let all_changed = hot_changed.len() + restart_changed.len();
    if all_changed == 0 {
        return Ok(Json(json!({
            "status": "no_changes",
            "note": "no known fields provided"
        })));
    }

    let saved_path = state.persist_config().await;
    let needs_restart = !restart_changed.is_empty();

    tracing::info!(
        "settings updated — hot: {:?}, restart-required: {:?}",
        hot_changed,
        restart_changed
    );

    if needs_restart {
        schedule_restart(&state);
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

/// Save the snapshot and exit, leaving the supervisor to start us again.
///
/// Delayed so this request's response gets out first — the caller is told a
/// restart is coming, then it happens.
#[cfg(not(test))]
pub(crate) fn schedule_restart(state: &AppState) {
    tracing::info!("restart-required settings changed, saving snapshot and exiting");
    let snap_state = state.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        if let Err(e) = snap_state.save_snapshot().await {
            tracing::error!("snapshot save before restart failed: {}", e);
        }
        std::process::exit(0);
    });
}

/// Under test this does nothing, because the real one ends in
/// `std::process::exit(0)`.
///
/// Today a test survives it by accident: each `#[tokio::test]` drops its
/// runtime when the test returns, which cancels the pending task before the
/// 300 ms elapses. A test that took longer would exit the whole binary with
/// status 0 — the suite would report success having silently skipped whatever
/// had not run yet. A false green is the one test failure worth engineering
/// against, so the exit is not reachable from a test at all.
#[cfg(test)]
pub(crate) fn schedule_restart(_state: &AppState) {}

/// Check a proposed `storage.path` before it reaches the config file.
///
/// The failure this prevents is the nasty one: an unusable path is accepted,
/// written to disk, and the box then refuses to come back up after the restart
/// the change itself triggered — with the panel gone, so the only way out is a
/// text editor on the device.
pub(crate) fn validate_storage_path(path: &Path) -> Result<PathBuf, ApiError> {
    let path = absolute_path("storage_path", path)?;

    if path.is_dir() {
        return Err(config_error(format!(
            "storage_path '{}' is a directory — give the database file's full path, \
             e.g. {}/ferrite.db",
            path.display(),
            path.display()
        )));
    }

    let parent = path
        .parent()
        .ok_or_else(|| config_error(format!("storage_path '{}' has no parent", path.display())))?;
    ensure_creatable(parent)?;
    Ok(path)
}

/// Check a proposed `storage.blocklist_cache_dir`, for the same reason as
/// [`validate_storage_path`]. A bad one would not stop the box booting — the
/// engine falls back to a RAM FST — but every refresh would then fail to write
/// and the lists would be downloaded again on each start, which is a worse
/// failure to discover than a refused request.
pub(crate) fn validate_blocklist_cache_dir(dir: &Path) -> Result<PathBuf, ApiError> {
    let dir = absolute_path("blocklist_cache_dir", dir)?;
    if dir.exists() && !dir.is_dir() {
        return Err(config_error(format!(
            "blocklist_cache_dir '{}' is a file — give a directory",
            dir.display()
        )));
    }
    ensure_creatable(&dir)?;
    Ok(dir)
}

fn config_error(msg: String) -> ApiError {
    ApiError(FeriteError::Config(msg))
}

/// Trim and require an absolute path. A relative one resolves against the
/// working directory, which for a service is whatever the supervisor chose and
/// can change between starts.
fn absolute_path(field: &str, path: &Path) -> Result<PathBuf, ApiError> {
    let raw = path.to_string_lossy();
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(config_error(format!("{field} must not be empty")));
    }
    let path = PathBuf::from(trimmed);
    if !path.is_absolute() {
        return Err(config_error(format!(
            "{field} must be an absolute path, got '{}'",
            path.display()
        )));
    }
    Ok(path)
}

/// Can ferrite create `dir` (or write into it, if it exists)? The directory
/// may not exist yet — startup creates it — so the question is whether the
/// nearest existing ancestor would let that happen.
fn ensure_creatable(dir: &Path) -> Result<(), ApiError> {
    let anchor = fsinfo::nearest_existing(dir).ok_or_else(|| {
        config_error(format!(
            "nothing along '{}' exists, so ferrite cannot create files there",
            dir.display()
        ))
    })?;
    if !fsinfo::probe_writable(&anchor) {
        return Err(config_error(format!(
            "ferrite cannot write to '{}' — pick a location it owns, or fix the permissions",
            anchor.display()
        )));
    }
    Ok(())
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

#[cfg(test)]
mod tests;
