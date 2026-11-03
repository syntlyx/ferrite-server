//! Following a primary ferrite (`[sync]`): two resolvers on one network that
//! answer alike, configured in one place.
//!
//! A secondary reads the primary's configuration — `GET /api/config/export`,
//! with the primary's API key — every `interval` seconds and takes the chosen
//! sections. When that changes anything here it writes the config and
//! restarts to apply it: about a second, with the DNS cache carried across by
//! the warm-restart snapshot, so clients barely notice (and those that do ask
//! the primary meanwhile). Nothing on the primary needs turning on but an API
//! key.
//!
//! What stays local, always: listeners, storage, the panel, passwords and
//! keys, notifications, MCP — and this box's own `[sync]`.

use std::time::Duration;

use axum::{Json, extract::State};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::ApiError;
use ferrite_app::AppState;
use ferrite_core::config::{Config, SyncConfig, SyncSection};
use ferrite_core::error::FeriteError;

/// How long one read of the primary may take.
const FETCH_TIMEOUT: Duration = Duration::from_secs(15);
/// Bounds on the interval, seconds.
const MIN_INTERVAL: u64 = 60;
const MAX_INTERVAL: u64 = 24 * 3600;

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// The background loop: sync, sleep `interval`, repeat — woken early when the
/// settings change or someone asks for a sync now. Runs for the life of the
/// process; does nothing while `[sync]` names no primary.
pub async fn run(state: AppState) {
    // Let startup settle — lists load, listeners bind — before the first read.
    tokio::time::sleep(Duration::from_secs(15)).await;
    loop {
        let sync = state.live_config.read().sync.clone();
        if !sync.is_off()
            && let Err(e) = sync_once(&state).await
        {
            tracing::warn!("sync from {}: {e}", sync.primary);
        }
        let wait = Duration::from_secs(sync.interval.clamp(MIN_INTERVAL, MAX_INTERVAL));
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = state.inner.sync_wake.notified() => {}
        }
    }
}

/// One sync: read the primary, take the chosen sections, and when that
/// changed anything, persist and restart. `Ok(true)` when a restart follows.
pub(crate) async fn sync_once(state: &AppState) -> Result<bool, String> {
    let sync = state.live_config.read().sync.clone();
    let result = fetch(&sync).await.map(|primary| {
        let local = state.live_config.read().clone();
        plan(&local, &primary, &sync.sections)
    });
    let mut status = state.inner.sync_status.lock().clone();
    status.last_attempt = Some(now());
    let (merged, changed) = match result {
        Ok(p) => p,
        Err(e) => {
            status.error = Some(e.clone());
            *state.inner.sync_status.lock() = status;
            return Err(e);
        }
    };
    status.last_ok = Some(now());
    status.error = None;
    if changed.is_empty() {
        *state.inner.sync_status.lock() = status;
        return Ok(false);
    }

    // Applying the very thing applied last time means the restart didn't
    // make this box match — something keeps them apart. Restarting again
    // would only loop; say so instead.
    let fingerprint = fingerprint(&merged, &sync.sections);
    if status.applied.as_deref() == Some(fingerprint.as_str()) {
        let e = format!(
            "{} still differ after applying them — not restarting again",
            names(&changed)
        );
        status.error = Some(e.clone());
        *state.inner.sync_status.lock() = status;
        return Err(e);
    }

    let previous = std::mem::replace(&mut *state.live_config.write(), merged);
    if state.persist_config().await.is_none() {
        *state.live_config.write() = previous;
        status.error = Some("couldn't write the config file".into());
        *state.inner.sync_status.lock() = status;
        return Err("couldn't write the config file".into());
    }
    status.last_change = Some(now());
    status.changed = changed
        .iter()
        .map(|s| section_name(*s).to_string())
        .collect();
    status.applied = Some(fingerprint);
    status.save();
    *state.inner.sync_status.lock() = status;
    tracing::info!(
        "synced {} from {} — restarting to apply",
        names(&changed),
        sync.primary
    );
    crate::settings::schedule_restart(state);
    Ok(true)
}

/// Read and parse the primary's configuration.
async fn fetch(sync: &SyncConfig) -> Result<Config, String> {
    let url = format!("{}/api/config/export", sync.primary.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .build()
        .map_err(|e| e.to_string())?;
    let mut request = client.get(&url);
    if let Some(key) = &sync.api_key {
        request = request.bearer_auth(key);
    }
    let response = request
        .send()
        .await
        .map_err(|e| format!("couldn't reach the primary: {e}"))?;
    match response.status().as_u16() {
        200 => {}
        401 | 403 => return Err("the primary refused the API key".into()),
        404 => {
            return Err("the primary has no config export — is it ferrite 0.1.10 or newer?".into());
        }
        code => return Err(format!("the primary answered {code}")),
    }
    let text = response
        .text()
        .await
        .map_err(|e| format!("couldn't read the primary's answer: {e}"))?;
    Config::from_toml(&text).map_err(|e| format!("the primary's config doesn't parse: {e}"))
}

/// This box's config with the chosen sections taken from `primary`, and the
/// sections that actually differ.
pub(crate) fn plan(
    local: &Config,
    primary: &Config,
    sections: &[SyncSection],
) -> (Config, Vec<SyncSection>) {
    let mut out = local.clone();
    for s in sections {
        match s {
            SyncSection::Filtering => {
                // The decision cache is sized for this box's memory.
                let cache = out.blocklist.decision_cache_size;
                out.blocklist = primary.blocklist.clone();
                out.blocklist.decision_cache_size = cache;
                out.allowlist = primary.allowlist.clone();
            }
            SyncSection::Records => out.custom_records = primary.custom_records.clone(),
            SyncSection::Devices => out.client_aliases = primary.client_aliases.clone(),
            SyncSection::Dns => {
                let (to, from) = (&mut out.dns, &primary.dns);
                to.min_ttl = from.min_ttl;
                to.max_ttl = from.max_ttl;
                to.client_ttl = from.client_ttl;
                to.log_ignore = from.log_ignore.clone();
                to.strip_ecs = from.strip_ecs;
                to.dnssec = from.dnssec;
                to.firefox_canary = from.firefox_canary;
                to.block_private_relay = from.block_private_relay;
                to.strip_ech = from.strip_ech;
                to.serve_stale = from.serve_stale;
                to.stale_max_age = from.stale_max_age;
                to.rate_limit = from.rate_limit;
                to.allowed_clients = from.allowed_clients.clone();
                to.denied_clients = from.denied_clients.clone();
                out.upstream = primary.upstream.clone();
                out.zones = primary.zones.clone();
            }
            SyncSection::Tunnels => out.proxy = primary.proxy.clone(),
        }
    }
    let changed = sections
        .iter()
        .copied()
        .filter(|s| part(local, *s) != part(&out, *s))
        .collect();
    (out, changed)
}

/// One section of a config, comparable.
fn part(c: &Config, s: SyncSection) -> String {
    let v = match s {
        SyncSection::Filtering => {
            let mut blocklist = serde_json::to_value(&c.blocklist).unwrap_or_default();
            blocklist["decision_cache_size"] = Value::Null;
            json!([blocklist, c.allowlist])
        }
        SyncSection::Records => json!(c.custom_records),
        SyncSection::Devices => json!(c.client_aliases),
        SyncSection::Dns => {
            let d = &c.dns;
            json!([
                d.min_ttl,
                d.max_ttl,
                d.client_ttl,
                d.log_ignore,
                d.strip_ecs,
                d.dnssec,
                d.firefox_canary,
                d.block_private_relay,
                d.strip_ech,
                d.serve_stale,
                d.stale_max_age,
                d.rate_limit,
                d.allowed_clients,
                d.denied_clients,
                c.upstream,
                c.zones,
            ])
        }
        SyncSection::Tunnels => json!(c.proxy),
    };
    v.to_string()
}

fn fingerprint(c: &Config, sections: &[SyncSection]) -> String {
    let all: String = sections.iter().map(|s| part(c, *s)).collect();
    hex::encode(ring::digest::digest(&ring::digest::SHA256, all.as_bytes()))
}

fn section_name(s: SyncSection) -> &'static str {
    match s {
        SyncSection::Filtering => "filtering",
        SyncSection::Records => "records",
        SyncSection::Devices => "devices",
        SyncSection::Dns => "dns",
        SyncSection::Tunnels => "tunnels",
    }
}

fn names(sections: &[SyncSection]) -> String {
    sections
        .iter()
        .map(|s| section_name(*s))
        .collect::<Vec<_>>()
        .join(", ")
}

// ── API ──────────────────────────────────────────────────────────────────────

fn view(state: &AppState) -> Value {
    let sync = state.live_config.read().sync.clone();
    let status = state.inner.sync_status.lock().clone();
    json!({
        "primary": sync.primary,
        "api_key_set": sync.api_key.as_deref().is_some_and(|k| !k.is_empty()),
        "interval": sync.interval,
        "sections": sync.sections,
        "status": status,
    })
}

/// GET /api/sync — whether this box follows a primary, and how that went.
pub async fn get_sync(State(state): State<AppState>) -> Json<Value> {
    Json(view(&state))
}

#[derive(Debug, Deserialize)]
pub struct SyncPatch {
    /// The primary's panel URL; empty stops following.
    pub primary: String,
    /// Absent = keep, `null` = clear, a string = set.
    #[serde(default, deserialize_with = "crate::settings::nullable::deserialize")]
    pub api_key: Option<Option<String>>,
    pub interval: Option<u64>,
    pub sections: Option<Vec<SyncSection>>,
}

/// PUT /api/sync — follow a primary (or stop). Saved, and the loop wakes to
/// try it at once.
pub async fn put_sync(
    State(state): State<AppState>,
    Json(patch): Json<SyncPatch>,
) -> Result<Json<Value>, ApiError> {
    let bad = |m: &str| ApiError(FeriteError::Config(m.into()));
    let primary = patch.primary.trim().trim_end_matches('/').to_string();
    if !primary.is_empty() && !ferrite_core::notify::valid_webhook(&primary) {
        return Err(bad(
            "the primary must be an http(s) URL, like http://192.168.1.10",
        ));
    }
    if let Some(i) = patch.interval
        && !(MIN_INTERVAL..=MAX_INTERVAL).contains(&i)
    {
        return Err(bad("interval must be between 60 seconds and a day"));
    }
    if patch.sections.as_ref().is_some_and(Vec::is_empty) && !primary.is_empty() {
        return Err(bad("choose at least one section to follow"));
    }
    {
        let mut cfg = state.live_config.write();
        let sync = &mut cfg.sync;
        sync.primary = primary;
        match patch.api_key {
            Some(Some(k)) if !k.trim().is_empty() => sync.api_key = Some(k.trim().to_string()),
            Some(_) => sync.api_key = None,
            None => {}
        }
        if let Some(i) = patch.interval {
            sync.interval = i;
        }
        if let Some(s) = patch.sections {
            sync.sections = s;
        }
    }
    state.persist_config().await;
    state.inner.sync_wake.notify_one();
    Ok(Json(view(&state)))
}

/// POST /api/sync/now — sync at once and say how it went. When it changes
/// something the box restarts right after answering.
pub async fn sync_now(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    if state.live_config.read().sync.is_off() {
        return Err(ApiError(FeriteError::Config(
            "this box doesn't follow a primary".into(),
        )));
    }
    let restarting = sync_once(&state)
        .await
        .map_err(|e| ApiError(FeriteError::Config(e)))?;
    let mut v = view(&state);
    v["restarting"] = json!(restarting);
    Ok(Json(v))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_core::config::{CustomRecordConfig, ListConfig, UpstreamConfig};

    fn primary() -> Config {
        let mut p = Config::default();
        p.blocklist.domains = vec!["ads.example.com".into()];
        p.blocklist.decision_cache_size = 1;
        p.blocklist.lists.push(ListConfig {
            url: "https://example.org/list.txt".into(),
            name: "Extra".into(),
            enabled: true,
        });
        p.custom_records.push(CustomRecordConfig {
            domain: "nas.lan".into(),
            record_type: "A".into(),
            value: "192.168.1.20".into(),
            ttl: 300,
        });
        p.dns.rate_limit = 600;
        p.dns.bind_addr = "0.0.0.0:5353".parse().unwrap();
        p.upstream = vec![UpstreamConfig::Plain {
            address: "9.9.9.9".into(),
            port: 53,
            egress: None,
        }];
        p.api.api_key = Some("primary-key".into());
        p.sync.primary = "http://somewhere".into();
        p
    }

    #[test]
    fn takes_the_chosen_sections_and_keeps_what_is_local() {
        let local = Config::default();
        let (merged, changed) = plan(
            &local,
            &primary(),
            &[
                SyncSection::Filtering,
                SyncSection::Records,
                SyncSection::Dns,
            ],
        );
        assert_eq!(
            changed,
            vec![
                SyncSection::Filtering,
                SyncSection::Records,
                SyncSection::Dns
            ]
        );
        assert_eq!(
            merged.blocklist.domains,
            vec!["ads.example.com".to_string()]
        );
        assert_eq!(merged.custom_records.len(), 1);
        assert_eq!(merged.dns.rate_limit, 600);
        assert_eq!(merged.upstream.len(), 1);
        // Local, always.
        assert_eq!(
            merged.blocklist.decision_cache_size,
            local.blocklist.decision_cache_size
        );
        assert_eq!(merged.dns.bind_addr, local.dns.bind_addr);
        assert_eq!(merged.api.api_key, local.api.api_key);
        assert!(merged.sync.is_off());

        // Applied once, nothing differs any more.
        let (_, again) = plan(
            &merged,
            &primary(),
            &[
                SyncSection::Filtering,
                SyncSection::Records,
                SyncSection::Dns,
            ],
        );
        assert!(again.is_empty());

        // A section not chosen is left alone.
        let (merged, changed) = plan(&local, &primary(), &[SyncSection::Devices]);
        assert!(changed.is_empty());
        assert!(merged.blocklist.domains.is_empty());
    }

    #[tokio::test]
    async fn put_validates_and_keeps_the_key_out_of_view() {
        let (state, db) = ferrite_app::test_support::app_state("sync-api").await;
        let bad = put_sync(
            State(state.clone()),
            Json(SyncPatch {
                primary: "192.168.1.10".into(),
                api_key: None,
                interval: None,
                sections: None,
            }),
        )
        .await;
        assert!(bad.is_err());

        let Json(v) = put_sync(
            State(state.clone()),
            Json(SyncPatch {
                // Nothing listens on the discard port: fails fast, offline.
                primary: "http://127.0.0.1:9/".into(),
                api_key: Some(Some("k".into())),
                interval: Some(120),
                sections: Some(vec![SyncSection::Filtering]),
            }),
        )
        .await
        .unwrap();
        assert_eq!(v["primary"], "http://127.0.0.1:9");
        assert_eq!(v["api_key_set"], true);
        assert!(v.get("api_key").is_none());
        assert_eq!(state.live_config.read().sync.interval, 120);

        // An unreachable primary is an error in the status, not a restart.
        ferrite_upstream::install_default_crypto();
        assert!(sync_once(&state).await.is_err());
        let status = state.inner.sync_status.lock().clone();
        assert!(status.error.unwrap().contains("couldn't reach"));
        assert!(status.last_ok.is_none());

        drop(state);
        ferrite_app::test_support::cleanup_sqlite(&db);
    }
}
