use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::ApiError;
use ferrite_app::AppState;
use ferrite_core::error::FeriteError;

#[derive(Deserialize)]
pub struct DomainPayload {
    pub domain: String,
}

#[derive(Serialize)]
pub struct DomainResponse {
    pub domain: String,
    pub status: String,
    /// Did the change reach `config.toml`? It is already live either way; this
    /// says whether it survives a restart.
    pub persisted: bool,
}

/// POST /api/blocklist/blacklist
pub async fn add_blacklist(
    State(state): State<AppState>,
    Json(payload): Json<DomainPayload>,
) -> Result<(StatusCode, Json<DomainResponse>), ApiError> {
    // Normalise once, identically to the engine, so the entry written to the
    // config matches the engine key and the value returned by list_*.
    let domain = ferrite_blocklist::normalise_domain(&payload.domain);
    // Engine first: it rejects a pattern that can't be compiled, and nothing
    // should reach the config file that the engine would refuse on reload.
    state.inner.blocklist.add_blacklist(&domain)?;
    add_config_domain(&state, Polarity::Block, &domain);
    // Evict cached (allowed) DNS responses so the block takes effect immediately.
    evict_domain_cache(&state, &domain);
    let persisted = state.persist_config().await.is_some();
    tracing::info!("blacklisted '{}'", domain);
    Ok((
        StatusCode::CREATED,
        Json(DomainResponse {
            domain,
            status: "blacklisted".into(),
            persisted,
        }),
    ))
}

/// DELETE /api/blocklist/blacklist/:domain
pub async fn del_blacklist(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let domain = ferrite_blocklist::normalise_domain(&domain);
    state.inner.blocklist.remove_blacklist(&domain);
    remove_config_domain(&state, Polarity::Block, &domain);
    evict_domain_cache(&state, &domain);
    let persisted = state.persist_config().await.is_some();
    tracing::info!("removed '{}' from blacklist", domain);
    Ok(Json(
        json!({ "domain": domain, "status": "removed", "persisted": persisted }),
    ))
}

/// POST /api/blocklist/whitelist
pub async fn add_whitelist(
    State(state): State<AppState>,
    Json(payload): Json<DomainPayload>,
) -> Result<(StatusCode, Json<DomainResponse>), ApiError> {
    let domain = ferrite_blocklist::normalise_domain(&payload.domain);
    state.inner.blocklist.add_whitelist(&domain)?;
    add_config_domain(&state, Polarity::Allow, &domain);
    // Evict stale cached responses so the whitelist takes effect immediately.
    evict_domain_cache(&state, &domain);
    let persisted = state.persist_config().await.is_some();
    tracing::info!("whitelisted '{}'", domain);
    Ok((
        StatusCode::CREATED,
        Json(DomainResponse {
            domain,
            status: "whitelisted".into(),
            persisted,
        }),
    ))
}

/// DELETE /api/blocklist/whitelist/:domain
pub async fn del_whitelist(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let domain = ferrite_blocklist::normalise_domain(&domain);
    state.inner.blocklist.remove_whitelist(&domain);
    remove_config_domain(&state, Polarity::Allow, &domain);
    evict_domain_cache(&state, &domain);
    let persisted = state.persist_config().await.is_some();
    tracing::info!("removed '{}' from whitelist", domain);
    Ok(Json(
        json!({ "domain": domain, "status": "removed", "persisted": persisted }),
    ))
}

/// Which manual list a config edit targets.
#[derive(Clone, Copy)]
enum Polarity {
    Block,
    Allow,
}

/// Mirror an engine addition into `live_config`. Held only for the push — the
/// file write happens afterwards, off the lock.
fn add_config_domain(state: &AppState, polarity: Polarity, domain: &str) {
    let mut cfg = state.live_config.write();
    let target = match polarity {
        Polarity::Block => &mut cfg.blocklist.domains,
        Polarity::Allow => &mut cfg.allowlist.domains,
    };
    if !target.iter().any(|d| d == domain) {
        target.push(domain.to_string());
    }
}

/// Add manual entries in bulk (an import): each one the engine accepts goes
/// into the config too. Entries already there are counted as skipped; nothing
/// is persisted or evicted here — the caller does both once.
pub(crate) fn import_entries(state: &AppState, allow: bool, entries: &[String]) -> Value {
    let engine = &state.inner.blocklist;
    let have: std::collections::HashSet<String> = if allow {
        engine.list_whitelist()
    } else {
        engine.list_blacklist()
    }
    .into_iter()
    .collect();
    let polarity = if allow {
        Polarity::Allow
    } else {
        Polarity::Block
    };
    let (mut added, mut already, mut skipped) = (0, 0, Vec::new());
    for raw in entries {
        let entry = ferrite_blocklist::normalise_domain(raw);
        if entry.is_empty() {
            continue;
        }
        if have.contains(&entry) {
            already += 1;
            continue;
        }
        let result = if allow {
            engine.add_whitelist(&entry)
        } else {
            engine.add_blacklist(&entry)
        };
        match result {
            Ok(()) => {
                add_config_domain(state, polarity, &entry);
                added += 1;
            }
            Err(e) => skipped.push(format!("{entry}: {e}")),
        }
    }
    json!({ "added": added, "already": already, "skipped": skipped })
}

/// Mirror an engine removal into `live_config`. Compares against the normalised
/// form of each entry, so an entry hand-written as `Ads.Example.COM.` is still
/// the one the UI deleted — before, a file-sourced entry survived the delete
/// and came back on the next restart.
fn remove_config_domain(state: &AppState, polarity: Polarity, domain: &str) {
    let mut cfg = state.live_config.write();
    let target = match polarity {
        Polarity::Block => &mut cfg.blocklist.domains,
        Polarity::Allow => &mut cfg.allowlist.domains,
    };
    target.retain(|d| ferrite_blocklist::normalise_domain(d) != domain);
}

/// Evict all cached DNS responses for `domain` (every qtype). A wildcard entry
/// can affect arbitrary names, so it flushes the whole cache.
fn evict_domain_cache(state: &AppState, domain: &str) {
    if ferrite_blocklist::is_pattern(domain) {
        state.inner.dns_cache.clear();
        return;
    }
    state.inner.dns_cache.evict_domain(domain);
}

#[derive(Debug, Default, Deserialize)]
pub struct CheckParams {
    /// A device IP or MAC: also answer for that device (its profile, pause,
    /// SafeSearch) under `for_client`.
    pub client: Option<String>,
}

/// GET /api/blocklist/check/:domain[?client=<ip|mac>]
///
/// Returns the block decision **plus attribution**: which source(s) match (manual
/// blacklist, wildcard, service, or a named subscription list), the whitelist
/// entry that exempts it, and the **routing decision** — which egress (if any)
/// the domain would be tunnelled through. With `client`, `for_client` gives that
/// device's own decision. The attribution scans each list's on-disk FST, so it
/// runs in `spawn_blocking` and off the DNS hot path.
pub async fn check_domain(
    State(state): State<AppState>,
    Path(domain): Path<String>,
    Query(params): Query<CheckParams>,
) -> Result<Json<Value>, ApiError> {
    let for_client = match params.client.as_deref().map(str::trim) {
        Some(client) if !client.is_empty() => Some(
            client_view(
                &state,
                &ferrite_blocklist::normalise_domain(&domain),
                client,
            )
            .map_err(|e| ApiError(FeriteError::Config(e)))?,
        ),
        _ => None,
    };
    // Routing decision (cheap, in-memory snapshot): paired with `enabled` so the UI
    // can distinguish "no rule matches" from "matches a rule but routing is off".
    let route = state
        .inner
        .proxy
        .route_egress(&domain.trim_end_matches('.').to_ascii_lowercase())
        .map(|(egress, client_scoped)| {
            let healthy = state.inner.proxy.is_egress_healthy(&egress);
            json!({ "egress": egress, "client_scoped": client_scoped, "healthy": healthy })
        });
    let routing = json!({ "enabled": state.inner.proxy.is_enabled(), "match": route });

    let explanation = tokio::task::spawn_blocking(move || state.inner.blocklist.explain(&domain))
        .await
        .map_err(|e| ApiError(FeriteError::Internal(format!("explain task failed: {e}"))))?;
    let mut value = serde_json::to_value(explanation)
        .map_err(|e| ApiError(FeriteError::Internal(format!("serialize explanation: {e}"))))?;
    if let Some(obj) = value.as_object_mut() {
        obj.insert("routing".to_string(), routing);
        if let Some(view) = for_client {
            obj.insert("for_client".to_string(), view);
        }
    }
    Ok(Json(value))
}

/// One device's decision for `domain` (normalised): the profile on for it right
/// now, whether its filtering is off (paused or bypassed), whether the name is
/// blocked for it, and the SafeSearch host it resolves to instead, if any.
pub(crate) fn client_view(state: &AppState, domain: &str, client: &str) -> Result<Value, String> {
    use ferrite_core::net::{normalize_client_key, parse_ip, unmap_v4};
    let bl = &state.inner.blocklist;
    let (ip, mac) = match parse_ip(client) {
        Some(ip) => {
            let ip = unmap_v4(ip);
            (ip.to_string(), state.inner.client_registry.get_mac(ip))
        }
        None => match normalize_client_key(client) {
            Some(mac) => (String::new(), Some(mac)),
            None => return Err(format!("`{client}` is neither an IP nor a MAC")),
        },
    };
    let filtering_off =
        !bl.blocking_enabled() || bl.client_filtering_off_normalized(&ip, mac.as_deref());
    let profile = bl.profile_for(&ip, mac.as_deref());
    let blocked = !filtering_off && bl.should_block_for(domain, profile.as_deref());
    // A block answers first; SafeSearch only rewrites what resolves.
    let safe_host = if filtering_off || blocked {
        None
    } else {
        bl.safe_search_target(domain, profile.as_deref())
    };
    Ok(json!({
        "client": client,
        "mac": mac,
        "profile": profile.as_ref().map(|p| p.id().to_string()),
        "filtering_off": filtering_off,
        "blocked": blocked,
        "safe_search_answer": safe_host,
    }))
}

/// GET /api/blocklist/blacklist
pub async fn list_blacklist(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let blacklist = state.inner.blocklist.list_blacklist();
    Ok(Json(json!({ "blacklist": blacklist })))
}

/// GET /api/blocklist/whitelist
pub async fn list_whitelist(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let whitelist = state.inner.blocklist.list_whitelist();
    Ok(Json(json!({ "whitelist": whitelist })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_app::test_support;

    #[tokio::test]
    async fn whitelist_add_normalizes_so_delete_clears_the_config() {
        let (state, db_path) = test_support::app_state("api-wl-normalize").await;

        // FQDN, mixed-case input — must be normalised identically for the
        // engine and the config so the listed value can delete the entry.
        let _ = add_whitelist(
            State(state.clone()),
            Json(DomainPayload {
                domain: "Ads.Example.Com.".into(),
            }),
        )
        .await
        .unwrap();

        assert!(state.inner.blocklist.is_whitelisted("ads.example.com"));
        assert_eq!(
            state.live_config.read().allowlist.domains,
            vec!["ads.example.com".to_string()]
        );

        // Delete by the normalised (UI-listed) value — the config entry must be
        // gone, so it can't resurrect on restart.
        let _ = del_whitelist(State(state.clone()), Path("ads.example.com".to_string()))
            .await
            .unwrap();
        assert!(state.live_config.read().allowlist.domains.is_empty());
        assert!(!state.inner.blocklist.is_whitelisted("ads.example.com"));

        drop(state);
        test_support::cleanup_sqlite(&db_path);
    }

    /// The bug the split caused: an entry written by hand in `config.toml` was
    /// seeded into the engine but had no database row, so deleting it in the UI
    /// cleared nothing and the file put it straight back on the next restart.
    #[tokio::test]
    async fn an_entry_from_the_config_file_can_be_deleted() {
        let (state, db_path) = test_support::app_state("api-bl-from-file").await;

        state
            .inner
            .blocklist
            .add_blacklist("*.ads.example")
            .unwrap();
        state
            .live_config
            .write()
            .blocklist
            .domains
            .push("*.Ads.Example.".to_string());

        let _ = del_blacklist(State(state.clone()), Path("*.ads.example".to_string()))
            .await
            .unwrap();

        assert!(state.live_config.read().blocklist.domains.is_empty());
        assert!(
            !state
                .inner
                .blocklist
                .is_blocked_normalized("tracker.ads.example")
        );

        drop(state);
        test_support::cleanup_sqlite(&db_path);
    }

    /// Manual entries are seeded from the config at construction, so an engine
    /// built from a file that names them already blocks and lists them.
    #[tokio::test]
    async fn manual_entries_in_the_config_seed_the_engine() {
        let (state, db_path) = test_support::app_state("api-bl-seed").await;
        drop(state);
        test_support::cleanup_sqlite(&db_path);

        let mut cfg = ferrite_core::config::BlocklistConfig::default();
        cfg.lists.clear();
        cfg.domains = vec!["evil.test".to_string(), "*.ads.test".to_string()];
        let engine = ferrite_blocklist::Blocklist::new(
            cfg,
            ferrite_core::config::AllowlistConfig::default(),
            std::env::temp_dir().join("ferrite-seed-test.fst"),
        );

        assert!(engine.is_blocked_normalized("evil.test"));
        assert!(engine.is_blocked_normalized("www.evil.test"));
        assert!(engine.is_blocked_normalized("tracker.ads.test"));

        let mut listed = engine.list_blacklist();
        listed.sort();
        assert_eq!(listed, vec!["*.ads.test", "evil.test"]);
    }
}
