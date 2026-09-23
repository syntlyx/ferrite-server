use axum::{
    Json,
    extract::{Path, State},
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
    if domain.contains('*') {
        state.inner.dns_cache.clear();
        return;
    }
    state.inner.dns_cache.evict_domain(domain);
}

/// GET /api/blocklist/check/:domain
///
/// Returns the block decision **plus attribution**: which source(s) match (manual
/// blacklist, wildcard, or a named subscription list), the whitelist entry that
/// exempts it, and the **routing decision** — which egress (if any) the domain
/// would be tunnelled through. The attribution scans each list's on-disk FST, so it
/// runs in `spawn_blocking` and off the DNS hot path.
pub async fn check_domain(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> Result<Json<Value>, ApiError> {
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
    }
    Ok(Json(value))
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
