use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::api::ApiError;
use crate::app::AppState;
use crate::error::FeriteError;

#[derive(Deserialize)]
pub struct DomainPayload {
    pub domain: String,
}

#[derive(Serialize)]
pub struct DomainResponse {
    pub domain: String,
    pub status: String,
}

/// POST /api/blocklist/blacklist
pub async fn add_blacklist(
    State(state): State<AppState>,
    Json(payload): Json<DomainPayload>,
) -> Result<(StatusCode, Json<DomainResponse>), ApiError> {
    // Normalise once, identically to the engine, so the persisted key matches
    // the engine key and the value returned by list_* (otherwise a UI-listed
    // entry can't delete its DB row and reappears on restart).
    let domain = crate::blocklist::normalise_domain(&payload.domain);
    state.inner.blocklist.add_blacklist(&domain)?;
    if let Err(e) = state
        .inner
        .storage
        .add_custom_entry(&domain, "blacklist")
        .await
    {
        // Roll back the in-memory engine so it can't diverge from storage.
        state.inner.blocklist.remove_blacklist(&domain);
        return Err(e.into());
    }
    // Evict cached (allowed) DNS responses so the block takes effect immediately.
    evict_domain_cache(&state, &domain);
    tracing::info!("blacklisted '{}'", domain);
    Ok((
        StatusCode::CREATED,
        Json(DomainResponse {
            domain,
            status: "blacklisted".into(),
        }),
    ))
}

/// DELETE /api/blocklist/blacklist/:domain
pub async fn del_blacklist(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let domain = crate::blocklist::normalise_domain(&domain);
    state.inner.blocklist.remove_blacklist(&domain);
    if let Err(e) = state.inner.storage.remove_custom_entry(&domain).await {
        // Restore the engine entry so it stays in sync with the surviving row.
        let _ = state.inner.blocklist.add_blacklist(&domain);
        return Err(e.into());
    }
    evict_domain_cache(&state, &domain);
    tracing::info!("removed '{}' from blacklist", domain);
    Ok(Json(json!({ "domain": domain, "status": "removed" })))
}

/// POST /api/blocklist/whitelist
pub async fn add_whitelist(
    State(state): State<AppState>,
    Json(payload): Json<DomainPayload>,
) -> Result<(StatusCode, Json<DomainResponse>), ApiError> {
    let domain = crate::blocklist::normalise_domain(&payload.domain);
    state.inner.blocklist.add_whitelist(&domain)?;
    if let Err(e) = state
        .inner
        .storage
        .add_custom_entry(&domain, "whitelist")
        .await
    {
        state.inner.blocklist.remove_whitelist(&domain);
        return Err(e.into());
    }
    // Evict stale cached responses so the whitelist takes effect immediately.
    evict_domain_cache(&state, &domain);
    tracing::info!("whitelisted '{}'", domain);
    Ok((
        StatusCode::CREATED,
        Json(DomainResponse {
            domain,
            status: "whitelisted".into(),
        }),
    ))
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

/// DELETE /api/blocklist/whitelist/:domain
pub async fn del_whitelist(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let domain = crate::blocklist::normalise_domain(&domain);
    state.inner.blocklist.remove_whitelist(&domain);
    if let Err(e) = state.inner.storage.remove_custom_entry(&domain).await {
        let _ = state.inner.blocklist.add_whitelist(&domain);
        return Err(e.into());
    }
    evict_domain_cache(&state, &domain);
    tracing::info!("removed '{}' from whitelist", domain);
    Ok(Json(json!({ "domain": domain, "status": "removed" })))
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
    use crate::test_support;

    #[tokio::test]
    async fn whitelist_add_normalizes_so_delete_clears_storage() {
        let (state, db_path) = test_support::app_state("api-wl-normalize").await;

        // FQDN, mixed-case input — must be normalised identically for the engine
        // and storage so the listed value can delete the persisted row.
        let _ = add_whitelist(
            State(state.clone()),
            Json(DomainPayload {
                domain: "Ads.Example.Com.".into(),
            }),
        )
        .await
        .unwrap();

        assert!(state.inner.blocklist.is_whitelisted("ads.example.com"));
        let entries = state.inner.storage.load_custom_entries().await.unwrap();
        assert_eq!(
            entries,
            vec![("ads.example.com".to_string(), "whitelist".to_string())]
        );

        // Delete by the normalised (UI-listed) value — the DB row must be gone,
        // so it can't resurrect on restart.
        let _ = del_whitelist(State(state.clone()), Path("ads.example.com".to_string()))
            .await
            .unwrap();
        assert!(
            state
                .inner
                .storage
                .load_custom_entries()
                .await
                .unwrap()
                .is_empty()
        );
        assert!(!state.inner.blocklist.is_whitelisted("ads.example.com"));

        drop(state);
        test_support::cleanup_sqlite(&db_path);
    }
}
