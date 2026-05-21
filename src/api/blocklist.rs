use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::api::ApiError;
use crate::app::AppState;

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
    let domain = payload.domain.to_ascii_lowercase();
    state.inner.blocklist.add_blacklist(&domain)?;
    state
        .inner
        .storage
        .add_custom_entry(&domain, "blacklist")
        .await?;
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
    let domain = domain.to_ascii_lowercase();
    state.inner.blocklist.remove_blacklist(&domain);
    state.inner.storage.remove_custom_entry(&domain).await?;
    evict_domain_cache(&state, &domain);
    tracing::info!("removed '{}' from blacklist", domain);
    Ok(Json(json!({ "domain": domain, "status": "removed" })))
}

/// POST /api/blocklist/whitelist
pub async fn add_whitelist(
    State(state): State<AppState>,
    Json(payload): Json<DomainPayload>,
) -> Result<(StatusCode, Json<DomainResponse>), ApiError> {
    let domain = payload.domain.to_ascii_lowercase();
    state.inner.blocklist.add_whitelist(&domain)?;
    state
        .inner
        .storage
        .add_custom_entry(&domain, "whitelist")
        .await?;
    // Evict stale cached NXDOMAIN responses so the whitelist takes effect immediately.
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

/// Evict DNS cache entries for all common record types of `domain`.
fn evict_domain_cache(state: &AppState, domain: &str) {
    if domain.contains('*') {
        state.inner.dns_cache.clear();
        return;
    }

    // A, AAAA, CNAME, MX, TXT, PTR, HTTPS
    for qtype in [1u16, 28, 5, 15, 16, 12, 65] {
        state.inner.dns_cache.evict(domain, qtype);
    }
}

/// DELETE /api/blocklist/whitelist/:domain
pub async fn del_whitelist(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let domain = domain.to_ascii_lowercase();
    state.inner.blocklist.remove_whitelist(&domain);
    state.inner.storage.remove_custom_entry(&domain).await?;
    evict_domain_cache(&state, &domain);
    tracing::info!("removed '{}' from whitelist", domain);
    Ok(Json(json!({ "domain": domain, "status": "removed" })))
}

/// GET /api/blocklist/check/:domain
pub async fn check_domain(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let domain = domain.to_ascii_lowercase();
    let blocked = state.inner.blocklist.is_blocked(&domain);
    let whitelisted = state.inner.blocklist.is_whitelisted(&domain);
    Ok(Json(json!({
        "domain": domain,
        "blocked": blocked,
        "whitelisted": whitelisted,
    })))
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
