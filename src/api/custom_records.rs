use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};

use crate::api::ApiError;
use crate::app::AppState;
use crate::config::CustomRecordConfig;
use crate::error::FeriteError;

/// GET /api/custom-records
pub async fn list_records(State(state): State<AppState>) -> Json<Value> {
    Json(json!({ "records": state.inner.custom_records.list() }))
}

/// POST /api/custom-records
pub async fn add_record(
    State(state): State<AppState>,
    Json(cfg): Json<CustomRecordConfig>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    state.inner.custom_records.add(&cfg)?;
    // Evict any cached response for this domain so the new record is served immediately.
    for qtype in [1u16, 28, 5] {
        state.inner.dns_cache.evict(&cfg.domain, qtype);
    }
    state
        .inner
        .storage
        .upsert_custom_record(&cfg.domain, &cfg.record_type, &cfg.value, cfg.ttl)
        .await?;
    tracing::info!(
        "custom record added: {} {} → {}",
        cfg.domain,
        cfg.record_type,
        cfg.value
    );
    Ok((StatusCode::CREATED, Json(json!({ "record": cfg }))))
}

/// DELETE /api/custom-records/:domain
pub async fn delete_record(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> Result<Json<Value>, ApiError> {
    if !state.inner.custom_records.remove(&domain) {
        return Err(ApiError(FeriteError::NotFound(format!(
            "no custom record for '{}'",
            domain
        ))));
    }
    for qtype in [1u16, 28, 5] {
        state.inner.dns_cache.evict(&domain, qtype);
    }
    state.inner.storage.delete_custom_record(&domain).await?;
    tracing::info!("custom record removed: {}", domain);
    Ok(Json(json!({ "domain": domain, "status": "removed" })))
}
