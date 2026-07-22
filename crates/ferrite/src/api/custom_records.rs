use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde_json::{Value, json};

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
    Json(mut cfg): Json<CustomRecordConfig>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    // Normalise to the same key the engine and `list()` use, so the persisted
    // row matches and `dns_cache.evict` targets the key the resolver caches under.
    cfg.domain = crate::blocklist::normalise_domain(&cfg.domain);
    // Snapshot existing records for this domain so we can restore on DB failure.
    let prior: Vec<CustomRecordConfig> = state
        .inner
        .custom_records
        .list()
        .into_iter()
        .filter(|c| c.domain == cfg.domain)
        .collect();
    state.inner.custom_records.add(&cfg)?;
    // Evict any cached response for this domain (all qtypes, incl. ANY) so the
    // new record is served immediately.
    state.inner.dns_cache.evict_domain(&cfg.domain);
    if let Err(e) = state
        .inner
        .storage
        .upsert_custom_record(&cfg.domain, &cfg.record_type, &cfg.value, cfg.ttl)
        .await
    {
        // Roll back the in-memory store to what it was before this request.
        state.inner.custom_records.remove(&cfg.domain);
        for p in &prior {
            let _ = state.inner.custom_records.add(p);
        }
        return Err(e.into());
    }
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
    let domain = crate::blocklist::normalise_domain(&domain);
    let prior: Vec<CustomRecordConfig> = state
        .inner
        .custom_records
        .list()
        .into_iter()
        .filter(|c| c.domain == domain)
        .collect();
    if !state.inner.custom_records.remove(&domain) {
        return Err(ApiError(FeriteError::NotFound(format!(
            "no custom record for '{}'",
            domain
        ))));
    }
    state.inner.dns_cache.evict_domain(&domain);
    if let Err(e) = state.inner.storage.delete_custom_record(&domain).await {
        // Restore the engine entries so they stay in sync with the surviving rows.
        for p in &prior {
            let _ = state.inner.custom_records.add(p);
        }
        return Err(e.into());
    }
    tracing::info!("custom record removed: {}", domain);
    Ok(Json(json!({ "domain": domain, "status": "removed" })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support;

    #[tokio::test]
    async fn custom_record_add_normalizes_so_delete_clears_storage() {
        let (state, db_path) = test_support::app_state("api-cr-normalize").await;

        let _ = add_record(
            State(state.clone()),
            Json(CustomRecordConfig {
                domain: "Router.LAN.".into(),
                record_type: "A".into(),
                value: "192.168.1.1".into(),
                ttl: 60,
            }),
        )
        .await
        .unwrap();

        // list() exposes the normalised key — that's what the UI deletes by.
        let listed = state.inner.custom_records.list();
        assert_eq!(listed[0].domain, "router.lan");

        let _ = delete_record(State(state.clone()), Path("router.lan".to_string()))
            .await
            .unwrap();

        // The persisted row must be gone, so it can't resurrect on restart.
        assert!(
            state
                .inner
                .storage
                .load_custom_records()
                .await
                .unwrap()
                .is_empty()
        );

        drop(state);
        test_support::cleanup_sqlite(&db_path);
    }
}
