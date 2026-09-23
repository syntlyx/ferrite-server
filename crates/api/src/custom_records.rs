use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde_json::{Value, json};

use crate::ApiError;
use ferrite_app::AppState;
use ferrite_core::config::CustomRecordConfig;
use ferrite_core::error::FeriteError;

/// GET /api/custom-records
pub async fn list_records(State(state): State<AppState>) -> Json<Value> {
    Json(json!({ "records": state.inner.custom_records.list() }))
}

/// POST /api/custom-records
pub async fn add_record(
    State(state): State<AppState>,
    Json(mut cfg): Json<CustomRecordConfig>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    // Normalise to the same key the engine and `list()` use, so the config
    // entry matches and `dns_cache.evict` targets the key the resolver caches
    // under.
    cfg.domain = ferrite_blocklist::normalise_domain(&cfg.domain);
    // Engine first — it rejects a malformed value, and nothing the engine
    // would refuse on reload should reach the config file.
    state.inner.custom_records.add(&cfg)?;
    // Evict any cached response for this domain (all qtypes, incl. ANY) so the
    // new record is served immediately.
    state.inner.dns_cache.evict_domain(&cfg.domain);

    {
        let mut live = state.live_config.write();
        // `add` replaces same-type records for a domain, so mirror that here
        // rather than accumulating duplicates in the file.
        live.custom_records
            .retain(|r| r.domain != cfg.domain || r.record_type != cfg.record_type);
        live.custom_records.push(cfg.clone());
    }
    let persisted = state.persist_config().await.is_some();

    tracing::info!(
        "custom record added: {} {} → {}",
        cfg.domain,
        cfg.record_type,
        cfg.value
    );
    Ok((
        StatusCode::CREATED,
        Json(json!({ "record": cfg, "persisted": persisted })),
    ))
}

/// DELETE /api/custom-records/:domain
pub async fn delete_record(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let domain = ferrite_blocklist::normalise_domain(&domain);
    if !state.inner.custom_records.remove(&domain) {
        return Err(ApiError(FeriteError::NotFound(format!(
            "no custom record for '{}'",
            domain
        ))));
    }
    state.inner.dns_cache.evict_domain(&domain);

    {
        let mut live = state.live_config.write();
        // Match on the normalised domain: an entry hand-written as
        // `Router.LAN.` is the same record the UI just deleted, and leaving it
        // in the file would resurrect it on the next restart.
        live.custom_records
            .retain(|r| ferrite_blocklist::normalise_domain(&r.domain) != domain);
    }
    let persisted = state.persist_config().await.is_some();

    tracing::info!("custom record removed: {}", domain);
    Ok(Json(
        json!({ "domain": domain, "status": "removed", "persisted": persisted }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_app::test_support;

    /// The UI deletes by the normalised key `list()` shows. That delete has to
    /// clear the config entry too, or the record comes back on the next start.
    #[tokio::test]
    async fn custom_record_add_normalizes_so_delete_clears_the_config() {
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

        let listed = state.inner.custom_records.list();
        assert_eq!(listed[0].domain, "router.lan");
        assert_eq!(state.live_config.read().custom_records.len(), 1);
        assert_eq!(
            state.live_config.read().custom_records[0].domain,
            "router.lan"
        );

        let _ = delete_record(State(state.clone()), Path("router.lan".to_string()))
            .await
            .unwrap();

        assert!(state.live_config.read().custom_records.is_empty());

        drop(state);
        test_support::cleanup_sqlite(&db_path);
    }

    /// A record written by hand in the config file must be deletable through
    /// the UI — the case the database-backed path got wrong.
    #[tokio::test]
    async fn a_record_from_the_config_file_can_be_deleted() {
        let (state, db_path) = test_support::app_state("api-cr-from-file").await;

        let record = CustomRecordConfig {
            domain: "Nas.LAN.".into(),
            record_type: "A".into(),
            value: "192.168.1.2".into(),
            ttl: 300,
        };
        state.inner.custom_records.add(&record).unwrap();
        state.live_config.write().custom_records.push(record);

        let _ = delete_record(State(state.clone()), Path("nas.lan".to_string()))
            .await
            .unwrap();

        assert!(state.live_config.read().custom_records.is_empty());
        assert!(state.inner.custom_records.list().is_empty());

        drop(state);
        test_support::cleanup_sqlite(&db_path);
    }
}
