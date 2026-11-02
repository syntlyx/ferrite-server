//! `/api/services` — the built-in service catalog — and
//! `/api/blocklist/services` — the catalog services blocked for every device.
//! Per-device service blocks live on the profiles (`/api/blocklist/profiles`),
//! and a tunnel rule routes a service through `/api/proxy`.

use axum::{Json, extract::State};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::ApiError;
use ferrite_app::AppState;
use ferrite_core::error::FeriteError;
use ferrite_core::services;

/// GET /api/services — every catalog service (id, name, category, whether a
/// tunnel can route it, and its domains), plus the category order.
pub async fn get_catalog() -> Json<Value> {
    Json(json!({
        "categories": services::CATEGORIES,
        "services": services::catalog(),
    }))
}

/// GET /api/blocklist/services — the services blocked for every device.
pub async fn get_blocked(State(state): State<AppState>) -> Json<Value> {
    Json(json!({ "services": state.inner.blocklist.blocked_services() }))
}

#[derive(Deserialize)]
pub struct ServicesPayload {
    pub services: Vec<String>,
}

/// PUT /api/blocklist/services — replace the services blocked for every
/// device. Live at once (decision caches drop), then persisted.
pub async fn put_blocked(
    State(state): State<AppState>,
    Json(payload): Json<ServicesPayload>,
) -> Result<Json<Value>, ApiError> {
    let ids = known_ids(&payload.services, "blocked services")?;
    state.inner.blocklist.set_blocked_services(&ids);
    state.live_config.write().blocklist.services = ids.clone();
    let saved_to = state.persist_config().await;
    tracing::info!("network-wide blocked services: {:?}", ids);
    Ok(Json(json!({
        "status": "ok",
        "services": ids,
        "persisted": saved_to.is_some(),
        "saved_to": saved_to,
    })))
}

/// Service ids cleaned up the way the config stores them, or a 400 naming the
/// first id the catalog doesn't know — a typo would otherwise block nothing.
pub(crate) fn known_ids(ids: &[String], owner: &str) -> Result<Vec<String>, ApiError> {
    let (known, unknown) = services::normalize_ids(ids);
    match unknown.first() {
        Some(id) => Err(ApiError(FeriteError::Config(format!(
            "{owner}: unknown service '{id}'"
        )))),
        None => Ok(known),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_app::test_support;

    #[tokio::test]
    async fn catalog_lists_services_with_their_domains() {
        let Json(body) = get_catalog().await;
        let list = body["services"].as_array().unwrap();
        let youtube = list.iter().find(|s| s["id"] == "youtube").unwrap();
        assert_eq!(youtube["name"], "YouTube");
        assert_eq!(youtube["routable"], true);
        assert!(
            youtube["domains"]
                .as_array()
                .unwrap()
                .iter()
                .any(|d| d == "googlevideo.com")
        );
        assert_eq!(body["categories"][0], "video");
    }

    #[tokio::test]
    async fn put_blocks_live_persists_and_rejects_unknown_ids() {
        let (state, db) = test_support::app_state("services-api-put").await;

        let bad = put_blocked(
            State(state.clone()),
            Json(ServicesPayload {
                services: vec!["tiktok".into(), "tiktak".into()],
            }),
        )
        .await
        .unwrap_err();
        assert!(matches!(bad.0, FeriteError::Config(ref m) if m.contains("tiktak")));
        assert!(state.inner.blocklist.blocked_services().is_empty());

        let Json(ok) = put_blocked(
            State(state.clone()),
            Json(ServicesPayload {
                services: vec![" TikTok ".into(), "tiktok".into()],
            }),
        )
        .await
        .unwrap();
        assert_eq!(ok["services"], json!(["tiktok"]));
        assert!(
            state
                .inner
                .blocklist
                .should_block_for("www.tiktok.com", None)
        );
        assert_eq!(state.live_config.read().blocklist.services, vec!["tiktok"]);

        let Json(listed) = get_blocked(State(state.clone())).await;
        assert_eq!(listed["services"], json!(["tiktok"]));

        drop(state);
        test_support::cleanup_sqlite(&db);
    }
}
