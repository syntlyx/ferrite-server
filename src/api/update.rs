use axum::{
    Json,
    extract::{Query, State},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::ApiError;
use crate::app::AppState;
use crate::error::FeriteError;
use crate::updater;

#[derive(Debug, Deserialize, Default)]
pub struct UpdateCheckQuery {
    #[serde(default)]
    pub force: bool,
}

/// GET /api/update/check — return cached update state unless `?force=true` is set.
pub async fn check_update(
    State(state): State<AppState>,
    Query(query): Query<UpdateCheckQuery>,
) -> Result<Json<Value>, ApiError> {
    let snapshot = updater::cached_update_check(&state, query.force).await?;
    Ok(Json(json!(snapshot)))
}

/// POST /api/update/server — download and replace the server binary
pub async fn update_server(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let current = env!("CARGO_PKG_VERSION");

    let info = updater::server::check(current).await?;

    match info {
        None => Ok(Json(json!({
            "status": "up_to_date",
            "version": current,
        }))),
        Some(info) => {
            let version = info.version.clone();
            updater::server::apply(&info).await?;
            restart_after_response(state);
            Ok(Json(json!({
                "status": "updated",
                "version": version,
                "sha256": info.sha256,
                "restart_required": true,
                "note": "server is restarting to apply the update",
            })))
        }
    }
}

fn restart_after_response(state: AppState) {
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let path = state.inner.snapshot_path.clone();
        if let Err(e) = crate::snapshot::save::save(&state, &path) {
            tracing::error!("snapshot save before server update restart failed: {}", e);
        }
        std::process::exit(0);
    });
}

/// POST /api/update/web — download and replace the web UI assets
pub async fn update_web(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let web_dir = state
        .live_config
        .read()
        .web_dir
        .clone()
        .unwrap_or_else(|| crate::config::data_dir().join("web"));

    // Read installed version from web.version file if it exists.
    let current_web = tokio::fs::read_to_string(web_dir.with_extension("version"))
        .await
        .unwrap_or_else(|_| "0.0.0".to_string());
    let current_web = updater::normalize_release_version(&current_web);
    let current_web_sha256 = updater::web::installed_sha256(&web_dir).await?;

    let latest = updater::web::check_web_update_for_server(
        &current_web,
        current_web_sha256.as_deref(),
        env!("CARGO_PKG_VERSION"),
    )
    .await?;

    match latest.update {
        None => {
            if let Some(blocked) = latest.incompatible_latest {
                return Err(ApiError(FeriteError::Update(blocked.reason)));
            }

            Ok(Json(json!({
                "status": "up_to_date",
                "version": current_web,
            })))
        }
        Some(info) => {
            let version = info.version.clone();
            let sha256 = info.sha256.clone();
            updater::web::apply_web_update(&info, &web_dir).await?;

            // Persist the installed version.
            let version_file = web_dir.with_extension("version");
            let _ = tokio::fs::write(&version_file, &version).await;
            updater::web::persist_installed_sha256(&web_dir, sha256.as_deref()).await?;
            state.update_check_cache.lock().await.clear();

            Ok(Json(json!({
                "status": "updated",
                "version": version,
                "sha256": sha256,
            })))
        }
    }
}
