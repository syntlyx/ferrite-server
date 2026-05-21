use axum::{extract::State, Json};
use serde_json::{json, Value};

use crate::api::ApiError;
use crate::app::AppState;
use crate::updater;

/// GET /api/update/check — check for available updates
pub async fn check_update(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let current = env!("CARGO_PKG_VERSION");

    let web_dir = state
        .live_config
        .read()
        .web_dir
        .clone()
        .unwrap_or_else(|| crate::config::data_dir().join("web"));
    let installed_web = tokio::fs::read_to_string(web_dir.with_extension("version"))
        .await
        .unwrap_or_else(|_| "0.0.0".to_string());
    let installed_web = installed_web.trim().to_string();
    let installed_web_sha256 = updater::web::installed_sha256(&web_dir)
        .await
        .ok()
        .flatten();
    let installed_server_sha256 = updater::server::installed_sha256().await.ok().flatten();

    let (server_info, web_version) = tokio::join!(
        updater::server::check(current),
        updater::web::check_web_update(&installed_web, installed_web_sha256.as_deref()),
    );
    let server_info = server_info?;
    let web_version = web_version?;

    Ok(Json(json!({
        "current_server_version": current,
        "current_server_sha256": installed_server_sha256,
        "current_web_version": installed_web,
        "current_web_sha256": installed_web_sha256,
        "server_update": server_info.map(|i| json!({
            "version": i.version,
            "download_url": i.download_url,
            "release_notes": i.release_notes,
            "sha256": i.sha256,
        })),
        "web_update": web_version.map(|v| json!({
            "version": v.version,
            "download_url": v.download_url,
            "release_notes": v.release_notes,
            "sha256": v.sha256,
        })),
    })))
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
    let current_web = current_web.trim().to_string();
    let current_web_sha256 = updater::web::installed_sha256(&web_dir).await?;

    let latest =
        updater::web::check_web_update(&current_web, current_web_sha256.as_deref()).await?;

    match latest {
        None => Ok(Json(json!({
            "status": "up_to_date",
            "version": current_web,
        }))),
        Some(info) => {
            let version = info.version.clone();
            let sha256 = info.sha256.clone();
            updater::web::apply_web_update(&info, &web_dir).await?;

            // Persist the installed version.
            let version_file = web_dir.with_extension("version");
            let _ = tokio::fs::write(&version_file, &version).await;
            updater::web::persist_installed_sha256(&web_dir, sha256.as_deref()).await?;

            Ok(Json(json!({
                "status": "updated",
                "version": version,
                "sha256": sha256,
            })))
        }
    }
}
