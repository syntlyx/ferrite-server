use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::api::ApiError;
use crate::app::AppState;
use crate::blocklist::{AdblockStats, Blocklist};
use crate::config::ListConfig;
use crate::error::FeriteError;

/// `ListConfig` enriched with the live domain count from the last refresh, plus
/// the Adblock parse breakdown for Adblock-format lists (absent otherwise).
#[derive(Serialize)]
struct ListInfo {
    name: String,
    url: String,
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    domains_loaded: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parse_stats: Option<AdblockStats>,
}

fn to_list_info(cfg: &ListConfig, bl: &Blocklist) -> ListInfo {
    ListInfo {
        name: cfg.name.clone(),
        url: cfg.url.clone(),
        enabled: cfg.enabled,
        domains_loaded: bl.domain_count(&cfg.name),
        parse_stats: bl.parse_stats(&cfg.name),
    }
}

/// GET /api/lists — enumerate all configured blocklist subscriptions
pub async fn list_lists(State(state): State<AppState>) -> Json<Value> {
    let lists: Vec<ListInfo> = state
        .inner
        .blocklist
        .get_lists()
        .iter()
        .map(|cfg| to_list_info(cfg, &state.inner.blocklist))
        .collect();
    Json(json!({ "lists": lists }))
}

#[derive(Deserialize)]
pub struct AddListPayload {
    pub url: String,
    pub name: String,
    pub enabled: Option<bool>,
}

/// POST /api/lists — add a new subscription list and trigger a refresh
pub async fn add_list(
    State(state): State<AppState>,
    Json(payload): Json<AddListPayload>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    // SSRF / local-file-read guard: validate the user-supplied URL before it is
    // persisted or fetched. Config-defined lists (incl. file://) bypass this by
    // loading through the loader directly, so trusted local lists keep working.
    crate::blocklist::loader::validate_remote_list_url(&payload.url).await?;

    let cfg = ListConfig {
        url: payload.url.clone(),
        name: payload.name.clone(),
        enabled: payload.enabled.unwrap_or(true),
    };

    state.inner.blocklist.add_list(cfg.clone())?;
    tracing::info!("added blocklist '{}' ({})", cfg.name, cfg.url);

    // Persist to config file.
    sync_lists_to_config(&state).await;

    // Trigger a background refresh so the new list is loaded immediately.
    {
        let blocklist = Arc::clone(&state.inner.blocklist);
        tokio::spawn(async move {
            if let Err(e) = blocklist.refresh(false).await {
                tracing::error!("refresh after add_list failed: {}", e);
            }
        });
    }

    Ok((
        StatusCode::CREATED,
        Json(json!({ "list": to_list_info(&cfg, &state.inner.blocklist) })),
    ))
}

/// DELETE /api/lists/:name — remove a list and rebuild the FST
pub async fn del_list(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    if !state.inner.blocklist.remove_list(&name) {
        return Err(ApiError(FeriteError::NotFound(format!(
            "list '{}' not found",
            name
        ))));
    }
    tracing::info!("removed blocklist '{}'", name);

    // Persist to config file.
    sync_lists_to_config(&state).await;

    // Rebuild FST without the removed list.
    {
        let blocklist = Arc::clone(&state.inner.blocklist);
        tokio::spawn(async move {
            if let Err(e) = blocklist.refresh(false).await {
                tracing::error!("refresh after del_list failed: {}", e);
            }
        });
    }

    Ok(Json(json!({ "name": name, "status": "removed" })))
}

/// Sync the current in-memory list of subscriptions into `live_config` and save to disk.
async fn sync_lists_to_config(state: &AppState) {
    let lists = state.inner.blocklist.get_lists();
    state.live_config.write().blocklist.lists = lists;

    let cfg = state.live_config.read().clone();
    let path = state.config_path.as_ref().clone().or_else(|| {
        crate::config::Config::config_candidates()
            .into_iter()
            .next()
    });

    if let Some(path) = path {
        match cfg.save(&path) {
            Ok(()) => tracing::info!("blocklist config saved to {}", path.display()),
            Err(e) => tracing::error!("failed to save blocklist config: {}", e),
        }
    }
}

/// PATCH /api/lists/:name — enable or disable a list without removing it
#[derive(Deserialize, Serialize)]
pub struct PatchListPayload {
    pub enabled: bool,
}

pub async fn patch_list(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(payload): Json<PatchListPayload>,
) -> Result<Json<Value>, ApiError> {
    if !state
        .inner
        .blocklist
        .set_list_enabled(&name, payload.enabled)
    {
        return Err(ApiError(FeriteError::NotFound(format!(
            "list '{}' not found",
            name
        ))));
    }
    tracing::info!(
        "blocklist '{}' {}",
        name,
        if payload.enabled {
            "enabled"
        } else {
            "disabled"
        }
    );

    sync_lists_to_config(&state).await;

    // Rebuild FST: disabling a list should remove its domains immediately,
    // enabling should add them back.
    {
        let blocklist = Arc::clone(&state.inner.blocklist);
        tokio::spawn(async move {
            if let Err(e) = blocklist.refresh(false).await {
                tracing::error!("refresh after patch_list failed: {}", e);
            }
        });
    }

    let updated = state
        .inner
        .blocklist
        .get_lists()
        .iter()
        .find(|l| l.name == name)
        .map(|cfg| to_list_info(cfg, &state.inner.blocklist));
    Ok(Json(json!({ "list": updated })))
}

/// POST /api/lists/refresh — re-fetch all lists and rebuild FST
pub async fn refresh_all_lists(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    state.inner.blocklist.refresh(true).await?;
    let lists: Vec<ListInfo> = state
        .inner
        .blocklist
        .get_lists()
        .iter()
        .map(|cfg| to_list_info(cfg, &state.inner.blocklist))
        .collect();
    Ok(Json(json!({ "lists": lists })))
}

/// POST /api/lists/:name/refresh — re-fetch a specific list and rebuild FST
pub async fn refresh_list(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let exists = state
        .inner
        .blocklist
        .get_lists()
        .iter()
        .any(|l| l.name == name);

    if !exists {
        return Err(ApiError(FeriteError::NotFound(format!(
            "list '{}' not found",
            name
        ))));
    }

    state.inner.blocklist.refresh(true).await?;
    let count = state.inner.blocklist.domain_count(&name);
    let parse_stats = state.inner.blocklist.parse_stats(&name);
    Ok(Json(json!({
        "name": name,
        "domains_loaded": count,
        "parse_stats": parse_stats,
    })))
}
