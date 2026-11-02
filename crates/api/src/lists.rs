//! Remote list subscriptions: `/api/lists` for blocklists and `/api/allowlists`
//! for allowlists. One set of handlers serves both; the polarity bound in
//! [`routes`] picks which subscription set they act on.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::ApiError;
use ferrite_app::AppState;
use ferrite_blocklist::{AdblockStats, ListPolarity, Subscriptions};
use ferrite_core::config::ListConfig;
use ferrite_core::error::FeriteError;

/// The subscription routes for one polarity, mounted under `prefix`:
///
/// - `GET    {prefix}` — every subscription with its live counts
/// - `POST   {prefix}` — add one and refresh in the background
/// - `DELETE {prefix}/{name}` — remove one and rebuild
/// - `PATCH  {prefix}/{name}` — enable or disable without removing
/// - `POST   {prefix}/refresh` — re-fetch everything (both polarities) now
/// - `POST   {prefix}/{name}/refresh` — the same, answering for one list
pub fn routes(prefix: &str, polarity: ListPolarity) -> Router<AppState> {
    Router::new()
        .route(
            prefix,
            get(move |state: State<AppState>| list(state, polarity)).post(
                move |state: State<AppState>, Json(payload): Json<AddListPayload>| {
                    add(state, payload, polarity)
                },
            ),
        )
        .route(
            &format!("{prefix}/refresh"),
            post(move |state: State<AppState>| refresh_all(state, polarity)),
        )
        .route(
            &format!("{prefix}/{{name}}"),
            axum::routing::delete(move |state: State<AppState>, Path(name): Path<String>| {
                remove(state, name, polarity)
            })
            .patch(
                move |state: State<AppState>,
                      Path(name): Path<String>,
                      Json(payload): Json<PatchListPayload>| {
                    set_enabled(state, name, payload, polarity)
                },
            ),
        )
        .route(
            &format!("{prefix}/{{name}}/refresh"),
            post(move |state: State<AppState>, Path(name): Path<String>| {
                refresh_one(state, name, polarity)
            }),
        )
}

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

fn to_list_info(cfg: &ListConfig, subs: &Subscriptions) -> ListInfo {
    ListInfo {
        name: cfg.name.clone(),
        url: cfg.url.clone(),
        enabled: cfg.enabled,
        domains_loaded: subs.domain_count(&cfg.name),
        parse_stats: subs.parse_stats(&cfg.name),
    }
}

fn all_list_info(subs: &Subscriptions) -> Vec<ListInfo> {
    subs.lists()
        .iter()
        .map(|cfg| to_list_info(cfg, subs))
        .collect()
}

fn not_found(polarity: ListPolarity, name: &str) -> ApiError {
    ApiError(FeriteError::NotFound(format!(
        "{} '{}' not found",
        polarity.noun(),
        name
    )))
}

/// Rebuild the FSTs off the request, so a list change answers right away and
/// still takes effect as soon as the fetch and merge are done.
fn refresh_in_background(state: &AppState, what: String) {
    let blocklist = Arc::clone(&state.inner.blocklist);
    tokio::spawn(async move {
        if let Err(e) = blocklist.refresh(false).await {
            tracing::error!("refresh after {} failed: {}", what, e);
        }
    });
}

/// After subscriptions were added in bulk: write them to the config once and
/// fetch what is new, off the request.
pub(crate) async fn sync_and_refresh(state: &AppState, what: &str) {
    sync_lists_to_config(state).await;
    refresh_in_background(state, what.to_string());
}

/// Sync the current in-memory subscription sets (block and allow) into
/// `live_config` and save to disk.
async fn sync_lists_to_config(state: &AppState) {
    {
        let blocklist = &state.inner.blocklist;
        let mut cfg = state.live_config.write();
        cfg.blocklist.lists = blocklist.subscriptions(ListPolarity::Block).lists();
        cfg.allowlist.lists = blocklist.subscriptions(ListPolarity::Allow).lists();
    }

    state.persist_config().await;
}

async fn list(State(state): State<AppState>, polarity: ListPolarity) -> Json<Value> {
    let subs = state.inner.blocklist.subscriptions(polarity);
    Json(json!({ "lists": all_list_info(subs) }))
}

#[derive(Deserialize)]
pub struct AddListPayload {
    pub url: String,
    pub name: String,
    pub enabled: Option<bool>,
}

async fn add(
    State(state): State<AppState>,
    payload: AddListPayload,
    polarity: ListPolarity,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    // SSRF / local-file-read guard: validate the user-supplied URL before it is
    // persisted or fetched. Config-defined lists (incl. file://) bypass this by
    // loading through the loader directly, so trusted local lists keep working.
    ferrite_blocklist::loader::validate_remote_list_url(&payload.url).await?;

    let cfg = ListConfig {
        url: payload.url,
        name: payload.name,
        enabled: payload.enabled.unwrap_or(true),
    };

    let subs = state.inner.blocklist.subscriptions(polarity);
    subs.add(cfg.clone())?;
    tracing::info!("added {} '{}' ({})", polarity.noun(), cfg.name, cfg.url);

    sync_lists_to_config(&state).await;
    // Load the new list right away.
    refresh_in_background(&state, format!("adding {} '{}'", polarity.noun(), cfg.name));

    Ok((
        StatusCode::CREATED,
        Json(json!({ "list": to_list_info(&cfg, subs) })),
    ))
}

async fn remove(
    State(state): State<AppState>,
    name: String,
    polarity: ListPolarity,
) -> Result<Json<Value>, ApiError> {
    if !state.inner.blocklist.subscriptions(polarity).remove(&name) {
        return Err(not_found(polarity, &name));
    }
    tracing::info!("removed {} '{}'", polarity.noun(), name);

    sync_lists_to_config(&state).await;
    // Rebuild the FST without the removed list.
    refresh_in_background(&state, format!("removing {} '{}'", polarity.noun(), name));

    Ok(Json(json!({ "name": name, "status": "removed" })))
}

#[derive(Deserialize, Serialize)]
pub struct PatchListPayload {
    pub enabled: bool,
}

async fn set_enabled(
    State(state): State<AppState>,
    name: String,
    payload: PatchListPayload,
    polarity: ListPolarity,
) -> Result<Json<Value>, ApiError> {
    let subs = state.inner.blocklist.subscriptions(polarity);
    if !subs.set_enabled(&name, payload.enabled) {
        return Err(not_found(polarity, &name));
    }
    let state_word = if payload.enabled {
        "enabled"
    } else {
        "disabled"
    };
    tracing::info!("{} '{}' {}", polarity.noun(), name, state_word);

    sync_lists_to_config(&state).await;
    // Disabling a list should remove its domains immediately, enabling should
    // add them back.
    refresh_in_background(
        &state,
        format!("{} {} '{}'", state_word, polarity.noun(), name),
    );

    let updated = subs
        .lists()
        .iter()
        .find(|l| l.name == name)
        .map(|cfg| to_list_info(cfg, subs));
    Ok(Json(json!({ "list": updated })))
}

/// Re-fetch every list — one pass rebuilds both polarities — and answer with
/// this polarity's set.
async fn refresh_all(
    State(state): State<AppState>,
    polarity: ListPolarity,
) -> Result<Json<Value>, ApiError> {
    state.inner.blocklist.refresh(true).await?;
    let subs = state.inner.blocklist.subscriptions(polarity);
    Ok(Json(json!({ "lists": all_list_info(subs) })))
}

/// Re-fetch every list, answering for one of them. A single list can't be
/// refreshed on its own: the merged FST is rebuilt from the whole set.
async fn refresh_one(
    State(state): State<AppState>,
    name: String,
    polarity: ListPolarity,
) -> Result<Json<Value>, ApiError> {
    let subs = state.inner.blocklist.subscriptions(polarity);
    if !subs.lists().iter().any(|l| l.name == name) {
        return Err(not_found(polarity, &name));
    }

    state.inner.blocklist.refresh(true).await?;
    Ok(Json(json!({
        "name": name,
        "domains_loaded": subs.domain_count(&name),
        "parse_stats": subs.parse_stats(&name),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_app::test_support;

    #[tokio::test]
    async fn add_allowlist_rejects_non_public_urls() {
        let (state, db_path) = test_support::app_state("api-allowlist-ssrf").await;

        // The same SSRF/local-file guard as blocklist subscriptions must apply.
        for url in ["file:///etc/passwd", "http://127.0.0.1/allow.txt"] {
            let res = add(
                State(state.clone()),
                AddListPayload {
                    url: url.into(),
                    name: "x".into(),
                    enabled: None,
                },
                ListPolarity::Allow,
            )
            .await;
            assert!(res.is_err(), "expected {url} to be rejected");
        }
        assert!(
            state
                .inner
                .blocklist
                .subscriptions(ListPolarity::Allow)
                .lists()
                .is_empty()
        );

        drop(state);
        test_support::cleanup_sqlite(&db_path);
    }
}
