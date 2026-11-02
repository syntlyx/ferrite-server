//! `/api/blocklist/safe-search` — SafeSearch and YouTube Restricted Mode for
//! every device. A profile sets its own (`safe_search`, `youtube_restricted`
//! in `/api/blocklist/profiles`); the stricter of the two applies.

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::ApiError;
use ferrite_app::AppState;
use ferrite_blocklist::SafeSearch;
use ferrite_core::config::YoutubeRestrict;

#[derive(Debug, Deserialize, Serialize)]
pub struct SafeSearchBody {
    pub safe_search: bool,
    pub youtube_restricted: YoutubeRestrict,
}

/// GET /api/blocklist/safe-search
pub async fn get_safe_search(State(state): State<AppState>) -> Json<SafeSearchBody> {
    let safe = state.inner.blocklist.safe_search();
    Json(SafeSearchBody {
        safe_search: safe.search,
        youtube_restricted: safe.youtube,
    })
}

/// PUT /api/blocklist/safe-search — live at once, then persisted. Devices may
/// keep an answer they already hold for up to the client TTL.
pub async fn put_safe_search(
    State(state): State<AppState>,
    Json(body): Json<SafeSearchBody>,
) -> Result<Json<Value>, ApiError> {
    state.inner.blocklist.set_safe_search(SafeSearch {
        search: body.safe_search,
        youtube: body.youtube_restricted,
    });
    {
        let mut cfg = state.live_config.write();
        cfg.blocklist.safe_search = body.safe_search;
        cfg.blocklist.youtube_restricted = body.youtube_restricted;
    }
    let saved_to = state.persist_config().await;
    tracing::info!(
        "network-wide safe search: search={} youtube={:?}",
        body.safe_search,
        body.youtube_restricted
    );
    Ok(Json(json!({
        "status": "ok",
        "persisted": saved_to.is_some(),
        "saved_to": saved_to,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_app::test_support;

    #[tokio::test]
    async fn put_applies_live_and_persists() {
        let (state, db) = test_support::app_state("safe-search-api").await;
        let Json(before) = get_safe_search(State(state.clone())).await;
        assert!(!before.safe_search);
        assert_eq!(before.youtube_restricted, YoutubeRestrict::Off);

        let body: SafeSearchBody =
            serde_json::from_value(json!({"safe_search": true, "youtube_restricted": "moderate"}))
                .unwrap();
        let Json(_) = put_safe_search(State(state.clone()), Json(body))
            .await
            .unwrap();

        assert_eq!(
            state
                .inner
                .blocklist
                .safe_search_target("www.google.com", None),
            Some("forcesafesearch.google.com")
        );
        assert_eq!(
            state
                .inner
                .blocklist
                .safe_search_target("www.youtube.com", None),
            Some("restrictmoderate.youtube.com")
        );
        let cfg = state.live_config.read().blocklist.clone();
        assert!(cfg.safe_search);
        assert_eq!(cfg.youtube_restricted, YoutubeRestrict::Moderate);
        let Json(after) = get_safe_search(State(state.clone())).await;
        assert_eq!(after.youtube_restricted, YoutubeRestrict::Moderate);

        drop(state);
        test_support::cleanup_sqlite(&db);
    }
}
