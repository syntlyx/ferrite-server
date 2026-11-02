//! `/api/notifications` — the webhook and which events go to it — plus
//! `POST /api/notifications/test`, which sends a test event so a setup can be
//! checked from the panel.

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::ApiError;
use ferrite_app::AppState;
use ferrite_core::config::NotificationsConfig;
use ferrite_core::error::FeriteError;
use ferrite_core::notify;

/// GET /api/notifications
pub async fn get_notifications(State(state): State<AppState>) -> Json<NotificationsConfig> {
    Json(state.live_config.read().notifications.clone())
}

/// PUT /api/notifications — replace the settings; live at once, persisted.
pub async fn put_notifications(
    State(state): State<AppState>,
    Json(mut body): Json<NotificationsConfig>,
) -> Result<Json<Value>, ApiError> {
    body.normalize();
    if let Some(url) = body.webhook.as_deref()
        && !notify::valid_webhook(url)
    {
        return Err(ApiError(FeriteError::Config(
            "the webhook must be an http(s) URL".into(),
        )));
    }
    state.live_config.write().notifications = body;
    let saved_to = state.persist_config().await;
    Ok(Json(json!({
        "status": "ok",
        "persisted": saved_to.is_some(),
        "saved_to": saved_to,
    })))
}

#[derive(Debug, Default, Deserialize)]
pub struct TestBody {
    /// Test this URL instead of the saved one — so a webhook can be checked
    /// before it is saved.
    #[serde(default)]
    pub webhook: Option<String>,
}

#[derive(Serialize)]
struct TestEvent {
    event: &'static str,
    message: &'static str,
    timestamp: String,
}

/// POST /api/notifications/test — send a `test` event now. `200` when the
/// receiver accepted it; `400` with the reason when it didn't or couldn't be
/// reached, so the panel can show what is wrong.
pub async fn test_notification(
    State(state): State<AppState>,
    body: Option<Json<TestBody>>,
) -> Result<Json<Value>, ApiError> {
    let url = body
        .and_then(|Json(b)| b.webhook)
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty())
        .or_else(|| state.live_config.read().notifications.webhook.clone());
    let Some(url) = url else {
        return Err(ApiError(FeriteError::Config("no webhook is set".into())));
    };
    if !notify::valid_webhook(&url) {
        return Err(ApiError(FeriteError::Config(
            "the webhook must be an http(s) URL".into(),
        )));
    }
    let event = TestEvent {
        event: "test",
        message: "Test notification from ferrite",
        timestamp: chrono::Utc::now().to_rfc3339(),
    };
    notify::post(&notify::client(), &url, &event)
        .await
        .map_err(|e| ApiError(FeriteError::Config(e)))?;
    Ok(Json(json!({ "status": "ok" })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_app::test_support;

    #[tokio::test]
    async fn put_validates_trims_and_persists() {
        let (state, db) = test_support::app_state("notifications-api").await;
        let Json(before) = get_notifications(State(state.clone())).await;
        assert!(before.tunnel_alerts && !before.new_device && before.webhook.is_none());

        let bad = put_notifications(
            State(state.clone()),
            Json(NotificationsConfig {
                webhook: Some("ntfy.sh/x".into()),
                tunnel_alerts: true,
                new_device: true,
            }),
        )
        .await;
        assert!(bad.is_err());

        let Json(_) = put_notifications(
            State(state.clone()),
            Json(NotificationsConfig {
                webhook: Some(" https://ntfy.sh/ferrite ".into()),
                tunnel_alerts: false,
                new_device: true,
            }),
        )
        .await
        .unwrap();
        let saved = state.live_config.read().notifications.clone();
        assert_eq!(saved.webhook.as_deref(), Some("https://ntfy.sh/ferrite"));
        assert!(!saved.tunnel_alerts && saved.new_device);

        drop(state);
        test_support::cleanup_sqlite(&db);
    }

    #[tokio::test]
    async fn test_without_a_webhook_says_so() {
        let (state, db) = test_support::app_state("notifications-test").await;
        let err = test_notification(State(state.clone()), None)
            .await
            .unwrap_err();
        assert!(matches!(err.0, FeriteError::Config(ref m) if m.contains("no webhook")));
        drop(state);
        test_support::cleanup_sqlite(&db);
    }
}
