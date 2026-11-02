//! Temporary pauses of filtering — box-wide or per device:
//! `GET /api/blocking/pause`, `POST /api/blocking/pause`, `POST /api/blocking/resume`.
//!
//! Nothing here reaches `config.toml`: a pause is "let me through for a few
//! minutes", and a restart resumes filtering.

use axum::{Json, extract::State};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::ApiError;
use ferrite_app::AppState;
use ferrite_blocklist::pause::unix_now;
use ferrite_core::error::FeriteError;

/// Longest pause on offer: a day. Longer than that is a setting, not a pause —
/// switch filtering off instead.
const MAX_MINUTES: u32 = 24 * 60;

fn snapshot(state: &AppState) -> Json<Value> {
    let snap = state.inner.blocklist.pauses().snapshot();
    Json(json!({
        "now": unix_now(),
        "global_until": snap.global_until,
        "clients": snap.clients,
    }))
}

/// GET /api/blocking/pause — what is paused, and until when (unix seconds).
pub async fn get_pause(State(state): State<AppState>) -> Json<Value> {
    snapshot(&state)
}

#[derive(Deserialize)]
pub struct PausePayload {
    pub minutes: u32,
    /// Device IPs and/or MACs. Empty pauses the whole box.
    #[serde(default)]
    pub clients: Vec<String>,
}

/// POST /api/blocking/pause — pause filtering for `minutes`, box-wide or for
/// the given devices. Pausing again replaces the deadline.
pub async fn pause(
    State(state): State<AppState>,
    Json(payload): Json<PausePayload>,
) -> Result<Json<Value>, ApiError> {
    if payload.minutes == 0 || payload.minutes > MAX_MINUTES {
        return Err(ApiError(FeriteError::Config(format!(
            "minutes must be between 1 and {MAX_MINUTES}"
        ))));
    }
    let until = unix_now() + i64::from(payload.minutes) * 60;
    let pauses = state.inner.blocklist.pauses();
    if payload.clients.is_empty() {
        pauses.pause_global(until);
        tracing::info!("blocking paused for {} min", payload.minutes);
    } else {
        let keys = pauses.pause_clients(&payload.clients, until);
        if keys.is_empty() {
            return Err(ApiError(FeriteError::Config(
                "no valid client IP or MAC given".into(),
            )));
        }
        tracing::info!(
            "blocking paused for {} min for {}",
            payload.minutes,
            keys.join(", ")
        );
    }
    Ok(snapshot(&state))
}

#[derive(Deserialize)]
pub struct ResumePayload {
    /// Devices to resume. Empty resumes the box-wide pause.
    #[serde(default)]
    pub clients: Vec<String>,
}

/// POST /api/blocking/resume — end a pause before its deadline.
pub async fn resume(
    State(state): State<AppState>,
    Json(payload): Json<ResumePayload>,
) -> Json<Value> {
    let pauses = state.inner.blocklist.pauses();
    if payload.clients.is_empty() {
        pauses.resume_global();
        tracing::info!("blocking resumed");
    } else {
        pauses.resume_clients(&payload.clients);
        tracing::info!("blocking resumed for {}", payload.clients.join(", "));
    }
    snapshot(&state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_app::test_support;

    #[tokio::test]
    async fn pausing_the_box_and_a_device_and_resuming() {
        let (state, db_path) = test_support::app_state("api-pause").await;
        let bl = &state.inner.blocklist;
        assert!(bl.blocking_enabled());

        let res = pause(
            State(state.clone()),
            Json(PausePayload {
                minutes: 5,
                clients: vec![],
            }),
        )
        .await
        .unwrap();
        let until = res.0["global_until"].as_i64().unwrap();
        assert!(
            (until - unix_now() - 300).abs() <= 2,
            "five minutes from now"
        );
        assert!(
            !bl.blocking_enabled(),
            "a box-wide pause switches filtering off"
        );

        let _ = resume(
            State(state.clone()),
            Json(ResumePayload { clients: vec![] }),
        )
        .await;
        assert!(bl.blocking_enabled());

        let _ = pause(
            State(state.clone()),
            Json(PausePayload {
                minutes: 30,
                clients: vec!["192.168.1.10".into()],
            }),
        )
        .await
        .unwrap();
        assert!(
            bl.blocking_enabled(),
            "a device pause leaves the box filtering"
        );
        assert!(bl.has_client_exceptions());
        assert!(bl.client_filtering_off_normalized("192.168.1.10", None));
        assert!(!bl.client_filtering_off_normalized("192.168.1.11", None));

        for minutes in [0, MAX_MINUTES + 1] {
            let res = pause(
                State(state.clone()),
                Json(PausePayload {
                    minutes,
                    clients: vec![],
                }),
            )
            .await;
            assert!(res.is_err(), "{minutes} minutes is out of range");
        }

        drop(state);
        test_support::cleanup_sqlite(&db_path);
    }
}
