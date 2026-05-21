use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use subtle::ConstantTimeEq;

use crate::api::auth;
use crate::app::AppState;

/// Axum middleware that enforces authentication when a password or API key is configured.
///
/// Accepts (in priority order):
/// 1. Valid session token (`X-Session-Token` or `Authorization: Bearer <token>`)
///    — issued by `POST /api/auth`.
/// 2. Legacy API key (`X-Api-Key` or `Authorization: Bearer <key>`)
///    — for script/automation access without a full login flow.
///
/// If neither a password nor an API key is configured, all requests pass through.
pub async fn require_api_key(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let cfg = state.live_config.read().api.clone();
    let password_set = cfg.has_password();
    let api_key = cfg.api_key().map(str::to_string);

    // No auth configured at all — allow everything.
    if !password_set && api_key.is_none() {
        return next.run(request).await;
    }

    let headers = request.headers();

    // 1. Check session token (password-based auth).
    if password_set && auth::is_authenticated(&state, headers) {
        return next.run(request).await;
    }

    // 2. Check legacy API key.
    if let Some(expected_key) = &api_key {
        if let Some(provided) = extract_api_key(headers) {
            if provided.as_bytes().ct_eq(expected_key.as_bytes()).into() {
                return next.run(request).await;
            }
        }
    }

    unauthorized()
}

fn extract_api_key(headers: &axum::http::HeaderMap) -> Option<String> {
    if let Some(v) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        return Some(v.to_string());
    }
    if let Some(v) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(token) = v.strip_prefix("Bearer ") {
            return Some(token.to_string());
        }
    }
    None
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "unauthorized" })),
    )
        .into_response()
}
