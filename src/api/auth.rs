use std::time::{Duration, Instant};

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::ApiError;
use crate::app::AppState;
use crate::error::FeriteError;

/// Session TTL — 24 hours.
const SESSION_TTL: Duration = Duration::from_secs(24 * 60 * 60);

// ── Public helpers ────────────────────────────────────────────────────────────

/// Hash a plaintext password with Argon2id. Returns a PHC string.
pub fn hash_password(password: &str) -> crate::error::Result<String> {
    let mut salt_bytes = [0u8; 16];
    fill_random(&mut salt_bytes)?;
    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|e| FeriteError::Config(format!("password salt encode failed: {}", e)))?;
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| FeriteError::Config(format!("password hash failed: {}", e)))?;
    Ok(hash.to_string())
}

/// Verify a plaintext password against a stored PHC hash string.
pub fn verify_password(password: &str, hash: &str) -> bool {
    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Extract session token from `X-Session-Token` or `Authorization: Bearer`.
pub fn extract_session_token(headers: &HeaderMap) -> Option<String> {
    if let Some(v) = headers.get("x-session-token").and_then(|v| v.to_str().ok()) {
        return Some(v.to_string());
    }
    if let Some(v) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(token) = v.strip_prefix("Bearer ") {
            return Some(token.to_string());
        }
    }
    None
}

/// Returns `true` if the request carries a valid, non-expired session token.
pub fn is_authenticated(state: &AppState, headers: &HeaderMap) -> bool {
    let token = match extract_session_token(headers) {
        Some(t) => t,
        None => return false,
    };
    // Copy the Instant out before dropping the Ref<> guard. DashMap's `get`
    // holds a read lock; calling `remove` on the same shard while the read
    // lock is still alive causes a self-deadlock in parking_lot (RwLock does
    // not support reentrancy). `Some(_)` in a match arm does NOT drop the
    // guard immediately — it lives until the end of the arm.
    let expiry = match state.sessions.get(&token) {
        Some(e) => *e,
        None => return false,
    };
    if expiry > Instant::now() {
        true
    } else {
        state.sessions.remove(&token);
        false
    }
}

// ── Route handlers ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LoginRequest {
    pub password: String,
}

/// POST /api/auth — verify password, issue session token.
pub async fn login(
    State(state): State<AppState>,
    Json(body): Json<LoginRequest>,
) -> Result<Json<Value>, ApiError> {
    let hash = {
        let cfg = state.live_config.read();
        match cfg.api.password_hash() {
            Some(hash) => hash.to_string(),
            None => {
                // No password set — nothing to authenticate against.
                return Err(ApiError(FeriteError::Config(
                    "no password configured; set one with `ferrite passwd`".into(),
                )));
            }
        }
    };

    if !verify_password(&body.password, &hash) {
        return Err(ApiError(FeriteError::Unauthorized));
    }

    let token = generate_session_token()?;

    let expiry = Instant::now() + SESSION_TTL;
    state.sessions.insert(token.clone(), expiry);

    // Evict expired sessions while we're here.
    let now = Instant::now();
    state.sessions.retain(|_, exp| *exp > now);

    Ok(Json(json!({
        "token": token,
        "expires_in": SESSION_TTL.as_secs(),
    })))
}

fn generate_session_token() -> crate::error::Result<String> {
    let mut bytes = [0u8; 32];
    fill_random(&mut bytes)?;
    Ok(to_lower_hex(&bytes))
}

fn fill_random(bytes: &mut [u8]) -> crate::error::Result<()> {
    SystemRandom::new()
        .fill(bytes)
        .map_err(|_| FeriteError::Internal("secure random generation failed".into()))
}

fn to_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// DELETE /api/auth — invalidate the current session token.
pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Json<Value> {
    if let Some(token) = extract_session_token(&headers) {
        state.sessions.remove(&token);
    }
    Json(json!({ "status": "ok" }))
}

/// GET /api/auth — check if the caller has a valid session.
pub async fn check_auth(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let has_password = state.live_config.read().api.has_password();

    if !has_password {
        return (
            StatusCode::OK,
            Json(json!({ "authenticated": true, "password_set": false })),
        );
    }

    if is_authenticated(&state, &headers) {
        (
            StatusCode::OK,
            Json(json!({ "authenticated": true, "password_set": true })),
        )
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "authenticated": false, "password_set": true })),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    use crate::test_support;

    #[test]
    fn password_hash_verifies_correct_password_and_rejects_wrong_password() {
        let hash = hash_password("correct horse battery staple").unwrap();

        assert!(verify_password("correct horse battery staple", &hash));
        assert!(!verify_password("wrong password", &hash));
        assert!(!verify_password("anything", "not-a-phc-hash"));
    }

    #[test]
    fn session_token_can_be_read_from_legacy_and_bearer_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-session-token", HeaderValue::from_static("session-token"));
        assert_eq!(
            extract_session_token(&headers),
            Some("session-token".to_string())
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer bearer-token"),
        );
        assert_eq!(
            extract_session_token(&headers),
            Some("bearer-token".to_string())
        );
    }

    #[tokio::test]
    async fn login_issues_session_and_logout_removes_it() {
        let (state, db_path) = test_support::app_state("auth-login").await;
        let hash = hash_password("secret").unwrap();
        state.live_config.write().api.password_hash = Some(hash);

        let Json(body) = login(
            State(state.clone()),
            Json(LoginRequest {
                password: "secret".to_string(),
            }),
        )
        .await
        .unwrap();
        let token = body["token"].as_str().unwrap().to_string();

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-session-token",
            HeaderValue::from_str(&token).expect("token is a valid header value"),
        );
        assert!(state.sessions.contains_key(&token));
        assert!(is_authenticated(&state, &headers));

        let Json(body) = logout(State(state.clone()), headers).await;
        assert_eq!(body["status"], "ok");
        assert!(!state.sessions.contains_key(&token));

        drop(state);
        test_support::cleanup_sqlite(&db_path);
    }

    #[tokio::test]
    async fn blank_password_hash_behaves_like_no_password_configured() {
        let (state, db_path) = test_support::app_state("auth-empty-password").await;
        state.live_config.write().api.password_hash = Some("  ".to_string());

        let err = login(
            State(state.clone()),
            Json(LoginRequest {
                password: "secret".to_string(),
            }),
        )
        .await
        .unwrap_err();

        assert!(err.0.to_string().contains("no password configured"));

        let response = check_auth(State(state.clone()), HeaderMap::new()).await;
        assert_eq!(response.into_response().status(), StatusCode::OK);

        drop(state);
        test_support::cleanup_sqlite(&db_path);
    }

    #[tokio::test]
    async fn expired_session_is_rejected_and_removed() {
        let (state, db_path) = test_support::app_state("auth-expired").await;
        state.sessions.insert(
            "expired-token".to_string(),
            Instant::now() - Duration::from_secs(1),
        );

        let mut headers = HeaderMap::new();
        headers.insert("x-session-token", HeaderValue::from_static("expired-token"));

        assert!(!is_authenticated(&state, &headers));
        assert!(!state.sessions.contains_key("expired-token"));

        drop(state);
        test_support::cleanup_sqlite(&db_path);
    }
}
