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

/// Token-bucket rate limiter for the password login endpoint.
///
/// `POST /api/auth` runs a deliberately-slow Argon2id verification on every
/// call. Without a limit, an unauthenticated client can both brute-force the
/// password and amplify a CPU denial-of-service (each request forces hundreds
/// of milliseconds of work). This bucket bounds the rate of verifications:
/// rejected requests return `429` *before* any hashing happens, so a flood
/// costs the server almost nothing.
///
/// It is process-global (not per-IP): the panel has a single admin, so a global
/// cap is sufficient and avoids threading client addresses through the router.
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

/// Bucket capacity (max burst) and refill rate (tokens per second).
const LOGIN_BURST: f64 = 10.0;
const LOGIN_REFILL_PER_SEC: f64 = 5.0;

impl TokenBucket {
    fn full() -> Self {
        Self {
            tokens: LOGIN_BURST,
            last_refill: Instant::now(),
        }
    }

    /// Refill based on elapsed time, then try to consume one token.
    /// Returns `true` if a token was available.
    fn try_take(&mut self, now: Instant) -> bool {
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * LOGIN_REFILL_PER_SEC).min(LOGIN_BURST);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

fn login_bucket() -> &'static parking_lot::Mutex<TokenBucket> {
    static BUCKET: std::sync::LazyLock<parking_lot::Mutex<TokenBucket>> =
        std::sync::LazyLock::new(|| parking_lot::Mutex::new(TokenBucket::full()));
    &BUCKET
}

/// Consume one token. Returns `Err(RateLimited)` if the bucket is empty.
fn check_login_rate() -> Result<(), FeriteError> {
    if login_bucket().lock().try_take(Instant::now()) {
        Ok(())
    } else {
        Err(FeriteError::RateLimited)
    }
}

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
    // Throttle before touching config or running Argon2 so a flood is cheap to reject.
    check_login_rate().map_err(ApiError)?;

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
    fn login_rate_limiter_allows_a_burst_then_rejects() {
        // Use a local bucket (not the process-global one) so this test can't
        // race other login tests. A full bucket allows exactly LOGIN_BURST
        // back-to-back takes (no time elapses, so no refill), then rejects.
        let mut bucket = TokenBucket::full();
        let now = Instant::now();
        let allowed = (0..(LOGIN_BURST as usize))
            .filter(|_| bucket.try_take(now))
            .count();
        assert_eq!(allowed, LOGIN_BURST as usize);
        assert!(!bucket.try_take(now), "drained bucket must reject");
    }

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
