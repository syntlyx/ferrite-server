use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use axum::{
    Extension, Json,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode, header::USER_AGENT},
    response::IntoResponse,
};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::ApiError;
use ferrite_app::AppState;
use ferrite_app::sessions::Session;
use ferrite_core::error::FeriteError;

/// A session lasts this long since it was last used — sliding, so someone
/// who opens the panel every few days stays signed in, and one left alone
/// for a week has to sign in again.
const SESSION_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// A session's expiry is pushed forward at most this often, so an active
/// panel writes to the database about once a day, not on every request.
const SESSION_RENEW_EVERY: i64 = 24 * 60 * 60;

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
pub fn hash_password(password: &str) -> ferrite_core::error::Result<String> {
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
    if let Some(v) = headers.get("authorization").and_then(|v| v.to_str().ok())
        && let Some(token) = v.strip_prefix("Bearer ")
    {
        return Some(token.to_string());
    }
    None
}

/// How a session is looked up: the SHA-256 of its token, hex. The token
/// itself is never kept — not in memory, not in the database.
fn session_key(token: &str) -> String {
    hex::encode(ring::digest::digest(
        &ring::digest::SHA256,
        token.as_bytes(),
    ))
}

/// A short fingerprint of a password hash. A session remembers the one it was
/// issued under; once the password changes — from the panel, `ferrite passwd`
/// or a restored config — every older session stops working.
fn password_fingerprint(password_hash: &str) -> String {
    hex::encode(
        &ring::digest::digest(&ring::digest::SHA256, password_hash.as_bytes()).as_ref()[..8],
    )
}

fn unix_now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Returns `true` if the request carries a valid, non-expired session token
/// issued under the current password. Using a session keeps it alive.
pub fn is_authenticated(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(token) = extract_session_token(headers) else {
        return false;
    };
    let Some(password_fp) = state
        .live_config
        .read()
        .api
        .password_hash()
        .map(password_fingerprint)
    else {
        return false;
    };
    let key = session_key(&token);
    let Some(session) = state.sessions.get(&key) else {
        return false;
    };
    let now = unix_now();
    if session.expires <= now || session.password_fp != password_fp {
        state.sessions.forget(&key);
        return false;
    }
    let ttl = SESSION_TTL.as_secs() as i64;
    if ttl - (session.expires - now) >= SESSION_RENEW_EVERY {
        state.sessions.update(
            &key,
            Session {
                password_fp,
                expires: now + ttl,
                last_seen: now,
                ..session
            },
        );
    } else if now - session.last_seen >= TOUCH_EVERY {
        state.sessions.touch(&key, now);
    }
    true
}

/// "Last used" is noted at most this often per session — it is shown to the
/// minute, and a busy panel makes several requests a second.
const TOUCH_EVERY: i64 = 30;

/// After the password changed, keep the session of the request that changed
/// it: re-issue it under the new password. Every other session lapses.
pub fn rebind_session(state: &AppState, headers: &HeaderMap, new_password_hash: &str) {
    let Some(token) = extract_session_token(headers) else {
        return;
    };
    let key = session_key(&token);
    if let Some(session) = state.sessions.get(&key) {
        let now = unix_now();
        state.sessions.update(
            &key,
            Session {
                password_fp: password_fingerprint(new_password_hash),
                expires: now + SESSION_TTL.as_secs() as i64,
                last_seen: now,
                ..session
            },
        );
    }
}

// ── Route handlers ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LoginRequest {
    pub password: String,
}

/// The longest User-Agent kept with a session — enough to tell browsers and
/// systems apart, short enough that a hostile header can't bloat the table.
const AGENT_MAX: usize = 256;

/// The address a request came from, when the listener recorded it.
type Peer = Option<Extension<ConnectInfo<SocketAddr>>>;

fn peer_ip(peer: &Peer) -> Option<IpAddr> {
    peer.as_ref()
        .map(|Extension(ConnectInfo(addr))| addr.ip().to_canonical())
}

/// POST /api/auth — verify password, issue session token.
pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Peer,
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
    let now = unix_now();
    let agent: String = headers
        .get(USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .chars()
        .take(AGENT_MAX)
        .collect();
    state
        .sessions
        .insert(
            session_key(&token),
            Session {
                password_fp: password_fingerprint(&hash),
                expires: now + SESSION_TTL.as_secs() as i64,
                created: now,
                last_seen: now,
                agent,
                ip: peer_ip(&peer).map(|ip| ip.to_string()).unwrap_or_default(),
            },
        )
        .await;

    Ok(Json(json!({
        "token": token,
        "expires_in": SESSION_TTL.as_secs(),
    })))
}

fn generate_session_token() -> ferrite_core::error::Result<String> {
    let mut bytes = [0u8; 32];
    fill_random(&mut bytes)?;
    Ok(hex::encode(bytes))
}

fn fill_random(bytes: &mut [u8]) -> ferrite_core::error::Result<()> {
    SystemRandom::new()
        .fill(bytes)
        .map_err(|_| FeriteError::Internal("secure random generation failed".into()))
}

/// DELETE /api/auth — invalidate the current session token.
pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Json<Value> {
    if let Some(token) = extract_session_token(&headers) {
        state.sessions.remove(&session_key(&token)).await;
    }
    Json(json!({ "status": "ok" }))
}

/// A session as the panel lists it. `id` is a prefix of the stored key —
/// enough to name it, useless for signing in.
#[derive(Debug, Serialize)]
pub struct SessionView {
    pub id: String,
    pub created: i64,
    pub last_seen: i64,
    pub expires: i64,
    pub agent: String,
    pub ip: String,
    /// The name of the device at `ip`, as the client list knows it.
    pub device: Option<String>,
    /// The session making this request.
    pub current: bool,
}

const SESSION_ID_LEN: usize = 16;

/// GET /api/auth/sessions — every session that can still sign in, oldest first.
pub async fn list_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Json<Vec<SessionView>> {
    let current = extract_session_token(&headers).map(|t| session_key(&t));
    let password_fp = state
        .live_config
        .read()
        .api
        .password_hash()
        .map(password_fingerprint);
    let now = unix_now();
    let registry = &state.inner.client_registry;
    let mut views = Vec::new();
    for (key, s) in state.sessions.list() {
        // One that can no longer sign in (an old password) is cleared out
        // rather than shown.
        if s.expires <= now || Some(&s.password_fp) != password_fp.as_ref() {
            state.sessions.forget(&key);
            continue;
        }
        views.push(SessionView {
            id: key[..SESSION_ID_LEN].to_string(),
            current: current.as_deref() == Some(key.as_str()),
            device: s.ip.parse().ok().and_then(|ip| registry.get_name(ip)),
            created: s.created,
            last_seen: s.last_seen,
            expires: s.expires,
            agent: s.agent,
            ip: s.ip,
        });
    }
    Json(views)
}

/// DELETE /api/auth/sessions/{id} — sign one session out. It may be the
/// caller's own.
pub async fn revoke_session(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let key = (id.len() == SESSION_ID_LEN)
        .then(|| {
            state
                .sessions
                .list()
                .into_iter()
                .map(|(key, _)| key)
                .find(|key| key.starts_with(&id))
        })
        .flatten()
        .ok_or_else(|| ApiError(FeriteError::NotFound(format!("session {id}"))))?;
    state.sessions.remove(&key).await;
    Ok(Json(json!({ "status": "ok" })))
}

/// DELETE /api/auth/sessions — sign out every session but the caller's own.
/// `removed` counts the ones that could still sign in — what the list showed.
pub async fn revoke_other_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Json<Value> {
    let current = extract_session_token(&headers).map(|t| session_key(&t));
    let password_fp = state
        .live_config
        .read()
        .api
        .password_hash()
        .map(password_fingerprint);
    let now = unix_now();
    let mut removed = 0;
    for (key, s) in state.sessions.list() {
        if current.as_deref() != Some(key.as_str()) {
            state.sessions.remove(&key).await;
            if s.expires > now && Some(&s.password_fp) == password_fp.as_ref() {
                removed += 1;
            }
        }
    }
    if removed > 0 {
        tracing::info!("signed out {removed} other panel session(s)");
    }
    Json(json!({ "status": "ok", "removed": removed }))
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

    use ferrite_app::test_support;

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
            axum::http::HeaderMap::new(),
            None,
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
        assert!(state.sessions.get(&session_key(&token)).is_some());
        assert!(is_authenticated(&state, &headers));

        let Json(body) = logout(State(state.clone()), headers).await;
        assert_eq!(body["status"], "ok");
        assert!(state.sessions.get(&session_key(&token)).is_none());

        drop(state);
        test_support::cleanup_sqlite(&db_path);
    }

    #[tokio::test]
    async fn blank_password_hash_behaves_like_no_password_configured() {
        let (state, db_path) = test_support::app_state("auth-empty-password").await;
        state.live_config.write().api.password_hash = Some("  ".to_string());

        let err = login(
            State(state.clone()),
            axum::http::HeaderMap::new(),
            None,
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
        let hash = hash_password("secret").unwrap();
        state.live_config.write().api.password_hash = Some(hash.clone());
        state
            .sessions
            .insert(
                session_key("expired-token"),
                Session {
                    password_fp: password_fingerprint(&hash),
                    expires: unix_now() - 1,
                    ..Session::default()
                },
            )
            .await;

        let mut headers = HeaderMap::new();
        headers.insert("x-session-token", HeaderValue::from_static("expired-token"));

        assert!(!is_authenticated(&state, &headers));
        assert!(state.sessions.get(&session_key("expired-token")).is_none());

        drop(state);
        test_support::cleanup_sqlite(&db_path);
    }

    async fn login_token(state: &AppState) -> String {
        let Json(body) = login(
            State(state.clone()),
            axum::http::HeaderMap::new(),
            None,
            Json(LoginRequest {
                password: "secret".to_string(),
            }),
        )
        .await
        .unwrap();
        body["token"].as_str().unwrap().to_string()
    }

    fn token_headers(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-session-token", HeaderValue::from_str(token).unwrap());
        headers
    }

    #[tokio::test]
    async fn a_session_survives_a_restart_but_not_a_password_change() {
        let (state, db_path) = test_support::app_state("auth-restart").await;
        let hash = hash_password("secret").unwrap();
        state.live_config.write().api.password_hash = Some(hash.clone());
        let token = login_token(&state).await;
        drop(state);

        // A new process over the same database: still signed in.
        let config = {
            let mut c = ferrite_core::config::Config::default();
            c.storage.path = db_path.clone();
            c.blocklist.lists.clear();
            c.api.password_hash = Some(hash);
            c
        };
        let state = AppState::init(&config, config.clone()).await.unwrap();
        assert!(is_authenticated(&state, &token_headers(&token)));
        // The database holds the token's hash, never the token.
        assert!(state.sessions.get(&token).is_none());

        // A new password — however it got there — ends the session.
        state.live_config.write().api.password_hash = Some(hash_password("other").unwrap());
        assert!(!is_authenticated(&state, &token_headers(&token)));

        drop(state);
        test_support::cleanup_sqlite(&db_path);
    }

    #[tokio::test]
    async fn sessions_are_listed_and_signed_out_one_by_one_or_all_but_mine() {
        let (state, db_path) = test_support::app_state("auth-sessions").await;
        state.live_config.write().api.password_hash = Some(hash_password("secret").unwrap());
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (iPhone)"));
        let peer: Peer = Some(Extension(ConnectInfo(
            "[::ffff:192.168.1.7]:5555".parse().unwrap(),
        )));
        let Json(body) = login(
            State(state.clone()),
            headers,
            peer,
            Json(LoginRequest {
                password: "secret".to_string(),
            }),
        )
        .await
        .unwrap();
        let phone = body["token"].as_str().unwrap().to_string();
        let mine = login_token(&state).await;
        let third = login_token(&state).await;

        let Json(list) = list_sessions(State(state.clone()), token_headers(&mine)).await;
        assert_eq!(list.len(), 3);
        let me: Vec<_> = list.iter().filter(|s| s.current).collect();
        assert_eq!(me.len(), 1);
        let iphone = list.iter().find(|s| s.agent.contains("iPhone")).unwrap();
        assert_eq!(iphone.ip, "192.168.1.7");
        assert_eq!(iphone.id.len(), SESSION_ID_LEN);

        // One by one, by its id…
        let Json(_) = revoke_session(State(state.clone()), Path(iphone.id.clone()))
            .await
            .unwrap();
        assert!(!is_authenticated(&state, &token_headers(&phone)));
        assert!(
            revoke_session(State(state.clone()), Path(iphone.id.clone()))
                .await
                .is_err()
        );
        assert!(
            revoke_session(State(state.clone()), Path("short".into()))
                .await
                .is_err()
        );

        // …or every one but the caller's.
        let Json(out) = revoke_other_sessions(State(state.clone()), token_headers(&mine)).await;
        assert_eq!(out["removed"], 1);
        assert!(is_authenticated(&state, &token_headers(&mine)));
        assert!(!is_authenticated(&state, &token_headers(&third)));

        drop(state);
        test_support::cleanup_sqlite(&db_path);
    }

    #[tokio::test]
    async fn changing_the_password_keeps_only_the_session_that_changed_it() {
        let (state, db_path) = test_support::app_state("auth-rebind").await;
        state.live_config.write().api.password_hash = Some(hash_password("secret").unwrap());
        let mine = login_token(&state).await;
        let other = login_token(&state).await;

        let new_hash = hash_password("new secret").unwrap();
        state.live_config.write().api.password_hash = Some(new_hash.clone());
        rebind_session(&state, &token_headers(&mine), &new_hash);

        assert!(is_authenticated(&state, &token_headers(&mine)));
        assert!(!is_authenticated(&state, &token_headers(&other)));

        drop(state);
        test_support::cleanup_sqlite(&db_path);
    }
}
