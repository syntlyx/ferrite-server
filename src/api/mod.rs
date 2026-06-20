pub mod auth;
pub mod blocklist;
pub mod clients;
pub mod custom_records;
pub mod error;
mod ingress;
pub mod lists;
pub mod logs;
pub mod middleware;
pub mod proxy;
pub mod queries;
pub mod settings;
pub mod stats;
pub mod system;
pub mod tools;
pub mod update;

pub use error::ApiError;

use axum::{
    Router, middleware as axum_middleware,
    routing::{delete, get, patch, post, put},
};
use tower_http::trace::TraceLayer;

use crate::app::AppState;

/// Build the full Axum router with all API routes.
pub fn build_router(state: AppState) -> Router {
    // Auth routes are public — no middleware (you need them to log in).
    let auth_routes = Router::new()
        .route("/auth", get(auth::check_auth))
        .route("/auth", post(auth::login))
        .route("/auth", delete(auth::logout))
        .with_state(state.clone());

    let api = Router::new()
        // Stats
        .route("/stats/summary", get(stats::get_summary))
        .route("/stats/timeseries", get(stats::get_timeseries))
        .route("/stats/top-blocked", get(stats::get_top_blocked))
        .route("/stats/system", get(system::get_system_stats))
        .route("/stats/top-domains", get(stats::get_top_domains))
        .route("/stats/top-clients", get(stats::get_top_clients))
        // Queries log
        .route("/queries", get(queries::list_queries))
        .route("/queries", delete(queries::delete_queries))
        // Clients
        .route("/clients", get(clients::list_clients))
        .route("/clients/aliases", get(clients::list_aliases))
        .route("/clients/aliases", post(clients::add_alias))
        .route("/clients/aliases/{ip}", delete(clients::remove_alias))
        .route("/clients/{ip}/stats", get(clients::client_ip_stats))
        // Blocklist management
        .route("/blocklist/blacklist", get(blocklist::list_blacklist))
        .route("/blocklist/blacklist", post(blocklist::add_blacklist))
        .route(
            "/blocklist/blacklist/{domain}",
            delete(blocklist::del_blacklist),
        )
        .route("/blocklist/whitelist", get(blocklist::list_whitelist))
        .route("/blocklist/whitelist", post(blocklist::add_whitelist))
        .route(
            "/blocklist/whitelist/{domain}",
            delete(blocklist::del_whitelist),
        )
        .route("/blocklist/check/{domain}", get(blocklist::check_domain))
        // Remote list subscriptions
        .route("/lists", get(lists::list_lists))
        .route("/lists", post(lists::add_list))
        .route("/lists/{name}", delete(lists::del_list))
        .route("/lists/{name}", patch(lists::patch_list))
        .route("/lists/refresh", post(lists::refresh_all_lists))
        .route("/lists/{name}/refresh", post(lists::refresh_list))
        // Custom DNS records (A / AAAA / CNAME overrides)
        .route("/custom-records", get(custom_records::list_records))
        .route("/custom-records", post(custom_records::add_record))
        .route(
            "/custom-records/{domain}",
            delete(custom_records::delete_record),
        )
        // Settings
        .route("/settings", get(settings::get_settings))
        .route("/settings", patch(settings::update_settings))
        // Selective routing / proxy
        .route("/proxy", get(proxy::get_proxy))
        .route("/proxy", put(proxy::put_proxy))
        // Live server logs (in-memory ring)
        .route("/logs", get(logs::get_logs))
        // Diagnostic tools (DNS lookup + WHOIS)
        .route("/tools/resolve", get(tools::resolve))
        .route("/tools/whois", get(tools::whois))
        // Updates
        .route("/update/check", get(update::check_update))
        .route("/update/server", post(update::update_server))
        .route("/update/web", post(update::update_web))
        // Auth middleware
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::require_api_key,
        ))
        .with_state(state.clone());

    Router::new()
        .nest("/api", auth_routes)
        .nest("/api", api)
        .fallback(crate::web::static_handler)
        .layer(TraceLayer::new_for_http())
        // No CORS layer: the web UI is served same-origin by this very server,
        // so browsers enforce same-origin access automatically. Permissive CORS
        // would let any website the operator visits drive the local API.
        .with_state(state)
}

/// Bind the HTTP listener and serve the router.
pub async fn serve(state: AppState) -> anyhow::Result<()> {
    let bind_addr = state.inner.config.api.bind_addr;

    // Warn loudly if the API is reachable with no authentication: every mutating
    // endpoint (settings, lists, custom records, self-update) is then open to
    // anyone who can reach this address.
    {
        let api = state.live_config.read().api.clone();
        if !api.has_password() && api.api_key().is_none() {
            tracing::warn!(
                "API authentication is NOT configured — all endpoints on {} are open. \
                 Set a web UI password or API key to restrict access.",
                bind_addr
            );
        }
    }

    let router = build_router(state.clone());

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    tracing::info!("panel/API listener on http://{}", bind_addr);

    // Per-connection demux: peek the Host and serve the panel or route via the
    // proxy (see `ingress`), so one port serves both.
    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("panel accept error: {e}");
                continue;
            }
        };
        tokio::spawn(ingress::dispatch(stream, state.clone(), router.clone()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::time::{Duration, Instant};
    use tower::ServiceExt;

    use crate::api::auth::hash_password;
    use crate::test_support;

    fn request(uri: &str) -> Request<Body> {
        Request::builder().uri(uri).body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn protected_api_allows_requests_when_no_auth_is_configured() {
        let (state, db_path) = test_support::app_state("api-no-auth").await;
        let response = build_router(state.clone())
            .oneshot(request("/api/settings"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        drop(state);
        test_support::cleanup_sqlite(&db_path);
    }

    #[tokio::test]
    async fn protected_api_allows_requests_when_auth_secrets_are_blank() {
        let (state, db_path) = test_support::app_state("api-empty-auth").await;
        {
            let mut cfg = state.live_config.write();
            cfg.api.api_key = Some("   ".to_string());
            cfg.api.password_hash = Some("".to_string());
        }

        let response = build_router(state.clone())
            .oneshot(request("/api/settings"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        drop(state);
        test_support::cleanup_sqlite(&db_path);
    }

    #[tokio::test]
    async fn api_key_middleware_accepts_x_api_key_and_bearer_token() {
        let (state, db_path) = test_support::app_state("api-key-auth").await;
        state.live_config.write().api.api_key = Some("secret-key".to_string());
        let app = build_router(state.clone());

        let missing = app.clone().oneshot(request("/api/settings")).await.unwrap();
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

        let x_api_key = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/settings")
                    .header("x-api-key", "secret-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(x_api_key.status(), StatusCode::OK);

        let bearer = app
            .oneshot(
                Request::builder()
                    .uri("/api/settings")
                    .header("authorization", "Bearer secret-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bearer.status(), StatusCode::OK);

        drop(state);
        test_support::cleanup_sqlite(&db_path);
    }

    #[tokio::test]
    async fn password_session_auth_allows_protected_api_access() {
        let (state, db_path) = test_support::app_state("api-session-auth").await;
        state.live_config.write().api.password_hash = Some(hash_password("secret").unwrap());
        state.sessions.insert(
            "session-token".to_string(),
            Instant::now() + Duration::from_secs(60),
        );
        let app = build_router(state.clone());

        let missing = app.clone().oneshot(request("/api/settings")).await.unwrap();
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

        let authed = app
            .oneshot(
                Request::builder()
                    .uri("/api/settings")
                    .header("x-session-token", "session-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authed.status(), StatusCode::OK);

        drop(state);
        test_support::cleanup_sqlite(&db_path);
    }

    #[tokio::test]
    async fn auth_routes_stay_public_when_api_key_is_configured() {
        let (state, db_path) = test_support::app_state("api-auth-public").await;
        state.live_config.write().api.api_key = Some("secret-key".to_string());

        let response = build_router(state.clone())
            .oneshot(request("/api/auth"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        drop(state);
        test_support::cleanup_sqlite(&db_path);
    }
}
