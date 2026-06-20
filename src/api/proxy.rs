//! `/api/proxy` — view and replace the selective-routing configuration.
//!
//! The web UI is the primary editor: it GETs the whole config and PUTs it back.
//! Rules/egresses/advertise hot-reload immediately (ArcSwap snapshot swap);
//! `enabled`, the listener ports, and the connection cap bind at startup, so
//! changing them is flagged `restart_required`.

use std::collections::HashSet;

use axum::{Json, extract::State};
use serde_json::{Value, json};

use crate::api::ApiError;
use crate::app::AppState;
use crate::config::ProxyConfig;
use crate::error::FeriteError;

/// GET /api/proxy — current config (socks5 passwords redacted) + egress health.
pub async fn get_proxy(State(state): State<AppState>) -> Json<Value> {
    let proxy = state.live_config.read().proxy.clone();

    let health: serde_json::Map<String, Value> = proxy
        .egresses
        .iter()
        .map(|e| {
            let status = if state.inner.proxy.is_egress_healthy(&e.id) {
                "up"
            } else {
                "down"
            };
            (e.id.clone(), Value::from(status))
        })
        .collect();

    let restart_pending = restart_required(&state, &proxy);

    Json(json!({
        "proxy": redacted(proxy),
        "egress_health": health,
        "restart_pending": restart_pending,
    }))
}

/// PUT /api/proxy — replace the whole proxy config.
pub async fn put_proxy(
    State(state): State<AppState>,
    Json(mut new): Json<ProxyConfig>,
) -> Result<Json<Value>, ApiError> {
    // Restore secrets the UI left blank (they're redacted on GET) BEFORE
    // validating, so an unchanged socks5 password / wireguard `.conf` still
    // satisfies the required-fields checks.
    {
        let old = state.live_config.read().proxy.clone();
        for e in &mut new.egresses {
            let id = e.id.trim().to_ascii_lowercase();
            let prev = old.egresses.iter().find(|p| p.id == id);
            if e.kind.eq_ignore_ascii_case("socks5")
                && e.password.as_deref().unwrap_or("").is_empty()
                && let Some(p) = prev
            {
                e.password = p.password.clone();
            }
            if e.kind.eq_ignore_ascii_case("wireguard")
                && e.config.as_deref().unwrap_or("").trim().is_empty()
                && let Some(p) = prev
            {
                e.config = p.config.clone();
            }
        }
    }

    validate(&new)?;
    new.normalize();
    let restart = restart_required(&state, &new);

    // Hot-reload routing immediately, then persist.
    state.inner.proxy.reload(&new);
    state.live_config.write().proxy = new;
    let saved_to = persist(&state);

    Ok(Json(json!({
        "status": "ok",
        "restart_required": restart,
        "persisted": saved_to.is_some(),
        "saved_to": saved_to,
    })))
}

/// Reject obviously-broken configs with a 400 so the UI can show a clear error
/// (rather than silently dropping egresses/rules at snapshot-build time).
fn validate(cfg: &ProxyConfig) -> Result<(), ApiError> {
    let mut ids: HashSet<String> = HashSet::new();
    for e in &cfg.egresses {
        let id = e.id.trim().to_ascii_lowercase();
        if id.is_empty() {
            return Err(bad("an egress is missing its id"));
        }
        if !ids.insert(id.clone()) {
            return Err(bad(&format!("duplicate egress id '{}'", e.id)));
        }
        match e.kind.trim().to_ascii_lowercase().as_str() {
            "direct" => {}
            "socks5" => {
                if e.address.as_deref().unwrap_or("").trim().is_empty() || e.port.is_none() {
                    return Err(bad(&format!(
                        "socks5 egress '{}' requires an address and port",
                        e.id
                    )));
                }
            }
            "wireguard" => {
                let text = e.config.as_deref().unwrap_or("").trim();
                if text.is_empty() {
                    return Err(bad(&format!(
                        "wireguard egress '{}' requires a config (.conf text)",
                        e.id
                    )));
                }
                crate::proxy::validate_wireguard_conf(text).map_err(ApiError)?;
            }
            other => return Err(bad(&format!("egress '{}': unknown kind '{}'", e.id, other))),
        }
    }
    for r in &cfg.rules {
        if r.pattern.trim().is_empty() {
            return Err(bad("a rule is missing its pattern"));
        }
        let eg = r.egress.trim().to_ascii_lowercase();
        if !ids.contains(&eg) {
            return Err(bad(&format!(
                "rule '{}' references unknown egress '{}'",
                r.pattern, r.egress
            )));
        }
    }
    Ok(())
}

/// Restart needed if a listener-affecting field differs from what's running
/// (enabling a cold-started proxy, or changing the ports / connection cap).
fn restart_required(state: &AppState, cfg: &ProxyConfig) -> bool {
    let startup = &state.inner.config.proxy;
    (cfg.enabled && !state.inner.proxy.is_active())
        || cfg.http_port != startup.http_port
        || cfg.https_port != startup.https_port
        || cfg.max_connections != startup.max_connections
}

/// Strip secrets before returning config to the UI: the socks5 password and the
/// whole wireguard `.conf` (it embeds the PrivateKey). The UI re-sends them only
/// when changing them; a blank value on save means "keep the stored one".
fn redacted(mut p: ProxyConfig) -> ProxyConfig {
    for e in &mut p.egresses {
        e.password = None;
        if e.kind.eq_ignore_ascii_case("wireguard") {
            e.config = None;
        }
    }
    p
}

fn persist(state: &AppState) -> Option<String> {
    let cfg = state.live_config.read().clone();
    let path = state.config_path.as_ref().clone().or_else(|| {
        crate::config::Config::config_candidates()
            .into_iter()
            .next()
    })?;
    match cfg.save(&path) {
        Ok(()) => {
            tracing::info!("proxy config saved to {}", path.display());
            Some(path.display().to_string())
        }
        Err(e) => {
            tracing::error!("failed to save proxy config: {}", e);
            None
        }
    }
}

fn bad(msg: &str) -> ApiError {
    ApiError(FeriteError::Config(msg.to_string()))
}

#[cfg(test)]
mod tests {
    use crate::config::{EgressConfig, RuleConfig};
    use crate::test_support;
    use axum::Json;
    use axum::extract::State;

    use super::*;

    fn egress(id: &str, kind: &str) -> EgressConfig {
        EgressConfig {
            id: id.to_string(),
            name: id.to_string(),
            enabled: true,
            kind: kind.to_string(),
            address: if kind == "socks5" {
                Some("127.0.0.1".to_string())
            } else {
                None
            },
            port: if kind == "socks5" { Some(1080) } else { None },
            username: None,
            password: None,
            config: None,
        }
    }

    #[tokio::test]
    async fn get_returns_disabled_default() {
        let (state, db) = test_support::app_state("proxy-get").await;
        let Json(v) = get_proxy(State(state.clone())).await;
        assert_eq!(v["proxy"]["enabled"], serde_json::json!(false));
        drop(state);
        test_support::cleanup_sqlite(&db);
    }

    #[tokio::test]
    async fn put_rejects_rule_with_unknown_egress() {
        let (state, db) = test_support::app_state("proxy-put-bad").await;
        let cfg = ProxyConfig {
            enabled: true,
            rules: vec![RuleConfig {
                pattern: "x.test".to_string(),
                egress: "ghost".to_string(),
                fail_closed: true,
            }],
            ..ProxyConfig::default()
        };
        let err = put_proxy(State(state.clone()), Json(cfg))
            .await
            .unwrap_err();
        assert!(matches!(err.0, FeriteError::Config(_)));
        drop(state);
        test_support::cleanup_sqlite(&db);
    }

    #[tokio::test]
    async fn put_updates_live_config_and_flags_restart() {
        let (state, db) = test_support::app_state("proxy-put-ok").await;
        let cfg = ProxyConfig {
            enabled: true,
            egresses: vec![egress("work", "socks5")],
            rules: vec![RuleConfig {
                pattern: "*.example.com".to_string(),
                egress: "work".to_string(),
                fail_closed: true,
            }],
            ..ProxyConfig::default()
        };
        let Json(resp) = put_proxy(State(state.clone()), Json(cfg)).await.unwrap();
        assert_eq!(resp["status"], serde_json::json!("ok"));
        // Default test state starts disabled, so enabling needs a restart.
        assert_eq!(resp["restart_required"], serde_json::json!(true));
        // The live config now reflects the new egress/rule.
        let live = state.live_config.read().proxy.clone();
        assert_eq!(live.egresses.len(), 1);
        assert_eq!(live.rules.len(), 1);
        assert_eq!(live.egresses[0].id, "work");
        drop(state);
        test_support::cleanup_sqlite(&db);
    }

    fn wg_egress(id: &str, config: Option<&str>) -> EgressConfig {
        EgressConfig {
            id: id.to_string(),
            name: id.to_string(),
            enabled: true,
            kind: "wireguard".to_string(),
            address: None,
            port: None,
            username: None,
            password: None,
            config: config.map(str::to_string),
        }
    }

    fn sample_wg_conf() -> String {
        use base64::Engine;
        let k = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        format!(
            "[Interface]\nPrivateKey = {k}\nAddress = 10.9.0.2/32\n[Peer]\nPublicKey = {k}\nEndpoint = 127.0.0.1:51820\n"
        )
    }

    #[tokio::test]
    async fn wireguard_config_is_redacted_on_get_and_kept_when_blank() {
        let (state, db) = test_support::app_state("proxy-wg-redact").await;
        let conf = sample_wg_conf();

        // Save a wireguard egress with its .conf.
        let cfg = ProxyConfig {
            enabled: true,
            egresses: vec![wg_egress("vpn", Some(&conf))],
            ..ProxyConfig::default()
        };
        let _ = put_proxy(State(state.clone()), Json(cfg)).await.unwrap();
        assert!(state.live_config.read().proxy.egresses[0].config.is_some());

        // GET must NOT echo the .conf (it embeds the PrivateKey).
        let Json(v) = get_proxy(State(state.clone())).await;
        assert!(v["proxy"]["egresses"][0]["config"].is_null());

        // Re-saving with a blank config keeps the stored one (and still validates).
        let cfg2 = ProxyConfig {
            enabled: true,
            egresses: vec![wg_egress("vpn", None)],
            ..ProxyConfig::default()
        };
        let _ = put_proxy(State(state.clone()), Json(cfg2)).await.unwrap();
        assert!(
            state.live_config.read().proxy.egresses[0]
                .config
                .as_deref()
                .unwrap_or("")
                .contains("PrivateKey")
        );

        drop(state);
        test_support::cleanup_sqlite(&db);
    }
}
