//! `/api/proxy` — view and replace the selective-routing configuration.
//!
//! The web UI is the primary editor: it GETs the whole config and PUTs it back.
//! Everything applies live — rules/egresses/advertise swap the routing snapshot,
//! and `enabled` / listener ports / connection cap rebind the listeners on the
//! fly (the supervisor in `proxy::intercept`), so nothing needs a restart.

use std::collections::HashSet;

use axum::{Json, extract::State};
use serde_json::{Value, json};

use crate::api::ApiError;
use crate::app::AppState;
use crate::config::{EgressConfig, ProxyConfig};
use crate::error::FeriteError;
use crate::proxy::usable_rcvbuf_bytes;

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

    Json(json!({
        "proxy": redacted(proxy),
        "egress_health": health,
        // Effective kernel UDP recv-buffer ceiling (KiB). A WireGuard egress whose
        // per-connection buffer exceeds this drops bursts under load; the UI warns
        // and suggests raising net.core.rmem_max.
        "max_buffer_kb": kernel_udp_recv_kb(),
    }))
}

/// Probe the effective UDP receive-buffer ceiling the kernel grants (KiB) by
/// requesting an oversized `SO_RCVBUF` on a throwaway socket and reading it back.
/// The kernel clamps the request to `net.core.rmem_max`, so the read-back reveals
/// the real limit the WireGuard tunnel is subject to — reported in usable bytes
/// (see [`usable_rcvbuf_bytes`]) so it's comparable to a per-connection buffer
/// setting. Requesting a small value (e.g. 8 MiB) would self-cap the answer at that
/// request rather than the kernel limit, making the "raise net.core.rmem_max"
/// advice unverifiable. Re-probed per call so a live sysctl change is reflected
/// without a restart.
fn kernel_udp_recv_kb() -> Option<u64> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    let r = socket2::SockRef::from(&sock);
    // Ask for far more than any real rmem_max so the read-back reflects the kernel
    // ceiling, not our request. i32::MAX is the largest SO_RCVBUF the syscall accepts.
    let _ = r.set_recv_buffer_size(i32::MAX as usize);
    let usable = usable_rcvbuf_bytes(r.recv_buffer_size().ok()?);
    Some((usable / 1024) as u64)
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
            // Match the previous egress by id; if the id changed (the UI derives it
            // from the name, so renaming changes it), fall back to a stable identity
            // in the config so masked secrets still restore instead of failing
            // validation as "PrivateKey is not valid base64".
            let prev = match_prev(&old, e, &id);
            if e.kind.eq_ignore_ascii_case("socks5")
                && e.password.as_deref().unwrap_or("").is_empty()
                && let Some(p) = prev
            {
                e.password = p.password.clone();
            }
            if e.kind.eq_ignore_ascii_case("wireguard")
                && let Some(p) = prev
                && let Some(stored) = p.config.as_deref()
            {
                let submitted = e.config.as_deref().unwrap_or("");
                e.config = Some(if submitted.trim().is_empty() {
                    stored.to_string() // blank → keep the whole stored .conf
                } else {
                    restore_wg_key(submitted, stored) // splice the key back if still masked
                });
            }
        }
    }

    validate(&new)?;
    new.normalize();

    // Apply live — routing snapshot swaps and the listeners rebind if their
    // settings changed (no restart) — then persist.
    state.inner.proxy.reload(&new);
    state.live_config.write().proxy = new;
    let saved_to = persist(&state);

    Ok(Json(json!({
        "status": "ok",
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
            // DirectEvasion needs no required fields; seg_position is optional and
            // any u16 offset is valid (out-of-range is ignored at runtime).
            "evasion" => {}
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

/// Strip secrets before returning config to the UI: the socks5 password and the
/// whole wireguard `.conf` (it embeds the PrivateKey). The UI re-sends them only
/// when changing them; a blank value on save means "keep the stored one".
fn redacted(mut p: ProxyConfig) -> ProxyConfig {
    for e in &mut p.egresses {
        e.password = None;
        if e.kind.eq_ignore_ascii_case("wireguard")
            && let Some(cfg) = e.config.as_deref()
        {
            // Show the .conf (so the UI can display it like Proton does) but mask
            // the PrivateKey value; the rest is non-secret and helps the operator
            // confirm what's configured.
            e.config = Some(mask_wg_key(cfg));
        }
    }
    p
}

/// Placeholder shown in place of a WireGuard PrivateKey on GET. A real key is
/// base64, so this is unmistakable; PUT treats it as "keep the stored key".
const WG_KEY_MASK: &str = "********";

/// Replace the `PrivateKey` value with [`WG_KEY_MASK`], leaving every other line
/// (Address, DNS, Endpoint, PublicKey, …) intact.
fn mask_wg_key(text: &str) -> String {
    map_private_key_line(text, |_| WG_KEY_MASK.to_string())
}

/// If the submitted `.conf` still carries the masked PrivateKey, splice the real
/// key back in from `stored`; otherwise return the submitted text unchanged (the
/// operator pasted a fresh key).
fn restore_wg_key(submitted: &str, stored: &str) -> String {
    let stored_key = private_key_value(stored);
    map_private_key_line(submitted, |value| {
        if value == WG_KEY_MASK {
            stored_key.clone().unwrap_or_else(|| value.to_string())
        } else {
            value.to_string()
        }
    })
}

/// Rewrite the value of the (case-insensitive) `PrivateKey` line via `f`,
/// preserving the key name and surrounding whitespace.
fn map_private_key_line(text: &str, f: impl Fn(&str) -> String) -> String {
    text.lines()
        .map(|line| match (is_private_key_line(line), line.find('=')) {
            (true, Some(eq)) => format!("{}= {}", &line[..eq], f(line[eq + 1..].trim())),
            _ => line.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn private_key_value(text: &str) -> Option<String> {
    text.lines()
        .find(|l| is_private_key_line(l))
        .and_then(|l| l.split_once('='))
        .map(|(_, v)| v.trim().to_string())
}

fn is_private_key_line(line: &str) -> bool {
    line.trim_start()
        .to_ascii_lowercase()
        .starts_with("privatekey")
}

/// The `PublicKey` value from a `.conf` — a stable per-peer identity (it isn't
/// masked) used to re-match a renamed WireGuard egress to its stored config.
fn wg_public_key(text: &str) -> Option<String> {
    text.lines()
        .find(|l| l.trim_start().to_ascii_lowercase().starts_with("publickey"))
        .and_then(|l| l.split_once('='))
        .map(|(_, v)| v.trim().to_string())
}

/// Find the previous version of egress `e`: by id, or — when the id changed (the
/// UI derives it from the display name) — by a stable property of the config so a
/// masked secret still restores. WireGuard matches on PublicKey, SOCKS5 on host+port.
fn match_prev<'a>(old: &'a ProxyConfig, e: &EgressConfig, id: &str) -> Option<&'a EgressConfig> {
    if let Some(p) = old.egresses.iter().find(|p| p.id == id) {
        return Some(p);
    }
    match e.kind.trim().to_ascii_lowercase().as_str() {
        "wireguard" => {
            let pk = wg_public_key(e.config.as_deref().unwrap_or(""))?;
            old.egresses.iter().find(|p| {
                p.kind.eq_ignore_ascii_case("wireguard")
                    && wg_public_key(p.config.as_deref().unwrap_or("")).as_deref()
                        == Some(pk.as_str())
            })
        }
        "socks5" => {
            let addr = e.address.as_deref()?;
            let port = e.port?;
            old.egresses.iter().find(|p| {
                p.kind.eq_ignore_ascii_case("socks5")
                    && p.address.as_deref() == Some(addr)
                    && p.port == Some(port)
            })
        }
        _ => None,
    }
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
            seg_position: None,
            buffer_kb: None,
            tx_buffer_kb: None,
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
                clients: Vec::new(),
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
    async fn put_updates_live_config() {
        let (state, db) = test_support::app_state("proxy-put-ok").await;
        let cfg = ProxyConfig {
            enabled: true,
            egresses: vec![egress("work", "socks5")],
            rules: vec![RuleConfig {
                pattern: "*.example.com".to_string(),
                egress: "work".to_string(),
                fail_closed: true,
                clients: Vec::new(),
            }],
            ..ProxyConfig::default()
        };
        let Json(resp) = put_proxy(State(state.clone()), Json(cfg)).await.unwrap();
        assert_eq!(resp["status"], serde_json::json!("ok"));
        // Everything applies live now — there is no restart_required field.
        assert!(resp.get("restart_required").is_none());
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
            seg_position: None,
            buffer_kb: None,
            tx_buffer_kb: None,
        }
    }

    fn sample_wg_conf() -> String {
        use base64::Engine;
        let k = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        format!(
            "[Interface]\nPrivateKey = {k}\nAddress = 10.9.0.2/32\n[Peer]\nPublicKey = {k}\nEndpoint = 127.0.0.1:51820\n"
        )
    }

    #[test]
    fn renamed_wireguard_egress_restores_key_by_public_key() {
        // Stored egress "vpn" with a real key; the UI re-submits it under a NEW id
        // (rename derives the id from the name) with the masked .conf.
        let conf = sample_wg_conf();
        let old = ProxyConfig {
            egresses: vec![wg_egress("vpn", Some(&conf))],
            ..ProxyConfig::default()
        };
        let submitted = wg_egress("vpn-renamed", Some(&mask_wg_key(&conf)));

        // id no longer matches → must fall back to the PublicKey to find the prev.
        let prev = match_prev(&old, &submitted, "vpn-renamed").expect("matched by PublicKey");
        assert_eq!(prev.id, "vpn");
        // And the masked key splices back to the real one (no validation failure).
        let restored = restore_wg_key(&mask_wg_key(&conf), prev.config.as_deref().unwrap());
        assert!(restored.contains("PrivateKey =") && !restored.contains("********"));
    }

    #[tokio::test]
    async fn wireguard_config_is_redacted_on_get_and_kept_when_blank() {
        let (state, db) = test_support::app_state("proxy-wg-redact").await;
        let conf = sample_wg_conf();
        let k = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode([7u8; 32])
        };

        // Save a wireguard egress with its .conf.
        let cfg = ProxyConfig {
            enabled: true,
            egresses: vec![wg_egress("vpn", Some(&conf))],
            ..ProxyConfig::default()
        };
        let _ = put_proxy(State(state.clone()), Json(cfg)).await.unwrap();
        assert!(state.live_config.read().proxy.egresses[0].config.is_some());

        // GET shows the .conf with ONLY the PrivateKey masked (Proton-style).
        let Json(v) = get_proxy(State(state.clone())).await;
        let shown = v["proxy"]["egresses"][0]["config"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(
            shown.contains("PrivateKey = ********"),
            "key must be masked: {shown}"
        );
        assert!(
            !shown.contains(&format!("PrivateKey = {k}")),
            "raw key leaked: {shown}"
        );
        assert!(
            shown.contains("Address = 10.9.0.2/32"),
            "non-secret lines must stay"
        );

        // Re-saving the masked .conf (what the UI echoes back) restores the real key.
        let cfg2 = ProxyConfig {
            enabled: true,
            egresses: vec![wg_egress("vpn", Some(&shown))],
            ..ProxyConfig::default()
        };
        let _ = put_proxy(State(state.clone()), Json(cfg2)).await.unwrap();
        assert!(
            state.live_config.read().proxy.egresses[0]
                .config
                .as_deref()
                .unwrap_or("")
                .contains(&format!("PrivateKey = {k}")),
            "real key must be restored when the mask is sent back"
        );

        // A fully blank config also keeps the stored one.
        let cfg3 = ProxyConfig {
            enabled: true,
            egresses: vec![wg_egress("vpn", None)],
            ..ProxyConfig::default()
        };
        let _ = put_proxy(State(state.clone()), Json(cfg3)).await.unwrap();
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
