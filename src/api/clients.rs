use std::collections::HashMap;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::api::ApiError;
use crate::app::AppState;
use crate::clients::{format_mac, parse_ip, parse_mac, ClientRegistry};

#[derive(Deserialize, Default)]
pub struct ListClientsParams {
    pub limit: Option<usize>,
    /// Rolling window in hours. Omit for all retained history.
    pub hours: Option<u64>,
    /// Force all retained history. `hours=0` is also treated as all-time.
    pub all_time: Option<bool>,
}

/// Aggregated stats per logical client (one entry per resolved name).
#[derive(Serialize)]
struct ClientGroup {
    name: String,
    ips: Vec<String>,
    macs: Vec<String>,
    total: u64,
    blocked: u64,
    last_seen: i64,
    /// `true` if the name came from a manual alias; `false` if from PTR.
    is_alias: bool,
    /// `true` when this client is explicitly exempt from blocklist filtering.
    blocking_bypassed: bool,
}

/// GET /api/clients
///
/// Returns clients grouped by resolved hostname (PTR or alias).
/// IPv4 and IPv6 addresses belonging to the same host are merged into one entry.
pub async fn list_clients(
    State(state): State<AppState>,
    Query(params): Query<ListClientsParams>,
) -> Result<Json<Value>, ApiError> {
    let (now, from) = client_time_window(&params);
    let limit = params.limit.unwrap_or(50).min(500);

    // Fetch more raw devices than the final limit because merging by resolved
    // name (e.g. a MAC device and its warm-up IP-tagged rows) may reduce count.
    let device_stats = state
        .inner
        .storage
        .top_clients(from, now, limit * 4)
        .await?;

    // Group by resolved name.
    let mut groups: HashMap<String, ClientGroup> = HashMap::new();

    for stat in &device_stats {
        let device = &stat.device;

        // Trigger background resolution for this device's IPs not yet in cache.
        ClientRegistry::trigger_resolve_device(&state.inner.client_registry, device);

        let info = state.inner.client_registry.describe_device(device);
        let name = info.name.clone().unwrap_or_else(|| device.clone());
        let mac0 = info.macs.first().map(|s| s.as_str());
        // The device bypasses filtering if any of its IPs (or the token itself,
        // when no IP is known) is exempt.
        let blocking_bypassed = if info.ips.is_empty() {
            state
                .inner
                .blocklist
                .client_bypasses_blocking(device, mac0)
        } else {
            info.ips.iter().any(|ip| {
                state
                    .inner
                    .blocklist
                    .client_bypasses_blocking(ip, mac0)
            })
        };

        let group = groups.entry(name.clone()).or_insert_with(|| ClientGroup {
            name,
            ips: vec![],
            macs: vec![],
            total: 0,
            blocked: 0,
            last_seen: 0,
            is_alias: info.is_alias,
            blocking_bypassed,
        });
        for ip in &info.ips {
            if !group.ips.iter().any(|x| x == ip) {
                group.ips.push(ip.clone());
            }
        }
        for mac in &info.macs {
            if !group.macs.iter().any(|m| m == mac) {
                group.macs.push(mac.clone());
            }
        }
        group.total += stat.total;
        group.blocked += stat.blocked;
        group.last_seen = group.last_seen.max(stat.last_seen);
        if info.is_alias {
            group.is_alias = true;
        }
        if blocking_bypassed {
            group.blocking_bypassed = true;
        }
    }

    let mut clients: Vec<ClientGroup> = groups.into_values().collect();
    clients.sort_by_key(|b| std::cmp::Reverse(b.total));
    clients.truncate(limit);

    Ok(Json(
        json!({ "clients": clients, "from_ts": from, "to_ts": now }),
    ))
}

fn client_time_window(params: &ListClientsParams) -> (i64, i64) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let all_time =
        params.all_time.unwrap_or_else(|| params.hours.is_none()) || params.hours == Some(0);
    if all_time {
        return (now, 0);
    }

    let hours = params.hours.unwrap_or(24).clamp(1, 168) as i64;
    (now, now - hours * 3600)
}

// ── Alias management ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AliasPayload {
    pub ip: Option<String>,
    pub mac: Option<String>,
    pub name: String,
}

/// GET /api/clients/aliases
pub async fn list_aliases(State(state): State<AppState>) -> Json<Value> {
    let aliases: Vec<Value> = state
        .inner
        .client_registry
        .list_aliases()
        .into_iter()
        .map(|(key, key_type, name)| {
            if key_type == "mac" {
                json!({ "mac": key, "name": name, "type": "mac" })
            } else {
                json!({ "ip": key, "name": name, "type": "ip" })
            }
        })
        .collect();
    Json(json!({ "aliases": aliases }))
}

/// POST /api/clients/aliases — add or update a manual alias
pub async fn add_alias(
    State(state): State<AppState>,
    Json(payload): Json<AliasPayload>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let name = payload.name.trim().to_string();
    if name.is_empty() {
        return Err(ApiError(crate::error::FeriteError::Config(
            "name must not be empty".into(),
        )));
    }

    match (payload.ip, payload.mac) {
        (Some(ip_str), None) => {
            let ip = parse_ip(&ip_str)
                .ok_or_else(|| crate::error::FeriteError::Config(format!("invalid IP: {}", ip_str)))
                .map_err(ApiError)?;
            state
                .inner
                .client_registry
                .add_ip_alias(ip, name.clone())
                .await?;
            tracing::info!("IP alias set: {} → {}", ip, name);
            Ok((
                StatusCode::CREATED,
                Json(json!({ "ip": ip.to_string(), "name": name, "type": "ip" })),
            ))
        }
        (None, Some(mac_str)) => {
            let mac = parse_mac(&mac_str)
                .ok_or_else(|| {
                    crate::error::FeriteError::Config(format!("invalid MAC: {}", mac_str))
                })
                .map_err(ApiError)?;
            state
                .inner
                .client_registry
                .add_mac_alias(mac, name.clone())
                .await?;
            tracing::info!("MAC alias set: {} → {}", mac_str, name);
            Ok((
                StatusCode::CREATED,
                Json(json!({ "mac": format_mac(&mac), "name": name, "type": "mac" })),
            ))
        }
        _ => Err(ApiError(crate::error::FeriteError::Config(
            "provide exactly one of 'ip' or 'mac'".into(),
        ))),
    }
}

/// GET /api/clients/:device/stats — per-device query stats.
/// `:device` is a device identity token: a MAC, or an IP fallback.
pub async fn client_ip_stats(
    State(state): State<AppState>,
    Path(device): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let stats = state
        .inner
        .storage
        .client_stats(&device)
        .await?
        .ok_or_else(|| {
            ApiError(crate::error::FeriteError::NotFound(format!(
                "client '{}' not found",
                device
            )))
        })?;

    ClientRegistry::trigger_resolve_device(&state.inner.client_registry, &device);
    let info = state.inner.client_registry.describe_device(&device);

    Ok(Json(json!({
        "device": stats.device,
        "name": info.name,
        "ips": info.ips,
        "mac": info.macs.first(),
        "total": stats.total,
        "blocked": stats.blocked,
        "last_seen": stats.last_seen,
    })))
}

/// DELETE /api/clients/aliases/:key — remove a manual alias (IP or MAC)
pub async fn remove_alias(
    State(state): State<AppState>,
    Path(key_str): Path<String>,
) -> Result<Json<Value>, ApiError> {
    // Try parsing as MAC first, then as IP.
    if let Some(mac) = parse_mac(&key_str) {
        state.inner.client_registry.remove_mac_alias(mac).await?;
        tracing::info!("MAC alias removed: {}", format_mac(&mac));
        return Ok(Json(
            json!({ "mac": format_mac(&mac), "status": "removed" }),
        ));
    }

    if let Some(ip) = parse_ip(&key_str) {
        state.inner.client_registry.remove_ip_alias(ip).await?;
        tracing::info!("IP alias removed: {}", ip);
        return Ok(Json(json!({ "ip": ip.to_string(), "status": "removed" })));
    }

    Err(ApiError(crate::error::FeriteError::Config(format!(
        "'{}' is neither a valid IP nor a MAC address",
        key_str
    ))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_list_defaults_to_all_retained_history() {
        let params = ListClientsParams::default();

        let (_now, from) = client_time_window(&params);

        assert_eq!(from, 0);
    }

    #[test]
    fn client_list_can_request_a_rolling_window() {
        let params = ListClientsParams {
            hours: Some(24),
            ..Default::default()
        };

        let (now, from) = client_time_window(&params);

        assert_eq!(now - from, 24 * 3600);
    }
}
