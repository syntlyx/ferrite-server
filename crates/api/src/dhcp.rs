//! `/api/dhcp`: ferrite's DHCP server and IPv6 DNS announcer — their settings,
//! what they are doing, and the leases. A change applies at once, no restart.
//!
//! Never synced to a secondary: two boxes handing out the same pool would
//! give one address to two devices.

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

use axum::{Json, extract::State};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::ApiError;
use ferrite_app::AppState;
use ferrite_app::dhcp::{self, Detected};
use ferrite_core::config::{DhcpConfig, RaConfig};
use ferrite_core::error::FeriteError;

/// Bounds on the lease time: two minutes to thirty days.
const MIN_LEASE: u32 = 120;
const MAX_LEASE: u32 = 30 * 24 * 3600;
/// Pools are walked address by address; a /16 is more than any home needs.
const MAX_POOL: u32 = 65_536;

fn view(state: &AppState) -> Value {
    let cfg = state.live_config.read();
    json!({
        "dhcp": cfg.dhcp,
        "ra": cfg.ra,
        "status": state.inner.dhcp.status(),
        "detected": dhcp::detect(),
    })
}

/// GET /api/dhcp
pub async fn get_dhcp(State(state): State<AppState>) -> Json<Value> {
    Json(view(&state))
}

/// GET /api/dhcp/leases
pub async fn get_leases(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "leases": state.inner.dhcp.leases(),
        "now": chrono::Utc::now().timestamp(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct DhcpPut {
    pub dhcp: DhcpConfig,
    pub ra: RaConfig,
}

/// PUT /api/dhcp — both sections whole. Checked, saved, and applied at once.
pub async fn put_dhcp(
    State(state): State<AppState>,
    Json(mut body): Json<DhcpPut>,
) -> Result<Json<Value>, ApiError> {
    tidy(&mut body.dhcp, &mut body.ra);
    validate(&body.dhcp, &body.ra, &dhcp::detect())
        .map_err(|m| ApiError(FeriteError::Config(m)))?;
    {
        let mut cfg = state.live_config.write();
        cfg.dhcp = body.dhcp.clone();
        cfg.ra = body.ra.clone();
    }
    state.persist_config().await;
    state.inner.dhcp.apply(&body.dhcp, &body.ra).await;
    Ok(Json(view(&state)))
}

/// Blank strings are "unset"; MACs in one spelling.
fn tidy(d: &mut DhcpConfig, r: &mut RaConfig) {
    d.domain = d
        .domain
        .take()
        .map(|s| s.trim().trim_matches('.').to_ascii_lowercase())
        .filter(|s| !s.is_empty());
    for res in &mut d.reservations {
        if let Some(mac) = ferrite_core::net::parse_mac(res.mac.trim()) {
            res.mac = ferrite_core::net::format_mac(&mac);
        }
        res.name = res
            .name
            .take()
            .map(|n| n.trim().to_string())
            .filter(|n| !n.is_empty());
    }
    r.interface = r
        .interface
        .take()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
}

fn valid_mask(mask: Ipv4Addr) -> bool {
    let m = u32::from(mask);
    m != 0 && m.leading_ones() + m.trailing_zeros() == 32
}

fn in_subnet(ip: Ipv4Addr, net: Ipv4Addr, mask: Ipv4Addr) -> bool {
    u32::from(ip) & u32::from(mask) == u32::from(net) & u32::from(mask)
}

fn valid_domain(d: &str) -> bool {
    d.len() <= 253
        && d.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

/// Everything a running server would trip over, said before it is saved.
pub(crate) fn validate(d: &DhcpConfig, r: &RaConfig, found: &Detected) -> Result<(), String> {
    if !valid_mask(d.subnet_mask) {
        return Err(format!("{} isn't a subnet mask", d.subnet_mask));
    }
    if !(MIN_LEASE..=MAX_LEASE).contains(&d.lease_secs) {
        return Err("the lease time must be between 2 minutes and 30 days".into());
    }
    if let Some(dom) = &d.domain
        && !valid_domain(dom)
    {
        return Err(format!("{dom} isn't a domain name"));
    }
    let server = d.server_ip.or(found.server_ip);
    if d.enabled {
        if d.pool_start.is_none() || d.pool_end.is_none() {
            return Err("set the first and last address of the pool".into());
        }
        if server.is_none() {
            return Err("couldn't find this box's address — set the server address".into());
        }
    }
    if let (Some(start), Some(end)) = (d.pool_start, d.pool_end) {
        if u32::from(start) > u32::from(end) {
            return Err("the pool's first address comes after its last".into());
        }
        if u32::from(end) - u32::from(start) >= MAX_POOL {
            return Err("the pool is larger than 65536 addresses".into());
        }
        if let Some(server) = server {
            for ip in [start, end] {
                if !in_subnet(ip, server, d.subnet_mask) {
                    return Err(format!(
                        "{ip} isn't in this box's network ({server} / {})",
                        d.subnet_mask
                    ));
                }
            }
        }
    }
    if let (Some(server), Some(gw)) = (server, d.gateway)
        && !in_subnet(gw, server, d.subnet_mask)
    {
        return Err(format!("the router {gw} isn't in this box's network"));
    }
    let mut macs = HashSet::new();
    let mut ips = HashSet::new();
    for res in &d.reservations {
        if ferrite_core::net::parse_mac(&res.mac).is_none() {
            return Err(format!("{} isn't a MAC address", res.mac));
        }
        if !macs.insert(res.mac.clone()) {
            return Err(format!("{} has two reservations", res.mac));
        }
        if !ips.insert(res.ip) {
            return Err(format!("{} is reserved twice", res.ip));
        }
        if let Some(server) = server {
            if res.ip == server {
                return Err(format!("{} is this box's own address", res.ip));
            }
            if !in_subnet(res.ip, server, d.subnet_mask) {
                return Err(format!("{} isn't in this box's network", res.ip));
            }
        }
        if d.gateway.or(found.gateway) == Some(res.ip) {
            return Err(format!("{} is the router's address", res.ip));
        }
    }

    if r.enabled {
        let has_interface = r.interface.is_some() || found.interface.is_some();
        if !has_interface {
            return Err("couldn't find the network interface — set it".into());
        }
        if r.rdnss.is_empty() && r.interface.is_none() && found.ipv6.is_empty() {
            return Err("this box has no IPv6 address to announce — set one".into());
        }
    }
    if let Some(i) = &r.interface
        && (i.len() > 15
            || !i
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_.@".contains(c)))
    {
        return Err(format!("{i} isn't an interface name"));
    }
    for a in &r.rdnss {
        if a.is_unspecified() || a.is_multicast() || a.is_loopback() || is_link_local(*a) {
            return Err(format!(
                "{a} can't be announced — use a global or unique-local address"
            ));
        }
    }
    if !(4..=1800).contains(&r.interval_secs) {
        return Err("announce every 4 to 1800 seconds".into());
    }
    if r.rdnss_lifetime < r.interval_secs as u32 {
        return Err("the announced lifetime must outlast the interval".into());
    }
    Ok(())
}

fn is_link_local(a: Ipv6Addr) -> bool {
    a.segments()[0] & 0xffc0 == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_core::config::DhcpReservation;

    fn found() -> Detected {
        Detected {
            server_ip: Some("192.168.1.10".parse().unwrap()),
            subnet_mask: Some("255.255.255.0".parse().unwrap()),
            gateway: Some("192.168.1.1".parse().unwrap()),
            interface: Some("eth0".into()),
            ipv6: vec!["fd00::10".parse().unwrap()],
        }
    }

    fn on() -> DhcpConfig {
        DhcpConfig {
            enabled: true,
            pool_start: Some("192.168.1.100".parse().unwrap()),
            pool_end: Some("192.168.1.200".parse().unwrap()),
            ..DhcpConfig::default()
        }
    }

    #[test]
    fn a_plain_pool_on_the_detected_network_passes() {
        assert_eq!(validate(&on(), &RaConfig::default(), &found()), Ok(()));
        // Off, with nothing set, is fine too.
        assert_eq!(
            validate(&DhcpConfig::default(), &RaConfig::default(), &found()),
            Ok(())
        );
    }

    #[test]
    fn pools_must_be_set_ordered_and_local() {
        let ra = RaConfig::default();
        let mut d = on();
        d.pool_end = None;
        assert!(validate(&d, &ra, &found()).unwrap_err().contains("pool"));

        let mut d = on();
        d.pool_start = Some("192.168.1.201".parse().unwrap());
        assert!(validate(&d, &ra, &found()).unwrap_err().contains("after"));

        let mut d = on();
        d.pool_end = Some("192.168.2.20".parse().unwrap());
        assert!(validate(&d, &ra, &found()).unwrap_err().contains("network"));

        let mut d = on();
        d.subnet_mask = "255.0.255.0".parse().unwrap();
        assert!(validate(&d, &ra, &found()).unwrap_err().contains("mask"));

        let mut d = on();
        d.lease_secs = 30;
        assert!(validate(&d, &ra, &found()).unwrap_err().contains("lease"));
    }

    #[test]
    fn reservations_are_unique_and_never_the_box_or_router() {
        let ra = RaConfig::default();
        let res = |mac: &str, ip: &str| DhcpReservation {
            mac: mac.into(),
            ip: ip.parse().unwrap(),
            name: None,
        };
        let mut d = on();
        d.reservations = vec![
            res("aa:bb:cc:dd:ee:01", "192.168.1.50"),
            res("aa:bb:cc:dd:ee:01", "192.168.1.51"),
        ];
        assert!(validate(&d, &ra, &found()).unwrap_err().contains("two"));

        d.reservations = vec![
            res("aa:bb:cc:dd:ee:01", "192.168.1.50"),
            res("aa:bb:cc:dd:ee:02", "192.168.1.50"),
        ];
        assert!(validate(&d, &ra, &found()).unwrap_err().contains("twice"));

        d.reservations = vec![res("aa:bb:cc:dd:ee:01", "192.168.1.10")];
        assert!(validate(&d, &ra, &found()).unwrap_err().contains("own"));

        d.reservations = vec![res("aa:bb:cc:dd:ee:01", "192.168.1.1")];
        assert!(validate(&d, &ra, &found()).unwrap_err().contains("router"));

        d.reservations = vec![res("nope", "192.168.1.50")];
        assert!(validate(&d, &ra, &found()).unwrap_err().contains("MAC"));
    }

    #[test]
    fn announcements_need_a_routable_address() {
        let d = DhcpConfig::default();
        let mut ra = RaConfig {
            enabled: true,
            ..RaConfig::default()
        };
        assert_eq!(validate(&d, &ra, &found()), Ok(()));

        ra.rdnss = vec!["fe80::1".parse().unwrap()];
        assert!(
            validate(&d, &ra, &found())
                .unwrap_err()
                .contains("unique-local")
        );

        let mut nothing = found();
        nothing.ipv6.clear();
        ra.rdnss.clear();
        assert!(validate(&d, &ra, &nothing).unwrap_err().contains("IPv6"));
    }

    #[tokio::test]
    async fn put_saves_and_reports_without_starting_anything_when_off() {
        let (state, db, config_path) =
            ferrite_app::test_support::app_state_with_config_path("dhcp-api").await;
        let Json(v) = get_dhcp(State(state.clone())).await;
        assert_eq!(v["dhcp"]["enabled"], false);
        assert_eq!(v["status"]["running"], false);
        assert!(v.get("detected").is_some());

        // Rejected: switched on without a pool. Nothing saved.
        let bad = put_dhcp(
            State(state.clone()),
            Json(DhcpPut {
                dhcp: DhcpConfig {
                    enabled: true,
                    ..DhcpConfig::default()
                },
                ra: RaConfig::default(),
            }),
        )
        .await;
        assert!(bad.is_err());
        assert!(!state.live_config.read().dhcp.enabled);

        // Off, with a pool and a domain: saved, tidied, nothing running.
        let Json(v) = put_dhcp(
            State(state.clone()),
            Json(DhcpPut {
                dhcp: DhcpConfig {
                    server_ip: Some("192.168.1.10".parse().unwrap()),
                    pool_start: Some("192.168.1.100".parse().unwrap()),
                    pool_end: Some("192.168.1.150".parse().unwrap()),
                    domain: Some("Home".into()),
                    ..DhcpConfig::default()
                },
                ra: RaConfig::default(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(v["dhcp"]["domain"], "home");
        assert_eq!(v["status"]["running"], false);
        assert_eq!(v["status"]["domain"], "home");
        let saved = std::fs::read_to_string(&config_path).unwrap();
        assert!(saved.contains("[dhcp]"), "{saved}");
        let Json(l) = get_leases(State(state.clone())).await;
        assert_eq!(l["leases"].as_array().unwrap().len(), 0);

        ferrite_app::test_support::cleanup_sqlite(&db);
        let _ = std::fs::remove_file(&config_path);
    }

    #[test]
    fn tidy_normalises_blanks_and_macs() {
        let mut d = DhcpConfig {
            domain: Some(" Home.LAN. ".into()),
            reservations: vec![DhcpReservation {
                mac: "AA-BB-CC-DD-EE-FF".into(),
                ip: "192.168.1.5".parse().unwrap(),
                name: Some("  ".into()),
            }],
            ..DhcpConfig::default()
        };
        let mut r = RaConfig {
            interface: Some(" ".into()),
            ..RaConfig::default()
        };
        tidy(&mut d, &mut r);
        assert_eq!(d.domain.as_deref(), Some("home.lan"));
        assert_eq!(d.reservations[0].mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(d.reservations[0].name, None);
        assert_eq!(r.interface, None);
    }
}
