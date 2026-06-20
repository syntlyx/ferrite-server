mod mac;
mod mdns;
mod registry;
mod resolver;

use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::{DashMap, DashSet};
use ring::rand::{SecureRandom, SystemRandom};

use crate::storage::Storage;
use crate::upstream::ZoneRouter;

// ── Constants (visible to registry.rs and resolver.rs) ───────────────────────

/// How long a successful PTR/mDNS result is considered fresh.
const RESOLVE_TTL: Duration = Duration::from_secs(1800);
/// Retry delay after a complete pipeline miss.
const MISS_TTL: Duration = Duration::from_secs(30);
/// Local suffixes stripped from PTR/mDNS hostnames in the UI.
const LOCAL_SUFFIXES: &[&str] = &[
    ".localdomain",
    ".home.arpa",
    ".local",
    ".home",
    ".lan",
    ".internal",
];

// ── Shared types ──────────────────────────────────────────────────────────────

struct PtrEntry {
    name: Option<String>,
    expires_at: Instant,
}

/// Resolved display info for a device identity token (a MAC, or an IP fallback).
/// Built by [`ClientRegistry::describe_device`] for the clients API.
pub struct DeviceInfo {
    /// Friendly name (alias or resolved hostname), if any.
    pub name: Option<String>,
    /// IP addresses currently associated with this device.
    pub ips: Vec<String>,
    /// MAC addresses for this device (at most one).
    pub macs: Vec<String>,
    /// `true` when the name came from a manual alias.
    pub is_alias: bool,
}

/// Maps client IP addresses to human-readable names.
///
/// # Resolution pipeline (fastest → slowest)
///
/// 1. Manual IP alias — user-set, persisted, never expires.
/// 2. MAC alias — EUI-64 or ARP-derived MAC matched to a previously resolved name.
/// 3. ptr_cache — result of the last full resolution attempt (stale-while-revalidate).
///
/// See [`registry`] for public API and [`resolver`] for the background pipeline.
pub struct ClientRegistry {
    ptr_cache: DashMap<IpAddr, PtrEntry>,
    ip_aliases: DashMap<IpAddr, String>,
    mac_aliases: DashMap<[u8; 6], String>,
    mac_to_name: DashMap<[u8; 6], (String, Instant)>,
    ip_to_mac: DashMap<IpAddr, [u8; 6]>,
    in_flight: DashSet<IpAddr>,
    upstream: Arc<ZoneRouter>,
    storage: Arc<dyn Storage>,
}

// ── Public utilities ──────────────────────────────────────────────────────────

/// Parse a MAC address in `"aa:bb:cc:dd:ee:ff"` or `"aa-bb-cc-dd-ee-ff"` format.
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let s = s.replace('-', ":");
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(mac)
}

/// Format a MAC address as `"aa:bb:cc:dd:ee:ff"`.
pub fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Parse an IP string, stripping IPv6 scope IDs (`%eth0`).
pub fn parse_ip(s: &str) -> Option<IpAddr> {
    s.split('%').next()?.parse().ok()
}

/// Normalize a client identity key accepted by policy/settings APIs.
/// Supports IP addresses and MAC addresses.
pub fn normalize_client_key(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(ip) = parse_ip(s) {
        return Some(unmap_v4(ip).to_string());
    }
    parse_mac(s).map(|mac| format_mac(&mac))
}

/// Convert IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to plain IPv4.
pub fn unmap_v4(ip: IpAddr) -> IpAddr {
    if let IpAddr::V6(v6) = ip {
        if let Some(v4) = v6.to_ipv4_mapped() {
            return IpAddr::V4(v4);
        }
    }
    ip
}

/// Build the reverse-DNS PTR domain for an IP.
/// Shared by `resolver.rs` and `mdns.rs` to avoid duplication.
pub(super) fn ip_to_ptr_domain(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let nibbles: Vec<String> = v6
                .octets()
                .iter()
                .rev()
                .flat_map(|b| {
                    [
                        char::from_digit((b & 0xf) as u32, 16).unwrap_or('0'),
                        char::from_digit((b >> 4) as u32, 16).unwrap_or('0'),
                    ]
                })
                .map(|c| c.to_string())
                .collect();
            format!("{}.ip6.arpa", nibbles.join("."))
        }
    }
}

pub(super) fn random_query_id() -> Option<u16> {
    let mut bytes = [0u8; 2];
    SystemRandom::new().fill(&mut bytes).ok()?;
    Some(u16::from_be_bytes(bytes))
}

fn is_link_local_v6(v6: Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xffc0) == 0xfe80
}
