mod mac;
mod mdns;
mod registry;
mod resolver;

use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::AtomicI64;
use std::time::{Duration, Instant};

use dashmap::{DashMap, DashSet};
use ring::rand::{SecureRandom, SystemRandom};

use ferrite_storage::Storage;
use ferrite_upstream::ZoneRouter;

// ── Constants (visible to registry.rs and resolver.rs) ───────────────────────

/// How long a successful PTR/mDNS result is considered fresh.
const RESOLVE_TTL: Duration = Duration::from_secs(1800);
/// Retry delay after a complete pipeline miss.
const MISS_TTL: Duration = Duration::from_secs(30);
/// Minimum gap between `last_seen` touches of present IP bindings. The neighbor
/// scan runs far more often (~10 s); touching every scan would churn the DB for
/// no benefit, so we only refresh once an hour — well inside the prune window.
const BINDING_TOUCH_INTERVAL: Duration = Duration::from_secs(3600);
/// Learned IP→MAC bindings not seen for this long are pruned (DB + memory). Long
/// enough that a device keeps its identity across a holiday away from the network,
/// short enough that churned addresses (rotating IPv6 privacy) don't accumulate.
const BINDING_RETENTION: Duration = Duration::from_secs(30 * 24 * 3600);
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
    /// Unix seconds of the last `last_seen` touch of present bindings; throttles
    /// the neighbor-scan touch to [`BINDING_TOUCH_INTERVAL`] (see registry).
    last_binding_touch: AtomicI64,
    upstream: Arc<ZoneRouter>,
    storage: Arc<dyn Storage>,
}

// ── Public utilities ──────────────────────────────────────────────────────────

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
