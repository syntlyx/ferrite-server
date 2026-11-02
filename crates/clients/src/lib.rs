mod mac;
mod mdns;
mod ptr;
mod registry;
mod resolver;

use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::AtomicI64;
use std::time::{Duration, Instant};

use dashmap::{DashMap, DashSet};

use ferrite_core::recording::RecordSwitches;
use ferrite_storage::Storage;
use ferrite_upstream::ZoneRouter;

/// A device the box had never seen joined the network.
#[derive(Debug, Clone)]
pub struct NewDevice {
    /// `aa:bb:cc:dd:ee:ff`.
    pub mac: String,
    /// The address it was first seen at.
    pub ip: IpAddr,
    /// Unix seconds.
    pub first_seen: i64,
}

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
    /// The reverse of `ip_to_mac`, kept in step by [`ClientRegistry::bind_ip`]
    /// and [`ClientRegistry::unbind_ip`]. "Which addresses does this device
    /// hold?" is asked for every device on every dashboard and clients poll,
    /// and answering it by scanning every address the box has ever seen made
    /// that poll proportional to the whole history — tens of thousands of
    /// entries once privacy addresses have been rotating for a while. The
    /// index costs one `IpAddr` per binding on top and is bounded by the same
    /// retention prune.
    mac_to_ips: DashMap<[u8; 6], Vec<IpAddr>>,
    in_flight: DashSet<IpAddr>,
    /// Unix seconds of the last `last_seen` touch of present bindings; throttles
    /// the neighbor-scan touch to [`BINDING_TOUCH_INTERVAL`] (see registry).
    last_binding_touch: AtomicI64,
    upstream: Arc<ZoneRouter>,
    storage: Arc<dyn Storage>,
    /// Every MAC the box knows, with the unix second it was first recorded
    /// (0 = known from before ferrite kept that). A MAC missing here is a new
    /// device — see [`ClientRegistry::subscribe_new_devices`].
    first_seen: DashMap<[u8; 6], i64>,
    /// Set until the first neighbour scan after startup has run: whatever is
    /// on the network then is the baseline, not news — so a restart, an
    /// upgrade or "record nothing" never announces the whole household.
    baseline: std::sync::atomic::AtomicBool,
    /// Where "a device never seen before joined" goes. Nobody listening is fine.
    new_devices: tokio::sync::broadcast::Sender<NewDevice>,
    /// The same switches the query log and statistics answer to. A device
    /// inventory — which MACs are on this network, and what they are called —
    /// is not query history, but it is still a record of the household, and
    /// "record nothing" has to mean nothing. In memory it keeps working (names
    /// in the UI, device attribution); what stops is writing it down.
    switches: Arc<RecordSwitches>,
}

// ── Public utilities ──────────────────────────────────────────────────────────

fn is_link_local_v6(v6: Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xffc0) == 0xfe80
}
