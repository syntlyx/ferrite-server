//! Selective per-domain routing through tunnels/proxies.
//!
//! For a domain that matches a routing rule, the DNS pipeline answers with
//! ferrite's own advertise IP (see [`ProxyState::maybe_intercept`]) so the
//! client connects to us. The listeners in [`intercept`] then read the SNI
//! (:443) or Host (:80), re-match the rule on the real host, and splice the
//! connection through the chosen [`Egress`] — without terminating TLS, so the
//! client validates the real server's certificate end-to-end.

mod egress;
mod health;
pub(crate) mod http_host;
mod intercept;
mod rules;
mod sni;

pub use intercept::run;
pub(crate) use intercept::forward_http;

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use arc_swap::ArcSwap;
use bytes::Bytes;
use dashmap::DashMap;
use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record};
use hickory_proto::serialize::binary::BinEncodable;
use tokio::sync::Notify;

use crate::config::ProxyConfig;
use crate::dns::types::{DnsResponse, qtype as qt};
use crate::upstream::ZoneRouter;

pub use egress::{Egress, EgressConn};
use health::Breaker;
use rules::CompiledRule;

/// TTL for synthesized routing answers. Short so disabling a rule recovers
/// within a minute instead of being pinned by downstream caches.
const SYNTH_TTL: u32 = 60;

/// A decision to route a query: the synthetic DNS answer plus which egress the
/// connection will eventually be sent through (for logging).
pub struct Intercept {
    pub response: DnsResponse,
    pub egress_id: String,
}

/// Shared proxy state: a hot-swappable routing snapshot, per-egress circuit
/// breakers, and the live listener settings (rebound by the supervisor on change,
/// so ports / enabled / connection-cap never need a process restart).
pub struct ProxyState {
    registry: ArcSwap<Snapshot>,
    breakers: DashMap<String, Breaker>,
    listeners: ArcSwap<ListenerCfg>,
    /// Pinged whenever a listener-affecting field changes; the supervisor
    /// (`intercept::run`) wakes, tears down the old listeners, and rebinds.
    listener_reload: Arc<Notify>,
    upstream: Arc<ZoneRouter>,
}

/// Listener-affecting settings, swapped live. The supervisor reads a fresh copy
/// each time it (re)binds, so changing any of these takes effect immediately.
struct ListenerCfg {
    enabled: bool,
    http_port: u16,
    https_port: u16,
    max_connections: usize,
}

impl ListenerCfg {
    fn from(cfg: &ProxyConfig) -> Self {
        Self {
            enabled: cfg.enabled,
            http_port: cfg.http_port,
            https_port: cfg.https_port,
            max_connections: cfg.max_connections.max(1),
        }
    }

    fn differs(&self, other: &Self) -> bool {
        self.enabled != other.enabled
            || self.http_port != other.http_port
            || self.https_port != other.https_port
            || self.max_connections != other.max_connections
    }
}

/// The compiled routing table, swapped atomically on config change.
struct Snapshot {
    enabled: bool,
    advertise_ipv4: Option<Ipv4Addr>,
    advertise_ipv6: Option<Ipv6Addr>,
    egresses: Vec<Arc<Egress>>,
    rules: Vec<CompiledRule>,
}

impl Snapshot {
    fn route(&self, name: &str, client_ip: &str, client_mac: Option<&str>) -> Option<&CompiledRule> {
        self.rules
            .iter()
            .find(|r| r.matches(name) && r.matches_client(client_ip, client_mac))
    }
}

impl ProxyState {
    pub fn from_config(cfg: &ProxyConfig, upstream: Arc<ZoneRouter>) -> Arc<Self> {
        let snapshot = build_snapshot(cfg, cfg.enabled, &upstream);
        Arc::new(Self {
            registry: ArcSwap::from_pointee(snapshot),
            breakers: DashMap::new(),
            listeners: ArcSwap::from_pointee(ListenerCfg::from(cfg)),
            listener_reload: Arc::new(Notify::new()),
            upstream,
        })
    }

    /// Hot-rebuild everything from a new config: the routing snapshot
    /// (rules/egresses/advertise/enabled) swaps atomically, and if any
    /// listener-affecting field changed (enabled / ports / connection cap) the
    /// supervisor is signalled to rebind the listeners — no process restart.
    pub fn reload(&self, cfg: &ProxyConfig) {
        self.registry
            .store(Arc::new(build_snapshot(cfg, cfg.enabled, &self.upstream)));
        let next = ListenerCfg::from(cfg);
        let changed = next.differs(&self.listeners.load());
        self.listeners.store(Arc::new(next));
        if changed {
            self.listener_reload.notify_one();
        }
    }

    /// Handle the supervisor waits on; pinged by [`Self::reload`] when listener
    /// settings change.
    fn listener_reload(&self) -> Arc<Notify> {
        Arc::clone(&self.listener_reload)
    }

    /// A fresh copy of the current listener settings (for the supervisor to bind).
    fn listener_cfg(&self) -> Arc<ListenerCfg> {
        self.listeners.load_full()
    }

    /// Is selective routing enabled? The shared HTTP listener uses this to decide
    /// whether a non-panel host should be handed to the proxy or served the panel.
    pub fn is_enabled(&self) -> bool {
        self.registry.load().enabled
    }

    /// Does any rule restrict to specific clients? The DNS handler resolves the
    /// client MAC for routing only when this is true (otherwise it's free).
    pub fn has_client_rules(&self) -> bool {
        self.registry.load().rules.iter().any(|r| !r.clients.is_empty())
    }

    /// DNS hot-path hook: returns an answer pointing at our advertise IP when
    /// `name` should be routed for this client, else `None`. One ArcSwap load, no
    /// lock held across an `.await`.
    pub fn maybe_intercept(
        &self,
        query: &Message,
        name: &str,
        qtype: u16,
        client_ip: &str,
        client_mac: Option<&str>,
    ) -> Option<Intercept> {
        let snap = self.registry.load();
        if !snap.enabled {
            return None;
        }
        // Routing is independent of the whitelist: the whitelist means "never
        // block this", not "never route this". An explicit rule wins regardless
        // (to exclude a subdomain from a broad rule, point it at a Direct egress).
        // A rule may also be scoped to specific clients (by IP/MAC).
        let rule = snap.route(name, client_ip, client_mac)?;
        let egress_id = snap.egresses[rule.egress_idx].id().to_string();
        let response = synth_response(query, qtype, snap.advertise_ipv4, snap.advertise_ipv6);
        Some(Intercept {
            response,
            egress_id,
        })
    }

    /// Look up a live egress by id from the current snapshot. Used by upstream
    /// resolvers configured to tunnel their DNS through a named egress; the lookup
    /// is by-value (cloned `Arc`) so it follows hot config swaps without a restart.
    pub fn egress(&self, id: &str) -> Option<Arc<Egress>> {
        self.registry
            .load()
            .egresses
            .iter()
            .find(|e| e.id() == id)
            .cloned()
    }

    pub fn is_egress_healthy(&self, id: &str) -> bool {
        // Both the connect circuit-breaker AND the egress's intrinsic readiness
        // (e.g. a WireGuard tunnel only counts as healthy once its handshake has
        // completed) must be green.
        let breaker_ok = self
            .breakers
            .get(id)
            .map(|b| b.is_healthy())
            .unwrap_or(true);
        let intrinsic_ok = self
            .registry
            .load()
            .egresses
            .iter()
            .find(|e| e.id() == id)
            .map(|e| e.is_healthy())
            .unwrap_or(true);
        breaker_ok && intrinsic_ok
    }

    fn note_success(&self, id: &str) {
        self.breakers
            .entry(id.to_string())
            .or_default()
            .record_success();
    }

    fn note_failure(&self, id: &str) {
        self.breakers
            .entry(id.to_string())
            .or_default()
            .record_failure();
    }
}

/// Validate a pasted WireGuard `.conf` so the API can reject a bad one with 400.
pub fn validate_wireguard_conf(text: &str) -> crate::error::Result<()> {
    egress::validate_wireguard_conf(text)
}

fn build_snapshot(cfg: &ProxyConfig, enabled: bool, upstream: &Arc<ZoneRouter>) -> Snapshot {
    let mut egresses = Vec::new();
    let mut by_id: HashMap<String, usize> = HashMap::new();
    for e in &cfg.egresses {
        if !e.enabled {
            continue;
        }
        match Egress::from_config(e, Arc::clone(upstream)) {
            Ok(eg) => {
                by_id.insert(eg.id().to_string(), egresses.len());
                egresses.push(Arc::new(eg));
            }
            Err(err) => tracing::warn!("proxy: skipping egress '{}': {}", e.id, err),
        }
    }
    let rules = rules::compile(&cfg.rules, &by_id);
    Snapshot {
        enabled,
        advertise_ipv4: cfg
            .advertise_ipv4
            .or_else(crate::setup::local_ipv4_for_internet),
        advertise_ipv6: cfg.advertise_ipv6,
        egresses,
        rules,
    }
}

/// Build the synthetic DNS answer for a routed domain. A/AAAA get the advertise
/// IP; every other qtype (including HTTPS/SVCB type 65) gets NODATA so a client
/// can't pick up an alternative address that would bypass the proxy.
fn synth_response(
    query: &Message,
    qtype: u16,
    v4: Option<Ipv4Addr>,
    v6: Option<Ipv6Addr>,
) -> DnsResponse {
    let mut resp = Message::response(query.metadata.id, OpCode::Query);
    resp.metadata.authoritative = true;
    resp.metadata.recursion_desired = query.metadata.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.metadata.response_code = ResponseCode::NoError;
    resp.add_queries(query.queries.iter().cloned());

    if let Some(qname) = query.queries.first().map(|q| q.name().clone()) {
        match qtype {
            qt::A => {
                if let Some(ip) = v4 {
                    resp.add_answer(Record::from_rdata(qname, SYNTH_TTL, RData::A(A(ip))));
                }
            }
            qt::AAAA => {
                if let Some(ip) = v6 {
                    resp.add_answer(Record::from_rdata(qname, SYNTH_TTL, RData::AAAA(AAAA(ip))));
                }
            }
            _ => {} // NODATA
        }
    }

    let bytes = resp.to_bytes().unwrap_or_default();
    DnsResponse {
        bytes: Bytes::from(bytes),
        ttl: SYNTH_TTL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use hickory_proto::serialize::binary::BinDecodable;

    use crate::config::{EgressConfig, ProxyConfig, RuleConfig, UpstreamConfig};
    use crate::dns::types::qtype;
    use crate::upstream::{UpstreamPool, ZoneRouter, no_proxy};

    fn upstream() -> Arc<ZoneRouter> {
        let pool = UpstreamPool::from_config(
            &[UpstreamConfig::Plain {
                address: "127.0.0.1".to_string(),
                port: 53,
                egress: None,
            }],
            no_proxy(),
        )
        .unwrap();
        ZoneRouter::new(&[], pool).unwrap()
    }

    fn state(enabled: bool) -> Arc<ProxyState> {
        let mut cfg = ProxyConfig {
            enabled,
            http_port: 8080,
            https_port: 8443,
            advertise_ipv4: Some(Ipv4Addr::new(192, 168, 1, 5)),
            advertise_ipv6: None,
            max_connections: 16,
            egresses: vec![EgressConfig {
                id: "t".to_string(),
                name: "t".to_string(),
                enabled: true,
                kind: "direct".to_string(),
                address: None,
                port: None,
                username: None,
                password: None,
                config: None,
                seg_position: None,
                buffer_kb: None,
            }],
            rules: vec![RuleConfig {
                pattern: "*.example.com".to_string(),
                egress: "t".to_string(),
                fail_closed: true,
                clients: Vec::new(),
            }],
        };
        cfg.normalize();
        ProxyState::from_config(&cfg, upstream())
    }

    fn query(name: &str, rt: RecordType) -> Message {
        let mut m = Message::new(0xABCD, MessageType::Query, OpCode::Query);
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(
            Name::from_str(&format!("{name}.")).unwrap(),
            rt,
        ));
        m
    }

    #[test]
    fn routes_matching_domain_to_advertise_ip() {
        let proxy = state(true);
        let q = query("www.example.com", RecordType::A);
        let hit = proxy
            .maybe_intercept(&q, "www.example.com", qtype::A, "0.0.0.0", None)
            .expect("should route");
        assert_eq!(hit.egress_id, "t");
        let msg = Message::from_bytes(&hit.response.bytes).unwrap();
        assert!(matches!(
            msg.answers[0].data,
            RData::A(A(ip)) if ip == Ipv4Addr::new(192, 168, 1, 5)
        ));
    }

    #[test]
    fn does_not_route_unmatched_domain() {
        let proxy = state(true);
        let q = query("other.test", RecordType::A);
        assert!(proxy.maybe_intercept(&q, "other.test", qtype::A, "0.0.0.0", None).is_none());
    }

    #[test]
    fn disabled_proxy_never_intercepts() {
        let proxy = state(false);
        let q = query("www.example.com", RecordType::A);
        assert!(
            proxy
                .maybe_intercept(&q, "www.example.com", qtype::A, "0.0.0.0", None)
                .is_none()
        );
    }

    #[test]
    fn aaaa_without_advertise_v6_returns_nodata() {
        let proxy = state(true);
        let q = query("www.example.com", RecordType::AAAA);
        let hit = proxy
            .maybe_intercept(&q, "www.example.com", qtype::AAAA, "0.0.0.0", None)
            .expect("should still intercept");
        let msg = Message::from_bytes(&hit.response.bytes).unwrap();
        // NODATA: NoError with no answers, so the client falls back to IPv4.
        assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
        assert!(msg.answers.is_empty());
    }

    #[test]
    fn https_type65_returns_nodata_to_avoid_bypass() {
        let proxy = state(true);
        let q = query("www.example.com", RecordType::from(qtype::HTTPS));
        let hit = proxy
            .maybe_intercept(&q, "www.example.com", qtype::HTTPS, "0.0.0.0", None)
            .expect("should intercept type 65");
        let msg = Message::from_bytes(&hit.response.bytes).unwrap();
        assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
        // No ipv4hint/ech leaked — empty answer forces classic A/AAAA resolution.
        assert!(msg.answers.is_empty());
    }
}
