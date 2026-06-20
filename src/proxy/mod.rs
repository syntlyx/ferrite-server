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
mod http_host;
mod intercept;
mod rules;
mod sni;

pub use intercept::run;

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
use tokio::sync::Semaphore;

use crate::blocklist::Blocklist;
use crate::config::ProxyConfig;
use crate::dns::types::{DnsResponse, qtype as qt};
use crate::upstream::ZoneRouter;

use egress::Egress;
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
/// breakers, and the connection-cap semaphore.
pub struct ProxyState {
    registry: ArcSwap<Snapshot>,
    breakers: DashMap<String, Breaker>,
    conn_semaphore: Arc<Semaphore>,
    http_port: u16,
    https_port: u16,
    /// Whether the listeners were bound at startup. Interception can only be
    /// live-toggled when this is true; enabling from a disabled start needs a
    /// restart to actually bind :80/:443.
    active: bool,
    upstream: Arc<ZoneRouter>,
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
    fn route(&self, name: &str) -> Option<&CompiledRule> {
        self.rules.iter().find(|r| r.matches(name))
    }
}

impl ProxyState {
    pub fn from_config(cfg: &ProxyConfig, upstream: Arc<ZoneRouter>) -> Arc<Self> {
        let snapshot = build_snapshot(cfg, cfg.enabled, &upstream);
        Arc::new(Self {
            registry: ArcSwap::from_pointee(snapshot),
            breakers: DashMap::new(),
            conn_semaphore: Arc::new(Semaphore::new(cfg.max_connections.max(1))),
            http_port: cfg.http_port,
            https_port: cfg.https_port,
            active: cfg.enabled,
            upstream,
        })
    }

    /// Were the listeners bound at startup? When false, enabling via the API
    /// requires a restart before routing takes effect.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Hot-rebuild the routing snapshot (rules/egresses/advertise). Ports and the
    /// connection cap are fixed at startup. Interception stays off unless the
    /// listeners were bound at startup (`active`), so enabling a cold-started
    /// proxy doesn't redirect DNS to listeners that aren't there.
    pub fn reload(&self, cfg: &ProxyConfig) {
        let enabled = cfg.enabled && self.active;
        self.registry
            .store(Arc::new(build_snapshot(cfg, enabled, &self.upstream)));
    }

    /// DNS hot-path hook: returns an answer pointing at our advertise IP when
    /// `name` should be routed, else `None`. One ArcSwap load, no lock held
    /// across an `.await`.
    pub fn maybe_intercept(
        &self,
        query: &Message,
        name: &str,
        qtype: u16,
        blocklist: &Blocklist,
    ) -> Option<Intercept> {
        let snap = self.registry.load();
        if !snap.enabled {
            return None;
        }
        // A whitelisted domain is exempt from routing (mirrors the blocklist),
        // so users can carve exceptions out of a broad routing rule.
        if blocklist.is_whitelisted_normalized(name) {
            return None;
        }
        let rule = snap.route(name)?;
        let egress_id = snap.egresses[rule.egress_idx].id().to_string();
        let response = synth_response(query, qtype, snap.advertise_ipv4, snap.advertise_ipv6);
        Some(Intercept {
            response,
            egress_id,
        })
    }

    pub fn is_egress_healthy(&self, id: &str) -> bool {
        self.breakers
            .get(id)
            .map(|b| b.is_healthy())
            .unwrap_or(true)
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

    use crate::config::{BlocklistConfig, EgressConfig, ProxyConfig, RuleConfig, UpstreamConfig};
    use crate::dns::types::qtype;
    use crate::upstream::{UpstreamPool, ZoneRouter};

    fn upstream() -> Arc<ZoneRouter> {
        let pool = UpstreamPool::from_config(&[UpstreamConfig::Plain {
            address: "127.0.0.1".to_string(),
            port: 53,
        }])
        .unwrap();
        ZoneRouter::new(&[], pool).unwrap()
    }

    fn blocklist(whitelist: &[&str]) -> Blocklist {
        let path = std::env::temp_dir().join(format!(
            "ferrite-proxy-{}-{}/bl.fst",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        Blocklist::new(
            BlocklistConfig {
                enabled: true,
                decision_cache_size: 64,
                lists: vec![],
                wildcard_block: vec![],
                whitelist: whitelist.iter().map(|s| s.to_string()).collect(),
                client_bypass: vec![],
            },
            path,
        )
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
            }],
            rules: vec![RuleConfig {
                pattern: "*.example.com".to_string(),
                egress: "t".to_string(),
                fail_closed: true,
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
        let bl = blocklist(&[]);
        let q = query("www.example.com", RecordType::A);
        let hit = proxy
            .maybe_intercept(&q, "www.example.com", qtype::A, &bl)
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
        let bl = blocklist(&[]);
        let q = query("other.test", RecordType::A);
        assert!(
            proxy
                .maybe_intercept(&q, "other.test", qtype::A, &bl)
                .is_none()
        );
    }

    #[test]
    fn disabled_proxy_never_intercepts() {
        let proxy = state(false);
        let bl = blocklist(&[]);
        let q = query("www.example.com", RecordType::A);
        assert!(
            proxy
                .maybe_intercept(&q, "www.example.com", qtype::A, &bl)
                .is_none()
        );
    }

    #[test]
    fn whitelisted_domain_is_exempt_from_routing() {
        let proxy = state(true);
        let bl = blocklist(&["example.com"]);
        let q = query("www.example.com", RecordType::A);
        assert!(
            proxy
                .maybe_intercept(&q, "www.example.com", qtype::A, &bl)
                .is_none()
        );
    }

    #[test]
    fn aaaa_without_advertise_v6_returns_nodata() {
        let proxy = state(true);
        let bl = blocklist(&[]);
        let q = query("www.example.com", RecordType::AAAA);
        let hit = proxy
            .maybe_intercept(&q, "www.example.com", qtype::AAAA, &bl)
            .expect("should still intercept");
        let msg = Message::from_bytes(&hit.response.bytes).unwrap();
        // NODATA: NoError with no answers, so the client falls back to IPv4.
        assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
        assert!(msg.answers.is_empty());
    }

    #[test]
    fn https_type65_returns_nodata_to_avoid_bypass() {
        let proxy = state(true);
        let bl = blocklist(&[]);
        let q = query("www.example.com", RecordType::from(qtype::HTTPS));
        let hit = proxy
            .maybe_intercept(&q, "www.example.com", qtype::HTTPS, &bl)
            .expect("should intercept type 65");
        let msg = Message::from_bytes(&hit.response.bytes).unwrap();
        assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
        // No ipv4hint/ech leaked — empty answer forces classic A/AAAA resolution.
        assert!(msg.answers.is_empty());
    }
}
