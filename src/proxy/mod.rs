//! Selective per-domain routing through tunnels/proxies.
//!
//! For a domain that matches a routing rule, the DNS pipeline answers with
//! ferrite's own advertise IP (see [`ProxyState::maybe_intercept`]) so the
//! client connects to us. The listeners in [`intercept`] then read the SNI
//! (:443) or Host (:80), re-match the rule on the real host, and splice the
//! connection through the chosen [`Egress`] — without terminating TLS, so the
//! client validates the real server's certificate end-to-end.

mod alerts;
mod egress;
mod health;
pub(crate) mod http_host;
mod intercept;
mod rules;
mod sni;
mod stats;

pub use alerts::watch;

pub(crate) use intercept::forward_http;
pub use intercept::run;

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use bytes::Bytes;
use dashmap::DashMap;
use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record};
use hickory_proto::serialize::binary::BinEncodable;
use tokio::sync::Notify;

use crate::config::{EgressConfig, ProxyConfig};
use crate::dns::types::{DnsResponse, qtype as qt};
use crate::upstream::ZoneRouter;

pub(crate) use egress::direct_connect;
pub(crate) use egress::usable_rcvbuf_bytes;
pub use egress::{Egress, EgressConn};
use health::Breaker;
use rules::CompiledRule;
pub use stats::ProxyStats;

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
    /// Traffic counters, keyed by egress id / rule so they survive snapshot
    /// reloads (see [`stats::ProxyStats`]).
    stats: ProxyStats,
    /// Egresses currently observed unhealthy by the alert watcher, with when
    /// each went down and whether its down alert already fired.
    down: DashMap<String, DownState>,
}

/// Per-egress downtime bookkeeping for the alert watcher.
struct DownState {
    since: Instant,
    alerted: bool,
}

/// A health transition worth reporting (see [`ProxyState::note_health`]).
pub enum AlertEvent {
    /// Unhealthy past the grace period — fired once per outage.
    Down { down_for: std::time::Duration },
    /// Healthy again after an alerted outage.
    Up { down_for: std::time::Duration },
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
    /// The config each `egresses[i]` was built from, in the same order. Kept so a
    /// reload can reuse an unchanged egress instead of tearing its tunnel down
    /// (see [`build_snapshot`]).
    egress_configs: Vec<EgressConfig>,
    rules: Vec<CompiledRule>,
}

impl Snapshot {
    fn route(
        &self,
        name: &str,
        client_ip: &str,
        client_mac: Option<&str>,
    ) -> Option<&CompiledRule> {
        self.rules
            .iter()
            .find(|r| r.matches(name) && r.matches_client(client_ip, client_mac))
    }
}

impl ProxyState {
    pub fn from_config(cfg: &ProxyConfig, upstream: Arc<ZoneRouter>) -> Arc<Self> {
        let snapshot = build_snapshot(cfg, cfg.enabled, &upstream, None);
        Arc::new(Self {
            registry: ArcSwap::from_pointee(snapshot),
            breakers: DashMap::new(),
            listeners: ArcSwap::from_pointee(ListenerCfg::from(cfg)),
            listener_reload: Arc::new(Notify::new()),
            upstream,
            stats: ProxyStats::default(),
            down: DashMap::new(),
        })
    }

    /// Hot-rebuild everything from a new config: the routing snapshot
    /// (rules/egresses/advertise/enabled) swaps atomically, and if any
    /// listener-affecting field changed (enabled / ports / connection cap) the
    /// supervisor is signalled to rebind the listeners — no process restart.
    pub fn reload(&self, cfg: &ProxyConfig) {
        // Reuse egresses whose config is unchanged so a rule-only edit (or any
        // change to an unrelated egress) doesn't tear down live tunnels.
        let prev = self.registry.load();
        self.registry.store(Arc::new(build_snapshot(
            cfg,
            cfg.enabled,
            &self.upstream,
            Some(&prev),
        )));
        let next = ListenerCfg::from(cfg);
        let changed = next.differs(&self.listeners.load());
        self.listeners.store(Arc::new(next));
        if changed {
            self.listener_reload.notify_one();
        }
        self.stats.prune(cfg);
    }

    /// Live traffic counters (per-egress bytes/connections, rule hits).
    pub fn stats(&self) -> &ProxyStats {
        &self.stats
    }

    /// Feed one health sample for `id` into the downtime state machine and
    /// return the transition to report, if any. `now` is injected so the grace
    /// logic is unit-testable. Called only by the alert watcher (one sequential
    /// task), so per-id samples never race each other.
    fn note_health(&self, id: &str, healthy: bool, now: Instant) -> Option<AlertEvent> {
        if healthy {
            let (_, d) = self.down.remove(id)?;
            return d.alerted.then_some(AlertEvent::Up {
                down_for: now.duration_since(d.since),
            });
        }
        let mut d = self.down.entry(id.to_string()).or_insert(DownState {
            since: now,
            alerted: false,
        });
        let down_for = now.duration_since(d.since);
        if !d.alerted && down_for >= alerts::ALERT_GRACE {
            d.alerted = true;
            return Some(AlertEvent::Down { down_for });
        }
        None
    }

    /// Downtime info for the stats API: `(seconds down so far, past the alert
    /// grace)`, or `None` while healthy.
    pub fn down_info(&self, id: &str) -> Option<(u64, bool)> {
        self.down
            .get(id)
            .map(|d| (d.since.elapsed().as_secs(), d.alerted))
    }

    /// Forget all downtime state (proxy disabled — tunnels are idle on purpose).
    fn clear_health_watch(&self) {
        self.down.clear();
    }

    /// Drop downtime state for egresses removed from the config.
    fn retain_health_watch(&self, keep: impl Fn(&str) -> bool) {
        self.down.retain(|id, _| keep(id));
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
        self.registry
            .load()
            .rules
            .iter()
            .any(|r| !r.clients.is_empty())
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

    /// Diagnostic: which egress (if any) a domain would route to, ignoring client
    /// scope. Returns the egress id and whether the matching rule is client-scoped
    /// (so the caller can note "applies only to specific clients"). A read-only
    /// snapshot load — does not consider whether routing is currently enabled
    /// (the caller pairs this with [`Self::is_enabled`]).
    pub fn route_egress(&self, name: &str) -> Option<(String, bool)> {
        let snap = self.registry.load();
        let rule = snap.rules.iter().find(|r| r.matches(name))?;
        let egress_id = snap.egresses[rule.egress_idx].id().to_string();
        Some((egress_id, !rule.clients.is_empty()))
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

fn build_snapshot(
    cfg: &ProxyConfig,
    enabled: bool,
    upstream: &Arc<ZoneRouter>,
    prev: Option<&Snapshot>,
) -> Snapshot {
    let mut egresses = Vec::new();
    let mut egress_configs = Vec::new();
    let mut by_id: HashMap<String, usize> = HashMap::new();
    for e in &cfg.egresses {
        if !e.enabled {
            continue;
        }
        // Reuse the previous egress instance when its runtime config is byte-for-
        // byte the same: rebuilding would restart a WireGuard tunnel (new handshake,
        // dropped in-flight connections, lost per-egress DNS cache) for no reason.
        let reused = prev.and_then(|p| {
            p.egress_configs
                .iter()
                .position(|pc| pc.id == e.id && egress_runtime_eq(pc, e))
                .map(|i| Arc::clone(&p.egresses[i]))
        });
        let egress = match reused {
            Some(existing) => existing,
            None => match Egress::from_config(e, Arc::clone(upstream)) {
                Ok(eg) => Arc::new(eg),
                Err(err) => {
                    tracing::warn!("proxy: skipping egress '{}': {}", e.id, err);
                    continue;
                }
            },
        };
        by_id.insert(egress.id().to_string(), egresses.len());
        egresses.push(egress);
        egress_configs.push(e.clone());
    }
    let rules = rules::compile(&cfg.rules, &by_id);
    Snapshot {
        enabled,
        advertise_ipv4: cfg
            .advertise_ipv4
            .or_else(crate::setup::local_ipv4_for_internet),
        advertise_ipv6: cfg.advertise_ipv6,
        egresses,
        egress_configs,
        rules,
    }
}

/// Do two egress configs describe the same *running* backend? Compares every field
/// that affects the built egress, ignoring the cosmetic display `name` (renaming
/// must not restart a tunnel). `enabled` is handled by the caller (disabled
/// egresses are skipped entirely), and a changed `id` is treated as a new egress.
///
/// `b` is destructured exhaustively (no `..`) on purpose: adding a field to
/// `EgressConfig` then becomes a compile error here, forcing a decision about
/// whether it affects the running backend — otherwise a new runtime field would be
/// silently ignored and its edits wouldn't rebuild the tunnel.
fn egress_runtime_eq(a: &EgressConfig, b: &EgressConfig) -> bool {
    let EgressConfig {
        id: _,      // matched separately by the caller
        name: _,    // cosmetic — a rename must not restart the tunnel
        enabled: _, // caller skips disabled egresses entirely
        kind,
        address,
        port,
        username,
        password,
        config,
        seg_position,
        buffer_kb,
        tx_buffer_kb,
    } = b;
    a.kind == *kind
        && a.address == *address
        && a.port == *port
        && a.username == *username
        && a.password == *password
        && a.config == *config
        && a.seg_position == *seg_position
        && a.buffer_kb == *buffer_kb
        && a.tx_buffer_kb == *tx_buffer_kb
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
            alert_webhook: None,
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
                tx_buffer_kb: None,
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
        assert!(
            proxy
                .maybe_intercept(&q, "other.test", qtype::A, "0.0.0.0", None)
                .is_none()
        );
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

    fn cfg_with(egresses: Vec<EgressConfig>, rules: Vec<RuleConfig>) -> ProxyConfig {
        let mut cfg = ProxyConfig {
            enabled: true,
            http_port: 8080,
            https_port: 8443,
            advertise_ipv4: Some(Ipv4Addr::new(192, 168, 1, 5)),
            advertise_ipv6: None,
            max_connections: 16,
            alert_webhook: None,
            egresses,
            rules,
        };
        cfg.normalize();
        cfg
    }

    fn direct_egress(id: &str) -> EgressConfig {
        EgressConfig {
            id: id.to_string(),
            name: id.to_string(),
            enabled: true,
            kind: "direct".to_string(),
            address: None,
            port: None,
            username: None,
            password: None,
            config: None,
            seg_position: None,
            buffer_kb: None,
            tx_buffer_kb: None,
        }
    }

    fn rule(pattern: &str, egress: &str) -> RuleConfig {
        RuleConfig {
            pattern: pattern.to_string(),
            egress: egress.to_string(),
            fail_closed: true,
            clients: Vec::new(),
        }
    }

    #[test]
    fn reload_reuses_unchanged_egress_but_rebuilds_changed_one() {
        let proxy = ProxyState::from_config(
            &cfg_with(vec![direct_egress("t")], vec![rule("*.example.com", "t")]),
            upstream(),
        );
        let before = proxy.egress("t").expect("egress exists");

        // A rule-only change must keep the very same egress instance (no tunnel
        // restart): the Arc is pointer-identical across the reload.
        proxy.reload(&cfg_with(
            vec![direct_egress("t")],
            vec![rule("*.other.test", "t")],
        ));
        let after_rule_change = proxy.egress("t").expect("egress still exists");
        assert!(
            Arc::ptr_eq(&before, &after_rule_change),
            "unchanged egress should be reused across a rule-only reload"
        );

        // Changing an egress's runtime config rebuilds just that egress.
        let mut changed = direct_egress("t");
        changed.buffer_kb = Some(512);
        proxy.reload(&cfg_with(vec![changed], vec![rule("*.other.test", "t")]));
        let after_egress_change = proxy.egress("t").expect("egress still exists");
        assert!(
            !Arc::ptr_eq(&after_rule_change, &after_egress_change),
            "a changed egress config should be rebuilt, not reused"
        );
    }

    #[test]
    fn health_transitions_fire_alerts_only_past_grace() {
        let proxy = state(true);
        let t0 = Instant::now();

        // Healthy from the start: no state, no event.
        assert!(proxy.note_health("t", true, t0).is_none());
        assert!(proxy.down_info("t").is_none());

        // Goes down: tracked immediately, but no alert inside the grace window.
        assert!(proxy.note_health("t", false, t0).is_none());
        assert!(proxy.down_info("t").is_some());
        assert!(
            proxy
                .note_health("t", false, t0 + alerts::ALERT_GRACE / 2)
                .is_none()
        );

        // A short blip that recovers before the grace: silent removal.
        assert!(
            proxy
                .note_health("t", true, t0 + alerts::ALERT_GRACE / 2)
                .is_none()
        );
        assert!(proxy.down_info("t").is_none());

        // Down past the grace: exactly one Down event, then silence.
        assert!(proxy.note_health("t", false, t0).is_none());
        let ev = proxy.note_health("t", false, t0 + alerts::ALERT_GRACE);
        assert!(
            matches!(ev, Some(AlertEvent::Down { down_for }) if down_for >= alerts::ALERT_GRACE)
        );
        assert!(
            proxy
                .note_health("t", false, t0 + alerts::ALERT_GRACE * 2)
                .is_none(),
            "a down alert must fire once per outage"
        );
        let (_, alerted) = proxy.down_info("t").unwrap();
        assert!(alerted, "stats API must see the alerting flag");

        // Recovery after an alerted outage: one Up event with the total downtime.
        let ev = proxy.note_health("t", true, t0 + alerts::ALERT_GRACE * 3);
        assert!(
            matches!(ev, Some(AlertEvent::Up { down_for }) if down_for == alerts::ALERT_GRACE * 3)
        );
        assert!(proxy.down_info("t").is_none());
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
