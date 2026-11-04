use super::*;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::AtomicU32;

use hickory_proto::op::{MessageType, Query};
use hickory_proto::rr::rdata::{A, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use parking_lot::RwLock;
use tokio::sync::Semaphore;

use crate::cache::DnsCache;
use crate::ctx::DnsCtx;
use crate::custom::CustomRecords;
use crate::intercept::{DnsInterceptor, Intercept};
use crate::query::LazyQuery;
use crate::types::DnsResponse;
use ferrite_blocklist::Blocklist;
use ferrite_clients::ClientRegistry;
use ferrite_core::config::{BlocklistConfig, CustomRecordConfig, DnsConfig};
use ferrite_core::recording::{RecordScope, RecordSwitches};
use ferrite_stats::live::LiveStats;
use ferrite_storage::SqliteStorage;
use ferrite_upstream::{UpstreamPool, ZoneRouter, no_proxy};

/// A stand-in for the proxy's routing hook, so the handler's step-2 behaviour
/// (answer with the advertise IP, log `Routed`/`proxy:<egress>`) is testable
/// here without depending on the proxy crate. The proxy's real rule-matching
/// and answer synthesis are covered by the proxy crate's own tests.
#[derive(Default)]
struct StubInterceptor {
    /// domain → (synthetic response bytes, egress id).
    routes: RwLock<std::collections::HashMap<String, (Vec<u8>, String)>>,
}

impl StubInterceptor {
    fn route(&self, domain: &str, response: Vec<u8>, egress_id: &str) {
        self.routes
            .write()
            .insert(domain.to_string(), (response, egress_id.to_string()));
    }
}

impl DnsInterceptor for StubInterceptor {
    fn has_client_rules(&self) -> bool {
        false
    }

    fn maybe_intercept(
        &self,
        _query: &LazyQuery,
        name: &str,
        _qtype: u16,
        _client_ip: &str,
        _client_mac: Option<&str>,
        _device: Option<&str>,
        away: bool,
    ) -> Option<Intercept> {
        // Away from home routing is off here: those go direct.
        if away {
            return None;
        }
        let routes = self.routes.read();
        let (bytes, egress_id) = routes.get(name)?;
        Some(Intercept {
            response: DnsResponse {
                bytes: bytes::Bytes::from(bytes.clone()),
                ttl: 60,
            },
            egress_id: egress_id.clone(),
        })
    }
}

/// Assembles a [`DnsCtx`] from real parts (no `AppState`), plus handles to the
/// pieces tests assert on. Replaces the former `test_support::app_state`.
struct Harness {
    live_stats: Arc<LiveStats>,
    blocklist: Arc<Blocklist>,
    dns_cache: Arc<DnsCache>,
    custom_records: Arc<CustomRecords>,
    interceptor: Arc<StubInterceptor>,
    client_registry: Arc<ClientRegistry>,
    upstream: Arc<ZoneRouter>,
    /// The client-facing TTL ceiling this harness hands to the pipeline.
    client_ttl: u32,
    query_tx: mpsc::Sender<QueryEntry>,
    rx: mpsc::Receiver<QueryEntry>,
    db_path: PathBuf,
}

impl Harness {
    async fn new(name: &str) -> Self {
        let db_path = temp_path(name, "db");
        let storage = SqliteStorage::open(&db_path).await.unwrap();
        let upstream = ZoneRouter::new(
            &[],
            UpstreamPool::from_config(
                &[ferrite_core::config::UpstreamConfig::Plain {
                    address: "127.0.0.1".to_string(),
                    port: 53,
                    egress: None,
                }],
                no_proxy(),
            )
            .unwrap(),
        )
        .unwrap();
        let client_registry = ClientRegistry::new(
            Arc::clone(&upstream),
            Arc::clone(&storage) as _,
            RecordSwitches::new(RecordScope::ALL),
            &[],
        )
        .await;
        let (query_tx, rx) = mpsc::channel(8_192);
        Self {
            // Deliberately not the production default, so a test asserting a
            // capped TTL can't pass by coincidence.
            client_ttl: 45,
            live_stats: LiveStats::new(),
            blocklist: Arc::new(blocklist()),
            dns_cache: Arc::new(DnsCache::new(1024, 0, 0, 86_400)),
            custom_records: CustomRecords::new(),
            interceptor: Arc::new(StubInterceptor::default()),
            client_registry,
            upstream,
            query_tx,
            rx,
            db_path,
        }
    }

    fn ctx(&self) -> DnsCtx {
        DnsCtx {
            dns_config: DnsConfig::default(),
            switches: crate::switches::DnsSwitches::new(&DnsConfig::default()),
            dns_cache: Arc::clone(&self.dns_cache),
            blocklist: Arc::clone(&self.blocklist),
            custom_records: Arc::clone(&self.custom_records),
            client_registry: Arc::clone(&self.client_registry),
            upstream_pool: Arc::clone(&self.upstream),
            interceptor: Arc::clone(&self.interceptor) as Arc<dyn DnsInterceptor>,
            live_stats: Arc::clone(&self.live_stats),
            log_ignore: Arc::new(RwLock::new(Vec::new())),
            client_ttl: Arc::new(AtomicU32::new(self.client_ttl)),
            record_switches: RecordSwitches::new(RecordScope::ALL),
            query_semaphore: Arc::new(Semaphore::new(256)),
            client_gate: Arc::new(crate::gate::ClientGate::new(&DnsConfig::default())),
            query_tx: self.query_tx.clone(),
        }
    }
}

fn temp_path(name: &str, extension: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut path =
        std::env::temp_dir().join(format!("ferrite-{name}-{}-{nanos}", std::process::id()));
    path.set_extension(extension);
    path
}

fn cleanup_sqlite(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(path.with_extension("db-shm"));
    let _ = std::fs::remove_file(path.with_extension("db-wal"));
}

#[test]
fn sanitize_query_strips_ecs_and_sets_do() {
    use hickory_proto::op::Edns;
    use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};

    // A query carrying EDNS Client Subnet and no DO bit.
    let mut q = Message::new(0x1234, MessageType::Query, OpCode::Query);
    q.add_query(Query::query(
        Name::from_str("example.com.").unwrap(),
        RecordType::A,
    ));
    let mut edns = Edns::new();
    edns.options_mut()
        .insert(EdnsOption::Subnet(ClientSubnet::new(
            "1.2.3.0".parse().unwrap(),
            24,
            0,
        )));
    q.set_edns(edns);
    let raw = q.to_bytes().unwrap();

    // Strip ECS + set DO.
    let out = sanitize_query(&raw, true, true);
    let parsed = Message::from_bytes(&out).unwrap();
    let edns = parsed.edns.as_ref().expect("edns present");
    assert!(
        edns.options().get(EdnsCode::Subnet).is_none(),
        "ECS must be stripped"
    );
    assert!(edns.flags().dnssec_ok, "DO bit must be set");
    assert_eq!(
        edns.max_payload(),
        1232,
        "upstream UDP payload must be normalized to 1232 even if the client advertised otherwise"
    );

    // want_do = false must CLEAR a DO bit the client set, so the upstream
    // returns no signatures and the response matches its non-DO cache key.
    let mut q_do = Message::new(0x1234, MessageType::Query, OpCode::Query);
    q_do.add_query(Query::query(
        Name::from_str("example.com.").unwrap(),
        RecordType::A,
    ));
    let mut edns_do = Edns::new();
    edns_do.set_dnssec_ok(true);
    q_do.set_edns(edns_do);
    let raw_do = q_do.to_bytes().unwrap();
    let stripped = sanitize_query(&raw_do, false, false);
    let parsed = Message::from_bytes(&stripped).unwrap();
    assert!(
        !parsed.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok),
        "DO bit must be cleared when DNSSEC is not wanted"
    );

    // DNSSEC on a query with no EDNS adds an OPT with DO set.
    let mut bare = Message::new(1, MessageType::Query, OpCode::Query);
    bare.add_query(Query::query(
        Name::from_str("test.").unwrap(),
        RecordType::A,
    ));
    let raw_bare = bare.to_bytes().unwrap();
    let out_bare = sanitize_query(&raw_bare, true, true);
    let parsed_bare = Message::from_bytes(&out_bare).unwrap();
    assert!(parsed_bare.edns.as_ref().unwrap().flags().dnssec_ok);
}

fn temp_fst_path(name: &str) -> PathBuf {
    let unique = format!(
        "{}-{}-{}",
        name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    std::env::temp_dir().join(unique).join("blocklist.fst")
}

fn name(value: &str) -> Name {
    Name::from_str(&format!("{}.", value.trim_end_matches('.'))).unwrap()
}

fn query(value: &str, record_type: RecordType) -> Message {
    query_with_id(0xCAFE, value, record_type)
}

/// The wire form of a query, as the pipeline receives it.
fn raw_query(value: &str, record_type: RecordType) -> Vec<u8> {
    query(value, record_type).to_bytes().unwrap()
}

fn query_with_id(id: u16, value: &str, record_type: RecordType) -> Message {
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(name(value), record_type));
    msg
}

fn a_response(id: u16, query_name: &str, ip: Ipv4Addr, ttl: u32) -> Vec<u8> {
    let query = query_with_id(id, query_name, RecordType::A);
    let mut resp = Message::response(query.metadata.id, OpCode::Query);
    resp.metadata.response_code = ResponseCode::NoError;
    resp.metadata.recursion_desired = true;
    resp.metadata.recursion_available = true;
    resp.add_queries(query.queries.iter().cloned());
    resp.add_answer(Record::from_rdata(name(query_name), ttl, RData::A(A(ip))));
    resp.to_bytes().unwrap()
}

fn blocklist() -> Blocklist {
    Blocklist::new(
        BlocklistConfig {
            enabled: true,
            decision_cache_size: 128,
            lists: vec![],
            domains: vec![],
            wildcard_block: vec![],
            services: vec![],
            safe_search: false,
            youtube_restricted: Default::default(),
            block_response: Default::default(),
            block_ipv4: None,
            block_ipv6: None,
            whitelist: vec![],
            client_bypass: vec![],
            profiles: vec![],
        },
        ferrite_core::config::AllowlistConfig::default(),
        temp_fst_path("ferrite-dns-handler"),
    )
}

fn cname_response(query_name: &str, target: &str) -> Vec<u8> {
    let query = query(query_name, RecordType::A);
    let mut resp = Message::response(query.metadata.id, OpCode::Query);
    resp.metadata.response_code = ResponseCode::NoError;
    resp.add_queries(query.queries.iter().cloned());
    resp.add_answer(Record::from_rdata(
        name(query_name),
        60,
        RData::CNAME(CNAME(name(target))),
    ));
    resp.to_bytes().unwrap()
}

#[test]
fn log_ignore_wildcard_matches_suffix_without_allocating_separator() {
    let patterns = vec!["*.local".to_string()];

    assert!(is_log_ignored("printer.local", &patterns));
    assert!(is_log_ignored("local", &patterns));
    assert!(!is_log_ignored("notlocal", &patterns));
}

#[test]
fn nxdomain_response_echoes_query_context() {
    let raw = raw_query("blocked.test", RecordType::A);
    let query = LazyQuery::new(&raw);
    // The hand-written answer and the encoded one are the same answer down
    // to the byte: the encoder is the reference, and this is what pins the
    // wire form to it.
    let wire_built = negative_on_wire(&raw, 60, ResponseCode::NXDomain).unwrap();
    let encoded = negative_encoded(&query, 60, ResponseCode::NXDomain);
    assert_eq!(wire_built, encoded);
    for bytes in [wire_built, encoded] {
        let msg = Message::from_bytes(&bytes).unwrap();

        assert_eq!(msg.metadata.id, 0xCAFE);
        assert_eq!(msg.metadata.response_code, ResponseCode::NXDomain);
        assert!(msg.metadata.authoritative);
        assert!(msg.metadata.recursion_desired);
        assert!(msg.metadata.recursion_available);
        assert_eq!(msg.queries.len(), 1);
        assert_eq!(msg.queries[0].name().to_utf8(), "blocked.test.");
        assert_eq!(msg.queries[0].query_type(), RecordType::A);
        assert!(msg.answers.is_empty());

        // The SOA is what bounds the client's negative caching.
        assert_eq!(msg.authorities.len(), 1);
        let soa_rr = &msg.authorities[0];
        assert_eq!(soa_rr.name.to_utf8(), "blocked.test.");
        assert_eq!(soa_rr.ttl, 60);
        let RData::SOA(soa) = &soa_rr.data else {
            panic!("authority is not an SOA");
        };
        assert_eq!(soa.mname.to_utf8(), "ferrite.invalid.");
        assert_eq!(soa.rname.to_utf8(), "ferrite.invalid.");
        assert_eq!(soa.minimum, 60);
        assert_eq!(soa.serial, 1);
        assert_eq!(soa.refresh, 60);
        assert_eq!(soa.retry, 60);
        assert_eq!(soa.expire, 60);
    }
}

#[test]
fn nxdomain_echoes_a_cleared_recursion_desired_bit() {
    let mut q = query("blocked.test", RecordType::A);
    q.metadata.recursion_desired = false;
    let raw = q.to_bytes().unwrap();
    let msg = Message::from_bytes(&build_nxdomain(&LazyQuery::new(&raw), 60)).unwrap();
    assert!(!msg.metadata.recursion_desired);
    assert!(msg.metadata.recursion_available);
}

#[test]
fn servfail_response_echoes_query_context() {
    let raw = raw_query("upstream.test", RecordType::AAAA);
    let bytes = build_servfail(&LazyQuery::new(&raw));
    // Same pinning as the NXDOMAIN form: hand-written == encoded.
    assert_eq!(
        bytes,
        error_encoded(&LazyQuery::new(&raw), ResponseCode::ServFail)
    );
    let msg = Message::from_bytes(&bytes).unwrap();

    assert_eq!(msg.metadata.id, 0xCAFE);
    assert_eq!(msg.metadata.response_code, ResponseCode::ServFail);
    assert!(msg.metadata.recursion_desired);
    assert!(msg.metadata.recursion_available);
    assert_eq!(msg.queries.len(), 1);
    assert_eq!(msg.queries[0].query_type(), RecordType::AAAA);
}

#[test]
fn patch_id_rewrites_wire_header_only() {
    let raw = raw_query("cached.test", RecordType::A);
    let original = build_servfail(&LazyQuery::new(&raw));
    let patched = patch_id(&original, 0xBEEF);

    assert_eq!(Message::from_bytes(&patched).unwrap().metadata.id, 0xBEEF);
    assert_eq!(&patched[2..], &original[2..]);
}

#[test]
fn rcode_reads_response_code_from_wire_bytes() {
    let raw = raw_query("broken.test", RecordType::A);
    let bytes = build_servfail(&LazyQuery::new(&raw));

    assert_eq!(wire::rcode(&bytes), Some(2));
    assert_eq!(wire::rcode(b"not dns"), None);
}

#[test]
fn cache_ttl_uses_lowest_answer_ttl() {
    let query = query("ttl.test", RecordType::A);
    let mut resp = Message::response(query.metadata.id, OpCode::Query);
    resp.add_queries(query.queries.iter().cloned());
    resp.add_answer(Record::from_rdata(
        name("ttl.test"),
        300,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
    ));
    resp.add_answer(Record::from_rdata(
        name("ttl.test"),
        45,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 2))),
    ));

    assert_eq!(wire::cache_ttl(&resp.to_bytes().unwrap()), Some(45));
}

#[test]
fn cache_ttl_skips_zero_answer_ttl() {
    let query = query("nocache.test", RecordType::A);
    let mut resp = Message::response(query.metadata.id, OpCode::Query);
    resp.add_queries(query.queries.iter().cloned());
    resp.add_answer(Record::from_rdata(
        name("nocache.test"),
        0,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
    ));

    assert_eq!(wire::cache_ttl(&resp.to_bytes().unwrap()), None);
}

#[test]
fn cache_ttl_nodata_uses_soa_negative_ttl() {
    use hickory_proto::rr::rdata::SOA;

    let query = query("host.test", RecordType::AAAA);
    let mut resp = Message::response(query.metadata.id, OpCode::Query);
    resp.add_queries(query.queries.iter().cloned());
    // NODATA: no answers, SOA in the authority section bounds caching.
    let soa = SOA::new(
        name("ns.test"),
        name("hostmaster.test"),
        1,
        3600,
        600,
        86400,
        30, // MINIMUM — the negative-cache TTL
    );
    let soa_rr = Record::from_rdata(name("test"), 120, RData::SOA(soa));
    resp.authorities.push(soa_rr);

    // min(record TTL 120, SOA MINIMUM 30) = 30.
    assert_eq!(wire::cache_ttl(&resp.to_bytes().unwrap()), Some(30));
}

#[test]
fn cache_ttl_nodata_without_soa_is_not_cached() {
    let query = query("host.test", RecordType::AAAA);
    let mut resp = Message::response(query.metadata.id, OpCode::Query);
    resp.add_queries(query.queries.iter().cloned());

    assert_eq!(wire::cache_ttl(&resp.to_bytes().unwrap()), None);
}

#[test]
fn patch_cached_rewrites_authority_section_ttl() {
    use hickory_proto::rr::rdata::SOA;

    // NODATA response: the negative-cache lifetime is the authority SOA TTL.
    let query = query("host.test", RecordType::AAAA);
    let mut resp = Message::response(query.metadata.id, OpCode::Query);
    resp.add_queries(query.queries.iter().cloned());
    let soa = SOA::new(name("ns.test"), name("hm.test"), 1, 3600, 600, 86400, 300);
    resp.authorities
        .push(Record::from_rdata(name("test"), 3600, RData::SOA(soa)));
    let bytes = resp.to_bytes().unwrap();

    let patched = patch_cached(&bytes, 0x4242, 42);
    let msg = Message::from_bytes(&patched).unwrap();

    assert_eq!(msg.metadata.id, 0x4242);
    // The authority SOA TTL is clamped to the entry's remaining lifetime,
    // not left at its original 3600 (which would over-cache downstream).
    assert_eq!(msg.authorities[0].ttl, 42);
}

#[test]
fn cap_ttls_caps_above_ceiling_and_leaves_below_untouched() {
    let query = query("host.test", RecordType::A);
    let mut resp = Message::response(query.metadata.id, OpCode::Query);
    resp.add_queries(query.queries.iter().cloned());
    resp.add_answer(Record::from_rdata(
        name("host.test"),
        3600,
        RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
    ));
    let bytes = resp.to_bytes().unwrap();

    // Above the cap → rewritten down to the ceiling.
    let capped = cap_ttls(bytes.clone(), 60);
    assert_eq!(Message::from_bytes(&capped).unwrap().answers[0].ttl, 60);

    // Already below the cap → returned byte-for-byte (no reserialization).
    assert_eq!(cap_ttls(bytes.clone(), 7200), bytes);
}

#[tokio::test]
async fn emit_counts_dropped_stats_when_channel_full() {
    let h = Harness::new("dns-emit-drop").await;
    // Keep the receiver alive (so try_send sees Full, not Closed) but never drain.
    let (tx, _rx) = mpsc::channel::<QueryEntry>(1);
    let entry = |status| make_entry("x.test".into(), 1, "192.0.2.1".into(), status, 0, None, 0);

    // Fill the single slot, then two further emits can't enqueue.
    tx.try_send(entry(QueryStatus::Upstream)).unwrap();
    let mut ctx = h.ctx();
    ctx.query_tx = tx.clone();
    emit(&ctx, None, QueryStatus::Upstream, entry);
    emit(&ctx, None, QueryStatus::Upstream, entry);

    assert_eq!(h.live_stats.dropped(), 2);

    cleanup_sqlite(&h.db_path);
}

#[tokio::test]
async fn recording_switched_off_counts_the_query_but_sends_nothing() {
    let h = Harness::new("dns-emit-privacy").await;
    let (tx, mut rx) = mpsc::channel::<QueryEntry>(4);
    let entry = |status| make_entry("x.test".into(), 1, "192.0.2.1".into(), status, 0, None, 0);

    let mut ctx = h.ctx();
    ctx.query_tx = tx;
    ctx.record_switches = RecordSwitches::new(RecordScope::NONE);
    emit(&ctx, None, QueryStatus::Blocked, entry);

    // The anonymous counters still move — the dashboard keeps working —
    // but nothing carrying a domain or a client reaches the pipeline.
    assert_eq!(h.live_stats.total(), 1);
    assert_eq!(h.live_stats.blocked(), 1);
    assert_eq!(h.live_stats.dropped(), 0);
    assert!(rx.try_recv().is_err());

    // Switched back on, the very next query flows again — no restart.
    ctx.record_switches.set_stats(true);
    emit(&ctx, None, QueryStatus::Blocked, entry);
    assert_eq!(rx.try_recv().unwrap().domain, "x.test");

    cleanup_sqlite(&h.db_path);
}

#[test]
fn cname_blocked_target_reports_blocked_cname_target() {
    let blocklist = blocklist();
    blocklist.add_blacklist("blocked.test").unwrap();

    assert_eq!(
        cname_blocked_target(
            &cname_response("cdn.example.test", "blocked.test"),
            "cdn.example.test",
            &blocklist,
            None,
        ),
        Some("blocked.test".to_string())
    );
}

#[test]
fn whitelisted_query_allows_blocked_cname_chain() {
    let blocklist = blocklist();
    blocklist.add_blacklist("blocked.test").unwrap();
    blocklist.add_whitelist("cdn.example.test").unwrap();

    assert_eq!(
        cname_blocked_target(
            &cname_response("cdn.example.test", "blocked.test"),
            "cdn.example.test",
            &blocklist,
            None,
        ),
        None
    );
}

#[tokio::test]
async fn malformed_wire_query_returns_empty_response() {
    let h = Harness::new("dns-malformed").await;
    let response = handle_query(
        vec![0xde, 0xad, 0xbe, 0xef],
        SocketAddr::from(([192, 0, 2, 10], 53_000)),
        Arc::new(h.ctx()),
    )
    .await
    .unwrap();

    assert!(response.is_empty());

    cleanup_sqlite(&h.db_path);
}

#[tokio::test]
async fn unsupported_opcode_returns_servfail() {
    let h = Harness::new("dns-opcode").await;
    let mut request = query("status.test", RecordType::A);
    request.metadata.op_code = OpCode::Status;

    let response = handle_query(
        request.to_bytes().unwrap(),
        SocketAddr::from(([192, 0, 2, 10], 53_000)),
        Arc::new(h.ctx()),
    )
    .await
    .unwrap();
    let msg = Message::from_bytes(&response).unwrap();

    assert_eq!(msg.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(msg.queries[0].name().to_utf8(), "status.test.");

    cleanup_sqlite(&h.db_path);
}

#[tokio::test]
async fn blocklisted_domain_returns_nxdomain_and_records_blocked_query() {
    let mut h = Harness::new("dns-blocked").await;
    h.blocklist.add_blacklist("ads.test").unwrap();

    let response = handle_query(
        query("ads.test", RecordType::A).to_bytes().unwrap(),
        SocketAddr::from(([192, 0, 2, 10], 53_000)),
        Arc::new(h.ctx()),
    )
    .await
    .unwrap();
    let msg = Message::from_bytes(&response).unwrap();
    let entry = h.rx.try_recv().unwrap();

    assert_eq!(msg.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(entry.domain, "ads.test");
    assert_eq!(entry.status, QueryStatus::Blocked);
    assert_eq!(entry.rcode, 3);
    assert_eq!(h.live_stats.blocked(), 1);

    cleanup_sqlite(&h.db_path);
}

#[tokio::test]
async fn routed_domain_is_logged_with_routed_status_and_egress() {
    let mut h = Harness::new("dns-routed").await;
    // The interceptor stands in for the proxy: it routes routed.test to an
    // answer pointing at the advertise IP, tagged with egress "t".
    h.interceptor.route(
        "routed.test",
        a_response(0, "routed.test", Ipv4Addr::new(192, 0, 2, 77), 60),
        "t",
    );

    let response = handle_query(
        query("routed.test", RecordType::A).to_bytes().unwrap(),
        SocketAddr::from(([192, 168, 1, 10], 53_000)),
        Arc::new(h.ctx()),
    )
    .await
    .unwrap();
    let msg = Message::from_bytes(&response).unwrap();
    let entry = h.rx.try_recv().unwrap();

    // The synthetic answer points at the advertise IP…
    assert!(matches!(
        msg.answers[0].data,
        RData::A(A(ip)) if ip == Ipv4Addr::new(192, 0, 2, 77)
    ));
    // …and the log entry carries the routed status + which egress will serve it.
    assert_eq!(entry.status, QueryStatus::Routed);
    assert_eq!(entry.upstream.as_deref(), Some("proxy:t"));

    cleanup_sqlite(&h.db_path);
}

/// A device that names itself is remembered at its address, so Tunnels'
/// listener can tell whose connection it is — away from home too, where that
/// is what lets the connection in.
#[tokio::test]
async fn a_named_device_is_known_at_its_home_address() {
    let mut h = Harness::new("dns-device-at").await;
    h.custom_records
        .add(&ferrite_core::config::CustomRecordConfig {
            domain: "home.test".into(),
            record_type: "A".into(),
            value: "10.0.0.7".into(),
            ttl: 60,
        })
        .unwrap();
    let home = SocketAddr::from(([192, 168, 1, 40], 40_000));
    let away = SocketAddr::from(([198, 51, 100, 20], 40_000));
    for src in [home, away] {
        handle_query_as(
            query("home.test", RecordType::A).to_bytes().unwrap(),
            src,
            Some("pixel"),
            Arc::new(h.ctx()),
        )
        .await
        .unwrap();
        let _ = h.rx.try_recv();
    }
    assert_eq!(
        h.client_registry.device_at(home.ip()).as_deref(),
        Some("id:pixel")
    );
    assert_eq!(
        h.client_registry.device_at(away.ip()).as_deref(),
        Some("id:pixel")
    );

    // Another device from the same address takes it over.
    handle_query_as(
        query("home.test", RecordType::A).to_bytes().unwrap(),
        home,
        Some("tv"),
        Arc::new(h.ctx()),
    )
    .await
    .unwrap();
    assert_eq!(
        h.client_registry.device_at(home.ip()).as_deref(),
        Some("id:tv")
    );

    cleanup_sqlite(&h.db_path);
}

/// A device away from home asked over encrypted DNS: it can't reach the
/// proxy at a home address, so a routed name resolves as any other.
#[tokio::test]
async fn a_device_away_from_home_is_not_routed() {
    let mut h = Harness::new("dns-routed-away").await;
    h.interceptor.route(
        "routed.test",
        a_response(0, "routed.test", Ipv4Addr::new(192, 168, 1, 2), 60),
        "t",
    );
    h.custom_records
        .load_builtin(&[ferrite_core::config::CustomRecordConfig {
            domain: "routed.test".into(),
            record_type: "A".into(),
            value: "203.0.113.9".into(),
            ttl: 60,
        }]);

    let response = handle_query_as(
        query("routed.test", RecordType::A).to_bytes().unwrap(),
        SocketAddr::from(([198, 51, 100, 20], 40_000)),
        Some("pixel"),
        Arc::new(h.ctx()),
    )
    .await
    .unwrap();
    let msg = Message::from_bytes(&response).unwrap();
    assert!(matches!(
        msg.answers[0].data,
        RData::A(A(ip)) if ip == Ipv4Addr::new(203, 0, 113, 9)
    ));
    let entry = h.rx.try_recv().unwrap();
    assert_ne!(entry.status, QueryStatus::Routed);

    cleanup_sqlite(&h.db_path);
}

/// The client-facing ceiling only ever lowers a TTL. An origin that asks for
/// a 5-second lifetime (CDN failover) must be passed through untouched —
/// raising it to our ceiling would defeat exactly what it asked for.
#[test]
fn client_ttl_lowers_but_never_raises() {
    let query = query("host.test", RecordType::A);
    let long = {
        let mut resp = Message::response(query.metadata.id, OpCode::Query);
        resp.add_queries(query.queries.iter().cloned());
        resp.add_answer(Record::from_rdata(
            name("host.test"),
            3600,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        ));
        resp.to_bytes().unwrap()
    };
    let short = {
        let mut resp = Message::response(query.metadata.id, OpCode::Query);
        resp.add_queries(query.queries.iter().cloned());
        resp.add_answer(Record::from_rdata(
            name("host.test"),
            5,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        ));
        resp.to_bytes().unwrap()
    };

    let capped = cap_ttls(long, 60);
    assert_eq!(Message::from_bytes(&capped).unwrap().answers[0].ttl, 60);

    let untouched = cap_ttls(short.clone(), 60);
    assert_eq!(
        Message::from_bytes(&untouched).unwrap().answers[0].ttl,
        5,
        "an upstream TTL below the ceiling must survive verbatim"
    );
    assert_eq!(untouched, short, "no reserialization when nothing changed");
}

/// A blocked name answers NXDOMAIN **with an SOA**, so the device's negative
/// cache is bounded by our ceiling instead of its own default. Without this
/// the whitelist appeared to "not work" on clients that had cached the
/// refusal.
#[tokio::test]
async fn blocked_answer_carries_an_soa_bounding_negative_caching() {
    let h = Harness::new("dns-block-soa").await;
    h.blocklist.add_blacklist("ads.test").unwrap();

    let response = handle_query(
        query("ads.test", RecordType::A).to_bytes().unwrap(),
        SocketAddr::from(([192, 0, 2, 10], 53_000)),
        Arc::new(h.ctx()),
    )
    .await
    .unwrap();
    let msg = Message::from_bytes(&response).unwrap();

    assert_eq!(msg.metadata.response_code, ResponseCode::NXDomain);
    let soa = msg
        .authorities
        .iter()
        .find_map(|rr| match &rr.data {
            RData::SOA(soa) => Some((rr.ttl, soa.minimum)),
            _ => None,
        })
        .expect("negative answer must carry an SOA");
    // The negative-cache lifetime is min(record TTL, SOA MINIMUM) — both are
    // the harness ceiling, so a device can't hold the refusal any longer.
    assert_eq!(soa, (h.client_ttl, h.client_ttl));

    cleanup_sqlite(&h.db_path);
}

/// The gate runs first: an outsider gets nothing back, a client over its
/// rate limit gets REFUSED, and neither reaches the query log.
#[tokio::test]
async fn the_client_gate_drops_outsiders_and_refuses_the_too_fast() {
    use crate::gate::ClientGate;

    let mut h = Harness::new("dns-client-gate").await;
    let mut ctx = h.ctx();
    ctx.client_gate = Arc::new(ClientGate::new(&DnsConfig {
        rate_limit: 1,
        allowed_clients: vec!["192.0.2.0/24".into()],
        ..DnsConfig::default()
    }));
    let ctx = Arc::new(ctx);
    h.blocklist.add_blacklist("ads.test").unwrap();
    let ask = || query("ads.test", RecordType::A).to_bytes().unwrap();

    let outsider = SocketAddr::from(([203, 0, 113, 9], 53_000));
    assert!(
        handle_query(ask(), outsider, Arc::clone(&ctx))
            .await
            .unwrap()
            .is_empty()
    );

    let inside = SocketAddr::from(([192, 0, 2, 10], 53_000));
    let first = handle_query(ask(), inside, Arc::clone(&ctx)).await.unwrap();
    assert_eq!(
        Message::from_bytes(&first).unwrap().metadata.response_code,
        ResponseCode::NXDomain
    );
    let second = handle_query(ask(), inside, Arc::clone(&ctx)).await.unwrap();
    assert_eq!(
        Message::from_bytes(&second).unwrap().metadata.response_code,
        ResponseCode::Refused
    );

    // Only the one answered query was logged.
    assert!(h.rx.try_recv().is_ok());
    assert!(h.rx.try_recv().is_err());
    assert_eq!(
        (ctx.client_gate.dropped(), ctx.client_gate.refused()),
        (1, 1)
    );

    cleanup_sqlite(&h.db_path);
}

/// With the optimistic cache on, an expired entry still answers — briefly,
/// logged as a stale cache hit — instead of sending the client upstream.
#[tokio::test]
async fn an_expired_entry_answers_stale_while_the_window_is_open() {
    let mut h = Harness::new("dns-serve-stale").await;
    h.dns_cache.insert(
        "stale.test",
        1,
        false,
        DnsResponse {
            bytes: bytes::Bytes::from(a_response(
                0x3333,
                "stale.test",
                Ipv4Addr::new(192, 0, 2, 7),
                0,
            )),
            ttl: 0,
        },
    );
    let client = SocketAddr::from(([192, 0, 2, 10], 53_000));
    let ctx = Arc::new(h.ctx());

    // Off: expired means upstream.
    let raw = query("stale.test", RecordType::A).to_bytes().unwrap();
    assert!(matches!(decide(&raw, client, &ctx), Decision::Upstream(_)));

    h.dns_cache.set_stale_window(3600);
    let Decision::Answer(bytes) = decide(&raw, client, &ctx) else {
        panic!("a stale entry inside the window answers");
    };
    let msg = Message::from_bytes(&bytes).unwrap();
    assert_eq!(
        msg.answers[0].data,
        RData::A(Ipv4Addr::new(192, 0, 2, 7).into())
    );
    // 30 s at most — and never past the client ceiling.
    assert_eq!(msg.answers[0].ttl, STALE_ANSWER_TTL.min(h.client_ttl));
    let entry = h.rx.try_recv().unwrap();
    assert_eq!(entry.status, QueryStatus::Cached);
    assert_eq!(entry.upstream.as_deref(), Some("stale"));

    cleanup_sqlite(&h.db_path);
}

/// Each `block_response` mode shapes the answer as documented, the address
/// forms per record type, and the query log keeps the RCODE that went out.
#[tokio::test]
async fn block_response_modes_shape_the_answer() {
    use ferrite_core::config::{BlockAnswer, BlockResponse};
    use std::net::Ipv6Addr;

    let mut h = Harness::new("dns-block-modes").await;
    h.blocklist.add_blacklist("ads.test").unwrap();
    let ask = |rt: RecordType| query("ads.test", rt).to_bytes().unwrap();
    let from = SocketAddr::from(([192, 0, 2, 10], 53_000));

    let cases: Vec<(BlockAnswer, RecordType, ResponseCode, Option<RData>, u8)> = vec![
        (
            BlockAnswer {
                response: BlockResponse::Nodata,
                ..Default::default()
            },
            RecordType::A,
            ResponseCode::NoError,
            None,
            0,
        ),
        (
            BlockAnswer {
                response: BlockResponse::NullIp,
                ..Default::default()
            },
            RecordType::A,
            ResponseCode::NoError,
            Some(RData::A(Ipv4Addr::UNSPECIFIED.into())),
            0,
        ),
        (
            BlockAnswer {
                response: BlockResponse::NullIp,
                ..Default::default()
            },
            RecordType::AAAA,
            ResponseCode::NoError,
            Some(RData::AAAA(Ipv6Addr::UNSPECIFIED.into())),
            0,
        ),
        (
            // Any other type gets no records, never an address.
            BlockAnswer {
                response: BlockResponse::NullIp,
                ..Default::default()
            },
            RecordType::HTTPS,
            ResponseCode::NoError,
            None,
            0,
        ),
        (
            BlockAnswer {
                response: BlockResponse::CustomIp,
                ipv4: Some(Ipv4Addr::new(192, 168, 1, 5)),
                ipv6: None,
            },
            RecordType::A,
            ResponseCode::NoError,
            Some(RData::A(Ipv4Addr::new(192, 168, 1, 5).into())),
            0,
        ),
        (
            // No IPv6 set: AAAA is NODATA, not ::.
            BlockAnswer {
                response: BlockResponse::CustomIp,
                ipv4: Some(Ipv4Addr::new(192, 168, 1, 5)),
                ipv6: None,
            },
            RecordType::AAAA,
            ResponseCode::NoError,
            None,
            0,
        ),
        (
            BlockAnswer {
                response: BlockResponse::Refused,
                ..Default::default()
            },
            RecordType::A,
            ResponseCode::Refused,
            None,
            5,
        ),
    ];

    for (answer, rt, rcode, rdata, logged) in cases {
        h.blocklist.set_block_answer(answer);
        let response = handle_query(ask(rt), from, Arc::new(h.ctx()))
            .await
            .unwrap();
        let msg = Message::from_bytes(&response).unwrap();
        let what = format!("{:?} for {rt:?}", answer.response);
        assert_eq!(msg.metadata.response_code, rcode, "{what}");
        assert_eq!(
            msg.answers.first().map(|rr| rr.data.clone()),
            rdata,
            "{what}"
        );
        if let Some(rr) = msg.answers.first() {
            assert_eq!(rr.ttl, h.client_ttl, "{what}");
        }
        // NODATA keeps the SOA that bounds negative caching.
        if rcode == ResponseCode::NoError && msg.answers.is_empty() {
            assert!(
                msg.authorities
                    .iter()
                    .any(|rr| matches!(rr.data, RData::SOA(_))),
                "{what}"
            );
        }
        let entry = h.rx.try_recv().unwrap();
        assert_eq!(entry.status, QueryStatus::Blocked, "{what}");
        assert_eq!(entry.rcode, logged, "{what}");
    }

    cleanup_sqlite(&h.db_path);
}

#[test]
fn address_answer_matches_the_encoded_form() {
    let raw = raw_query("ads.test", RecordType::AAAA);
    let ip: std::net::IpAddr = "fd00::5".parse().unwrap();
    assert_eq!(
        address_on_wire(&raw, ip, 60).unwrap(),
        address_encoded(&LazyQuery::new(&raw), ip, 60)
    );
    let raw = raw_query("ads.test", RecordType::A);
    let ip: std::net::IpAddr = "10.0.0.5".parse().unwrap();
    assert_eq!(
        address_on_wire(&raw, ip, 60).unwrap(),
        address_encoded(&LazyQuery::new(&raw), ip, 60)
    );
}

/// Every exit path is capped, including the two that used to bypass it: a
/// custom (local) record and a cache hit.
#[tokio::test]
async fn custom_records_and_cache_hits_respect_the_client_ceiling() {
    let h = Harness::new("dns-client-ttl-paths").await;
    h.custom_records
        .add(&CustomRecordConfig {
            domain: "local.test".into(),
            record_type: "A".into(),
            value: "10.0.0.9".into(),
            ttl: 86_400, // operator asked for a day
        })
        .unwrap();

    let custom = handle_query(
        query("local.test", RecordType::A).to_bytes().unwrap(),
        SocketAddr::from(([192, 0, 2, 10], 53_000)),
        Arc::new(h.ctx()),
    )
    .await
    .unwrap();
    assert_eq!(
        Message::from_bytes(&custom).unwrap().answers[0].ttl,
        h.client_ttl,
        "a custom record's own TTL must still be capped"
    );

    // Cache hit: stored with a long TTL, served capped.
    h.dns_cache.insert(
        "cached.test",
        1,
        false,
        DnsResponse {
            bytes: bytes::Bytes::from(a_response(
                0x2222,
                "cached.test",
                Ipv4Addr::new(192, 0, 2, 8),
                3600,
            )),
            ttl: 3600,
        },
    );
    let hit = handle_query(
        query("cached.test", RecordType::A).to_bytes().unwrap(),
        SocketAddr::from(([192, 0, 2, 10], 53_000)),
        Arc::new(h.ctx()),
    )
    .await
    .unwrap();
    assert_eq!(
        Message::from_bytes(&hit).unwrap().answers[0].ttl,
        h.client_ttl,
        "a cache hit must not advertise more than the ceiling"
    );

    cleanup_sqlite(&h.db_path);
}

#[tokio::test]
async fn blocklist_wins_over_routing_rule() {
    let mut h = Harness::new("dns-routed-blocked").await;
    // A routing rule covers the name AND it is blocklisted (the typical
    // case: a tracker subdomain under a routed domain). The block must win
    // — routing decides how traffic leaves, never whether a name resolves.
    h.interceptor.route(
        "ads.routed.test",
        a_response(0, "ads.routed.test", Ipv4Addr::new(192, 0, 2, 77), 60),
        "t",
    );
    h.blocklist.add_blacklist("ads.routed.test").unwrap();

    let response = handle_query(
        query("ads.routed.test", RecordType::A).to_bytes().unwrap(),
        SocketAddr::from(([192, 0, 2, 10], 53_000)),
        Arc::new(h.ctx()),
    )
    .await
    .unwrap();
    let msg = Message::from_bytes(&response).unwrap();
    let entry = h.rx.try_recv().unwrap();

    assert_eq!(msg.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(entry.status, QueryStatus::Blocked);

    cleanup_sqlite(&h.db_path);
}

#[tokio::test]
async fn whitelist_restores_routing_for_blocklisted_domain() {
    let mut h = Harness::new("dns-routed-whitelisted").await;
    // The escape hatch for deliberately routing a blocklisted domain: the
    // whitelist lifts the block, and the routing rule then applies.
    h.interceptor.route(
        "ads.routed.test",
        a_response(0, "ads.routed.test", Ipv4Addr::new(192, 0, 2, 77), 60),
        "t",
    );
    h.blocklist.add_blacklist("ads.routed.test").unwrap();
    h.blocklist.add_whitelist("ads.routed.test").unwrap();

    let response = handle_query(
        query("ads.routed.test", RecordType::A).to_bytes().unwrap(),
        SocketAddr::from(([192, 168, 1, 10], 53_000)),
        Arc::new(h.ctx()),
    )
    .await
    .unwrap();
    let msg = Message::from_bytes(&response).unwrap();
    let entry = h.rx.try_recv().unwrap();

    assert!(matches!(
        msg.answers[0].data,
        RData::A(A(ip)) if ip == Ipv4Addr::new(192, 0, 2, 77)
    ));
    assert_eq!(entry.status, QueryStatus::Routed);
    assert_eq!(entry.upstream.as_deref(), Some("proxy:t"));

    cleanup_sqlite(&h.db_path);
}

#[tokio::test]
async fn blocklist_check_precedes_cached_response_for_filtered_clients() {
    let mut h = Harness::new("dns-blocked-cache").await;
    h.blocklist.add_blacklist("ads.test").unwrap();
    h.dns_cache.insert(
        "ads.test",
        1,
        false,
        DnsResponse {
            bytes: bytes::Bytes::from(a_response(
                0x1111,
                "ads.test",
                Ipv4Addr::new(192, 0, 2, 9),
                120,
            )),
            ttl: 120,
        },
    );

    let response = handle_query(
        query("ads.test", RecordType::A).to_bytes().unwrap(),
        SocketAddr::from(([192, 0, 2, 10], 53_000)),
        Arc::new(h.ctx()),
    )
    .await
    .unwrap();
    let msg = Message::from_bytes(&response).unwrap();
    let entry = h.rx.try_recv().unwrap();

    assert_eq!(msg.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(entry.status, QueryStatus::Blocked);

    cleanup_sqlite(&h.db_path);
}

#[tokio::test]
async fn client_bypass_allows_cached_blacklisted_domain() {
    let mut h = Harness::new("dns-client-bypass").await;
    h.blocklist.add_blacklist("ads.test").unwrap();
    h.blocklist.set_client_bypass(&["192.0.2.10".to_string()]);
    h.dns_cache.insert(
        "ads.test",
        1,
        false,
        DnsResponse {
            bytes: bytes::Bytes::from(a_response(
                0x1111,
                "ads.test",
                Ipv4Addr::new(192, 0, 2, 9),
                120,
            )),
            ttl: 120,
        },
    );

    let response = handle_query(
        query_with_id(0x2222, "ads.test", RecordType::A)
            .to_bytes()
            .unwrap(),
        SocketAddr::from(([192, 0, 2, 10], 53_000)),
        Arc::new(h.ctx()),
    )
    .await
    .unwrap();
    let msg = Message::from_bytes(&response).unwrap();
    let entry = h.rx.try_recv().unwrap();

    assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
    assert_eq!(msg.metadata.id, 0x2222);
    assert_eq!(entry.status, QueryStatus::Cached);

    cleanup_sqlite(&h.db_path);
}

#[tokio::test]
async fn custom_record_beats_blocklist_and_records_allowed_query() {
    let mut h = Harness::new("dns-custom-beats-block").await;
    h.blocklist.add_blacklist("panel.test").unwrap();
    h.custom_records
        .add(&CustomRecordConfig {
            domain: "panel.test".to_string(),
            record_type: "A".to_string(),
            value: "192.0.2.55".to_string(),
            ttl: 120,
        })
        .unwrap();

    let response = handle_query(
        query("panel.test", RecordType::A).to_bytes().unwrap(),
        SocketAddr::from(([192, 0, 2, 10], 53_000)),
        Arc::new(h.ctx()),
    )
    .await
    .unwrap();
    let msg = Message::from_bytes(&response).unwrap();
    let entry = h.rx.try_recv().unwrap();

    assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
    assert!(matches!(
        msg.answers[0].data,
        RData::A(A(ip)) if ip == Ipv4Addr::new(192, 0, 2, 55)
    ));
    assert_eq!(entry.status, QueryStatus::Allowed);
    assert_eq!(entry.upstream.as_deref(), Some("custom"));
    assert_eq!(h.live_stats.total(), 1);
    assert_eq!(h.live_stats.blocked(), 0);

    cleanup_sqlite(&h.db_path);
}

#[tokio::test]
async fn cache_hit_patches_response_id_and_records_cached_query() {
    let mut h = Harness::new("dns-cache-hit").await;
    let cached_bytes = a_response(0x1111, "cache.test", Ipv4Addr::new(192, 0, 2, 9), 120);
    h.dns_cache.insert(
        "cache.test",
        1,
        false,
        DnsResponse {
            bytes: bytes::Bytes::from(cached_bytes.clone()),
            ttl: 120,
        },
    );

    let response = handle_query(
        query_with_id(0x2222, "cache.test", RecordType::A)
            .to_bytes()
            .unwrap(),
        SocketAddr::from(([192, 0, 2, 10], 53_000)),
        Arc::new(h.ctx()),
    )
    .await
    .unwrap();
    let msg = Message::from_bytes(&response).unwrap();
    let entry = h.rx.try_recv().unwrap();

    assert_eq!(msg.metadata.id, 0x2222);
    // The answer is preserved, but its TTL is rewritten down to the entry's
    // remaining lifetime (<= the original 120s it was cached with).
    assert!(matches!(
        msg.answers[0].data,
        RData::A(A(ip)) if ip == Ipv4Addr::new(192, 0, 2, 9)
    ));
    assert!(msg.answers[0].ttl <= 120);
    assert_eq!(entry.status, QueryStatus::Cached);
    assert_eq!(entry.domain, "cache.test");
    assert_eq!(h.live_stats.total(), 1);

    cleanup_sqlite(&h.db_path);
}

/// What one query costs end to end, with no sockets in the way — the number
/// every optimisation on this path moves, and the one that quietly comes
/// back if someone reintroduces a decode or an allocation.
///
/// Ignored by default (it is a measurement, not an assertion):
/// `cargo test --release -p ferrite-dns -- --ignored --nocapture pipeline_cost`
///
/// For reference, on an M-series laptop: ~360 ns for a cache hit and ~230 ns
/// for a block. It was 1365 / 1244 ns before the 2026-09 pass, so a result
/// in that range means something was undone.
#[tokio::test]
#[ignore]
async fn pipeline_cost() {
    use std::time::Instant;

    let h = Harness::new("dns-pipeline-cost").await;
    h.blocklist.add_blacklist("ads.test").unwrap();
    h.dns_cache.insert(
        "cached.test",
        1,
        false,
        DnsResponse {
            bytes: bytes::Bytes::from(a_response(
                0x2222,
                "cached.test",
                Ipv4Addr::new(192, 0, 2, 8),
                3600,
            )),
            ttl: 3600,
        },
    );
    let ctx = Arc::new(h.ctx());
    let src = SocketAddr::from(([192, 0, 2, 10], 53_000));
    let cached = raw_query("cached.test", RecordType::A);
    let blocked = raw_query("ads.test", RecordType::A);

    const ROUNDS: u32 = 50_000;
    for raw in [&cached, &blocked] {
        for _ in 0..2_000 {
            let _ = handle_query(raw.clone(), src, Arc::clone(&ctx)).await;
        }
    }
    for (label, raw) in [("cache hit", &cached), ("blocked", &blocked)] {
        let start = Instant::now();
        for _ in 0..ROUNDS {
            let answer = handle_query(raw.clone(), src, Arc::clone(&ctx)).await;
            std::hint::black_box(answer).unwrap();
        }
        println!(
            "pipeline {label:<10} {:>7.0} ns/query",
            start.elapsed().as_nanos() as f64 / ROUNDS as f64
        );
    }

    cleanup_sqlite(&h.db_path);
}

#[tokio::test]
async fn safe_search_answers_with_a_cname_to_the_safe_host() {
    use ferrite_blocklist::SafeSearch;
    use ferrite_core::config::YoutubeRestrict;

    let mut h = Harness::new("dns-safe-search").await;
    let client = SocketAddr::from(([192, 0, 2, 10], 53_000));

    // Off: the name is forwarded as asked.
    let decision = decide(
        &raw_query("www.google.com", RecordType::A),
        client,
        &Arc::new(h.ctx()),
    );
    assert!(matches!(decision, Decision::Upstream(ref p) if p.rewrite.is_none()));

    h.blocklist.set_safe_search(SafeSearch {
        search: true,
        youtube: YoutubeRestrict::Strict,
    });
    // On, with the safe host's answer cached: served at once as a chain.
    h.dns_cache.insert(
        "forcesafesearch.google.com",
        1,
        false,
        DnsResponse {
            bytes: bytes::Bytes::from(a_response(
                0,
                "forcesafesearch.google.com",
                Ipv4Addr::new(216, 239, 38, 120),
                300,
            )),
            ttl: 300,
        },
    );
    let response = handle_query(
        query_with_id(0x4242, "www.google.com", RecordType::A)
            .to_bytes()
            .unwrap(),
        client,
        Arc::new(h.ctx()),
    )
    .await
    .unwrap();
    let msg = Message::from_bytes(&response).unwrap();
    assert_eq!(msg.metadata.id, 0x4242);
    assert_eq!(msg.queries[0].name().to_string(), "www.google.com.");
    assert!(matches!(
        &msg.answers[0].data,
        RData::CNAME(c) if c.0.to_string() == "forcesafesearch.google.com."
    ));
    assert!(matches!(
        msg.answers[1].data,
        RData::A(A(ip)) if ip == Ipv4Addr::new(216, 239, 38, 120)
    ));
    assert!(msg.answers.iter().all(|r| r.ttl <= h.client_ttl));
    let entry = h.rx.try_recv().unwrap();
    assert_eq!(entry.status, QueryStatus::Cached);
    assert_eq!(
        entry.upstream.as_deref(),
        Some("safesearch:forcesafesearch.google.com")
    );

    // Not cached yet: the upstream leg is asked for the safe host instead.
    let decision = decide(
        &raw_query("www.youtube.com", RecordType::AAAA),
        client,
        &Arc::new(h.ctx()),
    );
    assert!(matches!(
        decision,
        Decision::Upstream(ref p) if p.rewrite == Some("restrict.youtube.com")
    ));

    // A blocked name stays blocked: the blocklist runs first.
    h.blocklist.add_blacklist("youtube.com").unwrap();
    let decision = decide(
        &raw_query("www.youtube.com", RecordType::A),
        client,
        &Arc::new(h.ctx()),
    );
    assert!(matches!(decision, Decision::Answer(_)));
    let blocked = Message::from_bytes(&match decision {
        Decision::Answer(b) => b,
        _ => unreachable!(),
    })
    .unwrap();
    assert_eq!(blocked.metadata.response_code, ResponseCode::NXDomain);

    cleanup_sqlite(&h.db_path);
}

/// The answer's RCODE, for a decision that settled in memory.
fn answered_rcode(decision: Decision) -> Option<ResponseCode> {
    match decision {
        Decision::Answer(bytes) => {
            Some(Message::from_bytes(&bytes).unwrap().metadata.response_code)
        }
        _ => None,
    }
}

/// Firefox's DoH canary is answered NXDOMAIN out of the box, and logged as
/// blocked with the canary as the reason.
#[tokio::test]
async fn firefox_canary_is_answered_nxdomain_by_default() {
    let mut h = Harness::new("dns-firefox-canary").await;
    let ctx = Arc::new(h.ctx());
    let src = SocketAddr::from(([192, 0, 2, 10], 53_000));

    let decision = decide(
        &raw_query("use-application-dns.net", RecordType::A),
        src,
        &ctx,
    );
    assert_eq!(answered_rcode(decision), Some(ResponseCode::NXDomain));

    let entry = h.rx.recv().await.unwrap();
    assert_eq!(entry.status, QueryStatus::Blocked);
    assert_eq!(entry.upstream.as_deref(), Some("canary:firefox-doh"));
    cleanup_sqlite(&h.db_path);
}

/// Private Relay's canaries go upstream until the switch is on, and the
/// switch reaches the very next query, with no restart.
#[tokio::test]
async fn private_relay_switch_applies_live() {
    let h = Harness::new("dns-private-relay").await;
    let ctx = Arc::new(h.ctx());
    let src = SocketAddr::from(([192, 0, 2, 10], 53_000));
    let ask = || decide(&raw_query("mask.icloud.com", RecordType::A), src, &ctx);

    assert!(matches!(ask(), Decision::Upstream(_)), "off by default");

    ctx.switches.apply(&DnsConfig {
        block_private_relay: true,
        ..DnsConfig::default()
    });
    assert_eq!(answered_rcode(ask()), Some(ResponseCode::NXDomain));
    cleanup_sqlite(&h.db_path);
}

/// A paused filter still answers the canary: Firefox would otherwise switch to
/// its own DoH and stay there until the next network change.
#[tokio::test]
async fn canary_is_answered_while_filtering_is_off() {
    let h = Harness::new("dns-canary-paused").await;
    h.blocklist.set_blocking_enabled(false);
    let ctx = Arc::new(h.ctx());
    let src = SocketAddr::from(([192, 0, 2, 10], 53_000));

    let decision = decide(
        &raw_query("use-application-dns.net", RecordType::AAAA),
        src,
        &ctx,
    );
    assert_eq!(answered_rcode(decision), Some(ResponseCode::NXDomain));
    cleanup_sqlite(&h.db_path);
}

#[tokio::test]
async fn a_client_id_is_its_own_device_with_its_own_profile() {
    let mut h = Harness::new("dns-client-id").await;
    let profile: ferrite_core::config::BlocklistProfileConfig = serde_json::from_value(
        serde_json::json!({"id": "kids", "name": "Kids", "clients": ["id:kid"], "block": ["games.test"]}),
    )
    .unwrap();
    h.blocklist.set_profiles(vec![profile]);
    let src = SocketAddr::from(([192, 0, 2, 10], 53_000));

    // Named as `kid`: the profile applies, and the log files it under id:kid.
    let response = handle_query_as(
        query("games.test", RecordType::A).to_bytes().unwrap(),
        src,
        Some("kid"),
        Arc::new(h.ctx()),
    )
    .await
    .unwrap();
    let msg = Message::from_bytes(&response).unwrap();
    assert_eq!(msg.metadata.response_code, ResponseCode::NXDomain);
    let entry = h.rx.try_recv().unwrap();
    assert_eq!(entry.device, "id:kid");
    assert_eq!(entry.client_ip, "192.0.2.10");

    // The same address without the ID is not in the profile.
    let ctx = Arc::new(h.ctx());
    let decision = decide(&raw_query("games.test", RecordType::A), src, &ctx);
    assert!(matches!(decision, Decision::Upstream(_)));

    cleanup_sqlite(&h.db_path);
}

/// A device set up for a client you named is that client wherever it asks
/// from: the profile given to the client's MAC applies to its encrypted
/// queries, away from home too.
#[tokio::test]
async fn a_device_carries_its_owners_profile_away_from_home() {
    let h = Harness::new("dns-owner-profile").await;
    let profile: ferrite_core::config::BlocklistProfileConfig = serde_json::from_value(
        serde_json::json!({"id": "kids", "name": "Kids", "clients": ["aa:bb:cc:dd:ee:01"], "block": ["games.test"]}),
    )
    .unwrap();
    h.blocklist.set_profiles(vec![profile]);
    let away = SocketAddr::from(([198, 51, 100, 30], 53_000));
    let ctx = Arc::new(h.ctx());
    let ask = || {
        decide_as(
            &raw_query("games.test", RecordType::A),
            away,
            Some("kid-phone-k7f3"),
            &ctx,
        )
    };
    // Nobody's yet: the MAC's profile doesn't reach it.
    assert!(matches!(ask(), Decision::Upstream(_)));

    let owners = [(
        "kid-phone-k7f3".to_string(),
        "aa:bb:cc:dd:ee:01".to_string(),
    )]
    .into_iter()
    .collect();
    h.client_registry.set_id_owners(&owners);
    assert_eq!(answered_rcode(ask()), Some(ResponseCode::NXDomain));

    cleanup_sqlite(&h.db_path);
}
