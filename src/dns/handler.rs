use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use chrono::Utc;
use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::RData;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::sync::mpsc;

use crate::app::AppStateInner;
use crate::clients::unmap_v4;
use crate::dns::types::{DnsResponse, QueryEntry, QueryStatus};
use crate::error::Result;

static QUERY_COUNTER: AtomicU64 = AtomicU64::new(1);

/// DNS query pipeline (per query, runs in its own tokio task):
///
///  1. Parse wire bytes.
///  2. Check DNS cache → return cached bytes immediately.
///  3. If not whitelisted → check blocklist → return NXDOMAIN.
///  4. Forward to upstream pool.
///  5. CNAME inspection — walk answer section, block if any CNAME target is blocked.
///  6. Cache successful response.
///  7. Send QueryEntry to stats writer (non-blocking).
pub async fn handle_query(
    raw: Vec<u8>,
    src: SocketAddr,
    state: Arc<AppStateInner>,
    query_tx: mpsc::Sender<QueryEntry>,
) -> Result<Vec<u8>> {
    let start = Instant::now();

    let query = match Message::from_bytes(&raw) {
        Ok(m) => m,
        Err(e) => {
            tracing::debug!("malformed DNS message from {}: {}", src, e);
            return Ok(vec![]);
        }
    };

    if query.metadata.op_code != OpCode::Query {
        return Ok(build_servfail(&query));
    }

    let question = match query.queries.first() {
        Some(q) => q.clone(),
        None => return Ok(build_servfail(&query)),
    };

    let name = question.name().to_lowercase().to_utf8();
    // Strip trailing dot (FQDN form).
    let name = name.trim_end_matches('.').to_string();
    // Normalise IPv4-mapped IPv6 (::ffff:a.b.c.d) to plain IPv4 so the DB
    // stores clean addresses and PTR grouping works correctly.
    let client_ip = unmap_v4(src.ip()).to_string();
    let qtype: u16 = question.query_type().into();
    let log_ignored = is_log_ignored(&name, &state.log_ignore.read());

    tracing::debug!("query {:?} {} from {}", question.query_type(), name, src);

    // ── Step 1: DNS response cache ────────────────────────────────────────
    if let Some(cached) = state.dns_cache.get(&name, qtype) {
        if !log_ignored {
            let elapsed = start.elapsed().as_millis() as u32;
            emit(
                &state,
                &query_tx,
                make_entry(
                    &name,
                    qtype,
                    &client_ip,
                    QueryStatus::Cached,
                    elapsed,
                    None,
                    0,
                ),
            );
        }
        return Ok(patch_id(&cached.bytes, query.metadata.id));
    }

    // ── Step 2: Custom DNS records (local overrides, beat blocklist) ──────
    if let Some(custom_resp) = state.custom_records.lookup(&query, &name, qtype) {
        state.dns_cache.insert(&name, qtype, custom_resp.clone());
        if !log_ignored {
            let elapsed = start.elapsed().as_millis() as u32;
            emit(
                &state,
                &query_tx,
                make_entry(
                    &name,
                    qtype,
                    &client_ip,
                    QueryStatus::Allowed,
                    elapsed,
                    Some("custom".into()),
                    0,
                ),
            );
        }
        return Ok(patch_id(&custom_resp.bytes, query.metadata.id));
    }

    // ── Step 3: Blocklist (skipped for whitelisted domains) ───────────────
    if !state.blocklist.is_whitelisted_normalized(&name)
        && state.blocklist.is_blocked_normalized(&name)
    {
        tracing::debug!("blocked: {}", name);
        if !log_ignored {
            let elapsed = start.elapsed().as_millis() as u32;
            emit(
                &state,
                &query_tx,
                make_entry(
                    &name,
                    qtype,
                    &client_ip,
                    QueryStatus::Blocked,
                    elapsed,
                    None,
                    3,
                ),
            );
        }
        return Ok(build_nxdomain(&query));
    }

    // ── Step 4: Forward to upstream ───────────────────────────────────────
    let (response_bytes, rcode, upstream_label) =
        match state.upstream_pool.resolve_raw(raw.clone()).await {
            Ok((bytes, label)) => {
                let rc = parse_rcode(&bytes);
                (bytes, rc, Some(label))
            }
            Err(e) => {
                tracing::warn!("upstream error for {}: {}", name, e);
                (build_servfail(&query), 2u8, None)
            }
        };

    // ── Step 5: CNAME inspection ───────────────────────────────────────────
    // Walk the answer section. If any CNAME target is blocked (and the queried
    // name is not whitelisted), return NXDOMAIN without caching.
    if rcode == 0 {
        if let Some(blocked_cname) = cname_blocked_target(&response_bytes, &name, &state.blocklist)
        {
            tracing::debug!("CNAME-blocked: {} → {}", name, blocked_cname);
            if !log_ignored {
                let elapsed = start.elapsed().as_millis() as u32;
                emit(
                    &state,
                    &query_tx,
                    make_entry(
                        &name,
                        qtype,
                        &client_ip,
                        QueryStatus::Blocked,
                        elapsed,
                        Some(format!("cname:{}", blocked_cname)),
                        3,
                    ),
                );
            }
            return Ok(build_nxdomain(&query));
        }
    }

    // ── Step 6: Cache NOERROR responses ───────────────────────────────────
    if rcode == 0 && !response_bytes.is_empty() {
        let ttl = extract_min_ttl(&response_bytes).unwrap_or(state.dns_cache.min_ttl_secs() as u32);
        state.dns_cache.insert(
            &name,
            qtype,
            DnsResponse {
                bytes: bytes::Bytes::copy_from_slice(&response_bytes),
                ttl,
            },
        );
    }

    if !log_ignored {
        let elapsed = start.elapsed().as_millis() as u32;
        emit(
            &state,
            &query_tx,
            make_entry(
                &name,
                qtype,
                &client_ip,
                QueryStatus::Upstream,
                elapsed,
                upstream_label,
                rcode,
            ),
        );
    }

    Ok(response_bytes)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn emit(state: &AppStateInner, tx: &mpsc::Sender<QueryEntry>, entry: QueryEntry) {
    state.live_stats.record_query(&entry);
    // try_send: if channel is full we drop the stat rather than block DNS.
    let _ = tx.try_send(entry);
}

fn make_entry(
    domain: &str,
    query_type: u16,
    client_ip: &str,
    status: QueryStatus,
    latency_ms: u32,
    upstream: Option<String>,
    rcode: u8,
) -> QueryEntry {
    QueryEntry {
        id: QUERY_COUNTER.fetch_add(1, Ordering::Relaxed),
        timestamp: Utc::now(),
        domain: domain.to_string(),
        query_type,
        client_ip: client_ip.to_string(),
        status,
        latency_ms,
        upstream,
        rcode,
    }
}

fn build_nxdomain(query: &Message) -> Vec<u8> {
    let mut resp = Message::response(query.metadata.id, OpCode::Query);
    resp.metadata.authoritative = true;
    // RFC 1035 §4.1.1: RD must be echoed; RA indicates we support recursion.
    resp.metadata.recursion_desired = query.metadata.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.metadata.response_code = ResponseCode::NXDomain;
    resp.add_queries(query.queries.iter().cloned());
    resp.to_bytes().unwrap_or_default()
}

fn build_servfail(query: &Message) -> Vec<u8> {
    let mut resp = Message::response(query.metadata.id, OpCode::Query);
    resp.metadata.recursion_desired = query.metadata.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.metadata.response_code = ResponseCode::ServFail;
    resp.add_queries(query.queries.iter().cloned());
    resp.to_bytes().unwrap_or_default()
}

/// Walk the CNAME chain in a DNS response and return the first blocked target.
///
/// If the original queried name is whitelisted, the entire chain is trusted
/// (the user explicitly allowed that domain and its resolution path).
/// Returns `None` if the chain is clean or the response has no CNAMEs.
fn cname_blocked_target(
    response_bytes: &[u8],
    queried_name: &str,
    blocklist: &crate::blocklist::Blocklist,
) -> Option<String> {
    if blocklist.is_whitelisted_normalized(queried_name) {
        return None;
    }
    let msg = Message::from_bytes(response_bytes).ok()?;
    for record in &msg.answers {
        if let RData::CNAME(cname) = &record.data {
            let target = cname.0.to_utf8().to_lowercase();
            let target = target.trim_end_matches('.');
            if !blocklist.is_whitelisted_normalized(target)
                && blocklist.is_blocked_normalized(target)
            {
                return Some(target.to_string());
            }
        }
    }
    None
}

/// Extract RCODE from raw DNS response bytes.
fn parse_rcode(bytes: &[u8]) -> u8 {
    Message::from_bytes(bytes)
        .map(|m| u16::from(m.metadata.response_code).min(255) as u8)
        .unwrap_or(0)
}

/// Patch the DNS message ID in raw wire bytes (bytes 0-1 = ID, big-endian).
fn patch_id(bytes: &[u8], id: u16) -> Vec<u8> {
    let mut out = bytes.to_vec();
    if out.len() >= 2 {
        let [hi, lo] = id.to_be_bytes();
        out[0] = hi;
        out[1] = lo;
    }
    out
}

/// Returns true if the domain should be silently dropped from the query log.
/// Patterns: `*.local` matches any subdomain of `local`; plain entries are exact.
fn is_log_ignored(name: &str, patterns: &[String]) -> bool {
    for pattern in patterns {
        if let Some(suffix) = pattern.strip_prefix("*.") {
            if name == suffix
                || name
                    .strip_suffix(suffix)
                    .is_some_and(|prefix| prefix.ends_with('.'))
            {
                return true;
            }
        } else if name == pattern.as_str() {
            return true;
        }
    }
    false
}

/// Extract the minimum TTL from answer records in a raw DNS response.
fn extract_min_ttl(bytes: &[u8]) -> Option<u32> {
    Message::from_bytes(bytes)
        .ok()?
        .answers
        .iter()
        .map(|rr| rr.ttl)
        .min()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;
    use std::str::FromStr;

    use hickory_proto::op::{MessageType, Query};
    use hickory_proto::rr::rdata::{A, CNAME};
    use hickory_proto::rr::{Name, RData, Record, RecordType};

    use crate::blocklist::Blocklist;
    use crate::config::{BlocklistConfig, CustomRecordConfig};
    use crate::test_support;

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
                decision_cache_size: 128,
                lists: vec![],
                wildcard_block: vec![],
                whitelist: vec![],
            },
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
        let bytes = build_nxdomain(&query("blocked.test", RecordType::A));
        let msg = Message::from_bytes(&bytes).unwrap();

        assert_eq!(msg.metadata.id, 0xCAFE);
        assert_eq!(msg.metadata.response_code, ResponseCode::NXDomain);
        assert!(msg.metadata.authoritative);
        assert!(msg.metadata.recursion_desired);
        assert!(msg.metadata.recursion_available);
        assert_eq!(msg.queries.len(), 1);
        assert_eq!(msg.queries[0].name().to_utf8(), "blocked.test.");
    }

    #[test]
    fn servfail_response_echoes_query_context() {
        let bytes = build_servfail(&query("upstream.test", RecordType::AAAA));
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
        let original = build_servfail(&query("cached.test", RecordType::A));
        let patched = patch_id(&original, 0xBEEF);

        assert_eq!(Message::from_bytes(&patched).unwrap().metadata.id, 0xBEEF);
        assert_eq!(&patched[2..], &original[2..]);
    }

    #[test]
    fn parse_rcode_reads_response_code_from_wire_bytes() {
        let bytes = build_servfail(&query("broken.test", RecordType::A));

        assert_eq!(parse_rcode(&bytes), 2);
        assert_eq!(parse_rcode(b"not dns"), 0);
    }

    #[test]
    fn extract_min_ttl_uses_lowest_answer_ttl() {
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

        assert_eq!(extract_min_ttl(&resp.to_bytes().unwrap()), Some(45));
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
            ),
            None
        );
    }

    #[tokio::test]
    async fn malformed_wire_query_returns_empty_response() {
        let (state, db_path) = test_support::app_state("dns-malformed").await;
        let response = handle_query(
            vec![0xde, 0xad, 0xbe, 0xef],
            SocketAddr::from(([192, 0, 2, 10], 53_000)),
            Arc::clone(&state.inner),
            state.query_tx.clone(),
        )
        .await
        .unwrap();

        assert!(response.is_empty());

        drop(state);
        test_support::cleanup_sqlite(&db_path);
    }

    #[tokio::test]
    async fn unsupported_opcode_returns_servfail() {
        let (state, db_path) = test_support::app_state("dns-opcode").await;
        let mut request = query("status.test", RecordType::A);
        request.metadata.op_code = OpCode::Status;

        let response = handle_query(
            request.to_bytes().unwrap(),
            SocketAddr::from(([192, 0, 2, 10], 53_000)),
            Arc::clone(&state.inner),
            state.query_tx.clone(),
        )
        .await
        .unwrap();
        let msg = Message::from_bytes(&response).unwrap();

        assert_eq!(msg.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(msg.queries[0].name().to_utf8(), "status.test.");

        drop(state);
        test_support::cleanup_sqlite(&db_path);
    }

    #[tokio::test]
    async fn blocklisted_domain_returns_nxdomain_and_records_blocked_query() {
        let (state, db_path) = test_support::app_state("dns-blocked").await;
        state.inner.blocklist.add_blacklist("ads.test").unwrap();
        let mut rx = state.query_rx.lock().take().unwrap();

        let response = handle_query(
            query("ads.test", RecordType::A).to_bytes().unwrap(),
            SocketAddr::from(([192, 0, 2, 10], 53_000)),
            Arc::clone(&state.inner),
            state.query_tx.clone(),
        )
        .await
        .unwrap();
        let msg = Message::from_bytes(&response).unwrap();
        let entry = rx.try_recv().unwrap();

        assert_eq!(msg.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(entry.domain, "ads.test");
        assert_eq!(entry.status, QueryStatus::Blocked);
        assert_eq!(entry.rcode, 3);
        assert_eq!(state.inner.live_stats.blocked(), 1);

        drop(rx);
        drop(state);
        test_support::cleanup_sqlite(&db_path);
    }

    #[tokio::test]
    async fn custom_record_beats_blocklist_and_records_allowed_query() {
        let (state, db_path) = test_support::app_state("dns-custom-beats-block").await;
        state.inner.blocklist.add_blacklist("panel.test").unwrap();
        state
            .inner
            .custom_records
            .add(&CustomRecordConfig {
                domain: "panel.test".to_string(),
                record_type: "A".to_string(),
                value: "192.0.2.55".to_string(),
                ttl: 120,
            })
            .unwrap();
        let mut rx = state.query_rx.lock().take().unwrap();

        let response = handle_query(
            query("panel.test", RecordType::A).to_bytes().unwrap(),
            SocketAddr::from(([192, 0, 2, 10], 53_000)),
            Arc::clone(&state.inner),
            state.query_tx.clone(),
        )
        .await
        .unwrap();
        let msg = Message::from_bytes(&response).unwrap();
        let entry = rx.try_recv().unwrap();

        assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
        assert!(matches!(
            msg.answers[0].data,
            RData::A(A(ip)) if ip == Ipv4Addr::new(192, 0, 2, 55)
        ));
        assert_eq!(entry.status, QueryStatus::Allowed);
        assert_eq!(entry.upstream.as_deref(), Some("custom"));
        assert_eq!(state.inner.live_stats.total(), 1);
        assert_eq!(state.inner.live_stats.blocked(), 0);

        drop(rx);
        drop(state);
        test_support::cleanup_sqlite(&db_path);
    }

    #[tokio::test]
    async fn cache_hit_patches_response_id_and_records_cached_query() {
        let (state, db_path) = test_support::app_state("dns-cache-hit").await;
        let cached_bytes = a_response(0x1111, "cache.test", Ipv4Addr::new(192, 0, 2, 9), 120);
        state.inner.dns_cache.insert(
            "cache.test",
            1,
            DnsResponse {
                bytes: bytes::Bytes::from(cached_bytes.clone()),
                ttl: 120,
            },
        );
        let mut rx = state.query_rx.lock().take().unwrap();

        let response = handle_query(
            query_with_id(0x2222, "cache.test", RecordType::A)
                .to_bytes()
                .unwrap(),
            SocketAddr::from(([192, 0, 2, 10], 53_000)),
            Arc::clone(&state.inner),
            state.query_tx.clone(),
        )
        .await
        .unwrap();
        let msg = Message::from_bytes(&response).unwrap();
        let entry = rx.try_recv().unwrap();

        assert_eq!(msg.metadata.id, 0x2222);
        assert_eq!(&response[2..], &cached_bytes[2..]);
        assert_eq!(entry.status, QueryStatus::Cached);
        assert_eq!(entry.domain, "cache.test");
        assert_eq!(state.inner.live_stats.total(), 1);

        drop(rx);
        drop(state);
        test_support::cleanup_sqlite(&db_path);
    }
}
