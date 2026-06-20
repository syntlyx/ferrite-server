use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
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

/// Bump the query id counter above the highest persisted id so that ids stay
/// monotonic across restarts (ring buffer is seeded with old entries, and the
/// `after_id` API cursor relies on strictly increasing ids).
pub fn seed_query_counter(max_persisted_id: u64) {
    QUERY_COUNTER.fetch_max(max_persisted_id + 1, Ordering::Relaxed);
}

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
    let client_addr = unmap_v4(src.ip());
    let client_ip = client_addr.to_string();
    let blocking_enabled = state.blocklist.blocking_enabled();
    // Resolve the client MAC when something keys on it: blocklist client-bypass,
    // or a proxy rule scoped to specific clients. Both are cheap in-memory lookups.
    let client_mac = if (blocking_enabled && state.blocklist.has_client_bypass())
        || state.proxy.has_client_rules()
    {
        state.client_registry.get_mac(client_addr)
    } else {
        None
    };
    let filtering_enabled = blocking_enabled
        && !state
            .blocklist
            .client_bypasses_blocking_normalized(&client_ip, client_mac.as_deref());
    let qtype: u16 = question.query_type().into();
    let log_ignored = is_log_ignored(&name, &state.log_ignore.read());

    tracing::debug!("query {:?} {} from {}", question.query_type(), name, src);

    // ── Step 1: Custom DNS records (local overrides, beat blocklist) ──────
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

    // ── Step 2: Selective routing / proxy interception ────────────────────
    // For a routed domain, answer with our advertise IP so the client connects
    // to the proxy listeners. Runs BEFORE the blocklist: an explicitly routed
    // domain is never blocked (you asked for it on purpose). Synthetic + returned
    // early (NOT cached): routing rules are runtime-mutable, so a cached redirect
    // could outlive a deletion.
    if let Some(intercept) = state
        .proxy
        .maybe_intercept(&query, &name, qtype, &client_ip, client_mac.as_deref())
    {
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
                    Some(format!("proxy:{}", intercept.egress_id)),
                    0,
                ),
            );
        }
        return Ok(patch_id(&intercept.response.bytes, query.metadata.id));
    }

    // ── Step 3: Blocklist (skipped when globally disabled or client bypasses filtering) ──
    if filtering_enabled
        && !state.blocklist.is_whitelisted_normalized(&name)
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

    // ── Step 3: DNS response cache ────────────────────────────────────────
    if let Some((cached, remaining_ttl)) = state.dns_cache.get_with_remaining(&name, qtype) {
        if filtering_enabled
            && let Some(blocked_cname) =
                cname_blocked_target(&cached.bytes, &name, &state.blocklist)
        {
            tracing::debug!("CNAME-blocked from cache: {} → {}", name, blocked_cname);
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
        return Ok(patch_cached(
            &cached.bytes,
            query.metadata.id,
            remaining_ttl,
        ));
    }

    // ── Step 4: Forward to upstream ───────────────────────────────────────
    let (response_bytes, rcode, upstream_label) =
        match state.upstream_pool.resolve_raw(raw.clone()).await {
            // Only trust a response we can actually decode. Unparseable bytes
            // are turned into SERVFAIL so they're never cached (step 6 caches
            // rcode==0 only) or served as if they were a valid NOERROR answer.
            Ok((bytes, label)) => match parse_rcode(&bytes) {
                Some(rc) => (bytes, rc, Some(label)),
                None => {
                    tracing::warn!("undecodable response from upstream {} for {}", label, name);
                    (build_servfail(&query), 2u8, None)
                }
            },
            Err(e) => {
                tracing::warn!("upstream error for {}: {}", name, e);
                (build_servfail(&query), 2u8, None)
            }
        };

    // ── Step 5: CNAME inspection ───────────────────────────────────────────
    // Walk the answer section. If any CNAME target is blocked (and the queried
    // name is not whitelisted), return NXDOMAIN without caching.
    if rcode == 0
        && filtering_enabled
        && let Some(blocked_cname) = cname_blocked_target(&response_bytes, &name, &state.blocklist)
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

    // ── Step 6: Cache NOERROR responses ───────────────────────────────────
    // A TTL of 0 means "do not cache" (RFC 1035/2181) — caching it would break
    // failover/GeoDNS that relies on near-zero TTLs. NODATA (empty answer)
    // responses are cached under the RFC 2308 negative TTL from the authority
    // SOA, or skipped when no SOA is present.
    if rcode == 0 && !response_bytes.is_empty() {
        match cache_ttl(&response_bytes) {
            Some(ttl) => {
                state.dns_cache.insert(
                    &name,
                    qtype,
                    DnsResponse {
                        bytes: bytes::Bytes::copy_from_slice(&response_bytes),
                        ttl,
                    },
                );
            }
            None => tracing::debug!("not caching {} (TTL 0 or no cacheable TTL)", name),
        }
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

    // Cap client-facing TTLs to the configured max. Cache hits are already
    // bounded (patch_cached rewrites to the remaining lifetime ≤ max_ttl); this
    // covers the first, uncached lookup so `max_ttl` reliably bounds what every
    // client caches — e.g. how long a client clings to a pre-rule direct answer
    // before re-querying and getting routed.
    Ok(cap_ttls(response_bytes, state.dns_cache.max_ttl_secs() as u32))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn emit(state: &AppStateInner, tx: &mpsc::Sender<QueryEntry>, entry: QueryEntry) {
    state.live_stats.record_query(&entry);
    // try_send: if the channel is full we drop the stat rather than block DNS,
    // but count the drop and warn (rate-limited) so a stalled writer surfaces
    // instead of silently diverging the persisted log from the live counters.
    if let Err(mpsc::error::TrySendError::Full(_)) = tx.try_send(entry) {
        let dropped = state
            .live_stats
            .total_dropped
            .fetch_add(1, Ordering::Relaxed)
            + 1;
        if dropped.is_power_of_two() {
            tracing::warn!(
                "stats writer back-pressure: {} query stats dropped (channel full)",
                dropped
            );
        }
    }
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
        // Tagged by the stats writer at drain time (see stats/writer.rs).
        device: String::new(),
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

/// Extract RCODE from raw DNS response bytes, or `None` if the bytes can't be
/// decoded as a DNS message (so the caller can avoid trusting/caching garbage).
fn parse_rcode(bytes: &[u8]) -> Option<u8> {
    Message::from_bytes(bytes)
        .ok()
        .map(|m| u16::from(m.metadata.response_code).min(255) as u8)
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

/// Prepare a cached response for delivery: rewrite the transaction ID to the
/// current query's, and rewrite each answer record's TTL down to the entry's
/// remaining lifetime. Without the TTL rewrite, a response cached with TTL
/// 3600 and served 3500s later would still advertise 3600, causing downstream
/// clients to over-cache well past the authoritative expiry (RFC 2181 §5.1).
///
/// EDNS OPT records live in `Message::edns`, not in `answers`, so rewriting
/// answer TTLs never corrupts the OPT pseudo-record. If the bytes can't be
/// decoded we fall back to an ID-only patch.
fn patch_cached(bytes: &[u8], id: u16, remaining_ttl: u32) -> Vec<u8> {
    match Message::from_bytes(bytes) {
        Ok(mut msg) => {
            msg.metadata.id = id;
            // Rewrite TTLs in every record section (answers, authority SOA,
            // additionals) so downstream resolvers don't over-cache past the
            // entry's expiry — in particular the SOA negative-cache TTL for
            // NODATA responses, which lives in the authority section.
            for rr in msg
                .answers
                .iter_mut()
                .chain(msg.authorities.iter_mut())
                .chain(msg.additionals.iter_mut())
            {
                rr.ttl = remaining_ttl;
            }
            msg.to_bytes().unwrap_or_else(|_| patch_id(bytes, id))
        }
        Err(_) => patch_id(bytes, id),
    }
}

/// Cap every record TTL in a response to `max_ttl` so no client caches an answer
/// longer than the operator's ceiling. Returns the bytes unchanged when nothing
/// exceeds the cap (the common case — only reserializes when needed) or the
/// message can't be decoded. EDNS OPT lives in `Message::edns`, not the record
/// sections, so its pseudo-TTL (flags/version) is never touched.
fn cap_ttls(bytes: Vec<u8>, max_ttl: u32) -> Vec<u8> {
    let Ok(mut msg) = Message::from_bytes(&bytes) else {
        return bytes;
    };
    let mut changed = false;
    for rr in msg
        .answers
        .iter_mut()
        .chain(msg.authorities.iter_mut())
        .chain(msg.additionals.iter_mut())
    {
        if rr.ttl > max_ttl {
            rr.ttl = max_ttl;
            changed = true;
        }
    }
    if !changed {
        return bytes;
    }
    msg.to_bytes().unwrap_or(bytes)
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

/// TTL (seconds) to cache a NOERROR response under, or `None` to skip caching.
///
/// Positive answers use the minimum answer-record TTL. Empty (NODATA) answers
/// use the RFC 2308 negative-cache TTL derived from the authority-section SOA
/// (the lesser of the SOA record TTL and its MINIMUM field). A TTL of 0 — or a
/// NODATA response with no SOA to bound it — is not cached.
fn cache_ttl(bytes: &[u8]) -> Option<u32> {
    let msg = Message::from_bytes(bytes).ok()?;
    if !msg.answers.is_empty() {
        let min = msg.answers.iter().map(|rr| rr.ttl).min()?;
        return (min > 0).then_some(min);
    }
    // NODATA: the negative-cache lifetime lives in the authority-section SOA.
    let neg = msg.authorities.iter().find_map(|rr| match &rr.data {
        RData::SOA(soa) => Some(rr.ttl.min(soa.minimum)),
        _ => None,
    })?;
    (neg > 0).then_some(neg)
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
                enabled: true,
                decision_cache_size: 128,
                lists: vec![],
                wildcard_block: vec![],
                whitelist: vec![],
                client_bypass: vec![],
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

        assert_eq!(parse_rcode(&bytes), Some(2));
        assert_eq!(parse_rcode(b"not dns"), None);
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

        assert_eq!(cache_ttl(&resp.to_bytes().unwrap()), Some(45));
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

        assert_eq!(cache_ttl(&resp.to_bytes().unwrap()), None);
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
        assert_eq!(cache_ttl(&resp.to_bytes().unwrap()), Some(30));
    }

    #[test]
    fn cache_ttl_nodata_without_soa_is_not_cached() {
        let query = query("host.test", RecordType::AAAA);
        let mut resp = Message::response(query.metadata.id, OpCode::Query);
        resp.add_queries(query.queries.iter().cloned());

        assert_eq!(cache_ttl(&resp.to_bytes().unwrap()), None);
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
        let (state, db_path) = test_support::app_state("dns-emit-drop").await;
        // Keep the receiver alive (so try_send sees Full, not Closed) but never drain.
        let (tx, _rx) = mpsc::channel::<QueryEntry>(1);
        let entry = || make_entry("x.test", 1, "192.0.2.1", QueryStatus::Upstream, 0, None, 0);

        // Fill the single slot, then two further emits can't enqueue.
        tx.try_send(entry()).unwrap();
        emit(&state.inner, &tx, entry());
        emit(&state.inner, &tx, entry());

        assert_eq!(state.inner.live_stats.dropped(), 2);

        drop(state);
        test_support::cleanup_sqlite(&db_path);
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
    async fn blocklist_check_precedes_cached_response_for_filtered_clients() {
        let (state, db_path) = test_support::app_state("dns-blocked-cache").await;
        state.inner.blocklist.add_blacklist("ads.test").unwrap();
        state.inner.dns_cache.insert(
            "ads.test",
            1,
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
        assert_eq!(entry.status, QueryStatus::Blocked);

        drop(rx);
        drop(state);
        test_support::cleanup_sqlite(&db_path);
    }

    #[tokio::test]
    async fn client_bypass_allows_cached_blacklisted_domain() {
        let (state, db_path) = test_support::app_state("dns-client-bypass").await;
        state.inner.blocklist.add_blacklist("ads.test").unwrap();
        state
            .inner
            .blocklist
            .set_client_bypass(&["192.0.2.10".to_string()]);
        state.inner.dns_cache.insert(
            "ads.test",
            1,
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
        let mut rx = state.query_rx.lock().take().unwrap();

        let response = handle_query(
            query_with_id(0x2222, "ads.test", RecordType::A)
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

        assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
        assert_eq!(msg.metadata.id, 0x2222);
        assert_eq!(entry.status, QueryStatus::Cached);

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
        // The answer is preserved, but its TTL is rewritten down to the entry's
        // remaining lifetime (<= the original 120s it was cached with).
        assert!(matches!(
            msg.answers[0].data,
            RData::A(A(ip)) if ip == Ipv4Addr::new(192, 0, 2, 9)
        ));
        assert!(msg.answers[0].ttl <= 120);
        assert_eq!(entry.status, QueryStatus::Cached);
        assert_eq!(entry.domain, "cache.test");
        assert_eq!(state.inner.live_stats.total(), 1);

        drop(rx);
        drop(state);
        test_support::cleanup_sqlite(&db_path);
    }
}
