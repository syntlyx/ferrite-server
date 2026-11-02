use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use chrono::Utc;
use hickory_proto::op::{Edns, Message, OpCode, ResponseCode};
use hickory_proto::rr::rdata::opt::EdnsCode;
use hickory_proto::rr::{RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::sync::mpsc;

use crate::ctx::DnsCtx;
use crate::query::LazyQuery;
use crate::types::DnsResponse;
use ferrite_core::error::Result;
use ferrite_core::net::{ip_to_string, unmap_v4};
use ferrite_core::types::{QueryEntry, QueryStatus};
use ferrite_core::wire;

static QUERY_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Bump the query id counter above the highest persisted id so that ids stay
/// monotonic across restarts (ring buffer is seeded with old entries, and the
/// `after_id` API cursor relies on strictly increasing ids).
pub fn seed_query_counter(max_persisted_id: u64) {
    QUERY_COUNTER.fetch_max(max_persisted_id + 1, Ordering::Relaxed);
}

/// What the in-memory half of the pipeline concluded for a query.
pub enum Decision {
    /// An answer to send as it stands: a local record, a block, a routing
    /// redirect, a cache hit — or SERVFAIL for a query we won't serve.
    Answer(Vec<u8>),
    /// Nothing in memory settles this one; it has to go upstream, which means
    /// waiting. Carries everything [`decide`] worked out so the wait is the
    /// only thing left to pay for.
    Upstream(Pending),
    /// Not a query we can read. Nothing goes back — there is no question to
    /// echo and no transaction id worth trusting.
    Drop,
}

/// What a query carries from the in-memory steps into the upstream leg.
pub struct Pending {
    name: String,
    qtype: u16,
    want_dnssec: bool,
    filtering_enabled: bool,
    profile: Option<Arc<ferrite_blocklist::CompiledProfile>>,
    client_addr: std::net::IpAddr,
    client_text: Option<String>,
    log_ignored: bool,
    client_ttl: u32,
    start: Instant,
}

/// DNS query pipeline. Steps 1-4 are [`decide`], steps 5-7
/// [`resolve_upstream`], and the `Step N` markers in both name them:
///
///  1. Custom DNS records — local overrides answer first.
///  2. Blocklist → NXDOMAIN. Runs before routing on purpose: blocking decides
///     WHETHER a name resolves, routing only HOW its traffic leaves — so a
///     blocklisted subdomain of a routed domain stays blocked (whitelist it
///     to route it anyway).
///  3. Selective routing → synthetic answer with the proxy's advertise IP.
///  4. DNS cache → return cached bytes (CNAME targets re-checked).
///  5. Forward to upstream pool.
///  6. CNAME inspection — walk answer section, block if any CNAME target is blocked.
///  7. Cache successful response; send QueryEntry to stats writer (non-blocking).
///
/// The split is where the waiting starts: everything above step 5 is memory
/// and CPU, so the UDP listener runs it inline and only puts a query on a task
/// once it has to wait for the network. TCP, already on a task of its own,
/// runs both halves through this function.
pub async fn handle_query(raw: Vec<u8>, src: SocketAddr, ctx: Arc<DnsCtx>) -> Result<Vec<u8>> {
    Ok(match decide(&raw, src, &ctx) {
        Decision::Answer(bytes) => bytes,
        Decision::Upstream(pending) => resolve_upstream(&raw, pending, &ctx).await,
        Decision::Drop => Vec::new(),
    })
}

/// Steps 1-4 of the pipeline (see [`handle_query`]): everything that can be
/// settled from memory. Runs on whichever thread received the datagram.
pub fn decide(raw: &[u8], src: SocketAddr, ctx: &DnsCtx) -> Decision {
    let start = Instant::now();

    // The query is read off the wire and decoded only if a step has to build an
    // answer of ferrite's own (see `LazyQuery`) — the paths that just look the
    // name up and forward or serve bytes never decode anything.
    let query = LazyQuery::new(raw);

    if wire::opcode(raw) != Some(OPCODE_QUERY) {
        return Decision::Answer(build_servfail(&query));
    }

    let Some((name, qtype)) = question(&query) else {
        // Nothing to answer. A message the decoder rejects too is dropped, as
        // an undecodable one always was: there is no question to echo and no
        // id worth trusting. One it accepts — a query with QDCOUNT 0 — gets
        // SERVFAIL, as before.
        return match query.message() {
            Some(_) => Decision::Answer(build_servfail(&query)),
            None => {
                tracing::debug!("malformed DNS message from {}", src);
                Decision::Drop
            }
        };
    };
    // Normalise IPv4-mapped IPv6 (::ffff:a.b.c.d) to plain IPv4 so the DB
    // stores clean addresses and PTR grouping works correctly.
    let client_addr = unmap_v4(src.ip());
    let blocking_enabled = ctx.blocklist.blocking_enabled();
    // Does anything below key on *which* client this is — a blocklist
    // client-bypass, a per-device blocking profile, or a proxy rule scoped to
    // specific clients? When nothing does, the three checks that take the
    // client all short-circuit on the same flags, so neither the MAC lookup nor
    // the address-as-text below has to happen.
    let client_scoped = (blocking_enabled
        && (ctx.blocklist.has_client_exceptions() || ctx.blocklist.has_profiles()))
        || ctx.interceptor.has_client_rules();
    let client_mac = if client_scoped {
        ctx.client_registry.get_mac(client_addr)
    } else {
        None
    };
    // The log entry wants the address as text too, but it formats its own —
    // inside a closure a switched-off log never runs.
    let client_text = client_scoped.then(|| ip_to_string(client_addr));
    let client_ip = client_text.as_deref().unwrap_or_default();
    let filtering_enabled = blocking_enabled
        && !ctx
            .blocklist
            .client_filtering_off_normalized(client_ip, client_mac.as_deref());
    // The per-device profile (subset of lists) for this client, if any. When
    // present it replaces the default all-lists FST for every block check below.
    let profile = if filtering_enabled {
        ctx.blocklist.profile_for(client_ip, client_mac.as_deref())
    } else {
        None
    };
    // DNSSEC is honored per-client. We only request signatures upstream — and
    // cache/serve them — when this client set the DO bit AND the feature is on.
    // Forwarding signatures to a client that didn't ask bloats the answer past
    // the UDP limit → truncation → TCP retry on every query, which is what made
    // DNSSEC feel slow. This flag also keys the cache so a DO client never gets
    // a stale unsigned answer (nor a non-DO client the bulky signed one).
    let want_dnssec = ctx.dns_config.dnssec && dnssec_ok(&query);
    let log_ignored = is_log_ignored(&name, &ctx.log_ignore.read());
    // The ceiling on what this client is told to cache. Applied to every exit
    // path below, so no answer leaves with a longer lifetime than the window in
    // which a list/rule/profile change is guaranteed to reach the device.
    let client_ttl = ctx.client_ttl.load(Ordering::Relaxed);

    tracing::debug!("query type {} {} from {}", qtype, name, src);

    // ── Step 1: Custom DNS records (local overrides, beat blocklist) ──────
    if let Some(custom_resp) = ctx.custom_records.lookup(&query, &name, qtype) {
        ctx.dns_cache
            .insert(&name, qtype, want_dnssec, custom_resp.clone());
        if !log_ignored {
            emit(ctx, QueryStatus::Allowed, |status| {
                make_entry(
                    name,
                    qtype,
                    client_text.unwrap_or_else(|| ip_to_string(client_addr)),
                    status,
                    start.elapsed().as_millis() as u32,
                    Some("custom".into()),
                    0,
                )
            });
        }
        // Custom records carry an operator-chosen TTL, but they are still a
        // local override that can be edited live — cap them like everything else.
        return Decision::Answer(cap_ttls(
            patch_id(&custom_resp.bytes, query.id()),
            client_ttl,
        ));
    }

    // ── Step 2: Blocklist (skipped when globally disabled or client bypasses filtering) ──
    // Runs BEFORE selective routing: the blocklist decides WHETHER a name
    // resolves, a routing rule only decides HOW its traffic leaves. A rule
    // matches its whole subtree, so letting routing pre-empt the block would
    // silently unblock every blocklisted subdomain under a routed domain. To
    // reach a blocklisted domain on purpose, whitelist it — the whitelist walk
    // covers the subtree, and routing still applies (the whitelist means
    // "never block", not "never route").
    if filtering_enabled && ctx.blocklist.should_block_for(&name, profile.as_deref()) {
        tracing::debug!("blocked: {}", name);
        if !log_ignored {
            emit(ctx, QueryStatus::Blocked, |status| {
                make_entry(
                    name,
                    qtype,
                    client_text.unwrap_or_else(|| ip_to_string(client_addr)),
                    status,
                    start.elapsed().as_millis() as u32,
                    None,
                    3,
                )
            });
        }
        return Decision::Answer(build_nxdomain(&query, client_ttl));
    }

    // ── Step 3: Selective routing / proxy interception ────────────────────
    // For a routed domain, answer with our advertise IP so the client connects
    // to the proxy listeners. The blocklist already ran, so a blocked name
    // never gets here. Synthetic + returned early (NOT cached): routing rules
    // are runtime-mutable, so a cached redirect could outlive a deletion.
    if let Some(intercept) =
        ctx.interceptor
            .maybe_intercept(&query, &name, qtype, client_ip, client_mac.as_deref())
    {
        if !log_ignored {
            emit(ctx, QueryStatus::Routed, |status| {
                make_entry(
                    name,
                    qtype,
                    client_text.unwrap_or_else(|| ip_to_string(client_addr)),
                    status,
                    start.elapsed().as_millis() as u32,
                    Some(format!("proxy:{}", intercept.egress_id)),
                    0,
                )
            });
        }
        return Decision::Answer(cap_ttls(
            patch_id(&intercept.response.bytes, query.id()),
            client_ttl,
        ));
    }

    // ── Step 4: DNS response cache ────────────────────────────────────────
    if let Some((cached, remaining_ttl)) =
        ctx.dns_cache.get_with_remaining(&name, qtype, want_dnssec)
    {
        if filtering_enabled
            && let Some(blocked_cname) =
                cname_blocked_target(&cached.bytes, &name, &ctx.blocklist, profile.as_deref())
        {
            tracing::debug!("CNAME-blocked from cache: {} → {}", name, blocked_cname);
            if !log_ignored {
                emit(ctx, QueryStatus::Blocked, |status| {
                    make_entry(
                        name,
                        qtype,
                        client_text.unwrap_or_else(|| ip_to_string(client_addr)),
                        status,
                        start.elapsed().as_millis() as u32,
                        Some(format!("cname:{}", blocked_cname)),
                        3,
                    )
                });
            }
            return Decision::Answer(build_nxdomain(&query, client_ttl));
        }

        if !log_ignored {
            emit(ctx, QueryStatus::Cached, |status| {
                make_entry(
                    name,
                    qtype,
                    client_text.unwrap_or_else(|| ip_to_string(client_addr)),
                    status,
                    start.elapsed().as_millis() as u32,
                    None,
                    0,
                )
            });
        }
        return Decision::Answer(patch_cached(
            &cached.bytes,
            query.id(),
            remaining_ttl.min(client_ttl),
        ));
    }

    Decision::Upstream(Pending {
        name,
        qtype,
        want_dnssec,
        filtering_enabled,
        profile,
        client_addr,
        client_text,
        log_ignored,
        client_ttl,
        start,
    })
}

/// Steps 5-7 of the pipeline: ask upstream, inspect the CNAME chain, cache and
/// log. Separate from [`decide`] so a datagram only reaches a task — and pays
/// for one — when it actually has to wait for the network.
pub async fn resolve_upstream(raw: &[u8], pending: Pending, ctx: &DnsCtx) -> Vec<u8> {
    let Pending {
        name,
        qtype,
        want_dnssec,
        filtering_enabled,
        profile,
        client_addr,
        client_text,
        log_ignored,
        client_ttl,
        start,
    } = pending;
    let query = LazyQuery::new(raw);

    // ── Step 5: Forward to upstream ───────────────────────────────────────
    // Harden the outbound query: drop EDNS Client Subnet (so the resolver never
    // learns the client's subnet) and set the upstream DO bit to `want_dnssec`
    // (honor this client's request, or strip it when the feature is off).
    let upstream_query = sanitize_query(raw, ctx.dns_config.strip_ecs, want_dnssec);
    let (response_bytes, rcode, upstream_label) =
        match ctx.upstream_pool.resolve_raw(upstream_query).await {
            // Only trust a response we can actually decode. Unparseable bytes
            // are turned into SERVFAIL so they're never cached (step 6 caches
            // rcode==0 only) or served as if they were a valid NOERROR answer.
            Ok((bytes, label)) => match wire::rcode(&bytes) {
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

    // ── Step 6: CNAME inspection ───────────────────────────────────────────
    // Walk the answer section. If any CNAME target is blocked (and the queried
    // name is not whitelisted), return NXDOMAIN without caching.
    if rcode == 0
        && filtering_enabled
        && let Some(blocked_cname) =
            cname_blocked_target(&response_bytes, &name, &ctx.blocklist, profile.as_deref())
    {
        tracing::debug!("CNAME-blocked: {} → {}", name, blocked_cname);
        if !log_ignored {
            emit(ctx, QueryStatus::Blocked, |status| {
                make_entry(
                    name,
                    qtype,
                    client_text.unwrap_or_else(|| ip_to_string(client_addr)),
                    status,
                    start.elapsed().as_millis() as u32,
                    Some(format!("cname:{}", blocked_cname)),
                    3,
                )
            });
        }
        return build_nxdomain(&query, client_ttl);
    }

    // ── Step 7: Cache NOERROR responses ───────────────────────────────────
    // A TTL of 0 means "do not cache" (RFC 1035/2181) — caching it would break
    // failover/GeoDNS that relies on near-zero TTLs. NODATA (empty answer)
    // responses are cached under the RFC 2308 negative TTL from the authority
    // SOA, or skipped when no SOA is present.
    if rcode == 0 && !response_bytes.is_empty() {
        match wire::cache_ttl(&response_bytes) {
            Some(ttl) => {
                ctx.dns_cache.insert(
                    &name,
                    qtype,
                    want_dnssec,
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
        emit(ctx, QueryStatus::Upstream, |status| {
            make_entry(
                name,
                qtype,
                client_text.unwrap_or_else(|| ip_to_string(client_addr)),
                status,
                start.elapsed().as_millis() as u32,
                upstream_label,
                rcode,
            )
        });
    }

    // Cap client-facing TTLs to the configured max. Cache hits are already
    // bounded (patch_cached rewrites to the remaining lifetime ≤ max_ttl); this
    // covers the first, uncached lookup so `max_ttl` reliably bounds what every
    // client caches — e.g. how long a client clings to a pre-rule direct answer
    // before re-querying and getting routed.
    cap_ttls(response_bytes, client_ttl)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A standard query (RFC 1035 §4.1.1). Everything else — UPDATE, NOTIFY — is
/// answered with SERVFAIL; ferrite is a forwarding resolver, not a zone server.
const OPCODE_QUERY: u8 = 0;

/// The queried name — lowercase, no trailing root dot, the spelling the
/// blocklist, the cache and the query log all use — and its QTYPE.
fn question(query: &LazyQuery) -> Option<(String, u16)> {
    match wire::question(query.raw()) {
        wire::QuestionScan::Found { name, qtype } => Some((name, qtype)),
        // An IDN or escaped name: only the decoder renders it the way every
        // other domain in ferrite is spelled.
        wire::QuestionScan::Unsupported => {
            let q = query.message()?.queries.first()?;
            let mut name = q.name().to_lowercase().to_utf8();
            // Strip the trailing dot in place — the same bytes, no second String.
            let stripped = name.trim_end_matches('.').len();
            name.truncate(stripped);
            Some((name, q.query_type().into()))
        }
        wire::QuestionScan::Missing => None,
    }
}

/// Whether the client set the EDNS DO bit, i.e. asked for signatures.
fn dnssec_ok(query: &LazyQuery) -> bool {
    match wire::edns(query.raw()) {
        wire::EdnsScan::Opt(opt) => opt.dnssec_ok,
        wire::EdnsScan::None => false,
        wire::EdnsScan::Malformed => query
            .message()
            .and_then(|m| m.edns.as_ref())
            .is_some_and(|e| e.flags().dnssec_ok),
    }
}

fn emit(ctx: &DnsCtx, status: QueryStatus, entry: impl FnOnce(QueryStatus) -> QueryEntry) {
    // The counters are process-lifetime totals in RAM with no domain or client
    // in them, so they keep the dashboard honest even in the strictest privacy
    // mode and are always updated.
    ctx.live_stats.record_query(status);
    // With both the query log and statistics switched off there is nothing
    // downstream to record the entry into — so the entry is a closure, and a
    // switched-off log costs the counters above and nothing else: no clock
    // read, none of the three strings, no channel hop.
    if !ctx.record_switches.scope().records_anything() {
        return;
    }
    let entry = entry(status);
    // try_send: if the channel is full we drop the stat rather than block DNS,
    // but count the drop and warn (rate-limited) so a stalled writer surfaces
    // instead of silently diverging the persisted log from the live counters.
    if let Err(mpsc::error::TrySendError::Full(_)) = ctx.query_tx.try_send(entry) {
        let dropped = ctx.live_stats.total_dropped.fetch_add(1, Ordering::Relaxed) + 1;
        if dropped.is_power_of_two() {
            tracing::warn!(
                "stats writer back-pressure: {} query stats dropped (channel full)",
                dropped
            );
        }
    }
}

/// The log row for a finished query. `domain` and `client_ip` are taken by
/// value: this is the last thing a query does with either, and the entry owns
/// them from here — copying them again is two allocations per query for
/// nothing.
fn make_entry(
    domain: String,
    query_type: u16,
    client_ip: String,
    status: QueryStatus,
    latency_ms: u32,
    upstream: Option<String>,
    rcode: u8,
) -> QueryEntry {
    QueryEntry {
        id: QUERY_COUNTER.fetch_add(1, Ordering::Relaxed),
        timestamp: Utc::now(),
        domain,
        query_type,
        client_ip,
        // Tagged by the stats writer at drain time (see stats/writer.rs).
        device: String::new(),
        status,
        latency_ms,
        upstream,
        rcode,
    }
}

/// The synthetic SOA's MNAME and RNAME, wire-encoded. Only the TTL and MINIMUM
/// carry meaning for a resolver; the names are cosmetic, and `.invalid`
/// (RFC 2606) can never collide with a real zone.
const SOA_ADMIN_NAME: &[u8] = b"\x07ferrite\x07invalid\x00";

/// NXDOMAIN for a blocked name, carrying an SOA in the authority section so the
/// client's *negative* caching is bounded by `ttl` too.
///
/// Without an SOA there is nothing for RFC 2308 negative caching to key on, and
/// each stub resolver falls back to its own default — which we neither control
/// nor can shorten. That is what used to make un-blocking a domain (adding it to
/// the whitelist) apply instantly on the server and stay broken on a device for
/// an unpredictable while. The SOA's own TTL and its MINIMUM field are both set
/// to `ttl`, since the negative-cache lifetime is the smaller of the two.
fn build_nxdomain(query: &LazyQuery, ttl: u32) -> Vec<u8> {
    match nxdomain_on_wire(query.raw(), ttl) {
        Some(bytes) => bytes,
        None => nxdomain_encoded(query, ttl),
    }
}

/// [`build_nxdomain`] written straight onto the wire, or `None` for a query
/// shape it doesn't cover (no readable question, or more than one).
///
/// A block is the one answer ferrite invents on its own, and on a filtered
/// network it invents a great many of them. [`nxdomain_encoded`] would re-parse
/// `ferrite.invalid.` into labels, clone the question's name and re-encode the
/// whole message for each — this produces the same bytes without decoding
/// anything, which is what `nxdomain_matches_the_encoded_form` pins down.
fn nxdomain_on_wire(raw: &[u8], ttl: u32) -> Option<Vec<u8>> {
    let q_end = wire::question_end(raw)?;
    if u16::from_be_bytes([raw[4], raw[5]]) != 1 {
        return None;
    }
    // MNAME, an RNAME pointing at it, and the five 32-bit fields.
    let rdata_len = SOA_ADMIN_NAME.len() + 2 + 20;
    let mut out = Vec::with_capacity(q_end + 12 + rdata_len);
    out.extend_from_slice(&raw[..q_end]); // header + question, ID included
    // QR=1, opcode QUERY, AA=1, TC=0, RD echoed (RFC 1035 §4.1.1).
    out[2] = 0b1000_0100 | (raw[2] & 0x01);
    // RA=1 — we do recurse — and RCODE=NXDOMAIN.
    out[3] = 0b1000_0000 | ResponseCode::NXDomain.low();
    // ANCOUNT=0, NSCOUNT=1 (the SOA below), ARCOUNT=0.
    out[6..12].copy_from_slice(&[0, 0, 0, 1, 0, 0]);
    // Authority SOA, owner = the queried name as a pointer to the question.
    out.extend_from_slice(&[0xC0, wire::HEADER_LEN as u8]);
    out.extend_from_slice(&u16::from(RecordType::SOA).to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&(rdata_len as u16).to_be_bytes());
    // MNAME, then RNAME as a pointer to it — the same name twice, and the
    // encoder compresses it the same way.
    let mname_off = (q_end + 12) as u16;
    out.extend_from_slice(SOA_ADMIN_NAME);
    out.extend_from_slice(&(0xC000 | mname_off).to_be_bytes());
    out.extend_from_slice(&1u32.to_be_bytes()); // serial
    // refresh, retry, expire, and MINIMUM — one half of the negative-cache
    // lifetime, the other being the record TTL above.
    for field in [ttl; 4] {
        out.extend_from_slice(&field.to_be_bytes());
    }
    Some(out)
}

/// The reference form of [`build_nxdomain`], through the message encoder. Used
/// for the query shapes [`nxdomain_on_wire`] declines; empty when the bytes
/// don't decode either, since there is then no question to echo.
fn nxdomain_encoded(query: &LazyQuery, ttl: u32) -> Vec<u8> {
    let Some(decoded) = query.message() else {
        return Vec::new();
    };
    let mut resp = Message::response(decoded.metadata.id, OpCode::Query);
    resp.metadata.authoritative = true;
    // RFC 1035 §4.1.1: RD must be echoed; RA indicates we support recursion.
    resp.metadata.recursion_desired = decoded.metadata.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.metadata.response_code = ResponseCode::NXDomain;
    resp.add_queries(decoded.queries.iter().cloned());
    if let Some(q) = decoded.queries.first() {
        // The SOA is synthetic: only its TTL and MINIMUM carry meaning for a
        // resolver, the names are cosmetic (`.invalid` per RFC 2606, so they can
        // never collide with a real zone).
        let apex = q.name().clone();
        let ns = hickory_proto::rr::Name::from_ascii("ferrite.invalid.")
            .unwrap_or_else(|_| apex.clone());
        let secs = ttl as i32;
        let soa = hickory_proto::rr::rdata::SOA::new(
            ns.clone(),
            ns,
            1,    // serial
            secs, // refresh
            secs, // retry
            secs, // expire
            ttl,  // minimum — one half of the negative-cache lifetime
        );
        resp.add_authority(hickory_proto::rr::Record::from_rdata(
            apex,
            ttl,
            RData::SOA(soa),
        ));
    }
    resp.to_bytes().unwrap_or_default()
}

/// SERVFAIL echoing the query's header and question, split the same way as
/// [`build_nxdomain`]: onto the wire for the ordinary shape, through the
/// encoder otherwise.
///
/// The response carries opcode QUERY even when the query didn't: ferrite
/// answers an UPDATE or a NOTIFY with "this server failed", not with a reply
/// pretending to be of that kind.
fn build_servfail(query: &LazyQuery) -> Vec<u8> {
    match servfail_on_wire(query.raw()) {
        Some(bytes) => bytes,
        None => servfail_encoded(query),
    }
}

fn servfail_on_wire(raw: &[u8]) -> Option<Vec<u8>> {
    let q_end = wire::question_end(raw)?;
    if u16::from_be_bytes([raw[4], raw[5]]) != 1 {
        return None;
    }
    let mut out = raw[..q_end].to_vec();
    // QR=1, opcode QUERY, AA=0, TC=0, RD echoed.
    out[2] = 0b1000_0000 | (raw[2] & 0x01);
    out[3] = 0b1000_0000 | ResponseCode::ServFail.low();
    // Nothing in any section but the question already copied above.
    out[6..12].copy_from_slice(&[0; 6]);
    Some(out)
}

/// The reference form of [`build_servfail`]; empty when the bytes are neither
/// readable nor decodable — there is then no question to echo and no id worth
/// trusting, so there is nothing to send.
fn servfail_encoded(query: &LazyQuery) -> Vec<u8> {
    let Some(decoded) = query.message() else {
        return Vec::new();
    };
    let mut resp = Message::response(decoded.metadata.id, OpCode::Query);
    resp.metadata.recursion_desired = decoded.metadata.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.metadata.response_code = ResponseCode::ServFail;
    resp.add_queries(decoded.queries.iter().cloned());
    resp.to_bytes().unwrap_or_default()
}

/// Walk the CNAME chain in a DNS response and return the first blocked target.
///
/// The decision runs through [`Blocklist::should_block_for`], so the global
/// whitelist and any per-device profile overrides (allow/block) apply to CNAME
/// targets exactly as they do to the queried name. If the queried name itself is
/// allowed for this client, the whole chain is trusted.
/// Returns `None` if the chain is clean or the response has no CNAMEs.
fn cname_blocked_target(
    response_bytes: &[u8],
    queried_name: &str,
    blocklist: &ferrite_blocklist::Blocklist,
    profile: Option<&ferrite_blocklist::CompiledProfile>,
) -> Option<String> {
    // If the queried name is *explicitly* allowed for this client (global
    // whitelist or a profile allow), trust its whole resolution path. Note this
    // is not "not blocked" — an ordinary unlisted name still has its CNAME chain
    // inspected, which is the entire point of this check.
    if blocklist.is_allowed_for(queried_name, profile) {
        return None;
    }
    // Walk the answer section where it lies. This check runs on every cache hit
    // and every upstream answer, and the overwhelming majority carry no CNAME
    // at all — decoding the whole message to find that out costs more than the
    // check itself.
    match wire::find_cname_target(response_bytes, |target| {
        blocklist.should_block_for(target, profile)
    }) {
        wire::CnameScan::Matched(target) => Some(target),
        wire::CnameScan::NoMatch => None,
        // An IDN or otherwise escaped target: only the full parser renders it
        // the way every other domain in ferrite is spelled, so defer to it
        // rather than match the blocklist against a second spelling.
        wire::CnameScan::Unsupported => {
            cname_blocked_target_decoded(response_bytes, blocklist, profile)
        }
    }
}

/// [`cname_blocked_target`]'s fallback for answers the wire walker won't render
/// (IDN labels, labels needing escapes). Decodes the message so the target is
/// spelled exactly as `Name::to_utf8` would.
fn cname_blocked_target_decoded(
    response_bytes: &[u8],
    blocklist: &ferrite_blocklist::Blocklist,
    profile: Option<&ferrite_blocklist::CompiledProfile>,
) -> Option<String> {
    let msg = Message::from_bytes(response_bytes).ok()?;
    for record in &msg.answers {
        if let RData::CNAME(cname) = &record.data {
            let target = cname.0.to_utf8().to_lowercase();
            let target = target.trim_end_matches('.');
            if blocklist.should_block_for(target, profile) {
                return Some(target.to_string());
            }
        }
    }
    None
}

/// Patch the DNS message ID in raw wire bytes (bytes 0-1 = ID, big-endian).
fn patch_id(bytes: &[u8], id: u16) -> Vec<u8> {
    let mut out = bytes.to_vec();
    wire::set_id(&mut out, id);
    out
}

/// Prepare a cached response for delivery: rewrite the transaction ID to the
/// current query's, and rewrite each answer record's TTL down to the entry's
/// remaining lifetime. Without the TTL rewrite, a response cached with TTL
/// 3600 and served 3500s later would still advertise 3600, causing downstream
/// clients to over-cache well past the authoritative expiry (RFC 2181 §5.1).
///
/// Both rewrites happen on the copy itself — this is the hottest path in the
/// whole pipeline, and decoding the entry only to re-encode it costs more than
/// everything else a cache hit does put together. TTLs are rewritten in every
/// record section (answers, authority SOA, additionals) so downstream resolvers
/// don't over-cache past the entry's expiry — in particular the SOA
/// negative-cache TTL for NODATA responses, which lives in the authority
/// section. The EDNS OPT pseudo-record is skipped: its TTL slot is
/// flags/version, not a lifetime. Bytes that don't walk cleanly keep their
/// TTLs and get the ID patch alone.
fn patch_cached(bytes: &[u8], id: u16, remaining_ttl: u32) -> Vec<u8> {
    let mut out = bytes.to_vec();
    wire::set_id(&mut out, id);
    wire::set_ttls(&mut out, remaining_ttl);
    out
}

/// Cap every record TTL in a response to `max_ttl` so no client caches an answer
/// longer than the operator's ceiling. Rewritten in place, so what the client
/// receives is the upstream's own answer with shorter lifetimes — not a
/// re-encoding of it, which is free to compress names differently or lose a
/// record type hickory has no model for. Bytes that don't walk cleanly are
/// returned untouched. The EDNS OPT pseudo-record is skipped: its TTL slot is
/// flags/version, not a lifetime.
fn cap_ttls(mut bytes: Vec<u8>, max_ttl: u32) -> Vec<u8> {
    wire::cap_ttls(&mut bytes, max_ttl);
    bytes
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

/// Payload size advertised upstream when we ask for DNSSEC: the DNS-flag-day-2020
/// / RFC 8900 anti-fragmentation value. It overrides whatever the client
/// advertised in both directions — a tiny client buffer (e.g. 512) would force
/// the resolver to truncate every signed answer, costing a TCP round trip per
/// query; an oversized one (e.g. 4096) risks IP fragmentation on the path to the
/// upstream, which is both unreliable and a cache-poisoning vector.
const UPSTREAM_UDP_PAYLOAD: u16 = 1232;

/// Harden a client query before it leaves ferrite: with `strip_ecs`, drop the
/// EDNS Client Subnet option (so the upstream resolver never learns the client's
/// subnet); set the upstream DNSSEC-OK (DO) bit to exactly `want_do`.
///
/// `want_do` reflects *this* client's request (see `want_dnssec` in the handler):
/// when set we request signatures, when clear we strip any DO bit the client
/// sent. Enforcing the bit both ways keeps the upstream query consistent with
/// the cache key the response is stored under — a DO and a non-DO query for the
/// same name must never share an entry. Returns the original bytes on any
/// parse/encode error — a sanitization hiccup must never break forwarding.
fn sanitize_query(raw: &[u8], strip_ecs: bool, want_do: bool) -> Vec<u8> {
    // Fast path: both fields we normally touch — the DO bit and the advertised
    // payload size — live in the OPT pseudo-record's fixed part, so they can be
    // overwritten where they sit. Only dropping an ECS option (just the clients
    // that send one) or adding a missing OPT record needs the encoder.
    match wire::edns(raw) {
        wire::EdnsScan::Opt(opt) if !(strip_ecs && opt.has_ecs) => {
            let mut out = raw.to_vec();
            wire::set_dnssec_ok(&mut out, &opt, want_do);
            if want_do {
                wire::set_udp_payload(&mut out, &opt, UPSTREAM_UDP_PAYLOAD);
            }
            return out;
        }
        // No OPT record and none wanted: the query already says what we mean.
        wire::EdnsScan::None if !want_do => return raw.to_vec(),
        _ => {}
    }
    let Ok(mut msg) = Message::from_bytes(raw) else {
        return raw.to_vec();
    };
    if strip_ecs && let Some(edns) = msg.edns.as_mut() {
        edns.options_mut().remove(EdnsCode::Subnet);
    }
    if want_do {
        let edns = msg.edns.get_or_insert_with(Edns::new);
        edns.set_max_payload(UPSTREAM_UDP_PAYLOAD);
        edns.set_dnssec_ok(true);
    } else if let Some(edns) = msg.edns.as_mut() {
        // No DNSSEC wanted for this query (client didn't ask, or the feature is
        // off): clear any DO bit so the upstream returns no signatures and the
        // lean response matches its non-DO cache key.
        edns.set_dnssec_ok(false);
    }
    msg.to_bytes().unwrap_or_else(|_| raw.to_vec())
}

#[cfg(test)]
mod tests;
