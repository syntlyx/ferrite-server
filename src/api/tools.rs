//! Diagnostic network tools for the web UI: DNS lookup (any record type) and
//! WHOIS. Admin-only (behind the API-key middleware) and used interactively, so
//! a little extra latency is fine — neither touches the DNS hot path.

use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::{Duration, Instant};

use axum::{
    Json,
    extract::{Query, State},
};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query as DnsQuery};
use hickory_proto::rr::{Name, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::api::ApiError;
use crate::app::AppState;
use crate::error::FeriteError;
use crate::proxy::{EgressConn, direct_connect};
use crate::upstream::tunneled::client_config;

/// Read budget + TLS handshake timeout for the connection-based tools.
const TLS_TIMEOUT: Duration = Duration::from_secs(10);
/// Cloudflare's trace endpoint echoes the observed client (= egress exit) IP.
const TRACE_HOST: &str = "cloudflare.com";
const TRACE_MAX: usize = 64 * 1024;

const WHOIS_PORT: u16 = 43;
const WHOIS_TIMEOUT: Duration = Duration::from_secs(10);
const WHOIS_MAX: usize = 256 * 1024;
const IANA_WHOIS: &str = "whois.iana.org";

#[derive(Deserialize)]
pub struct ResolveParams {
    pub name: String,
    /// Record type (A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, SRV, CAA). Default A.
    #[serde(default)]
    pub r#type: Option<String>,
}

/// GET /api/tools/resolve?name=example.com&type=A
///
/// Resolve `name` for the given record type through ferrite's own upstreams
/// (a fresh query, not the cache), returning the parsed answers — a dig/nslookup
/// for the admin UI.
pub async fn resolve(
    State(state): State<AppState>,
    Query(params): Query<ResolveParams>,
) -> Result<Json<Value>, ApiError> {
    let name_in = params.name.trim();
    if name_in.is_empty() || name_in.len() > 253 {
        return Err(ApiError(FeriteError::Config(
            "name is empty or too long".into(),
        )));
    }
    let rtype_str = params.r#type.as_deref().unwrap_or("A").to_ascii_uppercase();
    let rtype = parse_rtype(&rtype_str).ok_or_else(|| {
        ApiError(FeriteError::Config(format!(
            "unsupported record type '{rtype_str}'"
        )))
    })?;

    // PTR convenience: a bare IP is turned into its reverse-DNS name.
    let qname = if rtype == RecordType::PTR {
        match name_in.parse::<IpAddr>() {
            Ok(ip) => reverse_name(ip),
            Err(_) => name_in.to_string(),
        }
    } else {
        name_in.to_string()
    };

    let name = Name::from_str(&qname)
        .map_err(|e| ApiError(FeriteError::Config(format!("invalid name '{qname}': {e}"))))?;
    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(DnsQuery::query(name, rtype));
    let raw = msg
        .to_bytes()
        .map_err(|e| ApiError(FeriteError::Dns(format!("encode query: {e}"))))?;

    let (resp_bytes, upstream) = state
        .inner
        .upstream_pool
        .resolve_raw(raw)
        .await
        .map_err(ApiError)?;
    let resp = Message::from_bytes(&resp_bytes)
        .map_err(|e| ApiError(FeriteError::Dns(format!("decode response: {e}"))))?;

    let answers: Vec<Value> = resp.answers.iter().map(record_json).collect();

    Ok(Json(json!({
        "query": qname,
        "type": rtype_str,
        "rcode": format!("{:?}", resp.metadata.response_code),
        "upstream": upstream,
        "answers": answers,
    })))
}

/// One resource record as JSON — shared by `resolve` and `dnssec`.
fn record_json(rr: &Record) -> Value {
    json!({
        "name": rr.name.to_utf8(),
        "type": rr.record_type().to_string(),
        "ttl": rr.ttl,
        "data": rr.data.to_string(),
    })
}

#[derive(Deserialize)]
pub struct WhoisParams {
    pub query: String,
}

/// GET /api/tools/whois?query=example.com
///
/// Two-step WHOIS: ask IANA which server is authoritative, then query it. Returns
/// the raw WHOIS text (what `whois(1)` users expect). The connect target is IANA
/// or its referral — never the user input — so the query can't redirect it.
pub async fn whois(Query(params): Query<WhoisParams>) -> Result<Json<Value>, ApiError> {
    let query = params.query.trim().to_string();
    // WHOIS is a single-line protocol; reject anything with whitespace/control so
    // the query can't inject extra protocol lines.
    if query.is_empty()
        || query.len() > 255
        || query.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(ApiError(FeriteError::Config(
            "invalid whois query (single token, no whitespace)".into(),
        )));
    }

    let iana = whois_query(IANA_WHOIS, &query).await?;
    let (server, result) = match parse_referral(&iana) {
        Some(srv) => match whois_query(&srv, &query).await {
            Ok(text) => (srv, text),
            // Referral unreachable — fall back to IANA's own answer.
            Err(_) => (IANA_WHOIS.to_string(), iana),
        },
        None => (IANA_WHOIS.to_string(), iana),
    };

    Ok(Json(json!({
        "query": query,
        "server": server,
        "result": result,
    })))
}

/// One WHOIS round-trip: connect to `server:43`, send `query\r\n`, read to EOF
/// (capped, timed out).
async fn whois_query(server: &str, query: &str) -> Result<String, ApiError> {
    let fut = async {
        let mut stream = TcpStream::connect((server, WHOIS_PORT))
            .await
            .map_err(|e| FeriteError::Dns(format!("whois connect {server}: {e}")))?;
        stream
            .write_all(format!("{query}\r\n").as_bytes())
            .await
            .map_err(|e| FeriteError::Dns(format!("whois write {server}: {e}")))?;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = stream
                .read(&mut chunk)
                .await
                .map_err(|e| FeriteError::Dns(format!("whois read {server}: {e}")))?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.len() > WHOIS_MAX {
                break;
            }
        }
        Ok::<String, FeriteError>(String::from_utf8_lossy(&buf).into_owned())
    };
    timeout(WHOIS_TIMEOUT, fut)
        .await
        .map_err(|_| ApiError(FeriteError::Dns(format!("whois {server} timed out"))))?
        .map_err(ApiError)
}

/// Extract the referred WHOIS server from an IANA response: `refer:` (IP/ASN) or
/// `whois:` (TLD).
fn parse_referral(text: &str) -> Option<String> {
    for line in text.lines() {
        let lower = line.trim().to_ascii_lowercase();
        for prefix in ["refer:", "whois:"] {
            if let Some(rest) = lower.strip_prefix(prefix) {
                let server = rest.trim();
                if !server.is_empty() {
                    return Some(server.to_string());
                }
            }
        }
    }
    None
}

fn parse_rtype(s: &str) -> Option<RecordType> {
    Some(match s {
        "A" => RecordType::A,
        "AAAA" => RecordType::AAAA,
        "CNAME" => RecordType::CNAME,
        "MX" => RecordType::MX,
        "TXT" => RecordType::TXT,
        "NS" => RecordType::NS,
        "SOA" => RecordType::SOA,
        "PTR" => RecordType::PTR,
        "SRV" => RecordType::SRV,
        "CAA" => RecordType::CAA,
        _ => return None,
    })
}

/// The reverse-DNS (PTR) name for an IP, e.g. `1.2.3.4` → `4.3.2.1.in-addr.arpa`.
fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut s = String::with_capacity(72);
            for octet in v6.octets().iter().rev() {
                s.push_str(&format!("{:x}.{:x}.", octet & 0x0f, octet >> 4));
            }
            s.push_str("ip6.arpa");
            s
        }
    }
}

// ── Connection-based tools (egress-check / cert / tcp-probe) ──────────────────

/// Reject host inputs with whitespace/control chars or absurd length before they
/// reach the resolver / TLS layer.
fn validate_host(host: &str) -> Result<(), ApiError> {
    if host.is_empty()
        || host.len() > 253
        || host.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(ApiError(FeriteError::Config(
            "invalid host (single token, no whitespace)".into(),
        )));
    }
    Ok(())
}

/// A connection opened for a diagnostic tool — either directly (the host is
/// resolved via ferrite's own upstreams, so no DNS leak) or through a named egress.
enum DiagStream {
    Direct(TcpStream),
    Egress(EgressConn),
}

/// Open `host:port` through `egress` (when given) or directly, returning the stream
/// and the connect latency in ms. An unknown egress id is a 4xx, not a hang.
async fn open_stream(
    state: &AppState,
    egress: Option<&str>,
    host: &str,
    port: u16,
) -> Result<(DiagStream, u128), ApiError> {
    let start = Instant::now();
    let stream = match egress {
        Some(id) => {
            let eg =
                state.inner.proxy.egress(id).ok_or_else(|| {
                    ApiError(FeriteError::Config(format!("unknown egress '{id}'")))
                })?;
            DiagStream::Egress(
                eg.connect(host, port)
                    .await
                    .map_err(|e| ApiError(e.into_inner()))?,
            )
        }
        None => DiagStream::Direct(
            direct_connect(&state.inner.upstream_pool, host, port)
                .await
                .map_err(ApiError)?,
        ),
    };
    Ok((stream, start.elapsed().as_millis()))
}

/// TLS handshake over an arbitrary stream using the shared verifying client config
/// (Mozilla roots) — the same path tunneled DoT uses. Verification is real, so an
/// expired / mis-issued / name-mismatched cert surfaces as a handshake error.
async fn tls_handshake<S>(
    stream: S,
    sni: &str,
) -> Result<tokio_rustls::client::TlsStream<S>, ApiError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let connector = TlsConnector::from(client_config().map_err(ApiError)?);
    let server_name = ServerName::try_from(sni.to_string()).map_err(|e| {
        ApiError(FeriteError::Config(format!(
            "invalid TLS name '{sni}': {e}"
        )))
    })?;
    timeout(TLS_TIMEOUT, connector.connect(server_name, stream))
        .await
        .map_err(|_| ApiError(FeriteError::Dns("TLS handshake timed out".into())))?
        .map_err(|e| ApiError(FeriteError::Dns(format!("TLS handshake failed: {e}"))))
}

/// Read up to `max` bytes (or EOF), per-read timeout — for short diagnostic bodies.
async fn read_capped<R: AsyncRead + Unpin>(r: &mut R, max: usize) -> Result<Vec<u8>, ApiError> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = timeout(TLS_TIMEOUT, r.read(&mut chunk))
            .await
            .map_err(|_| ApiError(FeriteError::Dns("read timed out".into())))?
            .map_err(|e| ApiError(FeriteError::Dns(format!("read: {e}"))))?;
        if n == 0 || buf.len() >= max {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(buf)
}

#[derive(Deserialize)]
pub struct EgressCheckParams {
    /// Egress id to test. Omit to check the box's own (direct) public IP.
    #[serde(default)]
    pub egress: Option<String>,
}

/// GET /api/tools/egress-check[?egress=…]
///
/// Connect through the chosen egress (or directly) to Cloudflare's trace endpoint
/// over TLS and report the OBSERVED exit IP, country and colo — proving the tunnel
/// actually carries traffic where it claims, end-to-end. One admin-initiated request
/// to a known third party; nothing leaves but a bare `GET /cdn-cgi/trace`.
pub async fn egress_check(
    State(state): State<AppState>,
    Query(params): Query<EgressCheckParams>,
) -> Result<Json<Value>, ApiError> {
    let egress = params
        .egress
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let (stream, connect_ms) = open_stream(&state, egress, TRACE_HOST, 443).await?;
    let trace = match stream {
        DiagStream::Direct(s) => fetch_trace(s).await?,
        DiagStream::Egress(s) => fetch_trace(s).await?,
    };
    Ok(Json(json!({
        "egress": egress,
        "healthy": egress.map(|id| state.inner.proxy.is_egress_healthy(id)),
        "connect_ms": connect_ms,
        "exit_ip": trace.get("ip").cloned(),
        "country": trace.get("loc").cloned(),
        "colo": trace.get("colo").cloned(),
        "tls": trace.get("tls").cloned(),
    })))
}

/// Fetch and parse Cloudflare's `key=value` trace body into a map.
async fn fetch_trace<S>(stream: S) -> Result<HashMap<String, String>, ApiError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut tls = tls_handshake(stream, TRACE_HOST).await?;
    let req = format!(
        "GET /cdn-cgi/trace HTTP/1.1\r\nHost: {TRACE_HOST}\r\nUser-Agent: ferrite-diag\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    tls.write_all(req.as_bytes())
        .await
        .map_err(|e| ApiError(FeriteError::Dns(format!("write: {e}"))))?;
    tls.flush()
        .await
        .map_err(|e| ApiError(FeriteError::Dns(format!("flush: {e}"))))?;
    let body = read_capped(&mut tls, TRACE_MAX).await?;
    Ok(parse_trace(&String::from_utf8_lossy(&body)))
}

/// Parse an HTTP response whose body is Cloudflare's `key=value`-per-line trace.
fn parse_trace(raw: &str) -> HashMap<String, String> {
    raw.split("\r\n\r\n")
        .nth(1)
        .unwrap_or(raw)
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

#[derive(Deserialize)]
pub struct CertParams {
    pub host: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub egress: Option<String>,
}

/// GET /api/tools/cert?host=example.com[&port=443][&egress=…]
///
/// TLS-handshake to the host (optionally through an egress) and return the presented
/// certificate chain: subject, issuer, SANs, validity, serial, signature algorithm
/// and SHA-256 fingerprint. Verification uses the Mozilla root store, so a bad cert
/// shows up as a handshake error whose message says why.
pub async fn cert(
    State(state): State<AppState>,
    Query(params): Query<CertParams>,
) -> Result<Json<Value>, ApiError> {
    let host = params.host.trim();
    validate_host(host)?;
    let port = params.port.unwrap_or(443);
    let egress = params
        .egress
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let (stream, connect_ms) = open_stream(&state, egress, host, port).await?;
    let chain = match stream {
        DiagStream::Direct(s) => inspect_cert(s, host).await?,
        DiagStream::Egress(s) => inspect_cert(s, host).await?,
    };
    Ok(Json(json!({
        "host": host,
        "port": port,
        "egress": egress,
        "connect_ms": connect_ms,
        "chain": chain,
    })))
}

/// Run the handshake and turn the peer's presented certificate chain into JSON.
async fn inspect_cert<S>(stream: S, sni: &str) -> Result<Vec<Value>, ApiError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let tls = tls_handshake(stream, sni).await?;
    let (_, conn) = tls.get_ref();
    let certs = conn
        .peer_certificates()
        .ok_or_else(|| ApiError(FeriteError::Dns("server presented no certificates".into())))?;
    Ok(certs
        .iter()
        .enumerate()
        .map(|(i, der)| cert_to_json(der.as_ref(), i == 0))
        .collect())
}

/// Parse a single DER cert into JSON; on parse failure still return the fingerprint.
fn cert_to_json(der: &[u8], is_leaf: bool) -> Value {
    use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

    let fingerprint = ring::digest::digest(&ring::digest::SHA256, der)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");

    match X509Certificate::from_der(der) {
        Ok((_, x)) => {
            let sans: Vec<String> = x
                .subject_alternative_name()
                .ok()
                .flatten()
                .map(|ext| {
                    ext.value
                        .general_names
                        .iter()
                        .map(|gn| match gn {
                            GeneralName::DNSName(s) => (*s).to_string(),
                            GeneralName::IPAddress(b) => format!("IP:{}", fmt_cert_ip(b)),
                            GeneralName::RFC822Name(s) => format!("email:{s}"),
                            GeneralName::URI(s) => format!("uri:{s}"),
                            other => format!("{other:?}"),
                        })
                        .collect()
                })
                .unwrap_or_default();
            json!({
                "is_leaf": is_leaf,
                "subject": x.subject().to_string(),
                "issuer": x.issuer().to_string(),
                "sans": sans,
                "not_before": x.validity().not_before.to_string(),
                "not_before_unix": x.validity().not_before.timestamp(),
                "not_after": x.validity().not_after.to_string(),
                "not_after_unix": x.validity().not_after.timestamp(),
                "serial": x.raw_serial_as_string(),
                "sig_alg": x.signature_algorithm.algorithm.to_string(),
                "sha256": fingerprint,
            })
        }
        Err(e) => json!({
            "is_leaf": is_leaf,
            "sha256": fingerprint,
            "parse_error": e.to_string(),
        }),
    }
}

/// Format a SAN IPAddress (4 or 16 raw bytes) as a human IP.
fn fmt_cert_ip(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => IpAddr::from([bytes[0], bytes[1], bytes[2], bytes[3]]).to_string(),
        16 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(bytes);
            IpAddr::from(o).to_string()
        }
        _ => bytes.iter().map(|b| format!("{b:02x}")).collect(),
    }
}

#[derive(Deserialize)]
pub struct TcpProbeParams {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub egress: Option<String>,
}

/// GET /api/tools/tcp-probe?host=…&port=…[&egress=…]
///
/// Open a TCP connection to host:port (optionally through an egress) and report
/// reachability + connect latency. A refused / timed-out connection is a normal
/// result (`reachable:false`), not an API error — only an unknown egress is a 4xx.
pub async fn tcp_probe(
    State(state): State<AppState>,
    Query(params): Query<TcpProbeParams>,
) -> Result<Json<Value>, ApiError> {
    let host = params.host.trim();
    validate_host(host)?;
    let port = params.port;
    let egress = params
        .egress
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    // Resolve the egress up front so an unknown id is a 4xx, not a "false".
    if let Some(id) = egress
        && state.inner.proxy.egress(id).is_none()
    {
        return Err(ApiError(FeriteError::Config(format!(
            "unknown egress '{id}'"
        ))));
    }
    let start = Instant::now();
    match open_stream(&state, egress, host, port).await {
        Ok(_) => Ok(Json(json!({
            "host": host,
            "port": port,
            "egress": egress,
            "reachable": true,
            "connect_ms": start.elapsed().as_millis(),
        }))),
        Err(e) => Ok(Json(json!({
            "host": host,
            "port": port,
            "egress": egress,
            "reachable": false,
            "error": e.0.to_string(),
        }))),
    }
}

/// GET /api/tools/dnssec?name=example.com[&type=A]
///
/// Resolve through ferrite's upstreams with the DNSSEC-OK (DO) bit set, then report
/// whether the answer was authenticated (the AD flag, set by a validating resolver)
/// and how many RRSIG records came back — a quick "is this name validating" check.
pub async fn dnssec(
    State(state): State<AppState>,
    Query(params): Query<ResolveParams>,
) -> Result<Json<Value>, ApiError> {
    let name_in = params.name.trim();
    if name_in.is_empty() || name_in.len() > 253 {
        return Err(ApiError(FeriteError::Config(
            "name is empty or too long".into(),
        )));
    }
    let rtype_str = params.r#type.as_deref().unwrap_or("A").to_ascii_uppercase();
    let rtype = parse_rtype(&rtype_str).ok_or_else(|| {
        ApiError(FeriteError::Config(format!(
            "unsupported record type '{rtype_str}'"
        )))
    })?;
    let name = Name::from_str(name_in).map_err(|e| {
        ApiError(FeriteError::Config(format!(
            "invalid name '{name_in}': {e}"
        )))
    })?;

    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(DnsQuery::query(name, rtype));
    // Request DNSSEC: set the DO bit (and a sane EDNS payload) so the resolver
    // returns signatures and reports validation via the AD flag.
    let mut edns = Edns::new();
    edns.set_max_payload(1232);
    edns.set_dnssec_ok(true);
    msg.set_edns(edns);
    let raw = msg
        .to_bytes()
        .map_err(|e| ApiError(FeriteError::Dns(format!("encode query: {e}"))))?;

    let (resp_bytes, upstream) = state
        .inner
        .upstream_pool
        .resolve_raw(raw)
        .await
        .map_err(ApiError)?;
    let resp = Message::from_bytes(&resp_bytes)
        .map_err(|e| ApiError(FeriteError::Dns(format!("decode response: {e}"))))?;

    let rrsig_count = resp
        .all_sections()
        .filter(|r| r.record_type() == RecordType::RRSIG)
        .count();
    let answers: Vec<Value> = resp.answers.iter().map(record_json).collect();

    Ok(Json(json!({
        "query": name_in,
        "type": rtype_str,
        "rcode": format!("{:?}", resp.metadata.response_code),
        "authenticated": resp.metadata.authentic_data,
        "rrsig_count": rrsig_count,
        "upstream": upstream,
        "answers": answers,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_trace_extracts_exit_ip_and_loc() {
        let raw = "HTTP/1.1 200 OK\r\nServer: cloudflare\r\nContent-Type: text/plain\r\n\r\n\
                   fl=123abc\r\nh=cloudflare.com\r\nip=203.0.113.7\r\nts=1.2\r\n\
                   colo=AMS\r\nloc=NL\r\ntls=TLSv1.3\r\n";
        let m = parse_trace(raw);
        assert_eq!(m.get("ip").map(String::as_str), Some("203.0.113.7"));
        assert_eq!(m.get("loc").map(String::as_str), Some("NL"));
        assert_eq!(m.get("colo").map(String::as_str), Some("AMS"));
        assert_eq!(m.get("tls").map(String::as_str), Some("TLSv1.3"));
    }

    #[test]
    fn parse_trace_without_header_split_still_reads_body() {
        // Defensive: if the split marker is absent we fall back to the whole string.
        let m = parse_trace("ip=198.51.100.9\nloc=DE");
        assert_eq!(m.get("ip").map(String::as_str), Some("198.51.100.9"));
        assert_eq!(m.get("loc").map(String::as_str), Some("DE"));
    }

    #[test]
    fn fmt_cert_ip_handles_v4_v6_and_garbage() {
        assert_eq!(fmt_cert_ip(&[192, 0, 2, 1]), "192.0.2.1");
        assert_eq!(
            fmt_cert_ip(&[0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            "2001:db8::1"
        );
        assert_eq!(fmt_cert_ip(&[0xde, 0xad]), "dead");
    }

    #[test]
    fn validate_host_rejects_whitespace_and_empty() {
        assert!(validate_host("example.com").is_ok());
        assert!(validate_host("").is_err());
        assert!(validate_host("a b").is_err());
        assert!(validate_host("a\nb").is_err());
    }
}
