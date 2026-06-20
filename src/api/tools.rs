//! Diagnostic network tools for the web UI: DNS lookup (any record type) and
//! WHOIS. Admin-only (behind the API-key middleware) and used interactively, so
//! a little extra latency is fine — neither touches the DNS hot path.

use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use axum::{
    Json,
    extract::{Query, State},
};
use hickory_proto::op::{Message, MessageType, OpCode, Query as DnsQuery};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::api::ApiError;
use crate::app::AppState;
use crate::error::FeriteError;

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

    let answers: Vec<Value> = resp
        .answers
        .iter()
        .map(|rr| {
            json!({
                "name": rr.name.to_utf8(),
                "type": rr.record_type().to_string(),
                "ttl": rr.ttl,
                "data": rr.data.to_string(),
            })
        })
        .collect();

    Ok(Json(json!({
        "query": qname,
        "type": rtype_str,
        "rcode": format!("{:?}", resp.metadata.response_code),
        "upstream": upstream,
        "answers": answers,
    })))
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
