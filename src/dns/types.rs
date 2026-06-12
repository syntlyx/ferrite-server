use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// DNS query type constants (subset of RFC 1035 + extensions).
/// u16 matches the wire format (RFC 1035 §3.2.2).
#[allow(dead_code)]
pub mod qtype {
    pub const A: u16 = 1;
    pub const NS: u16 = 2;
    pub const CNAME: u16 = 5;
    pub const SOA: u16 = 6;
    pub const PTR: u16 = 12;
    pub const MX: u16 = 15;
    pub const TXT: u16 = 16;
    pub const AAAA: u16 = 28;
    pub const SRV: u16 = 33;
    pub const HTTPS: u16 = 65;
    pub const CAA: u16 = 257;
    pub const ANY: u16 = 255;
}

/// How the query was resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QueryStatus {
    /// Passed through to upstream, response returned.
    Upstream,
    /// Served from the DNS cache.
    Cached,
    /// Blocked by a blocklist entry.
    Blocked,
    /// Explicitly allowed (whitelist / whitelist cache).
    Allowed,
}

impl QueryStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            QueryStatus::Upstream => "upstream",
            QueryStatus::Cached => "cached",
            QueryStatus::Blocked => "blocked",
            QueryStatus::Allowed => "allowed",
        }
    }
}

impl std::fmt::Display for QueryStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single completed DNS query that will be persisted and shown in the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryEntry {
    /// Monotonically increasing query ID within this process.
    pub id: u64,
    /// Timestamp when the query arrived.
    pub timestamp: DateTime<Utc>,
    /// The queried domain name.
    pub domain: String,
    /// Query type (A=1, AAAA=28, CAA=257, …). Matches the 16-bit wire format.
    pub query_type: u16,
    /// Source IP of the client.
    pub client_ip: String,
    /// How the query was resolved.
    pub status: QueryStatus,
    /// Round-trip latency in milliseconds.
    pub latency_ms: u32,
    /// Upstream resolver used (if status == Upstream).
    pub upstream: Option<String>,
    /// RCODE returned to the client (0 = NOERROR, 3 = NXDOMAIN, etc.).
    pub rcode: u8,
}

impl QueryEntry {}

/// Lightweight struct used inside the DNS response cache.
#[derive(Debug, Clone)]
pub struct DnsResponse {
    /// Raw DNS wire-format response bytes.
    pub bytes: bytes::Bytes,
    /// How many seconds this answer should be considered valid (clamped TTL).
    pub ttl: u32,
}

/// Byte offset just past the first DNS question (QNAME + QTYPE + QCLASS) in a
/// wire-format message, or `None` if there is no question or the name is
/// malformed/unterminated. Compression pointers are rejected — they must not
/// appear in a question name. All indexing is bounds-checked for untrusted input.
pub(crate) fn question_end(msg: &[u8]) -> Option<usize> {
    if msg.len() < 12 {
        return None;
    }
    // QDCOUNT == 0 → no question to delimit.
    if u16::from_be_bytes([msg[4], msg[5]]) == 0 {
        return None;
    }
    let mut i = 12; // questions start right after the 12-byte header
    loop {
        let len = *msg.get(i)? as usize;
        if len == 0 {
            i += 1; // consume the root-label terminator
            break;
        }
        if len & 0xC0 != 0 {
            return None; // compression pointer not allowed in a question name
        }
        i += 1 + len;
        if i > msg.len() {
            return None;
        }
    }
    let end = i + 4; // QTYPE (2) + QCLASS (2)
    (end <= msg.len()).then_some(end)
}
