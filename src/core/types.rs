//! Record types shared across subsystem boundaries (query log rows, stats
//! rollup rows) and the wire helpers more than one subsystem needs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
    /// Matched a routing rule: answered with the proxy's advertise IP so the
    /// connection goes through the chosen egress (`upstream` = `proxy:<egress>`).
    Routed,
}

impl QueryStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            QueryStatus::Upstream => "upstream",
            QueryStatus::Cached => "cached",
            QueryStatus::Blocked => "blocked",
            QueryStatus::Allowed => "allowed",
            QueryStatus::Routed => "routed",
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
    /// Source IP of the client at the time of the query.
    pub client_ip: String,
    /// Stable device identity this query is attributed to: the client's MAC
    /// (`aa:bb:cc:dd:ee:ff`) when known, else the IP as a fallback. Assigned by
    /// the stats writer at drain time. Lets a device's history stay contiguous
    /// across IP changes. Empty until tagged.
    #[serde(default)]
    pub device: String,
    /// How the query was resolved.
    pub status: QueryStatus,
    /// Round-trip latency in milliseconds.
    pub latency_ms: u32,
    /// Upstream resolver used (if status == Upstream).
    pub upstream: Option<String>,
    /// RCODE returned to the client (0 = NOERROR, 3 = NXDOMAIN, etc.).
    pub rcode: u8,
}

/// One 600-second stats rollup bucket (persisted by storage, served by the
/// stats API and the in-memory timeseries).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeseriesBucket {
    /// Unix timestamp of the start of this bucket (aligned to 600 s).
    pub bucket: u64,
    /// Total queries in this bucket.
    pub total: u64,
    /// Blocked queries in this bucket.
    pub blocked: u64,
    /// Served from DNS cache in this bucket.
    pub cached: u64,
    /// Forwarded to upstream resolvers in this bucket.
    pub upstream: u64,
}

/// Byte offset just past the first DNS question (QNAME + QTYPE + QCLASS) in a
/// wire-format message, or `None` if there is no question or the name is
/// malformed/unterminated. Compression pointers are rejected — they must not
/// appear in a question name. All indexing is bounds-checked for untrusted input.
pub fn question_end(msg: &[u8]) -> Option<usize> {
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
