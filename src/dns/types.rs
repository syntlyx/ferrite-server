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

/// Lightweight struct used inside the DNS response cache.
#[derive(Debug, Clone)]
pub struct DnsResponse {
    /// Raw DNS wire-format response bytes.
    pub bytes: bytes::Bytes,
    /// How many seconds this answer should be considered valid (clamped TTL).
    pub ttl: u32,
}
