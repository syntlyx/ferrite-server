use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::error::{FeriteError, Result};
use crate::upstream::stream::StreamPool;

const UDP_TIMEOUT: Duration = Duration::from_secs(5);
/// Max DNS message size over UDP (EDNS0).
const MAX_UDP_SIZE: usize = 4096;

/// A plain DNS upstream (UDP with automatic TCP fallback on truncation).
///
/// The TCP fallback rides a pooled, persistent connection (`tcp_pool`) rather
/// than dialing fresh each time — with DNSSEC the truncation path is hot (large
/// signed answers don't fit a UDP datagram), so reconnecting per query was the
/// dominant cost.
pub struct PlainResolver {
    addr: SocketAddr,
    label: String,
    tcp_pool: StreamPool,
}

impl PlainResolver {
    pub fn new(address: &str, port: u16) -> Result<Self> {
        let addr: SocketAddr = format!("{}:{}", address, port)
            .parse()
            .map_err(|e| FeriteError::Config(format!("invalid upstream address: {}", e)))?;
        Ok(Self {
            addr,
            label: format!("{}:{}", address, port),
            tcp_pool: StreamPool::plain(addr),
        })
    }

    /// Forward raw DNS query bytes to the upstream server and return the raw response.
    pub async fn resolve_raw(&self, raw: Vec<u8>) -> Result<(Vec<u8>, String)> {
        // Anti-spoofing: do NOT forward the client's transaction ID upstream.
        // The client chose that ID, so reusing it gives a malicious client all
        // the entropy needed to forge a matching off-path reply and poison the
        // shared cache. Instead we send a fresh random ID for the upstream
        // exchange, validate the reply against it (in `send_udp`), then restore
        // the client's original ID before returning.
        let client_id = if raw.len() >= 2 {
            [raw[0], raw[1]]
        } else {
            [0, 0]
        };
        let mut query = raw;
        let txid = random_txid().to_be_bytes();
        if query.len() >= 2 {
            query[0] = txid[0];
            query[1] = txid[1];
        }

        // Try UDP first.
        let mut response = self.send_udp(&query).await?;

        // If TC (truncated) bit is set, retry over TCP (pooled connection).
        if is_truncated(&response) {
            tracing::debug!("upstream {} set TC bit, retrying over TCP", self.addr);
            response = self.tcp_pool.exchange(&query).await?;
        }

        // Restore the client's transaction ID before handing the response back.
        if response.len() >= 2 {
            response[0] = client_id[0];
            response[1] = client_id[1];
        }

        Ok((response, self.label.clone()))
    }

    async fn send_udp(&self, raw: &[u8]) -> Result<Vec<u8>> {
        let bind_addr = if self.addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| FeriteError::Dns(format!("udp bind: {}", e)))?;

        socket
            .connect(self.addr)
            .await
            .map_err(|e| FeriteError::Dns(format!("udp connect {}: {}", self.addr, e)))?;

        timeout(UDP_TIMEOUT, socket.send(raw))
            .await
            .map_err(|_| FeriteError::Dns(format!("udp send timeout to {}", self.addr)))?
            .map_err(|e| FeriteError::Dns(format!("udp send to {}: {}", self.addr, e)))?;

        let mut buf = vec![0u8; MAX_UDP_SIZE];
        let n = timeout(UDP_TIMEOUT, socket.recv(&mut buf))
            .await
            .map_err(|_| FeriteError::Dns(format!("udp recv timeout from {}", self.addr)))?
            .map_err(|e| FeriteError::Dns(format!("udp recv from {}: {}", self.addr, e)))?;

        let response = &buf[..n];

        // Application-layer anti-spoofing: the kernel `connect()` above already
        // drops datagrams whose source isn't `self.addr`, but for plain UDP we
        // additionally require the response transaction ID and question section
        // to echo the query before we hand it back to be cached/served. A packet
        // that doesn't match (off-path spoof or corruption) is rejected rather
        // than trusted — fail closed.
        if !response_matches_query(raw, response) {
            return Err(FeriteError::Dns(format!(
                "udp response from {} did not match query (id/question mismatch)",
                self.addr
            )));
        }

        Ok(response.to_vec())
    }

    pub fn label(&self) -> &str {
        &self.label
    }
}

/// Generate a fresh random 16-bit DNS transaction ID for an upstream query.
/// Falls back to 0 only if the system RNG fails (effectively never).
fn random_txid() -> u16 {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 2];
    if ring::rand::SystemRandom::new().fill(&mut b).is_ok() {
        u16::from_be_bytes(b)
    } else {
        0
    }
}

/// Returns true if the TC (truncated) bit is set in the DNS message header.
///
/// Bit layout of the 3rd byte of a DNS message:
///   QR(1) | Opcode(4) | AA(1) | TC(1) | RD(1)
/// TC is bit 1 of byte 2.
fn is_truncated(raw: &[u8]) -> bool {
    raw.len() >= 3 && (raw[2] & 0b0000_0010) != 0
}

/// Returns true if `response` is a plausible reply to `query`: identical
/// transaction ID, the QR (response) bit set, the same QDCOUNT, and a byte-for-
/// byte identical question section. The question section is never compressed,
/// so a direct byte comparison is valid. All indexing is bounds-checked because
/// `response` is attacker-influenced.
fn response_matches_query(query: &[u8], response: &[u8]) -> bool {
    // Both need at least a full 12-byte header.
    if query.len() < 12 || response.len() < 12 {
        return false;
    }
    // Transaction ID must match.
    if query[0..2] != response[0..2] {
        return false;
    }
    // Response must have the QR bit set (bit 7 of byte 2).
    if response[2] & 0b1000_0000 == 0 {
        return false;
    }
    // QDCOUNT must match (normally exactly 1).
    if query[4..6] != response[4..6] {
        return false;
    }
    // Compare the question section verbatim.
    match crate::dns::types::question_end(query) {
        Some(end) => response.len() >= end && query[12..end] == response[12..end],
        // No question to compare (qdcount 0 or malformed query): the header
        // checks above are all we can assert.
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal DNS wire message: header + one question for `example.com` A IN.
    /// `qr` sets the response bit; `id` is the transaction ID.
    fn message(id: u16, qr: bool) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&id.to_be_bytes()); // ID
        m.push(if qr { 0x80 } else { 0x00 }); // flags hi (QR bit)
        m.push(0x00); // flags lo
        m.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
        m.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        m.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        m.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        for label in ["example", "com"] {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0); // root label
        m.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
        m.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
        m
    }

    #[test]
    fn accepts_matching_response() {
        let q = message(0x1234, false);
        let r = message(0x1234, true);
        assert!(response_matches_query(&q, &r));
    }

    #[test]
    fn rejects_transaction_id_mismatch() {
        let q = message(0x1234, false);
        let r = message(0xBEEF, true);
        assert!(!response_matches_query(&q, &r));
    }

    #[test]
    fn rejects_response_without_qr_bit() {
        let q = message(0x1234, false);
        let r = message(0x1234, false); // QR not set
        assert!(!response_matches_query(&q, &r));
    }

    #[test]
    fn rejects_question_mismatch() {
        let q = message(0x1234, false);
        let mut r = message(0x1234, true);
        // Flip a byte inside the QNAME ("example" -> "exbmple").
        r[14] = b'b';
        assert!(!response_matches_query(&q, &r));
    }

    #[test]
    fn rejects_truncated_messages() {
        let q = message(0x1234, false);
        assert!(!response_matches_query(&q, &q[..8]));
        assert!(!response_matches_query(&q[..5], &message(0x1234, true)));
    }
}
