use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use crate::app::AppState;
use crate::error::FeriteError;

/// Maximum DNS UDP payload (EDNS0).
const MAX_UDP_PAYLOAD: usize = 4096;
/// Maximum DNS TCP message size (2-byte length prefix → max 65535).
const MAX_TCP_PAYLOAD: usize = 65535;

/// Start UDP and TCP DNS listeners, plus the cache janitor.
/// Runs until a fatal error or the process exits.
pub async fn run(state: AppState) -> anyhow::Result<()> {
    let bind_addr = state.inner.config.dns.bind_addr;

    let udp = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| FeriteError::Dns(format!("UDP bind {}: {}", bind_addr, e)))?;

    let tcp = TcpListener::bind(bind_addr)
        .await
        .map_err(|e| FeriteError::Dns(format!("TCP bind {}: {}", bind_addr, e)))?;

    tracing::info!("DNS server listening on {}", bind_addr);

    // Cache janitor.
    tokio::spawn(crate::dns::cache::janitor(Arc::clone(
        &state.inner.dns_cache,
    )));

    tokio::try_join!(udp_loop(udp, state.clone()), tcp_loop(tcp, state))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// UDP
// ---------------------------------------------------------------------------

async fn udp_loop(socket: UdpSocket, state: AppState) -> anyhow::Result<()> {
    let socket = Arc::new(socket);
    let mut buf = vec![0u8; MAX_UDP_PAYLOAD];

    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("UDP recv_from: {}", e);
                continue;
            }
        };

        let raw = buf[..len].to_vec();
        let state = state.clone();
        let socket = Arc::clone(&socket);

        // Shed load immediately if too many queries are in-flight: prevents
        // memory exhaustion when upstream is slow (unbounded spawn otherwise).
        let permit = match state.inner.query_semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!(
                    "query concurrency limit reached, dropping UDP query from {}",
                    src
                );
                // Send SERVFAIL so the client gets a response instead of timing out.
                // We only need the query ID (bytes 0-1) to build a valid SERVFAIL.
                if raw.len() >= 2 {
                    let mut servfail = [
                        raw[0], raw[1], // ID
                        0x80,
                        0x02, // QR=1, OPCODE=0, AA=0, TC=0, RD=0; RA=0, RCODE=SERVFAIL(2)
                        0x00, 0x00, // QDCOUNT=0
                        0x00, 0x00, // ANCOUNT=0
                        0x00, 0x00, // NSCOUNT=0
                        0x00, 0x00, // ARCOUNT=0
                    ];
                    // Echo RD bit from the query. Byte 2 only exists on a
                    // header of at least 3 bytes — a 2-byte datagram passes the
                    // guard above but has no flags byte, so bounds-check before
                    // reading it (otherwise a 2-byte packet panics this loop).
                    if raw.len() >= 3 && raw[2] & 0x01 != 0 {
                        servfail[2] |= 0x01;
                    }
                    let _ = socket.send_to(&servfail, src).await;
                }
                continue;
            }
        };

        tokio::spawn(async move {
            let _permit = permit;
            // Capture the client's advertised UDP buffer size before `raw` is
            // moved into the handler (512 without EDNS0, larger if advertised).
            let max_udp = client_udp_payload(&raw);
            match crate::dns::handler::handle_query(
                raw,
                src,
                Arc::clone(&state.inner),
                state.query_tx.clone(),
            )
            .await
            {
                Ok(resp) if !resp.is_empty() => {
                    // If the answer is larger than the client can accept over
                    // UDP, send a truncated (TC=1) reply so it retries over TCP
                    // rather than receiving an oversized datagram the network may
                    // silently drop (RFC 1035 §4.2.1).
                    let datagram = if resp.len() > max_udp {
                        truncate_response(&resp)
                    } else {
                        resp
                    };
                    if let Err(e) = socket.send_to(&datagram, src).await {
                        tracing::warn!("UDP send to {}: {}", src, e);
                    }
                }
                Ok(_) => {}
                Err(e) => tracing::warn!("handle_query (UDP) for {}: {}", src, e),
            }
        });
    }
}

/// The client's maximum UDP payload size: 512 bytes by default (RFC 1035), or
/// the EDNS0 advertised size (clamped to our receive buffer) when the query
/// carries an OPT record. Falls back to 512 for unparseable queries.
fn client_udp_payload(query: &[u8]) -> usize {
    use hickory_proto::op::Message;
    use hickory_proto::serialize::binary::BinDecodable;
    // `Message::max_payload()` already returns the EDNS0 advertised size with a
    // 512-byte floor; we just cap it to our own receive buffer.
    Message::from_bytes(query)
        .map(|m| (m.max_payload() as usize).min(MAX_UDP_PAYLOAD))
        .unwrap_or(512)
}

/// Build a minimal truncated response from `resp`: the 12-byte header with the
/// TC bit set and the answer/authority/additional counts cleared, followed by
/// the question section echoed verbatim. This is a valid, empty, truncated
/// answer that tells the client to retry the query over TCP.
fn truncate_response(resp: &[u8]) -> Vec<u8> {
    if resp.len() < 12 {
        return resp.to_vec();
    }
    let mut out = resp[..12].to_vec();
    out[2] |= 0b0000_0010; // set TC (truncated) bit
    out[6] = 0;
    out[7] = 0; // ANCOUNT = 0
    out[8] = 0;
    out[9] = 0; // NSCOUNT = 0
    out[10] = 0;
    out[11] = 0; // ARCOUNT = 0
    match crate::dns::types::question_end(resp) {
        Some(end) => out.extend_from_slice(&resp[12..end]),
        // No parseable question — keep the header consistent by zeroing QDCOUNT.
        None => {
            out[4] = 0;
            out[5] = 0;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// TCP
// ---------------------------------------------------------------------------

async fn tcp_loop(listener: TcpListener, state: AppState) -> anyhow::Result<()> {
    loop {
        let (stream, src) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("TCP accept: {}", e);
                continue;
            }
        };

        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_tcp_connection(stream, src, state).await {
                tracing::warn!("TCP connection {} closed: {}", src, e);
            }
        });
    }
}

/// Handle a single TCP DNS connection.
/// A client may pipeline multiple queries on one connection, so we loop.
async fn handle_tcp_connection(
    mut stream: tokio::net::TcpStream,
    src: std::net::SocketAddr,
    state: AppState,
) -> anyhow::Result<()> {
    use tokio::time::{timeout, Duration};
    const IDLE_TIMEOUT: Duration = Duration::from_secs(10);

    loop {
        // Read 2-byte length prefix.
        let mut len_buf = [0u8; 2];
        match timeout(IDLE_TIMEOUT, stream.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => break, // Client closed connection.
            Err(_) => break,     // Idle timeout.
        }

        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 || msg_len > MAX_TCP_PAYLOAD {
            tracing::warn!("TCP {}: invalid message length {}", src, msg_len);
            break;
        }

        let mut raw = vec![0u8; msg_len];
        match timeout(IDLE_TIMEOUT, stream.read_exact(&mut raw)).await {
            Ok(Ok(_)) => {}
            // Inner I/O error (e.g. connection reset mid-body): the buffer is
            // only partially filled, so don't process it as a complete query.
            Ok(Err(e)) => {
                tracing::warn!("TCP {}: read message: {}", src, e);
                break;
            }
            Err(e) => {
                tracing::warn!("TCP {}: read message timed out: {}", src, e);
                break;
            }
        }

        let _permit = match state.inner.query_semaphore.try_acquire() {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!(
                    "query concurrency limit reached, dropping TCP query from {}",
                    src
                );
                break;
            }
        };

        let response = match crate::dns::handler::handle_query(
            raw,
            src,
            Arc::clone(&state.inner),
            state.query_tx.clone(),
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("handle_query (TCP) for {}: {}", src, e);
                break;
            }
        };

        if response.is_empty() {
            continue;
        }

        // Write 2-byte length prefix + response.
        let resp_len = response.len() as u16;
        let mut framed = Vec::with_capacity(2 + response.len());
        framed.extend_from_slice(&resp_len.to_be_bytes());
        framed.extend_from_slice(&response);

        if let Err(e) = timeout(IDLE_TIMEOUT, stream.write_all(&framed)).await {
            tracing::warn!("TCP {}: write response: {}", src, e);
            break;
        }
    }

    Ok(())
}

#[cfg(test)]
mod udp_tests {
    use super::*;

    /// Wire-format query (no EDNS) for `example.com` A IN, id 0x1234.
    fn query_no_edns() -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in ["example", "com"] {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE A, QCLASS IN
        m
    }

    #[test]
    fn no_edns_query_caps_at_512() {
        assert_eq!(client_udp_payload(&query_no_edns()), 512);
    }

    #[test]
    fn unparseable_query_caps_at_512() {
        assert_eq!(client_udp_payload(b"\x00\x01"), 512);
    }

    #[test]
    fn truncate_sets_tc_and_keeps_question() {
        // A "response": query bytes with QR set and a fake oversized answer tail.
        let mut resp = query_no_edns();
        resp[2] |= 0x80; // QR
        let q_end = crate::dns::types::question_end(&resp).unwrap();
        resp.truncate(q_end);
        resp.extend_from_slice(&[0xFF; 200]); // pretend answer payload

        let out = truncate_response(&resp);
        assert_eq!(out[2] & 0b0000_0010, 0b0000_0010, "TC bit set");
        assert_eq!(&out[6..12], &[0, 0, 0, 0, 0, 0], "AN/NS/AR counts cleared");
        // Question section preserved.
        assert_eq!(&out[12..], &resp[12..q_end]);
    }
}
