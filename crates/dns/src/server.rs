use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use crate::ctx::DnsCtx;
use ferrite_core::error::FeriteError;

/// Maximum DNS UDP payload (EDNS0).
const MAX_UDP_PAYLOAD: usize = 4096;
/// Maximum DNS TCP message size (2-byte length prefix → max 65535).
const MAX_TCP_PAYLOAD: usize = 65535;

/// Start UDP and TCP DNS listeners, plus the cache janitor.
/// Runs until a fatal error or the process exits.
pub async fn run(ctx: Arc<DnsCtx>) -> anyhow::Result<()> {
    let bind_addr = ctx.dns_config.bind_addr;

    let udp = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| FeriteError::Dns(format!("UDP bind {}: {}", bind_addr, e)))?;

    let tcp = TcpListener::bind(bind_addr)
        .await
        .map_err(|e| FeriteError::Dns(format!("TCP bind {}: {}", bind_addr, e)))?;

    tracing::info!("DNS server listening on {}", bind_addr);

    // Cache janitor.
    tokio::spawn(crate::cache::janitor(Arc::clone(&ctx.dns_cache)));

    tokio::try_join!(udp_loop(udp, Arc::clone(&ctx)), tcp_loop(tcp, ctx))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// UDP
// ---------------------------------------------------------------------------

/// The DNS receive loop.
///
/// On Linux it moves datagrams in batches ([`crate::udp_batch`]): after the
/// in-memory pipeline was cut to a few hundred nanoseconds per query, the two
/// system calls around it are what a query mostly costs, and `recvmmsg` /
/// `sendmmsg` amortise them over a burst. Elsewhere — and for a single
/// datagram, where a batch holds one — it is the same loop one datagram at a
/// time.
#[cfg(target_os = "linux")]
async fn udp_loop(socket: UdpSocket, ctx: Arc<DnsCtx>) -> anyhow::Result<()> {
    use crate::udp_batch::{BATCH, UdpBatch};

    let socket = Arc::new(socket);
    let mut batch = UdpBatch::new(MAX_UDP_PAYLOAD);
    // Answers settled from memory, sent together once the batch is worked
    // through. Worst case every datagram in the batch is answered inline.
    let mut replies: Vec<(Vec<u8>, SocketAddr)> = Vec::with_capacity(BATCH);

    loop {
        let received = match batch.recv(&socket).await {
            Ok(n) => n,
            Err(e) => {
                tracing::error!("UDP recvmmsg: {}", e);
                continue;
            }
        };

        replies.clear();
        for i in 0..received {
            let Some((raw, src)) = batch.datagram(i) else {
                continue; // a source address in a family we can't answer
            };
            if let Some(answer) = dispatch(raw, src, &socket, &ctx) {
                replies.push(answer);
            }
        }

        if !replies.is_empty()
            && let Err(e) = batch.send(&socket, &replies).await
        {
            tracing::warn!("UDP sendmmsg: {}", e);
        }
    }
}

#[cfg(not(target_os = "linux"))]
async fn udp_loop(socket: UdpSocket, ctx: Arc<DnsCtx>) -> anyhow::Result<()> {
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
        if let Some((resp, dest)) = dispatch(&buf[..len], src, &socket, &ctx) {
            send_datagram(&socket, &resp, dest).await;
        }
    }
}

/// Handle one received datagram.
///
/// The in-memory half of the pipeline runs right here, on the receive loop: a
/// cache hit, a block, a local record or a routing redirect is settled in a few
/// hundred nanoseconds, while handing it to a task costs ~340 ns on its own —
/// more than the answer itself. Only a query that has to wait for the network
/// gets a task, a permit and a copy of the datagram.
///
/// Returns the answer to send back, when there is one to send now; a query that
/// went upstream answers from its own task.
fn dispatch(
    raw: &[u8],
    src: SocketAddr,
    socket: &Arc<UdpSocket>,
    ctx: &Arc<DnsCtx>,
) -> Option<(Vec<u8>, SocketAddr)> {
    let max_udp = client_udp_payload(raw);
    let pending = match crate::handler::decide(raw, src, ctx) {
        crate::handler::Decision::Answer(resp) => {
            return for_wire(resp, max_udp).map(|resp| (resp, src));
        }
        crate::handler::Decision::Drop => return None,
        crate::handler::Decision::Upstream(pending) => pending,
    };

    let raw = raw.to_vec();
    let ctx = Arc::clone(ctx);
    let socket = Arc::clone(socket);

    // Shed load immediately if too many queries are in-flight: prevents
    // memory exhaustion when upstream is slow (unbounded spawn otherwise).
    let permit = match ctx.query_semaphore.clone().try_acquire_owned() {
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
                    0x80, 0x02, // QR=1, OPCODE=0, AA=0, TC=0, RD=0; RA=0, RCODE=SERVFAIL(2)
                    0x00, 0x00, // QDCOUNT=0
                    0x00, 0x00, // ANCOUNT=0
                    0x00, 0x00, // NSCOUNT=0
                    0x00, 0x00, // ARCOUNT=0
                ];
                // Echo RD bit from the query. Byte 2 only exists on a header of
                // at least 3 bytes — a 2-byte datagram passes the guard above
                // but has no flags byte, so bounds-check before reading it
                // (otherwise a 2-byte packet panics this loop).
                if raw.len() >= 3 && raw[2] & 0x01 != 0 {
                    servfail[2] |= 0x01;
                }
                return Some((servfail.to_vec(), src));
            }
            return None;
        }
    };

    tokio::spawn(async move {
        let _permit = permit;
        let resp = crate::handler::resolve_upstream(&raw, pending, &ctx).await;
        if let Some(resp) = for_wire(resp, max_udp) {
            send_datagram(&socket, &resp, src).await;
        }
    });
    None
}

/// The client's maximum UDP payload size: 512 bytes by default (RFC 1035), or
/// the EDNS0 advertised size (clamped to our receive buffer) when the query
/// carries an OPT record. Falls back to 512 for unparseable queries.
///
/// One EDNS field is not worth decoding the whole message for — this runs on
/// every datagram, before the handler has even started — so it walks the wire
/// bytes instead.
fn client_udp_payload(query: &[u8]) -> usize {
    ferrite_core::wire::udp_payload(query).min(MAX_UDP_PAYLOAD)
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
    match ferrite_core::wire::question_end(resp) {
        Some(end) => out.extend_from_slice(&resp[12..end]),
        // No parseable question — keep the header consistent by zeroing QDCOUNT.
        None => {
            out[4] = 0;
            out[5] = 0;
        }
    }
    out
}

/// Prepare an answer for the wire: nothing to send for an empty one, and an
/// answer larger than the client said it can accept over UDP is truncated so it
/// retries over TCP rather than receiving an oversized datagram the network may
/// silently drop (RFC 1035 §4.2.1).
fn for_wire(resp: Vec<u8>, max_udp: usize) -> Option<Vec<u8>> {
    if resp.is_empty() {
        return None;
    }
    Some(if resp.len() > max_udp {
        truncate_response(&resp)
    } else {
        resp
    })
}

/// Send one answer back. The socket is non-blocking and its send buffer is all
/// but always free, so the common case never yields; `send_to` covers the
/// moment it isn't.
async fn send_datagram(socket: &UdpSocket, datagram: &[u8], dest: SocketAddr) {
    match socket.try_send_to(datagram, dest) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            if let Err(e) = socket.send_to(datagram, dest).await {
                tracing::warn!("UDP send to {}: {}", dest, e);
            }
        }
        Err(e) => tracing::warn!("UDP send to {}: {}", dest, e),
    }
}

// ---------------------------------------------------------------------------
// TCP
// ---------------------------------------------------------------------------

async fn tcp_loop(listener: TcpListener, ctx: Arc<DnsCtx>) -> anyhow::Result<()> {
    loop {
        let (stream, src) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("TCP accept: {}", e);
                continue;
            }
        };

        let ctx = Arc::clone(&ctx);
        tokio::spawn(async move {
            if let Err(e) = handle_tcp_connection(stream, src, ctx).await {
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
    ctx: Arc<DnsCtx>,
) -> anyhow::Result<()> {
    use tokio::time::{Duration, timeout};
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

        let _permit = match ctx.query_semaphore.try_acquire() {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!(
                    "query concurrency limit reached, dropping TCP query from {}",
                    src
                );
                break;
            }
        };

        let response = match crate::handler::handle_query(raw, src, Arc::clone(&ctx)).await {
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
        let q_end = ferrite_core::wire::question_end(&resp).unwrap();
        resp.truncate(q_end);
        resp.extend_from_slice(&[0xFF; 200]); // pretend answer payload

        let out = truncate_response(&resp);
        assert_eq!(out[2] & 0b0000_0010, 0b0000_0010, "TC bit set");
        assert_eq!(&out[6..12], &[0, 0, 0, 0, 0, 0], "AN/NS/AR counts cleared");
        // Question section preserved.
        assert_eq!(&out[12..], &resp[12..q_end]);
    }
}
