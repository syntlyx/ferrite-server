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
                    // Echo RD bit from the query.
                    if raw[2] & 0x01 != 0 {
                        servfail[2] |= 0x01;
                    }
                    let _ = socket.send_to(&servfail, src).await;
                }
                continue;
            }
        };

        tokio::spawn(async move {
            let _permit = permit;
            match crate::dns::handler::handle_query(
                raw,
                src,
                Arc::clone(&state.inner),
                state.query_tx.clone(),
            )
            .await
            {
                Ok(resp) if !resp.is_empty() => {
                    // DNS over UDP is limited to 512 bytes without EDNS0.
                    // If our response exceeds MAX_UDP_PAYLOAD just send it anyway —
                    // the client should retry over TCP if it gets a TC response.
                    if let Err(e) = socket.send_to(&resp, src).await {
                        tracing::warn!("UDP send to {}: {}", src, e);
                    }
                }
                Ok(_) => {}
                Err(e) => tracing::warn!("handle_query (UDP) for {}: {}", src, e),
            }
        });
    }
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
        if let Err(e) = timeout(IDLE_TIMEOUT, stream.read_exact(&mut raw)).await {
            tracing::warn!("TCP {}: read message: {}", src, e);
            break;
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
