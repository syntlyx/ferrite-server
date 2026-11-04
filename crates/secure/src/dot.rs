//! DNS over TLS (RFC 7858): two-byte length, message, repeat. A client may
//! send several queries before reading any answer — Android does — so each is
//! answered as it resolves, not in turn.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Semaphore, mpsc};
use tokio::time::timeout;

use ferrite_dns::ctx::DnsCtx;

use crate::gate::Gate;

/// A connection with nothing to say this long is closed; the device reopens
/// it when it next asks.
const IDLE: Duration = Duration::from_secs(60);
/// One message has this long to arrive whole once its length did.
const BODY: Duration = Duration::from_secs(10);
/// Queries in flight on one connection.
const PER_CONNECTION: usize = 32;
const MAX_MESSAGE: usize = 65_535;

pub(crate) async fn serve<S>(
    stream: S,
    peer: SocketAddr,
    client_id: Option<String>,
    ctx: Arc<DnsCtx>,
    gate: Arc<Gate>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // A stream passed on by a proxy can't say whose it is, and every one of
    // them would look like it came from home.
    if gate.trusts(peer.ip()) {
        tracing::warn!(
            "dot: {peer} is a proxy, which can't say who it forwards for over DNS over TLS; \
             forward the port to this box directly"
        );
        return;
    }
    let (mut rd, mut wr) = tokio::io::split(stream);
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(PER_CONNECTION);

    let writer = tokio::spawn(async move {
        while let Some(answer) = rx.recv().await {
            let mut framed = Vec::with_capacity(answer.len() + 2);
            framed.extend_from_slice(&(answer.len() as u16).to_be_bytes());
            framed.extend_from_slice(&answer);
            if wr.write_all(&framed).await.is_err() || wr.flush().await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    });

    let in_flight = Arc::new(Semaphore::new(PER_CONNECTION));
    loop {
        let mut len = [0u8; 2];
        match timeout(IDLE, rd.read_exact(&mut len)).await {
            Ok(Ok(_)) => {}
            _ => break,
        }
        let len = u16::from_be_bytes(len) as usize;
        if len == 0 || len > MAX_MESSAGE {
            break;
        }
        let mut raw = vec![0u8; len];
        match timeout(BODY, rd.read_exact(&mut raw)).await {
            Ok(Ok(_)) => {}
            _ => break,
        }
        if !gate.allows(peer.ip(), client_id.as_deref()) {
            let answer = ferrite_dns::handler::refused(&raw);
            if answer.is_empty() || tx.send(answer).await.is_err() {
                break;
            }
            continue;
        }
        let Ok(slot) = Arc::clone(&in_flight).acquire_owned().await else {
            break;
        };
        // The box-wide cap on queries waiting for upstream, as plain TCP has.
        let Ok(permit) = Arc::clone(&ctx.query_semaphore).try_acquire_owned() else {
            tracing::warn!("query concurrency limit reached, dropping a DoT query from {peer}");
            continue;
        };
        let (tx, ctx, id) = (tx.clone(), Arc::clone(&ctx), client_id.clone());
        tokio::spawn(async move {
            let answer = ferrite_dns::handler::handle_query_as(raw, peer, id.as_deref(), ctx).await;
            drop(permit);
            if let Ok(answer) = answer
                && !answer.is_empty()
            {
                let _ = tx.send(answer).await;
            }
            drop(slot);
        });
    }
    // Answers still on their way are written before the connection closes.
    drop(tx);
    let _ = writer.await;
}
