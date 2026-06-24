//! Pooled, raw DNS-over-stream upstream (TCP per RFC 7766, optionally wrapped in
//! TLS for DoT per RFC 7858).
//!
//! Unlike the hickory-based resolvers, this forwards the **raw wire query**
//! verbatim and returns the **raw wire response** untouched — so DNSSEC records
//! (RRSIG/DNSKEY/NSEC…) ride through unmodified regardless of transport. DNSSEC
//! is a property of the data, not the channel, so every stream transport must
//! treat it the same way (see [`crate::upstream::tunneled`], which does the same
//! over an egress).
//!
//! Connections are **pooled**: an idle connection is reused for the next query
//! instead of paying a fresh TCP (and TLS) handshake every time. This is what
//! makes DNSSEC fast — large signed answers force UDP truncation, and the TCP
//! fallback would otherwise reconnect on every single query.

use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::error::{FeriteError, Result};
use crate::upstream::tunneled::client_config;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const IO_TIMEOUT: Duration = Duration::from_secs(8);
/// How long an idle pooled connection is eligible for reuse. Kept below the
/// idle timeout typical DNS-over-TCP servers enforce (RFC 7766 suggests a few
/// seconds to tens of seconds) so we rarely hand out a connection the peer has
/// already closed; the stale-retry in `exchange` covers the races that remain.
const IDLE_TTL: Duration = Duration::from_secs(10);
/// Cap on connections kept warm between queries. Bursts may open more, but only
/// this many are retained once the burst subsides.
const MAX_IDLE: usize = 4;

/// TLS parameters for a DoT pool. Absent for plain DNS-over-TCP.
struct TlsParts {
    connector: TlsConnector,
    server_name: ServerName<'static>,
}

/// One pooled connection, plain or TLS-wrapped.
enum Conn {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

struct Idle {
    conn: Conn,
    since: Instant,
}

/// A pool of persistent stream connections to a single resolver address.
pub struct StreamPool {
    addr: SocketAddr,
    tls: Option<TlsParts>,
    idle: Mutex<Vec<Idle>>,
}

impl StreamPool {
    /// Plain DNS-over-TCP pool.
    pub fn plain(addr: SocketAddr) -> Self {
        Self {
            addr,
            tls: None,
            idle: Mutex::new(Vec::new()),
        }
    }

    /// DoT (TLS) pool. `tls_name` is the SNI / certificate name.
    pub fn tls(addr: SocketAddr, tls_name: &str) -> Result<Self> {
        let server_name = ServerName::try_from(tls_name.to_string())
            .map_err(|e| FeriteError::Config(format!("invalid DoT tls_name '{tls_name}': {e}")))?;
        Ok(Self {
            addr,
            tls: Some(TlsParts {
                connector: TlsConnector::from(client_config()?),
                server_name,
            }),
            idle: Mutex::new(Vec::new()),
        })
    }

    /// Send `raw` and return the raw response. Reuses a pooled connection when
    /// one is available, falling back to a fresh connection (also retried once
    /// if a reused connection turns out to be stale).
    pub async fn exchange(&self, raw: &[u8]) -> Result<Vec<u8>> {
        // 1. Try a warm connection. A pooled connection the peer closed while
        //    idle surfaces as an I/O error here; we just drop it and connect
        //    fresh below — one cheap retry, never a loop.
        if let Some(mut conn) = self.take_idle()
            && let Ok(resp) = exchange_on(&mut conn, raw).await
        {
            self.put_idle(conn);
            return Ok(resp);
        }

        // 2. Fresh connection. A connection is only returned to the pool after a
        //    fully successful exchange, so pooled connections are always in a
        //    clean (no half-read response) state.
        let mut conn = self.connect().await?;
        let resp = exchange_on(&mut conn, raw).await?;
        self.put_idle(conn);
        Ok(resp)
    }

    /// Pop the most-recently-returned connection that hasn't aged out, dropping
    /// any expired ones encountered along the way.
    fn take_idle(&self) -> Option<Conn> {
        let mut idle = self.idle.lock().unwrap();
        while let Some(entry) = idle.pop() {
            if entry.since.elapsed() < IDLE_TTL {
                return Some(entry.conn);
            }
            // Expired — let it drop (closes the socket) and keep looking.
        }
        None
    }

    /// Return a healthy connection to the pool, or drop it if the pool is full.
    fn put_idle(&self, conn: Conn) {
        let mut idle = self.idle.lock().unwrap();
        if idle.len() < MAX_IDLE {
            idle.push(Idle {
                conn,
                since: Instant::now(),
            });
        }
    }

    /// Open a fresh connection (TCP, then TLS if configured).
    async fn connect(&self) -> Result<Conn> {
        let tcp = timeout(CONNECT_TIMEOUT, TcpStream::connect(self.addr))
            .await
            .map_err(|_| FeriteError::Dns(format!("tcp connect timeout to {}", self.addr)))?
            .map_err(|e| FeriteError::Dns(format!("tcp connect to {}: {e}", self.addr)))?;
        // Nagle off: a DNS query is a single small write we want on the wire
        // immediately, not coalesced.
        let _ = tcp.set_nodelay(true);

        match &self.tls {
            None => Ok(Conn::Plain(tcp)),
            Some(tls) => {
                let stream = timeout(
                    CONNECT_TIMEOUT,
                    tls.connector.connect(tls.server_name.clone(), tcp),
                )
                .await
                .map_err(|_| FeriteError::Dns(format!("tls handshake timeout to {}", self.addr)))?
                .map_err(|e| FeriteError::Dns(format!("tls handshake to {}: {e}", self.addr)))?;
                Ok(Conn::Tls(Box::new(stream)))
            }
        }
    }
}

/// One DNS-over-TCP exchange (RFC 7766): write `[u16 len][message]`, read the
/// same framing back. Leaves the connection fully drained on success so it can
/// be pooled; on any error the caller drops the connection.
async fn exchange_on(conn: &mut Conn, raw: &[u8]) -> Result<Vec<u8>> {
    match conn {
        Conn::Plain(s) => framed_exchange(s, raw).await,
        Conn::Tls(s) => framed_exchange(s, raw).await,
    }
}

async fn framed_exchange<S>(s: &mut S, raw: &[u8]) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if raw.len() > u16::MAX as usize {
        return Err(FeriteError::Dns("query too large for TCP framing".into()));
    }
    let fut = async {
        let mut framed = Vec::with_capacity(raw.len() + 2);
        framed.extend_from_slice(&(raw.len() as u16).to_be_bytes());
        framed.extend_from_slice(raw);
        s.write_all(&framed).await.map_err(io_dns)?;
        s.flush().await.map_err(io_dns)?;

        let mut len = [0u8; 2];
        s.read_exact(&mut len).await.map_err(io_dns)?;
        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
        s.read_exact(&mut buf).await.map_err(io_dns)?;
        Ok::<_, FeriteError>(buf)
    };
    timeout(IO_TIMEOUT, fut)
        .await
        .map_err(|_| FeriteError::Dns("tcp exchange timed out".into()))?
}

fn io_dns(e: std::io::Error) -> FeriteError {
    FeriteError::Dns(format!("stream dns io: {e}"))
}

/// A direct (no-egress) DoT upstream backed by a [`StreamPool`].
///
/// Forwards the query verbatim, so the DNSSEC-OK bit set by the handler and any
/// returned signatures are preserved — the hickory-based resolver this replaces
/// rebuilt the query via `lookup(name, type)` and silently dropped both.
pub struct StreamResolver {
    pool: StreamPool,
    label: String,
}

impl StreamResolver {
    /// Direct DoT to `address:port` with SNI/cert name `tls_name`.
    pub fn dot(address: &str, port: u16, tls_name: &str) -> Result<Self> {
        let addr: SocketAddr = format!("{address}:{port}")
            .parse()
            .map_err(|e| FeriteError::Config(format!("invalid DoT address: {e}")))?;
        Ok(Self {
            pool: StreamPool::tls(addr, tls_name)?,
            label: format!("dot://{address}:{port}#{tls_name}"),
        })
    }

    pub async fn resolve_raw(&self, raw: Vec<u8>) -> Result<(Vec<u8>, String)> {
        let resp = self.pool.exchange(&raw).await?;
        Ok((resp, self.label.clone()))
    }

    pub fn label(&self) -> &str {
        &self.label
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// Spawn a length-prefixed echo server that answers `replies` queries then
    /// closes. Returns its address.
    async fn echo_server(replies: usize) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            for _ in 0..replies {
                let mut len = [0u8; 2];
                if s.read_exact(&mut len).await.is_err() {
                    break;
                }
                let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
                if s.read_exact(&mut buf).await.is_err() {
                    break;
                }
                let mut out = (buf.len() as u16).to_be_bytes().to_vec();
                out.extend_from_slice(&buf);
                s.write_all(&out).await.unwrap();
                s.flush().await.unwrap();
            }
        });
        addr
    }

    #[tokio::test]
    async fn forwards_raw_bytes_unchanged() {
        let addr = echo_server(1).await;
        let pool = StreamPool::plain(addr);
        let resp = pool.exchange(&[0xab, 0xcd, 0x01, 0x02]).await.unwrap();
        assert_eq!(resp, vec![0xab, 0xcd, 0x01, 0x02]);
    }

    #[tokio::test]
    async fn reuses_a_pooled_connection() {
        // The echo server accepts exactly one connection. Two sequential
        // exchanges both succeeding proves the second reused the first's
        // connection rather than dialing again.
        let addr = echo_server(2).await;
        let pool = StreamPool::plain(addr);
        assert_eq!(pool.exchange(&[1, 2, 3]).await.unwrap(), vec![1, 2, 3]);
        assert_eq!(pool.exchange(&[4, 5, 6]).await.unwrap(), vec![4, 5, 6]);
        assert_eq!(
            pool.idle.lock().unwrap().len(),
            1,
            "connection back in pool"
        );
    }

    #[tokio::test]
    async fn reconnects_when_pooled_connection_is_stale() {
        // First server handles one query then closes. The pooled (now dead)
        // connection should be detected stale on the next query and replaced.
        let addr = echo_server(1).await;
        let pool = StreamPool::plain(addr);
        assert_eq!(pool.exchange(&[1]).await.unwrap(), vec![1]);

        // Stand up a new listener on the SAME address so the retry can connect.
        // (The OS frees the port once the first server's task ends.)
        // Give the first server a beat to drop its socket.
        for _ in 0..50 {
            if TcpListener::bind(addr).await.is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
        let listener = TcpListener::bind(addr).await.unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut len = [0u8; 2];
            s.read_exact(&mut len).await.unwrap();
            let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
            s.read_exact(&mut buf).await.unwrap();
            let mut out = (buf.len() as u16).to_be_bytes().to_vec();
            out.extend_from_slice(&buf);
            s.write_all(&out).await.unwrap();
            s.flush().await.unwrap();
        });

        assert_eq!(pool.exchange(&[2]).await.unwrap(), vec![2]);
    }
}
