use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use crate::error::{FeriteError, Result};

const UDP_TIMEOUT: Duration = Duration::from_secs(5);
const TCP_TIMEOUT: Duration = Duration::from_secs(8);
/// Max DNS message size over UDP (EDNS0).
const MAX_UDP_SIZE: usize = 4096;

/// A plain DNS upstream (UDP with automatic TCP fallback on truncation).
pub struct PlainResolver {
    addr: SocketAddr,
    label: String,
}

impl PlainResolver {
    pub fn new(address: &str, port: u16) -> Result<Self> {
        let addr: SocketAddr = format!("{}:{}", address, port)
            .parse()
            .map_err(|e| FeriteError::Config(format!("invalid upstream address: {}", e)))?;
        Ok(Self {
            addr,
            label: format!("{}:{}", address, port),
        })
    }

    /// Forward raw DNS query bytes to the upstream server and return the raw response.
    pub async fn resolve_raw(&self, raw: Vec<u8>) -> Result<(Vec<u8>, String)> {
        // Try UDP first.
        let response = self.send_udp(&raw).await?;

        // If TC (truncated) bit is set, retry over TCP.
        if is_truncated(&response) {
            tracing::debug!("upstream {} set TC bit, retrying over TCP", self.addr);
            let tcp_response = self.send_tcp(&raw).await?;
            return Ok((tcp_response, self.label.clone()));
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

        Ok(buf[..n].to_vec())
    }

    async fn send_tcp(&self, raw: &[u8]) -> Result<Vec<u8>> {
        let mut stream = timeout(TCP_TIMEOUT, TcpStream::connect(self.addr))
            .await
            .map_err(|_| FeriteError::Dns(format!("tcp connect timeout to {}", self.addr)))?
            .map_err(|e| FeriteError::Dns(format!("tcp connect to {}: {}", self.addr, e)))?;

        // DNS over TCP: 2-byte length prefix (big-endian) + message bytes.
        let len = raw.len() as u16;
        let mut framed = Vec::with_capacity(2 + raw.len());
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(raw);

        timeout(TCP_TIMEOUT, stream.write_all(&framed))
            .await
            .map_err(|_| FeriteError::Dns(format!("tcp write timeout to {}", self.addr)))?
            .map_err(|e| FeriteError::Dns(format!("tcp write to {}: {}", self.addr, e)))?;

        // Read the 2-byte length prefix.
        let mut len_buf = [0u8; 2];
        timeout(TCP_TIMEOUT, stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| FeriteError::Dns(format!("tcp read len timeout from {}", self.addr)))?
            .map_err(|e| FeriteError::Dns(format!("tcp read len from {}: {}", self.addr, e)))?;

        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 || msg_len > 8192 {
            return Err(FeriteError::Dns(format!(
                "tcp response length invalid ({} bytes) from {}",
                msg_len, self.addr
            )));
        }

        let mut response = vec![0u8; msg_len];
        timeout(TCP_TIMEOUT, stream.read_exact(&mut response))
            .await
            .map_err(|_| FeriteError::Dns(format!("tcp read body timeout from {}", self.addr)))?
            .map_err(|e| FeriteError::Dns(format!("tcp read body from {}: {}", self.addr, e)))?;

        Ok(response)
    }

    pub fn label(&self) -> &str {
        &self.label
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
