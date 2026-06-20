//! DirectEvasion egress: like Direct, but defeats SNI-based DPI by splitting the
//! TLS ClientHello across two TCP segments so a middlebox that matches the SNI
//! within a single segment never sees the whole host name.
//!
//! The bytes are never modified — only the write boundary changes — so the server
//! reassembles an identical ClientHello (no MITM, no handshake corruption). This
//! is a pure-userspace technique (TCP_NODELAY + a flush between fragments); the
//! stronger raw-socket tricks (out-of-order send, faked TTL/checksum) and TLS
//! record-layer splitting are deliberate follow-ups, not in this slice.

use std::io;
use std::sync::Arc;

use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::Result;
use crate::upstream::ZoneRouter;

/// Tunables for ClientHello fragmentation.
#[derive(Clone, Copy)]
pub struct EvasionParams {
    /// Fixed byte offset to split the ClientHello at. `None` = auto-split inside
    /// the SNI host name (the most effective spot, and what most clients need).
    pub seg_position: Option<u16>,
}

/// A Direct-style egress that fragments the first TLS ClientHello write.
pub struct EvasionEgress {
    id: String,
    upstream: Arc<ZoneRouter>,
    params: EvasionParams,
}

impl EvasionEgress {
    pub fn new(id: String, upstream: Arc<ZoneRouter>, seg_position: Option<u16>) -> Self {
        Self { id, upstream, params: EvasionParams { seg_position } }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn params(&self) -> EvasionParams {
        self.params
    }

    /// Connect straight to the destination (resolved via ferrite's upstream, like
    /// Direct) with Nagle disabled so each fragment lands in its own TCP segment.
    pub async fn connect(&self, host: &str, port: u16) -> Result<TcpStream> {
        let stream = super::direct::direct_connect(&self.upstream, host, port).await?;
        let _ = stream.set_nodelay(true);
        Ok(stream)
    }
}

/// Write the buffered TLS ClientHello split into two TCP segments. Falls back to a
/// single write when there is no usable split point (not a ClientHello with SNI,
/// or an out-of-range configured offset).
pub async fn write_split<W: AsyncWrite + Unpin>(
    w: &mut W,
    buf: &[u8],
    params: &EvasionParams,
) -> io::Result<()> {
    match split_position(buf, params) {
        Some(pos) => {
            w.write_all(&buf[..pos]).await?;
            w.flush().await?; // force the first segment out before the rest
            w.write_all(&buf[pos..]).await?;
            w.flush().await?;
        }
        None => w.write_all(buf).await?,
    }
    Ok(())
}

/// Where to cut the ClientHello: a configured in-bounds offset if given, else the
/// middle of the SNI host name. `None` when no in-bounds split exists.
fn split_position(buf: &[u8], params: &EvasionParams) -> Option<usize> {
    if let Some(p) = params.seg_position {
        let p = p as usize;
        if p > 0 && p < buf.len() {
            return Some(p);
        }
    }
    let (start, len) = super::super::sni::sni_host_range(buf)?;
    let pos = start + len / 2;
    (pos > 0 && pos < buf.len()).then_some(pos)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[test]
    fn configured_offset_is_used_when_in_bounds() {
        let buf = vec![0u8; 40];
        assert_eq!(split_position(&buf, &EvasionParams { seg_position: Some(10) }), Some(10));
    }

    #[test]
    fn out_of_range_or_zero_offset_falls_through_to_sni() {
        // Junk has no SNI, so with no usable offset there's no split point.
        let junk = b"GET / HTTP/1.1\r\n\r\n".to_vec();
        assert_eq!(split_position(&junk, &EvasionParams { seg_position: Some(0) }), None);
        assert_eq!(split_position(&junk, &EvasionParams { seg_position: Some(9999) }), None);
        assert_eq!(split_position(&junk, &EvasionParams { seg_position: None }), None);
    }

    #[tokio::test]
    async fn write_split_preserves_every_byte() {
        let data: Vec<u8> = (0..=200).collect();
        let (mut tx, mut rx) = tokio::io::duplex(64 * 1024);
        let payload = data.clone();
        let writer = tokio::spawn(async move {
            write_split(&mut tx, &payload, &EvasionParams { seg_position: Some(73) })
                .await
                .unwrap();
            tx.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        rx.read_to_end(&mut got).await.unwrap();
        writer.await.unwrap();
        assert_eq!(got, data, "split must not alter the byte stream");
    }

    #[tokio::test]
    async fn no_split_point_still_writes_everything() {
        let data = b"not a tls clienthello".to_vec();
        let (mut tx, mut rx) = tokio::io::duplex(4096);
        let payload = data.clone();
        let writer = tokio::spawn(async move {
            write_split(&mut tx, &payload, &EvasionParams { seg_position: None })
                .await
                .unwrap();
            tx.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        rx.read_to_end(&mut got).await.unwrap();
        writer.await.unwrap();
        assert_eq!(got, data);
    }
}
