//! What a box and its relay say to each other. The box opens one stream
//! first, the control stream, where each side writes one JSON object per
//! line ([`Control`]). Every other stream the relay opens, one per device
//! connection: it starts with an [`Opening`] — whose connection it is — and
//! then carries the connection's bytes, still encrypted for the box.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The protocol a box speaks; a relay turns away one it doesn't know.
pub const PROTOCOL: u32 = 1;
/// A control line longer than this is a broken peer.
const MAX_LINE: usize = 64 * 1024;
const OPENING_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Control {
    /// Box → relay, first thing.
    Hello { protocol: u32, software: String },
    /// Relay → box: it's in. `name` is the box's own name under the relay's
    /// zone; `names` everything the relay passes on to it.
    Welcome {
        id: String,
        name: String,
        names: Vec<String>,
    },
    /// Relay → box: not now, and why. The relay closes the connection.
    Refused { reason: String },
}

pub async fn send<W: AsyncWrite + Unpin>(w: &mut W, msg: &Control) -> io::Result<()> {
    let mut line = serde_json::to_vec(msg).map_err(io::Error::other)?;
    line.push(b'\n');
    w.write_all(&line).await?;
    w.flush().await
}

/// The next message; `None` when the other side has finished.
pub async fn recv<R: AsyncBufReadExt + Unpin>(r: &mut R) -> io::Result<Option<Control>> {
    let mut line = Vec::new();
    let n = (&mut *r)
        .take(MAX_LINE as u64 + 1)
        .read_until(b'\n', &mut line)
        .await?;
    if n == 0 {
        return Ok(None);
    }
    if line.len() > MAX_LINE {
        return Err(io::Error::other("control line too long"));
    }
    serde_json::from_slice(&line)
        .map(Some)
        .map_err(io::Error::other)
}

/// Whose a connection the relay passes on is, and which of the relay's
/// ports it came in on (443 or 853: how the box should take it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Opening {
    pub port: u16,
    pub from: SocketAddr,
}

impl Opening {
    /// `[version][port][4|6][address][client port]`, all big-endian.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![OPENING_VERSION];
        out.extend_from_slice(&self.port.to_be_bytes());
        match self.from.ip() {
            IpAddr::V4(v4) => {
                out.push(4);
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.push(6);
                out.extend_from_slice(&v6.octets());
            }
        }
        out.extend_from_slice(&self.from.port().to_be_bytes());
        out
    }

    pub async fn read<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Self> {
        if r.read_u8().await? != OPENING_VERSION {
            return Err(io::Error::other("unknown opening"));
        }
        let port = r.read_u16().await?;
        let ip = match r.read_u8().await? {
            4 => {
                let mut b = [0u8; 4];
                r.read_exact(&mut b).await?;
                IpAddr::V4(Ipv4Addr::from(b))
            }
            6 => {
                let mut b = [0u8; 16];
                r.read_exact(&mut b).await?;
                IpAddr::V6(Ipv6Addr::from(b))
            }
            _ => return Err(io::Error::other("unknown address family")),
        };
        let client_port = r.read_u16().await?;
        Ok(Opening {
            port,
            from: SocketAddr::new(ip, client_port),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn openings_read_back() {
        for from in ["198.51.100.7:40000", "[2001:db8::7]:1234"] {
            let o = Opening {
                port: 853,
                from: from.parse().unwrap(),
            };
            let bytes = o.encode();
            assert_eq!(Opening::read(&mut bytes.as_slice()).await.unwrap(), o);
        }
        assert!(Opening::read(&mut [9u8, 0, 0].as_slice()).await.is_err());
    }

    #[tokio::test]
    async fn control_lines_read_back() {
        let msgs = [
            Control::Hello {
                protocol: PROTOCOL,
                software: "ferrite 0.2.0".into(),
            },
            Control::Welcome {
                id: "abc".into(),
                name: "abc.r.test".into(),
                names: vec!["abc.r.test".into(), "*.abc.r.test".into()],
            },
        ];
        let mut wire = Vec::new();
        for m in &msgs {
            send(&mut wire, m).await.unwrap();
        }
        let mut r = tokio::io::BufReader::new(wire.as_slice());
        for m in &msgs {
            assert_eq!(recv(&mut r).await.unwrap().as_ref(), Some(m));
        }
        assert_eq!(recv(&mut r).await.unwrap(), None);
    }
}
