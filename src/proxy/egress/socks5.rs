//! SOCKS5 egress (RFC 1928 + RFC 1929 user/pass auth).
//!
//! Issues a CONNECT with the **domain-name** address type (ATYP=0x03) so the
//! proxy resolves the host remotely — the real hostname never hits the local
//! resolver, giving no-DNS-leak for free. The returned `TcpStream` is the
//! connection to the proxy, which now tunnels bytes to the destination.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::config::EgressConfig;
use crate::error::{FeriteError, Result};

use super::{ConnectError, enable_keepalive};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Socks5Egress {
    id: String,
    proxy_addr: String,
    auth: Option<(String, String)>,
}

impl Socks5Egress {
    pub fn from_config(cfg: &EgressConfig) -> Result<Self> {
        let address = cfg
            .address
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| {
                FeriteError::Config(format!("socks5 egress '{}' requires an address", cfg.id))
            })?;
        let port = cfg.port.ok_or_else(|| {
            FeriteError::Config(format!("socks5 egress '{}' requires a port", cfg.id))
        })?;
        let auth = match (&cfg.username, &cfg.password) {
            (Some(u), Some(p)) if !u.is_empty() => Some((u.clone(), p.clone())),
            (Some(u), None) if !u.is_empty() => Some((u.clone(), String::new())),
            _ => None,
        };
        Ok(Self {
            id: cfg.id.clone(),
            proxy_addr: format!("{}:{}", address.trim(), port),
            auth,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub async fn connect(
        &self,
        host: &str,
        port: u16,
    ) -> std::result::Result<TcpStream, ConnectError> {
        self.handshake(host, port).await
    }

    async fn handshake(
        &self,
        host: &str,
        port: u16,
    ) -> std::result::Result<TcpStream, ConnectError> {
        if host.len() > 255 {
            // A caller-side limit, not a proxy fault → destination-class.
            return Err(ConnectError::destination(FeriteError::Dns(
                "socks5: hostname too long for ATYP=domain".into(),
            )));
        }

        // Phase 1 — reach the proxy and negotiate auth + send CONNECT. A failure or
        // timeout here means the proxy itself is unreachable/broken → egress-class,
        // so it counts against the breaker.
        let mut s = match timeout(CONNECT_TIMEOUT, self.negotiate(host, port)).await {
            Ok(r) => r.map_err(ConnectError::egress)?,
            Err(_) => {
                return Err(ConnectError::egress(FeriteError::Dns(format!(
                    "socks5 {}: proxy handshake timed out",
                    self.proxy_addr
                ))));
            }
        };

        // Phase 2 — wait for the CONNECT reply. The proxy has already answered the
        // greeting/auth, so it's alive; it only replies here once it has (tried to)
        // reach the *destination*. A timeout is therefore the destination being
        // slow/blackholed, NOT the egress — classifying it egress would let one dead
        // site fail-close the whole egress. So this phase is destination-class.
        let mut head = [0u8; 4];
        match timeout(CONNECT_TIMEOUT, s.read_exact(&mut head)).await {
            Ok(r) => r.map_err(|e| ConnectError::destination(io_err(e)))?,
            Err(_) => {
                return Err(ConnectError::destination(FeriteError::Dns(format!(
                    "socks5: CONNECT to {host}:{port} timed out"
                ))));
            }
        };
        // Reply: VER REP RSV ATYP BND.ADDR BND.PORT.
        if head[1] != 0x00 {
            return Err(classify_reply(head[1], host, port));
        }
        // Drain the bound address/port so the stream starts at tunneled data.
        let addr_len = match head[3] {
            0x01 => 4,
            0x04 => 16,
            0x03 => {
                let mut l = [0u8; 1];
                s.read_exact(&mut l)
                    .await
                    .map_err(|e| ConnectError::egress(io_err(e)))?;
                l[0] as usize
            }
            other => {
                return Err(ConnectError::egress(FeriteError::Dns(format!(
                    "socks5: bad reply ATYP {other}"
                ))));
            }
        };
        let mut bnd = vec![0u8; addr_len + 2];
        s.read_exact(&mut bnd)
            .await
            .map_err(|e| ConnectError::egress(io_err(e)))?;

        Ok(s)
    }

    /// Connect to the proxy, negotiate the auth method, and send the CONNECT
    /// request. Every failure here is proxy-transport (egress-class); the caller
    /// maps it accordingly. Returns the stream positioned to read the reply.
    async fn negotiate(&self, host: &str, port: u16) -> Result<TcpStream> {
        let mut s = TcpStream::connect(&self.proxy_addr)
            .await
            .map_err(|e| FeriteError::Dns(format!("socks5 connect {}: {}", self.proxy_addr, e)))?;
        enable_keepalive(&s);

        // ── Greeting: offer either user/pass or no-auth. ──
        if self.auth.is_some() {
            s.write_all(&[0x05, 0x01, 0x02]).await?;
        } else {
            s.write_all(&[0x05, 0x01, 0x00]).await?;
        }
        let mut method = [0u8; 2];
        s.read_exact(&mut method).await?;
        if method[0] != 0x05 {
            return Err(FeriteError::Dns(
                "socks5: bad version in method reply".into(),
            ));
        }
        match method[1] {
            0x00 => {} // no auth required
            0x02 => self.user_pass_auth(&mut s).await?,
            0xFF => {
                return Err(FeriteError::Dns(
                    "socks5: no acceptable auth methods".into(),
                ));
            }
            other => {
                return Err(FeriteError::Dns(format!(
                    "socks5: unexpected method {other}"
                )));
            }
        }

        // ── CONNECT request (ATYP=domain → remote resolution). ──
        let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        req.extend_from_slice(host.as_bytes());
        req.extend_from_slice(&port.to_be_bytes());
        s.write_all(&req).await?;
        Ok(s)
    }

    async fn user_pass_auth(&self, s: &mut TcpStream) -> Result<()> {
        let (user, pass) = self.auth.as_ref().ok_or_else(|| {
            FeriteError::Dns("socks5: server requires auth but none configured".into())
        })?;
        if user.len() > 255 || pass.len() > 255 {
            return Err(FeriteError::Dns(
                "socks5: username/password too long".into(),
            ));
        }
        let mut msg = vec![0x01, user.len() as u8];
        msg.extend_from_slice(user.as_bytes());
        msg.push(pass.len() as u8);
        msg.extend_from_slice(pass.as_bytes());
        s.write_all(&msg).await?;

        let mut reply = [0u8; 2];
        s.read_exact(&mut reply).await?;
        if reply[1] != 0x00 {
            return Err(FeriteError::Dns("socks5: authentication failed".into()));
        }
        Ok(())
    }
}

fn io_err(e: std::io::Error) -> FeriteError {
    FeriteError::Dns(format!("socks5 io: {e}"))
}

/// Classify a non-zero SOCKS5 CONNECT reply code (RFC 1928 §6). Reachability
/// results for the *destination* (network/host unreachable, refused, TTL expired,
/// blocked by ruleset) are destination-class so one dead site can't fail-close the
/// whole egress; codes that indicate the *proxy* itself failed or can't perform the
/// request (general failure, command / address-type unsupported) are egress-class.
fn classify_reply(code: u8, host: &str, port: u16) -> ConnectError {
    let err = FeriteError::Dns(format!(
        "socks5: CONNECT to {host}:{port} failed (reply code {code})"
    ));
    match code {
        0x02..=0x06 => ConnectError::destination(err),
        _ => ConnectError::egress(err), // 0x01 general failure, 0x07/0x08 capability, unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::egress::ConnectErrorKind;

    #[test]
    fn reply_codes_classify_destination_vs_egress() {
        // Reachability failures for the destination must NOT trip the breaker.
        for code in [0x02, 0x03, 0x04, 0x05, 0x06] {
            assert_eq!(
                classify_reply(code, "example.com", 443).kind(),
                ConnectErrorKind::Destination,
                "reply code {code:#x} should be destination-class"
            );
        }
        // Proxy-side / capability failures should count against the egress breaker.
        for code in [0x01, 0x07, 0x08, 0x7f] {
            assert_eq!(
                classify_reply(code, "example.com", 443).kind(),
                ConnectErrorKind::Egress,
                "reply code {code:#x} should be egress-class"
            );
        }
    }
}
