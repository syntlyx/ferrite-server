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

use super::enable_keepalive;

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

    pub async fn connect(&self, host: &str, port: u16) -> Result<TcpStream> {
        timeout(CONNECT_TIMEOUT, self.handshake(host, port))
            .await
            .map_err(|_| FeriteError::Dns(format!("socks5 {} timeout", self.proxy_addr)))?
    }

    async fn handshake(&self, host: &str, port: u16) -> Result<TcpStream> {
        if host.len() > 255 {
            return Err(FeriteError::Dns(
                "socks5: hostname too long for ATYP=domain".into(),
            ));
        }

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

        // Reply: VER REP RSV ATYP BND.ADDR BND.PORT
        let mut head = [0u8; 4];
        s.read_exact(&mut head).await?;
        if head[1] != 0x00 {
            return Err(FeriteError::Dns(format!(
                "socks5: CONNECT to {host}:{port} failed (reply code {})",
                head[1]
            )));
        }
        // Drain the bound address/port so the stream starts at tunneled data.
        let addr_len = match head[3] {
            0x01 => 4,
            0x04 => 16,
            0x03 => {
                let mut l = [0u8; 1];
                s.read_exact(&mut l).await?;
                l[0] as usize
            }
            other => return Err(FeriteError::Dns(format!("socks5: bad reply ATYP {other}"))),
        };
        let mut bnd = vec![0u8; addr_len + 2];
        s.read_exact(&mut bnd).await?;

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
