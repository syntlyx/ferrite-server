//! WireGuard `.conf` parser (`[Interface]`/`[Peer]`, `wg-quick` format) — the
//! text the web UI pastes in, turned into the fields ferrite needs to bring up
//! a userspace client tunnel.

use std::net::IpAddr;
use std::str::FromStr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::error::{FeriteError, Result};

/// A parsed WireGuard configuration (the subset ferrite needs to bring up a
/// userspace client tunnel).
#[derive(Debug, Clone)]
pub struct WgConf {
    /// Our private key (32 bytes, decoded from base64).
    pub private_key: [u8; 32],
    /// Interface addresses to assign on the tunnel (IP + prefix length).
    pub addresses: Vec<(IpAddr, u8)>,
    /// DNS servers to resolve through the tunnel (queried over DNS-over-TCP from
    /// inside the tunnel — see `WgEgress::resolve`).
    pub dns: Vec<IpAddr>,
    /// Inner MTU (default 1420 if unset).
    pub mtu: Option<u32>,
    /// The peer's public key (32 bytes).
    pub peer_public_key: [u8; 32],
    /// Optional pre-shared key (32 bytes).
    pub preshared_key: Option<[u8; 32]>,
    /// Peer endpoint as `host:port` (host may be a name — resolved at startup).
    pub endpoint: String,
    /// Networks routed through the peer (informational; we route per-connection).
    #[allow(dead_code)]
    pub allowed_ips: Vec<(IpAddr, u8)>,
    /// Keepalive interval in seconds.
    pub persistent_keepalive: Option<u16>,
}

#[derive(PartialEq)]
enum Section {
    None,
    Interface,
    Peer,
}

/// Parse a WireGuard `.conf` (`wg-quick` format). Tolerant of comments
/// (`#`/`;`), blank lines, and case-insensitive keys; strict about the fields
/// ferrite actually needs.
pub fn parse(text: &str) -> Result<WgConf> {
    let mut section = Section::None;

    let mut private_key: Option<[u8; 32]> = None;
    let mut addresses = Vec::new();
    let mut dns = Vec::new();
    let mut mtu = None;
    let mut peer_public_key: Option<[u8; 32]> = None;
    let mut preshared_key = None;
    let mut endpoint: Option<String> = None;
    let mut allowed_ips = Vec::new();
    let mut persistent_keepalive = None;

    for raw in text.lines() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = match name.trim().to_ascii_lowercase().as_str() {
                "interface" => Section::Interface,
                "peer" => Section::Peer,
                _ => Section::None,
            };
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            return Err(cfg(format!(
                "malformed line (expected key = value): '{line}'"
            )));
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();

        match (&section, key.as_str()) {
            (Section::Interface, "privatekey") => {
                private_key = Some(decode_key(value, "PrivateKey")?)
            }
            (Section::Interface, "address") => {
                for item in split_list(value) {
                    addresses.push(parse_cidr(item)?);
                }
            }
            (Section::Interface, "dns") => {
                for item in split_list(value) {
                    dns.push(
                        IpAddr::from_str(item)
                            .map_err(|_| cfg(format!("invalid DNS address '{item}'")))?,
                    );
                }
            }
            (Section::Interface, "mtu") => {
                mtu = Some(
                    value
                        .parse()
                        .map_err(|_| cfg(format!("invalid MTU '{value}'")))?,
                );
            }
            (Section::Interface, "listenport") => {} // client doesn't need a fixed port
            (Section::Peer, "publickey") => peer_public_key = Some(decode_key(value, "PublicKey")?),
            (Section::Peer, "presharedkey") => {
                preshared_key = Some(decode_key(value, "PresharedKey")?)
            }
            (Section::Peer, "endpoint") => endpoint = Some(value.to_string()),
            (Section::Peer, "allowedips") => {
                for item in split_list(value) {
                    allowed_ips.push(parse_cidr(item)?);
                }
            }
            (Section::Peer, "persistentkeepalive") => {
                persistent_keepalive = Some(
                    value
                        .parse()
                        .map_err(|_| cfg(format!("invalid PersistentKeepalive '{value}'")))?,
                );
            }
            // Unknown keys are ignored for forward-compat with wg-quick extras.
            _ => {}
        }
    }

    Ok(WgConf {
        private_key: private_key.ok_or_else(|| cfg("[Interface] PrivateKey is required".into()))?,
        addresses: require_nonempty(addresses, "[Interface] Address is required")?,
        dns,
        mtu,
        peer_public_key: peer_public_key
            .ok_or_else(|| cfg("[Peer] PublicKey is required".into()))?,
        preshared_key,
        endpoint: endpoint.ok_or_else(|| cfg("[Peer] Endpoint is required".into()))?,
        allowed_ips,
        persistent_keepalive,
    })
}

fn strip_comment(line: &str) -> &str {
    let end = line.find(['#', ';']).unwrap_or(line.len());
    &line[..end]
}

fn split_list(value: &str) -> impl Iterator<Item = &str> {
    value.split(',').map(str::trim).filter(|s| !s.is_empty())
}

fn decode_key(value: &str, what: &str) -> Result<[u8; 32]> {
    let bytes = BASE64
        .decode(value.trim())
        .map_err(|_| cfg(format!("{what} is not valid base64")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| cfg(format!("{what} must decode to 32 bytes")))?;
    Ok(arr)
}

fn parse_cidr(item: &str) -> Result<(IpAddr, u8)> {
    match item.split_once('/') {
        Some((ip, prefix)) => {
            let ip = IpAddr::from_str(ip.trim())
                .map_err(|_| cfg(format!("invalid address '{item}'")))?;
            let prefix = prefix
                .trim()
                .parse::<u8>()
                .map_err(|_| cfg(format!("invalid prefix in '{item}'")))?;
            let max = if ip.is_ipv4() { 32 } else { 128 };
            if prefix > max {
                return Err(cfg(format!("prefix /{prefix} out of range in '{item}'")));
            }
            Ok((ip, prefix))
        }
        None => {
            let ip = IpAddr::from_str(item.trim())
                .map_err(|_| cfg(format!("invalid address '{item}'")))?;
            Ok((ip, if ip.is_ipv4() { 32 } else { 128 }))
        }
    }
}

fn require_nonempty<T>(v: Vec<T>, msg: &str) -> Result<Vec<T>> {
    if v.is_empty() {
        Err(cfg(msg.to_string()))
    } else {
        Ok(v)
    }
}

fn cfg(msg: String) -> FeriteError {
    FeriteError::Config(format!("wireguard config: {msg}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn key(seed: u8) -> String {
        BASE64.encode([seed; 32])
    }

    fn sample() -> String {
        format!(
            "# my tunnel\n\
             [Interface]\n\
             PrivateKey = {priv}\n\
             Address = 10.0.0.2/24, fd00::2/64\n\
             DNS = 10.0.0.1, 1.1.1.1\n\
             MTU = 1380   ; provider MTU\n\
             ListenPort = 51820\n\
             \n\
             [Peer]\n\
             PublicKey = {pub}\n\
             PresharedKey = {psk}\n\
             Endpoint = vpn.example.com:51820\n\
             AllowedIPs = 0.0.0.0/0, ::/0\n\
             PersistentKeepalive = 25\n",
            priv = key(1),
            pub = key(2),
            psk = key(3),
        )
    }

    #[test]
    fn parses_a_full_conf() {
        let c = parse(&sample()).unwrap();
        assert_eq!(c.private_key, [1u8; 32]);
        assert_eq!(c.peer_public_key, [2u8; 32]);
        assert_eq!(c.preshared_key, Some([3u8; 32]));
        assert_eq!(c.endpoint, "vpn.example.com:51820");
        assert_eq!(c.mtu, Some(1380));
        assert_eq!(c.persistent_keepalive, Some(25));
        assert_eq!(
            c.addresses,
            vec![
                (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 24),
                (IpAddr::V6("fd00::2".parse::<Ipv6Addr>().unwrap()), 64),
            ]
        );
        assert_eq!(
            c.dns,
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            ]
        );
        assert_eq!(c.allowed_ips.len(), 2);
    }

    #[test]
    fn missing_private_key_is_an_error() {
        let conf = format!("[Peer]\nPublicKey = {}\nEndpoint = h:1\n", key(2));
        assert!(parse(&conf).is_err());
    }

    #[test]
    fn missing_endpoint_is_an_error() {
        let conf = format!(
            "[Interface]\nPrivateKey = {}\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = {}\n",
            key(1),
            key(2)
        );
        assert!(parse(&conf).is_err());
    }

    #[test]
    fn bad_base64_key_is_an_error() {
        let conf = "[Interface]\nPrivateKey = not-base64!!\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = x\nEndpoint = h:1\n";
        assert!(parse(conf).is_err());
    }

    #[test]
    fn address_without_prefix_defaults_to_host_route() {
        let conf = format!(
            "[Interface]\nPrivateKey = {}\nAddress = 10.0.0.2\n[Peer]\nPublicKey = {}\nEndpoint = h:1\n",
            key(1),
            key(2)
        );
        let c = parse(&conf).unwrap();
        assert_eq!(
            c.addresses,
            vec![(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 32)]
        );
    }
}
