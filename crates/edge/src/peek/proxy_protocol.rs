//! The PROXY protocol header (v1 text, v2 binary) a reverse proxy puts in
//! front of a connection it passes on without opening it — nginx's `stream`
//! with `proxy_protocol on`, HAProxy's `send-proxy` — saying whose it is.
//! Believed only from a proxy listed as trusted; from anyone else a header
//! is just bytes that aren't TLS.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// v2's twelve-byte signature.
const V2_SIG: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";
/// The longest v1 line, CRLF included.
const V1_MAX: usize = 107;

#[derive(Debug, PartialEq, Eq)]
pub enum Header {
    /// Not enough bytes yet to tell.
    Incomplete,
    /// No header: the connection starts straight away.
    Absent,
    /// A header `len` bytes long. `from` is the client it names; `None` when
    /// it names none (v1 `UNKNOWN`, v2 `LOCAL` — the proxy's own check).
    Present {
        from: Option<SocketAddr>,
        len: usize,
    },
    /// Starts like a header and isn't one.
    Invalid,
}

/// The v1 line for a connection from `from` to `to`, to put in front of it
/// when passing it on to something that expects one.
pub fn v1_header(from: SocketAddr, to: SocketAddr) -> String {
    let (from_ip, to_ip) = (canonical(from.ip()), canonical(to.ip()));
    let family = if from_ip.is_ipv4() && to_ip.is_ipv4() {
        "TCP4"
    } else {
        "TCP6"
    };
    // One family for both ends: an IPv4 address next to IPv6 is written mapped.
    let show = |ip: IpAddr| match (family, ip) {
        ("TCP6", IpAddr::V4(v4)) => IpAddr::V6(v4.to_ipv6_mapped()).to_string(),
        _ => ip.to_string(),
    };
    format!(
        "PROXY {family} {} {} {} {}\r\n",
        show(from_ip),
        show(to_ip),
        from.port(),
        to.port()
    )
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

pub fn parse(buf: &[u8]) -> Header {
    let v1 = b"PROXY ";
    let prefix = |sig: &[u8]| buf.len() < sig.len() && sig.starts_with(buf);
    if prefix(v1) || prefix(V2_SIG) || buf.is_empty() {
        return Header::Incomplete;
    }
    if buf.starts_with(v1) {
        return v1_line(buf);
    }
    if buf.starts_with(V2_SIG) {
        return v2(buf);
    }
    Header::Absent
}

fn v1_line(buf: &[u8]) -> Header {
    let Some(end) = buf.windows(2).position(|w| w == b"\r\n") else {
        return if buf.len() >= V1_MAX {
            Header::Invalid
        } else {
            Header::Incomplete
        };
    };
    let len = end + 2;
    if len > V1_MAX {
        return Header::Invalid;
    }
    let Ok(line) = std::str::from_utf8(&buf[..end]) else {
        return Header::Invalid;
    };
    let parts: Vec<&str> = line.split(' ').collect();
    match parts.as_slice() {
        ["PROXY", "UNKNOWN", ..] => Header::Present { from: None, len },
        ["PROXY", "TCP4" | "TCP6", src, _dst, sport, _dport] => {
            match (src.parse::<IpAddr>(), sport.parse::<u16>()) {
                (Ok(ip), Ok(port)) => Header::Present {
                    from: Some(SocketAddr::new(ip, port)),
                    len,
                },
                _ => Header::Invalid,
            }
        }
        _ => Header::Invalid,
    }
}

fn v2(buf: &[u8]) -> Header {
    if buf.len() < 16 {
        return Header::Incomplete;
    }
    let (ver_cmd, family) = (buf[12], buf[13]);
    let body = u16::from_be_bytes([buf[14], buf[15]]) as usize;
    let len = 16 + body;
    if ver_cmd >> 4 != 2 {
        return Header::Invalid;
    }
    if buf.len() < len {
        return Header::Incomplete;
    }
    // LOCAL: the proxy speaking for itself.
    if ver_cmd & 0x0f == 0 {
        return Header::Present { from: None, len };
    }
    let a = &buf[16..len];
    let from = match family {
        // TCP over IPv4: src, dst, src port, dst port.
        0x11 if a.len() >= 12 => Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(a[0], a[1], a[2], a[3])),
            u16::from_be_bytes([a[8], a[9]]),
        )),
        // TCP over IPv6.
        0x21 if a.len() >= 36 => {
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&a[..16]);
            Some(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(ip)),
                u16::from_be_bytes([a[32], a[33]]),
            ))
        }
        // Anything else (UDP, unix sockets): no client address to take.
        _ => None,
    };
    Header::Present { from, len }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_one_names_the_client() {
        let mut buf = b"PROXY TCP4 198.51.100.7 192.168.1.10 51234 443\r\n".to_vec();
        let len = buf.len();
        buf.extend_from_slice(&[0x16, 0x03, 0x01]);
        assert_eq!(
            parse(&buf),
            Header::Present {
                from: Some("198.51.100.7:51234".parse().unwrap()),
                len
            }
        );
        let v6 = b"PROXY TCP6 2001:db8::7 2001:db8::1 4000 443\r\n";
        assert!(matches!(parse(v6), Header::Present { from: Some(a), .. } if a.ip().is_ipv6()));
        assert_eq!(
            parse(b"PROXY UNKNOWN\r\n"),
            Header::Present {
                from: None,
                len: 15
            }
        );
    }

    #[test]
    fn a_written_line_reads_back() {
        let from: SocketAddr = "198.51.100.7:40000".parse().unwrap();
        let to: SocketAddr = "[::ffff:192.168.1.4]:443".parse().unwrap();
        let line = v1_header(from, to);
        assert_eq!(line, "PROXY TCP4 198.51.100.7 192.168.1.4 40000 443\r\n");
        assert_eq!(
            parse(line.as_bytes()),
            Header::Present {
                from: Some(from),
                len: line.len()
            }
        );
        let six = v1_header("[2001:db8::7]:1".parse().unwrap(), to);
        assert!(
            six.starts_with("PROXY TCP6 2001:db8::7 ::ffff:192.168.1.4 "),
            "{six}"
        );
    }

    #[test]
    fn version_two_names_the_client() {
        let mut buf = V2_SIG.to_vec();
        buf.extend_from_slice(&[0x21, 0x11, 0, 12]);
        buf.extend_from_slice(&[198, 51, 100, 7, 192, 168, 1, 10]);
        buf.extend_from_slice(&51234u16.to_be_bytes());
        buf.extend_from_slice(&443u16.to_be_bytes());
        buf.push(0x16);
        assert_eq!(
            parse(&buf),
            Header::Present {
                from: Some("198.51.100.7:51234".parse().unwrap()),
                len: 28
            }
        );
        assert_eq!(parse(&buf[..20]), Header::Incomplete);
    }

    #[test]
    fn tls_and_partial_headers_are_told_apart() {
        assert_eq!(parse(&[0x16, 0x03, 0x01, 0x02]), Header::Absent);
        assert_eq!(parse(b"GET / HTTP/1.1\r\n"), Header::Absent);
        assert_eq!(parse(b"PRO"), Header::Incomplete);
        assert_eq!(parse(b"PROXY TCP4 1.2"), Header::Incomplete);
        assert_eq!(parse(b"PROXY BOGUS\r\n"), Header::Invalid);
        assert_eq!(parse(b"PROXY TCP4 x y 1 2\r\n"), Header::Invalid);
        assert_eq!(parse(&[b'P'; 200]), Header::Absent);
    }
}
