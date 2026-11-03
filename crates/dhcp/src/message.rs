//! DHCPv4 message (RFC 2131): the fixed BOOTP header, the magic cookie, and the
//! variable option area. Only Ethernet hardware (htype 1, 6-byte MAC) is
//! handled — the only kind a LAN DHCP server sees.

use std::net::Ipv4Addr;

use crate::options::{self, DhcpOption, MessageType};

/// Magic cookie that separates the BOOTP header from the options (RFC 2132).
const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
/// Fixed BOOTP header size, up to (not including) the magic cookie.
const HEADER_LEN: usize = 236;
/// Smallest valid message: header + cookie.
const MIN_LEN: usize = HEADER_LEN + 4;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("message shorter than the fixed BOOTP header + magic cookie")]
    TooShort,
    #[error("missing or wrong DHCP magic cookie")]
    BadMagicCookie,
    #[error("an option ran past the end of the buffer")]
    TruncatedOption,
}

/// BOOTP op code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// Client → server.
    BootRequest,
    /// Server → client.
    BootReply,
}

impl Op {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::BootRequest),
            2 => Some(Self::BootReply),
            _ => None,
        }
    }
    fn to_u8(self) -> u8 {
        match self {
            Self::BootRequest => 1,
            Self::BootReply => 2,
        }
    }
}

/// A parsed DHCPv4 message. Address fields keep their RFC names:
/// `ciaddr` (client's current addr), `yiaddr` ("your" — the address being
/// assigned), `siaddr` (next server), `giaddr` (relay agent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpMessage {
    pub op: Op,
    pub xid: u32,
    pub secs: u16,
    /// Raw flags field; bit 15 is the broadcast flag (see [`Self::broadcast`]).
    pub flags: u16,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    /// Client hardware (MAC) address. Ethernet only.
    pub chaddr: [u8; 6],
    pub options: Vec<DhcpOption>,
}

impl DhcpMessage {
    /// True when the client set the broadcast flag: it has no configured address
    /// yet, so the reply must go to 255.255.255.255 rather than unicast.
    pub fn broadcast(&self) -> bool {
        self.flags & 0x8000 != 0
    }

    /// The DHCP message type (option 53), if present.
    pub fn message_type(&self) -> Option<MessageType> {
        self.options.iter().find_map(|o| match o {
            DhcpOption::MessageType(t) => Some(*t),
            _ => None,
        })
    }

    /// The address requested in option 50, if any (present in REQUEST).
    pub fn requested_ip(&self) -> Option<Ipv4Addr> {
        self.options.iter().find_map(|o| match o {
            DhcpOption::RequestedIp(ip) => Some(*ip),
            _ => None,
        })
    }

    /// The server identifier the client selected (option 54), if any.
    pub fn server_identifier(&self) -> Option<Ipv4Addr> {
        self.options.iter().find_map(|o| match o {
            DhcpOption::ServerIdentifier(ip) => Some(*ip),
            _ => None,
        })
    }

    /// The client's self-reported hostname (option 12), if any.
    pub fn hostname(&self) -> Option<&str> {
        self.options.iter().find_map(|o| match o {
            DhcpOption::Hostname(h) => Some(h.as_str()),
            _ => None,
        })
    }

    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() < MIN_LEN {
            return Err(DecodeError::TooShort);
        }
        if buf[236..240] != MAGIC_COOKIE {
            return Err(DecodeError::BadMagicCookie);
        }
        let op = Op::from_u8(buf[0]).ok_or(DecodeError::BadMagicCookie)?;
        let xid = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let secs = u16::from_be_bytes([buf[8], buf[9]]);
        let flags = u16::from_be_bytes([buf[10], buf[11]]);
        let ip = |o: usize| Ipv4Addr::new(buf[o], buf[o + 1], buf[o + 2], buf[o + 3]);
        let mut chaddr = [0u8; 6];
        chaddr.copy_from_slice(&buf[28..34]); // first 6 of the 16-byte chaddr
        let options = options::decode(&buf[240..])?;
        Ok(Self {
            op,
            xid,
            secs,
            flags,
            ciaddr: ip(12),
            yiaddr: ip(16),
            siaddr: ip(20),
            giaddr: ip(24),
            chaddr,
            options,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![0u8; HEADER_LEN];
        buf[0] = self.op.to_u8();
        buf[1] = 1; // htype: Ethernet
        buf[2] = 6; // hlen: 6-byte MAC
        // hops (buf[3]) stays 0 — set by relays, not us.
        buf[4..8].copy_from_slice(&self.xid.to_be_bytes());
        buf[8..10].copy_from_slice(&self.secs.to_be_bytes());
        buf[10..12].copy_from_slice(&self.flags.to_be_bytes());
        buf[12..16].copy_from_slice(&self.ciaddr.octets());
        buf[16..20].copy_from_slice(&self.yiaddr.octets());
        buf[20..24].copy_from_slice(&self.siaddr.octets());
        buf[24..28].copy_from_slice(&self.giaddr.octets());
        buf[28..34].copy_from_slice(&self.chaddr);
        // chaddr[6..16], sname[64], file[128] stay zero.
        buf.extend_from_slice(&MAGIC_COOKIE);
        buf.extend_from_slice(&options::encode(&self.options));
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_discover() -> DhcpMessage {
        DhcpMessage {
            op: Op::BootRequest,
            xid: 0x1234_5678,
            secs: 0,
            flags: 0x8000, // broadcast
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            options: vec![
                DhcpOption::MessageType(MessageType::Discover),
                DhcpOption::Hostname("laptop".to_string()),
                DhcpOption::ParameterRequestList(vec![1, 3, 6]),
            ],
        }
    }

    #[test]
    fn encode_decode_round_trips() {
        let msg = sample_discover();
        let wire = DhcpMessage::decode(&msg.encode()).unwrap();
        assert_eq!(wire, msg);
    }

    #[test]
    fn encode_sets_ethernet_htype_hlen_and_cookie() {
        let wire = sample_discover().encode();
        assert_eq!(wire[0], 1, "op = BootRequest");
        assert_eq!(wire[1], 1, "htype = Ethernet");
        assert_eq!(wire[2], 6, "hlen = 6");
        assert_eq!(&wire[236..240], &MAGIC_COOKIE);
    }

    #[test]
    fn accessors_read_typed_options() {
        let msg = sample_discover();
        assert_eq!(msg.message_type(), Some(MessageType::Discover));
        assert!(msg.broadcast());
        assert_eq!(msg.hostname(), Some("laptop"));
        assert_eq!(msg.requested_ip(), None);
    }

    #[test]
    fn too_short_is_rejected() {
        assert_eq!(DhcpMessage::decode(&[0u8; 100]), Err(DecodeError::TooShort));
    }

    #[test]
    fn bad_magic_cookie_is_rejected() {
        let mut wire = sample_discover().encode();
        wire[238] = 0; // corrupt the cookie
        assert_eq!(DhcpMessage::decode(&wire), Err(DecodeError::BadMagicCookie));
    }

    #[test]
    fn chaddr_is_the_first_six_bytes() {
        let wire = sample_discover().encode();
        assert_eq!(&wire[28..34], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        // Remaining 10 bytes of the 16-byte chaddr field are zero.
        assert_eq!(&wire[34..44], &[0u8; 10]);
    }
}
