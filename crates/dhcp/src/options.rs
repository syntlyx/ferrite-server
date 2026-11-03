//! DHCPv4 options (RFC 2132) — the subset a filtering-router DHCP server needs,
//! plus a raw fallback for everything else so unknown options round-trip.

use std::net::Ipv4Addr;

use crate::message::DecodeError;

/// DHCP message type (option 53).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
}

impl MessageType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Discover,
            2 => Self::Offer,
            3 => Self::Request,
            4 => Self::Decline,
            5 => Self::Ack,
            6 => Self::Nak,
            7 => Self::Release,
            8 => Self::Inform,
            _ => return None,
        })
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::Discover => 1,
            Self::Offer => 2,
            Self::Request => 3,
            Self::Decline => 4,
            Self::Ack => 5,
            Self::Nak => 6,
            Self::Release => 7,
            Self::Inform => 8,
        }
    }
}

/// A single DHCP option. Common ones are typed; anything else is preserved as
/// [`DhcpOption::Unknown`] so decode→encode round-trips faithfully.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhcpOption {
    MessageType(MessageType),
    /// Option 54 — the server's own address, echoed so the client knows which
    /// server it is talking to.
    ServerIdentifier(Ipv4Addr),
    /// Option 50 — the address a client asks to keep (in a REQUEST).
    RequestedIp(Ipv4Addr),
    /// Option 51 — lease duration, seconds.
    LeaseTime(u32),
    /// Option 1.
    SubnetMask(Ipv4Addr),
    /// Option 3 — default gateway(s).
    Router(Vec<Ipv4Addr>),
    /// Option 6 — DNS resolver(s) (this is how ferrite advertises itself).
    DnsServers(Vec<Ipv4Addr>),
    /// Option 12 — the client's self-reported hostname.
    Hostname(String),
    /// Option 15 — DNS search domain.
    DomainName(String),
    /// Option 55 — the option codes the client wants in the reply.
    ParameterRequestList(Vec<u8>),
    /// Option 61 — stable client identity, used in preference to chaddr when set.
    ClientIdentifier(Vec<u8>),
    /// Option 58 (T1) and 59 (T2) — renewal / rebind timers, seconds.
    RenewalTime(u32),
    RebindingTime(u32),
    /// Any option this server doesn't model: `(code, payload)`.
    Unknown(u8, Vec<u8>),
}

const PAD: u8 = 0;
const END: u8 = 255;

impl DhcpOption {
    /// The RFC 2132 option code.
    pub fn code(&self) -> u8 {
        match self {
            Self::SubnetMask(_) => 1,
            Self::Router(_) => 3,
            Self::DnsServers(_) => 6,
            Self::Hostname(_) => 12,
            Self::DomainName(_) => 15,
            Self::RequestedIp(_) => 50,
            Self::LeaseTime(_) => 51,
            Self::MessageType(_) => 53,
            Self::ServerIdentifier(_) => 54,
            Self::ParameterRequestList(_) => 55,
            Self::RenewalTime(_) => 58,
            Self::RebindingTime(_) => 59,
            Self::ClientIdentifier(_) => 61,
            Self::Unknown(code, _) => *code,
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        fn put(out: &mut Vec<u8>, code: u8, data: &[u8]) {
            // Option payloads are length-prefixed with a single byte; nothing we
            // emit exceeds 255 bytes (IP lists on a LAN are short).
            out.push(code);
            out.push(data.len() as u8);
            out.extend_from_slice(data);
        }
        fn ips(list: &[Ipv4Addr]) -> Vec<u8> {
            list.iter().flat_map(|ip| ip.octets()).collect()
        }
        let code = self.code();
        match self {
            Self::MessageType(t) => put(out, code, &[t.to_u8()]),
            Self::ServerIdentifier(ip) | Self::RequestedIp(ip) | Self::SubnetMask(ip) => {
                put(out, code, &ip.octets())
            }
            Self::LeaseTime(secs) | Self::RenewalTime(secs) | Self::RebindingTime(secs) => {
                put(out, code, &secs.to_be_bytes())
            }
            Self::Router(list) | Self::DnsServers(list) => put(out, code, &ips(list)),
            Self::Hostname(s) | Self::DomainName(s) => put(out, code, s.as_bytes()),
            Self::ParameterRequestList(codes) | Self::ClientIdentifier(codes) => {
                put(out, code, codes)
            }
            Self::Unknown(_, data) => put(out, code, data),
        }
    }

    fn decode_one(code: u8, data: &[u8]) -> Self {
        fn ip(data: &[u8]) -> Option<Ipv4Addr> {
            let b: [u8; 4] = data.get(..4)?.try_into().ok()?;
            Some(Ipv4Addr::from(b))
        }
        fn ip_list(data: &[u8]) -> Vec<Ipv4Addr> {
            data.as_chunks::<4>()
                .0
                .iter()
                .map(|&c| Ipv4Addr::from(c))
                .collect()
        }
        fn u32be(data: &[u8]) -> Option<u32> {
            let b: [u8; 4] = data.get(..4)?.try_into().ok()?;
            Some(u32::from_be_bytes(b))
        }
        // A malformed typed option (wrong length) degrades to Unknown rather
        // than failing the whole message — a hostile or buggy client can't take
        // the server down by mis-sizing one option.
        let unknown = || Self::Unknown(code, data.to_vec());
        match code {
            1 => ip(data).map(Self::SubnetMask).unwrap_or_else(unknown),
            3 => Self::Router(ip_list(data)),
            6 => Self::DnsServers(ip_list(data)),
            12 => Self::Hostname(String::from_utf8_lossy(data).into_owned()),
            15 => Self::DomainName(String::from_utf8_lossy(data).into_owned()),
            50 => ip(data).map(Self::RequestedIp).unwrap_or_else(unknown),
            51 => u32be(data).map(Self::LeaseTime).unwrap_or_else(unknown),
            53 => data
                .first()
                .and_then(|b| MessageType::from_u8(*b))
                .map(Self::MessageType)
                .unwrap_or_else(unknown),
            54 => ip(data).map(Self::ServerIdentifier).unwrap_or_else(unknown),
            55 => Self::ParameterRequestList(data.to_vec()),
            58 => u32be(data).map(Self::RenewalTime).unwrap_or_else(unknown),
            59 => u32be(data).map(Self::RebindingTime).unwrap_or_else(unknown),
            61 => Self::ClientIdentifier(data.to_vec()),
            _ => unknown(),
        }
    }
}

/// Decode the option area (everything after the magic cookie). Pad (0) bytes are
/// skipped and End (255) terminates; a truncated option is an error.
pub fn decode(buf: &[u8]) -> Result<Vec<DhcpOption>, DecodeError> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < buf.len() {
        let code = buf[i];
        i += 1;
        if code == PAD {
            continue;
        }
        if code == END {
            break;
        }
        let len = *buf.get(i).ok_or(DecodeError::TruncatedOption)? as usize;
        i += 1;
        let data = buf.get(i..i + len).ok_or(DecodeError::TruncatedOption)?;
        out.push(DhcpOption::decode_one(code, data));
        i += len;
    }
    Ok(out)
}

/// Encode options in order, terminated by End (255).
pub fn encode(options: &[DhcpOption]) -> Vec<u8> {
    let mut out = Vec::new();
    for opt in options {
        opt.encode_into(&mut out);
    }
    out.push(END);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_type_round_trips() {
        for t in [
            MessageType::Discover,
            MessageType::Offer,
            MessageType::Request,
            MessageType::Ack,
            MessageType::Nak,
            MessageType::Release,
        ] {
            assert_eq!(MessageType::from_u8(t.to_u8()), Some(t));
        }
        assert_eq!(MessageType::from_u8(0), None);
        assert_eq!(MessageType::from_u8(99), None);
    }

    #[test]
    fn options_round_trip_through_wire() {
        let opts = vec![
            DhcpOption::MessageType(MessageType::Offer),
            DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 168, 1, 1)),
            DhcpOption::LeaseTime(86_400),
            DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
            DhcpOption::Router(vec![Ipv4Addr::new(192, 168, 1, 1)]),
            DhcpOption::DnsServers(vec![
                Ipv4Addr::new(192, 168, 1, 1),
                Ipv4Addr::new(192, 168, 1, 2),
            ]),
            DhcpOption::Hostname("laptop".to_string()),
            DhcpOption::ParameterRequestList(vec![1, 3, 6, 15]),
        ];
        let wire = encode(&opts);
        assert_eq!(*wire.last().unwrap(), END);
        let back = decode(&wire).unwrap();
        assert_eq!(back, opts);
    }

    #[test]
    fn unknown_option_is_preserved() {
        let opts = vec![DhcpOption::Unknown(200, vec![0xde, 0xad])];
        assert_eq!(decode(&encode(&opts)).unwrap(), opts);
    }

    #[test]
    fn pad_bytes_are_skipped_and_end_terminates() {
        // pad, pad, msgtype=discover, end, then trailing junk that must be ignored.
        let wire = [PAD, PAD, 53, 1, 1, END, 0xff, 0xff];
        let opts = decode(&wire).unwrap();
        assert_eq!(opts, vec![DhcpOption::MessageType(MessageType::Discover)]);
    }

    #[test]
    fn truncated_option_is_an_error() {
        // code 6 (DNS), claims 8 bytes, only 2 present.
        let wire = [6, 8, 0x01, 0x02];
        assert!(matches!(decode(&wire), Err(DecodeError::TruncatedOption)));
    }

    #[test]
    fn missized_typed_option_degrades_to_unknown() {
        // Lease time (51) must be 4 bytes; give 2 → Unknown, not a hard error.
        let wire = [51, 2, 0x01, 0x02, END];
        assert_eq!(
            decode(&wire).unwrap(),
            vec![DhcpOption::Unknown(51, vec![0x01, 0x02])]
        );
    }
}
