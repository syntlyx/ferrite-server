//! Reverse-DNS (PTR) query plumbing shared by the unicast resolver and mDNS.

use std::net::IpAddr;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use ring::rand::{SecureRandom, SystemRandom};

/// Build the reverse-DNS PTR domain for an IP.
pub(crate) fn ip_to_ptr_domain(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let nibbles: Vec<String> = v6
                .octets()
                .iter()
                .rev()
                .flat_map(|b| {
                    [
                        char::from_digit((b & 0xf) as u32, 16).unwrap_or('0'),
                        char::from_digit((b >> 4) as u32, 16).unwrap_or('0'),
                    ]
                })
                .map(|c| c.to_string())
                .collect();
            format!("{}.ip6.arpa", nibbles.join("."))
        }
    }
}

fn random_query_id() -> Option<u16> {
    let mut bytes = [0u8; 2];
    SystemRandom::new().fill(&mut bytes).ok()?;
    Some(u16::from_be_bytes(bytes))
}

/// A PTR query for `ptr_domain`. A unicast resolver gets `recursion_desired`;
/// mDNS does not use recursion.
pub(crate) fn build_query(ptr_domain: &str, recursion_desired: bool) -> Option<Vec<u8>> {
    let name = Name::from_ascii(ptr_domain).ok()?;

    let mut question = Query::new();
    question.set_name(name);
    question.set_query_type(RecordType::PTR);
    question.set_query_class(DNSClass::IN);

    let mut msg = Message::new(random_query_id()?, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = recursion_desired;
    msg.add_query(question);

    msg.to_bytes().ok()
}

/// The first non-empty PTR name in a response, lowercased, root dot dropped.
pub(crate) fn parse_response(bytes: &[u8]) -> Option<String> {
    let msg = Message::from_bytes(bytes).ok()?;
    for answer in &msg.answers {
        if let RData::PTR(ptr) = &answer.data {
            let s = ptr.to_string();
            let s = s.trim_end_matches('.');
            if !s.is_empty() {
                return Some(s.to_ascii_lowercase());
            }
        }
    }
    None
}
