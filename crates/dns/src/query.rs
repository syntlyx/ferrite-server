//! The client's query as the pipeline sees it: raw bytes, decoded on demand.
//!
//! Most of what a query is asked for — its id, its opcode, the queried name,
//! the DO bit — are fixed-offset fields that [`ferrite_core::wire`] reads
//! without allocating. What genuinely needs a decoded message is building an
//! answer of ferrite's own: a custom record, a routing redirect, an error
//! reply. Those are the uncommon endings of a query, so the decode is deferred
//! until one of them actually happens and the ordinary paths — cache hit,
//! forward upstream — never pay for it.
//!
//! The decode is attempted at most once; a message hickory rejects stays
//! `None`, and a caller that needs one answers with nothing rather than
//! guessing.

use std::cell::OnceCell;

use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;

/// A client query: the bytes as they arrived, plus the decoded form once
/// something has asked for it.
pub struct LazyQuery<'a> {
    raw: &'a [u8],
    decoded: OnceCell<Option<Message>>,
}

impl<'a> LazyQuery<'a> {
    pub fn new(raw: &'a [u8]) -> Self {
        Self {
            raw,
            decoded: OnceCell::new(),
        }
    }

    /// The query exactly as it arrived.
    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// The transaction id (0 for a message too short to have one — such a
    /// datagram is dropped long before the id matters).
    pub fn id(&self) -> u16 {
        match self.raw.first_chunk::<2>() {
            Some(bytes) => u16::from_be_bytes(*bytes),
            None => 0,
        }
    }

    /// The decoded message, or `None` if these bytes aren't one hickory
    /// accepts. Decodes on the first call and remembers the outcome.
    pub fn message(&self) -> Option<&Message> {
        self.decoded
            .get_or_init(|| Message::from_bytes(self.raw).ok())
            .as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use hickory_proto::serialize::binary::BinEncodable;
    use std::str::FromStr;

    fn query_bytes(id: u16) -> Vec<u8> {
        let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));
        msg.to_bytes().unwrap()
    }

    #[test]
    fn reads_the_id_without_decoding() {
        let raw = query_bytes(0xBEEF);
        let q = LazyQuery::new(&raw);
        assert_eq!(q.id(), 0xBEEF);
        // Nothing has asked for a message, so nothing has been decoded.
        assert!(q.decoded.get().is_none());
        assert_eq!(q.message().unwrap().metadata.id, 0xBEEF);
        assert!(q.decoded.get().is_some());
    }

    #[test]
    fn undecodable_bytes_stay_undecodable() {
        let q = LazyQuery::new(b"not a dns message");
        assert!(q.message().is_none());
        assert!(q.message().is_none());
        assert_eq!(LazyQuery::new(&[]).id(), 0);
    }
}
