//! The wire half of SafeSearch / YouTube Restricted Mode: the query ferrite
//! sends for the safe host, and the answer it builds for the client — a CNAME
//! from the name asked to the safe host, followed by the safe host's own
//! records. Which name maps to which host is the blocklist's call
//! ([`ferrite_blocklist::SafeSearch`]).

use std::str::FromStr;

use hickory_proto::op::{Message, OpCode};
use hickory_proto::rr::rdata::CNAME;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};

use crate::query::LazyQuery;

/// Lifetime of the synthetic CNAME. The pipeline caps it to the client TTL.
const CNAME_TTL: u32 = 300;

/// A recursive query for `target`, of the type the client asked for.
pub(crate) fn target_query(id: u16, target: &str, qtype: u16) -> Option<Vec<u8>> {
    let mut msg = Message::new(id, hickory_proto::op::MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(hickory_proto::op::Query::query(
        Name::from_str(&format!("{target}.")).ok()?,
        RecordType::from(qtype),
    ));
    msg.to_bytes().ok()
}

/// The client's answer: its own question, `name CNAME target`, then whatever
/// the upstream answered for `target` (records, and the SOA of a NODATA so
/// the client can cache the absence). The response code is the upstream's.
pub(crate) fn rewrite_answer(
    query: &LazyQuery,
    name: &str,
    target: &str,
    upstream: &[u8],
) -> Option<Vec<u8>> {
    let asked = query.message()?;
    let answered = Message::from_bytes(upstream).ok()?;
    let mut resp = Message::response(asked.metadata.id, OpCode::Query);
    resp.metadata.recursion_desired = asked.metadata.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.metadata.response_code = answered.metadata.response_code;
    resp.add_queries(asked.queries.iter().cloned());
    resp.add_answer(Record::from_rdata(
        Name::from_str(&format!("{name}.")).ok()?,
        CNAME_TTL,
        RData::CNAME(CNAME(Name::from_str(&format!("{target}.")).ok()?)),
    ));
    resp.add_answers(answered.answers);
    resp.add_authorities(answered.authorities);
    resp.to_bytes().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::A;
    use std::net::Ipv4Addr;

    #[test]
    fn answer_chains_the_name_to_the_safe_host() {
        let mut q = Message::new(7, hickory_proto::op::MessageType::Query, OpCode::Query);
        q.metadata.recursion_desired = true;
        q.add_query(hickory_proto::op::Query::query(
            Name::from_str("www.google.com.").unwrap(),
            RecordType::A,
        ));
        let raw = q.to_bytes().unwrap();
        let query = LazyQuery::new(&raw);

        let upstream_q = target_query(9, "forcesafesearch.google.com", 1).unwrap();
        let mut up = Message::from_bytes(&upstream_q).unwrap();
        assert_eq!(
            up.queries[0].name().to_string(),
            "forcesafesearch.google.com."
        );
        up.metadata.message_type = hickory_proto::op::MessageType::Response;
        up.add_answer(Record::from_rdata(
            Name::from_str("forcesafesearch.google.com.").unwrap(),
            600,
            RData::A(A(Ipv4Addr::new(216, 239, 38, 120))),
        ));
        let bytes = rewrite_answer(
            &query,
            "www.google.com",
            "forcesafesearch.google.com",
            &up.to_bytes().unwrap(),
        )
        .unwrap();

        let msg = Message::from_bytes(&bytes).unwrap();
        assert_eq!(msg.metadata.id, 7);
        assert_eq!(msg.queries[0].name().to_string(), "www.google.com.");
        assert_eq!(msg.answers.len(), 2);
        match &msg.answers[0].data {
            RData::CNAME(c) => assert_eq!(c.0.to_string(), "forcesafesearch.google.com."),
            other => panic!("first answer should be the CNAME, got {other:?}"),
        }
        assert!(matches!(msg.answers[1].data, RData::A(_)));
    }
}
