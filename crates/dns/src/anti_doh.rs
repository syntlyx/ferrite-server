//! Keeping devices on this resolver.
//!
//! Two kinds of lever, neither of which a blocklist can provide:
//!
//! - **Canaries.** Firefox and Apple devices ask a well-known name before
//!   going around the network's resolver (Firefox's automatic DNS over HTTPS,
//!   iCloud Private Relay). An NXDOMAIN for that name is the network saying
//!   "not here", and they stay on plain DNS, i.e. on ferrite.
//! - **ECH.** Browsers only encrypt the TLS ClientHello when the resolver hands
//!   them an `ech` parameter; without it the hostname stays readable in the
//!   handshake.
//!
//! Blocking DoH *endpoints* by name is left to the blocklist engine and a
//! maintained subscription (HaGeZi's `doh-vpn-proxy-bypass`), which covers far
//! more of them than a hand-kept list could.

use crate::switches::DnsSwitches;

/// Firefox asks this before turning on DNS over HTTPS by itself.
pub const FIREFOX_CANARY: &str = "use-application-dns.net";
/// Apple devices ask these to learn whether iCloud Private Relay may be used.
pub const PRIVATE_RELAY_CANARIES: [&str; 2] = ["mask.icloud.com", "mask-h2.icloud.com"];

/// Which canary `name` is, when the switch for it is on — the label the query
/// log shows as the reason. `name` is lower-case without a trailing dot, as
/// the pipeline spells every name.
pub fn canary(name: &str, switches: &DnsSwitches) -> Option<&'static str> {
    if name == FIREFOX_CANARY && switches.firefox_canary() {
        return Some("canary:firefox-doh");
    }
    if PRIVATE_RELAY_CANARIES.contains(&name) && switches.block_private_relay() {
        return Some("canary:private-relay");
    }
    None
}

/// Strip the Encrypted Client Hello (`ech`) parameter from every HTTPS/SVCB
/// record in a wire-format DNS response. Nothing else in the record is
/// touched, so ALPN, address hints and priority still work.
///
/// Returns `Some(new_bytes)` only when an `ech` param was actually removed, so
/// the caller pays the re-encode only when there was something to strip;
/// `None` when there was nothing to remove or the message didn't parse — the
/// caller then serves the original bytes.
///
/// NB: ECH (Encrypted Client Hello), not ECS (EDNS Client Subnet), which is
/// the unrelated `strip_ecs`.
pub fn strip_ech(bytes: &[u8]) -> Option<Vec<u8>> {
    use hickory_proto::op::Message;
    use hickory_proto::rr::RData;
    use hickory_proto::rr::rdata::svcb::SvcParamKey;
    use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};

    let mut msg = Message::from_bytes(bytes).ok()?;
    let mut changed = false;
    for record in &mut msg.answers {
        let params = match &mut record.data {
            RData::HTTPS(https) => &mut https.0.svc_params,
            RData::SVCB(svcb) => &mut svcb.svc_params,
            _ => continue,
        };
        let before = params.len();
        params.retain(|(key, _)| *key != SvcParamKey::EchConfigList);
        if params.len() != before {
            changed = true;
        }
    }
    if !changed {
        return None;
    }
    msg.to_bytes().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_core::config::DnsConfig;
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::HTTPS;
    use hickory_proto::rr::rdata::svcb::{Alpn, EchConfigList, SVCB, SvcParamKey, SvcParamValue};
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
    use std::str::FromStr;

    fn https_response(params: Vec<(SvcParamKey, SvcParamValue)>) -> Vec<u8> {
        let name = Name::from_str("example.com.").unwrap();
        let rdata = RData::HTTPS(HTTPS(SVCB::new(1, name.clone(), params)));
        let mut msg = Message::new(0x1234, MessageType::Response, OpCode::Query);
        msg.add_query(Query::query(name.clone(), RecordType::HTTPS));
        msg.add_answer(Record::from_rdata(name, 300, rdata));
        msg.to_bytes().unwrap()
    }

    fn alpn() -> (SvcParamKey, SvcParamValue) {
        (
            SvcParamKey::Alpn,
            SvcParamValue::Alpn(Alpn(vec!["h2".to_string(), "h3".to_string()])),
        )
    }

    fn has(bytes: &[u8], key: SvcParamKey) -> bool {
        Message::from_bytes(bytes).unwrap().answers.iter().any(
            |r| matches!(&r.data, RData::HTTPS(h) if h.0.svc_params.iter().any(|(k, _)| *k == key)),
        )
    }

    #[test]
    fn removes_ech_keeps_other_params() {
        let ech = (
            SvcParamKey::EchConfigList,
            SvcParamValue::EchConfigList(EchConfigList(vec![0xaa, 0xbb, 0xcc])),
        );
        let original = https_response(vec![alpn(), ech]);
        assert!(has(&original, SvcParamKey::EchConfigList));

        let stripped = strip_ech(&original).expect("something was stripped");
        assert!(
            !has(&stripped, SvcParamKey::EchConfigList),
            "ech must be gone"
        );
        assert!(has(&stripped, SvcParamKey::Alpn), "alpn must survive");
        assert_eq!(Message::from_bytes(&stripped).unwrap().id, 0x1234);
    }

    #[test]
    fn leaves_answers_without_ech_alone() {
        assert!(strip_ech(&https_response(vec![alpn()])).is_none());

        use hickory_proto::rr::rdata::A;
        let name = Name::from_str("example.com.").unwrap();
        let mut msg = Message::new(1, MessageType::Response, OpCode::Query);
        msg.add_query(Query::query(name.clone(), RecordType::A));
        msg.add_answer(Record::from_rdata(
            name,
            300,
            RData::A(A("192.0.2.1".parse().unwrap())),
        ));
        assert!(strip_ech(&msg.to_bytes().unwrap()).is_none());
    }

    #[test]
    fn canaries_follow_their_switches() {
        let defaults = DnsSwitches::new(&DnsConfig::default());
        assert_eq!(
            canary(FIREFOX_CANARY, &defaults),
            Some("canary:firefox-doh")
        );
        assert_eq!(
            canary("mask.icloud.com", &defaults),
            None,
            "private relay is opt-in"
        );
        assert_eq!(canary("example.com", &defaults), None);

        let cfg = DnsConfig {
            firefox_canary: false,
            block_private_relay: true,
            ..DnsConfig::default()
        };
        defaults.apply(&cfg);
        assert_eq!(canary(FIREFOX_CANARY, &defaults), None);
        assert_eq!(
            canary("mask.icloud.com", &defaults),
            Some("canary:private-relay")
        );
        assert_eq!(
            canary("mask-h2.icloud.com", &defaults),
            Some("canary:private-relay")
        );
        assert_eq!(
            canary("www.icloud.com", &defaults),
            None,
            "only the canaries themselves"
        );
    }
}
