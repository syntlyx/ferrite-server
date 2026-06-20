/// Shared resolve logic for hickory-based upstreams (DoT and DoQ).
///
/// Both protocols use the same TokioResolver API and produce identical
/// wire-format responses — only the transport differs. This module avoids
/// duplicating that logic.
use hickory_proto::op::{Edns, Message, ResponseCode};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use hickory_resolver::TokioResolver;
use hickory_resolver::net::{DnsError, NetError};

use crate::error::{FeriteError, Result};

/// Forward `raw` DNS wire bytes through `resolver` and return a wire-format
/// response with correct flags, EDNS echo, and NXDOMAIN propagation.
///
/// Errors returned here are *transport / timeout* errors — the caller (pool)
/// will try the next upstream. NXDOMAIN and NOERROR/NODATA are *valid* DNS
/// responses and are returned as `Ok(bytes)`.
pub async fn resolve_raw(
    resolver: &TokioResolver,
    label: &str,
    raw: Vec<u8>,
) -> Result<(Vec<u8>, String)> {
    let query =
        Message::from_bytes(&raw).map_err(|e| FeriteError::Dns(format!("parse query: {}", e)))?;

    let question = query
        .queries
        .first()
        .ok_or_else(|| FeriteError::Dns("no question in query".into()))?;

    let name = question.name().to_utf8();
    let record_type = question.query_type();

    // Build the response skeleton, copying flags from the incoming query.
    let mut response = Message::response(query.metadata.id, query.metadata.op_code);
    response.metadata.recursion_desired = query.metadata.recursion_desired;
    response.metadata.checking_disabled = query.metadata.checking_disabled;
    response.metadata.recursion_available = true;
    // We do not set AD — we can't vouch for DNSSEC without validating ourselves.
    response.metadata.authentic_data = false;
    response.add_queries(query.queries.iter().cloned());

    // Echo EDNS back if the client advertised it (RFC 6891 §7).
    if query.edns.is_some() {
        let mut edns = Edns::new();
        // Cap at 1232 bytes (QUIC / DoT safe MTU per RFC 8900).
        edns.set_max_payload(1232);
        response.set_edns(edns);
    }

    match resolver.lookup(&name, record_type).await {
        Ok(lookup) => {
            response.metadata.response_code = ResponseCode::NoError;
            for record in lookup.answers() {
                response.add_answer(record.clone());
            }
        }
        Err(e) => {
            // NoRecordsFound is a valid DNS answer shape (NXDOMAIN/NODATA),
            // not a transport failure. Preserve its rcode and authority data.
            match e {
                NetError::Dns(DnsError::NoRecordsFound(no_records)) => {
                    response.metadata.response_code = no_records.response_code;
                    if let Some(records) = no_records.authorities {
                        response.add_authorities(records.iter().cloned());
                    } else if let Some(soa_record) = no_records.soa {
                        response.add_authority((*soa_record).into_record_of_rdata());
                    }
                }
                other => return Err(FeriteError::Dns(format!("{}: {}", label, other))),
            }
        }
    }

    let bytes = response
        .to_bytes()
        .map_err(|e| FeriteError::Dns(format!("encode response: {}", e)))?;

    Ok((bytes, label.to_string()))
}
