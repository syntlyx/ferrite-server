//! Wire-format DNS helpers (RFC 1035 §4): read and patch a message where it
//! lies, without decoding it.
//!
//! The query path needs a handful of small facts about a message — the RCODE,
//! the advertised UDP buffer, the smallest answer TTL — and it needs to rewrite
//! two fields: the transaction ID and the record TTLs. Reaching for
//! `hickory_proto::op::Message::from_bytes` for each of those allocates a Vec
//! per section plus a `Name` and an `RData` per record, and rewriting a TTL
//! that way costs a full re-serialisation on top. Per query the pipeline was
//! doing that three to seven times over.
//!
//! Everything here walks the buffer instead: one bounds-checked pass, no
//! allocation, offsets only. Rewrites are in place, so what leaves ferrite is
//! the upstream's own bytes with the TTLs changed — not hickory's re-encoding
//! of them, which is free to compress names differently or drop record types it
//! doesn't model.
//!
//! Input is attacker-controlled, so every read is bounds-checked and every
//! walker fails closed: callers get `None`/`Malformed` and fall back to the
//! full parser (or to leaving the bytes alone).

/// Fixed DNS header: ID, flags, and the four section counts.
pub const HEADER_LEN: usize = 12;

/// EDNS0 pseudo-record. Its "TTL" field is extended-RCODE/version/flags, so
/// every TTL rewrite here skips it.
const TYPE_OPT: u16 = 41;
const TYPE_SOA: u16 = 6;
const TYPE_CNAME: u16 = 5;
/// EDNS option code for Client Subnet (RFC 7871).
const OPT_CODE_ECS: u16 = 8;
/// Fixed part of an RR after the name: TYPE(2) CLASS(2) TTL(4) RDLENGTH(2).
const RR_FIXED_LEN: usize = 10;
/// MNAME and RNAME (≥2 bytes each as pointers) plus five 32-bit fields.
const SOA_MIN_RDATA: usize = 22;
/// Default UDP answer size without EDNS0, and the floor EDNS0 can't go under
/// (RFC 1035 §4.2.1) — matches `Message::max_payload`.
const MIN_UDP_PAYLOAD: usize = 512;

/// Byte offset just past the first DNS question (QNAME + QTYPE + QCLASS) in a
/// wire-format message, or `None` if there is no question or the name is
/// malformed/unterminated. Compression pointers are rejected — they must not
/// appear in a question name. All indexing is bounds-checked for untrusted input.
pub fn question_end(msg: &[u8]) -> Option<usize> {
    if msg.len() < HEADER_LEN {
        return None;
    }
    // QDCOUNT == 0 → no question to delimit.
    if u16::from_be_bytes([msg[4], msg[5]]) == 0 {
        return None;
    }
    let mut i = HEADER_LEN; // questions start right after the header
    loop {
        let len = *msg.get(i)? as usize;
        if len == 0 {
            i += 1; // consume the root-label terminator
            break;
        }
        if len & 0xC0 != 0 {
            return None; // compression pointer not allowed in a question name
        }
        i += 1 + len;
        if i > msg.len() {
            return None;
        }
    }
    let end = i + 4; // QTYPE (2) + QCLASS (2)
    (end <= msg.len()).then_some(end)
}

/// The message's OPCODE (RFC 1035 §4.1.1: bits 1-4 of the flags), or `None` if
/// there is no header to read it from. 0 is a standard query.
pub fn opcode(msg: &[u8]) -> Option<u8> {
    msg.get(2).map(|flags| (flags >> 3) & 0x0F)
}

/// Rewrite the transaction ID (bytes 0-1, big-endian). A message too short to
/// hold a header is left alone.
pub fn set_id(msg: &mut [u8], id: u16) {
    if msg.len() >= 2 {
        msg[..2].copy_from_slice(&id.to_be_bytes());
    }
}

/// The section a record was found in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Section {
    Answer,
    Authority,
    Additional,
}

/// One resource record, located rather than decoded: every field is an offset
/// into the message the cursor is walking.
#[derive(Clone, Copy, Debug)]
pub struct RecordRef {
    pub section: Section,
    pub rtype: u16,
    /// CLASS — the advertised UDP payload size on an OPT pseudo-record.
    pub class: u16,
    /// Offset of the 4-byte TTL field.
    pub ttl_off: usize,
    /// Offset and length of the RDATA.
    pub rdata_off: usize,
    pub rdata_len: usize,
}

/// What a cursor step produced.
#[derive(Clone, Copy, Debug)]
pub enum Step {
    Record(RecordRef),
    /// Every record in every section has been visited.
    End,
    /// The message is structurally broken from here on — a truncated name, an
    /// RDLENGTH past the end, a reserved label type. Callers treat this as "do
    /// not trust these bytes"; a rewrite must therefore validate before it
    /// writes, or it could stop half-way through.
    Malformed,
}

/// Walks the record sections of a message.
///
/// It borrows the buffer only for the duration of each [`Self::next`] call, so
/// a caller can hold a `&mut [u8]` across the walk and patch each record as it
/// is visited — that is how the in-place TTL rewrites below work.
pub struct RecordCursor {
    at: usize,
    /// Records left to visit in answers / authorities / additionals.
    left: [u16; 3],
    section: usize,
}

const SECTIONS: [Section; 3] = [Section::Answer, Section::Authority, Section::Additional];

impl RecordCursor {
    /// Position a cursor just past the question section, or `None` if the
    /// header or a question name is malformed.
    pub fn new(msg: &[u8]) -> Option<Self> {
        if msg.len() < HEADER_LEN {
            return None;
        }
        let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
        let mut at = HEADER_LEN;
        for _ in 0..qdcount {
            at = skip_name(msg, at)?;
            at = at.checked_add(4)?; // QTYPE + QCLASS
            if at > msg.len() {
                return None;
            }
        }
        Some(Self {
            at,
            left: [
                u16::from_be_bytes([msg[6], msg[7]]),
                u16::from_be_bytes([msg[8], msg[9]]),
                u16::from_be_bytes([msg[10], msg[11]]),
            ],
            section: 0,
        })
    }

    pub fn next(&mut self, msg: &[u8]) -> Step {
        while self.section < SECTIONS.len() && self.left[self.section] == 0 {
            self.section += 1;
        }
        if self.section >= SECTIONS.len() {
            return Step::End;
        }
        self.left[self.section] -= 1;

        let Some(after_name) = skip_name(msg, self.at) else {
            return Step::Malformed;
        };
        let Some(rdata_off) = after_name.checked_add(RR_FIXED_LEN) else {
            return Step::Malformed;
        };
        if rdata_off > msg.len() {
            return Step::Malformed;
        }
        let rdata_len = u16::from_be_bytes([msg[after_name + 8], msg[after_name + 9]]) as usize;
        let Some(end) = rdata_off.checked_add(rdata_len) else {
            return Step::Malformed;
        };
        if end > msg.len() {
            return Step::Malformed;
        }
        self.at = end;
        Step::Record(RecordRef {
            section: SECTIONS[self.section],
            rtype: u16::from_be_bytes([msg[after_name], msg[after_name + 1]]),
            class: u16::from_be_bytes([msg[after_name + 2], msg[after_name + 3]]),
            ttl_off: after_name + 4,
            rdata_off,
            rdata_len,
        })
    }
}

/// Offset just past the domain name starting at `at`. A compression pointer
/// ends the name (we only skip, never follow, so no loop is possible).
fn skip_name(msg: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let len = *msg.get(at)? as usize;
        match len & 0xC0 {
            // Ordinary label, or the root label that terminates the name.
            0x00 => {
                if len == 0 {
                    return Some(at + 1);
                }
                at = at.checked_add(1 + len)?;
                if at > msg.len() {
                    return None;
                }
            }
            // Pointer: two bytes, and the name ends there.
            0xC0 => {
                msg.get(at + 1)?;
                return Some(at + 2);
            }
            // 0x40/0x80 are reserved label types (RFC 6891 §6.1.1 retired the
            // only assignment); nothing we can walk past.
            _ => return None,
        }
    }
}

fn read_u32(msg: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([msg[at], msg[at + 1], msg[at + 2], msg[at + 3]])
}

/// True if every section of the message walks cleanly to its end: all names
/// terminate inside the buffer, every RDLENGTH fits, and the section counts
/// match what is actually there.
///
/// This is a structural check, not a decode: unknown record types and RDATA we
/// don't model pass, which is the point — a resolver is not entitled to reject
/// an answer merely because it carries an RR type it has no parser for.
pub fn is_well_formed(msg: &[u8]) -> bool {
    let Some(mut cur) = RecordCursor::new(msg) else {
        return false;
    };
    loop {
        match cur.next(msg) {
            Step::Record(_) => {}
            Step::End => return true,
            Step::Malformed => return false,
        }
    }
}

/// The message's RCODE, or `None` if it isn't structurally sound (the caller's
/// cue to distrust the bytes entirely).
///
/// The 4 bits in the header are the low half; an OPT record's extended RCODE
/// (RFC 6891 §6.1.3) supplies the high 8, so BADVERS (16) and friends don't
/// read as NOERROR. Values above 255 can't occur — the wire fields are 4 + 8
/// bits — but the result is saturated rather than truncated so a hostile
/// message can't fake a 0.
pub fn rcode(msg: &[u8]) -> Option<u8> {
    if msg.len() < HEADER_LEN {
        return None;
    }
    let low = u16::from(msg[3] & 0x0F);
    let mut high = 0u16;
    let mut cur = RecordCursor::new(msg)?;
    loop {
        match cur.next(msg) {
            Step::Record(r) if r.rtype == TYPE_OPT && r.section == Section::Additional => {
                high = u16::from(msg[r.ttl_off]);
            }
            Step::Record(_) => {}
            Step::End => break,
            Step::Malformed => return None,
        }
    }
    Some(((high << 4) | low).min(255) as u8)
}

/// The UDP answer size this query advertises: the EDNS0 payload size with the
/// 512-byte floor, or 512 when there is no OPT record. Mirrors
/// `Message::max_payload` without decoding the message.
pub fn udp_payload(query: &[u8]) -> usize {
    let mut payload = MIN_UDP_PAYLOAD;
    let Some(mut cur) = RecordCursor::new(query) else {
        return payload;
    };
    loop {
        match cur.next(query) {
            Step::Record(r) if r.rtype == TYPE_OPT && r.section == Section::Additional => {
                payload = payload.max(usize::from(r.class));
            }
            Step::Record(_) => {}
            _ => return payload,
        }
    }
}

/// Clamp every record TTL to `max_ttl`, in place. Returns true if anything was
/// rewritten. A message that doesn't walk cleanly is left untouched.
pub fn cap_ttls(msg: &mut [u8], max_ttl: u32) -> bool {
    rewrite_ttls(msg, |ttl| (ttl > max_ttl).then_some(max_ttl))
}

/// Set every record TTL to `ttl`, in place — what a cache hit needs, so the
/// client is told the entry's remaining lifetime instead of the lifetime it had
/// when it was stored (RFC 2181 §5.1). A message that doesn't walk cleanly is
/// left untouched.
pub fn set_ttls(msg: &mut [u8], ttl: u32) -> bool {
    rewrite_ttls(msg, |current| (current != ttl).then_some(ttl))
}

/// Shared body of the TTL rewrites: validate first (a half-patched message is
/// worse than an unpatched one), then walk again and apply `f` to each record's
/// TTL. OPT is skipped — that field is flags, not a lifetime.
fn rewrite_ttls(msg: &mut [u8], f: impl Fn(u32) -> Option<u32>) -> bool {
    if !is_well_formed(msg) {
        return false;
    }
    let Some(mut cur) = RecordCursor::new(msg) else {
        return false;
    };
    let mut changed = false;
    loop {
        // The immutable borrow ends with the call, leaving the buffer free to
        // patch through the offsets it just handed back.
        match cur.next(msg) {
            Step::Record(r) => {
                if r.rtype == TYPE_OPT {
                    continue;
                }
                if let Some(new) = f(read_u32(msg, r.ttl_off)) {
                    msg[r.ttl_off..r.ttl_off + 4].copy_from_slice(&new.to_be_bytes());
                    changed = true;
                }
            }
            // `is_well_formed` already ruled Malformed out.
            Step::End | Step::Malformed => return changed,
        }
    }
}

/// TTL (seconds) to cache a NOERROR response under, or `None` for "don't
/// cache".
///
/// A positive answer is bounded by its shortest answer-record TTL. An empty
/// (NODATA) answer is bounded by the RFC 2308 negative TTL from the
/// authority-section SOA: the lesser of that record's own TTL and its MINIMUM
/// field. A TTL of 0 — or a NODATA answer with no SOA to bound it — is not
/// cacheable, and neither is a message that doesn't walk cleanly.
pub fn cache_ttl(msg: &[u8]) -> Option<u32> {
    let mut cur = RecordCursor::new(msg)?;
    let mut min_answer: Option<u32> = None;
    let mut negative: Option<u32> = None;
    loop {
        match cur.next(msg) {
            Step::Record(r) => match r.section {
                Section::Answer => {
                    let ttl = read_u32(msg, r.ttl_off);
                    min_answer = Some(min_answer.map_or(ttl, |m: u32| m.min(ttl)));
                }
                // MINIMUM is the last of the SOA's five 32-bit fields, so it
                // sits at the end of the RDATA whatever MNAME/RNAME cost.
                Section::Authority
                    if r.rtype == TYPE_SOA
                        && negative.is_none()
                        && r.rdata_len >= SOA_MIN_RDATA =>
                {
                    let minimum = read_u32(msg, r.rdata_off + r.rdata_len - 4);
                    negative = Some(read_u32(msg, r.ttl_off).min(minimum));
                }
                _ => {}
            },
            Step::End => break,
            Step::Malformed => return None,
        }
    }
    let ttl = match min_answer {
        Some(min) => min,
        None => negative?,
    };
    (ttl > 0).then_some(ttl)
}

// ---------------------------------------------------------------------------
// EDNS0
// ---------------------------------------------------------------------------

/// The OPT pseudo-record of a message, located.
#[derive(Clone, Copy, Debug)]
pub struct EdnsRef {
    /// Offset of the CLASS field, which on OPT is the advertised payload size.
    pub payload_off: usize,
    pub payload: u16,
    /// Offset of the 4-byte TTL field: extended RCODE, version, flags.
    pub ttl_off: usize,
    pub dnssec_ok: bool,
    /// Whether the record carries an EDNS Client Subnet option.
    pub has_ecs: bool,
}

/// Result of looking for the OPT record.
#[derive(Clone, Copy, Debug)]
pub enum EdnsScan {
    Opt(EdnsRef),
    /// Walked fine; the message carries no OPT record.
    None,
    Malformed,
}

/// Locate the EDNS0 OPT record without decoding the message.
pub fn edns(msg: &[u8]) -> EdnsScan {
    let Some(mut cur) = RecordCursor::new(msg) else {
        return EdnsScan::Malformed;
    };
    let mut found = EdnsScan::None;
    loop {
        match cur.next(msg) {
            Step::Record(r) if r.rtype == TYPE_OPT && r.section == Section::Additional => {
                if matches!(found, EdnsScan::None) {
                    found = EdnsScan::Opt(EdnsRef {
                        payload_off: r.ttl_off - 2,
                        payload: r.class,
                        ttl_off: r.ttl_off,
                        // DO is the top bit of the 16-bit flags field, which
                        // occupies the last two bytes of the TTL slot.
                        dnssec_ok: msg[r.ttl_off + 2] & 0x80 != 0,
                        has_ecs: has_ecs(msg, r.rdata_off, r.rdata_len),
                    });
                }
            }
            Step::Record(_) => {}
            Step::End => return found,
            Step::Malformed => return EdnsScan::Malformed,
        }
    }
}

/// Whether the OPT RDATA at `off` carries a Client Subnet option. The RDATA is
/// a sequence of {code(2), length(2), data} triples.
fn has_ecs(msg: &[u8], off: usize, len: usize) -> bool {
    let mut i = off;
    let end = off + len;
    while i + 4 <= end {
        let code = u16::from_be_bytes([msg[i], msg[i + 1]]);
        let olen = usize::from(u16::from_be_bytes([msg[i + 2], msg[i + 3]]));
        if code == OPT_CODE_ECS {
            return true;
        }
        match i.checked_add(4 + olen) {
            Some(next) if next <= end => i = next,
            _ => return false,
        }
    }
    false
}

/// Set the DO (DNSSEC OK) bit of an already-located OPT record.
pub fn set_dnssec_ok(msg: &mut [u8], opt: &EdnsRef, want: bool) {
    if want {
        msg[opt.ttl_off + 2] |= 0x80;
    } else {
        msg[opt.ttl_off + 2] &= !0x80;
    }
}

/// Set the advertised UDP payload size (the OPT CLASS field) of an already-
/// located OPT record.
pub fn set_udp_payload(msg: &mut [u8], opt: &EdnsRef, payload: u16) {
    msg[opt.payload_off..opt.payload_off + 2].copy_from_slice(&payload.to_be_bytes());
}

/// What reading the first question produced.
pub enum QuestionScan {
    /// The queried name — lowercase, no trailing root dot — and its QTYPE.
    Found { name: String, qtype: u16 },
    /// The name isn't a plain LDH one (an IDN `xn--` label, or one holding
    /// bytes a text form has to escape). The full parser spells those the way
    /// the rest of ferrite does, so the caller defers to it — see
    /// [`CnameScan::Unsupported`], which draws the same line for the same
    /// reason.
    Unsupported,
    /// No question to read: QDCOUNT is 0, or the message doesn't walk.
    Missing,
}

/// Read the first question of a query without decoding the message.
pub fn question(msg: &[u8]) -> QuestionScan {
    if msg.len() < HEADER_LEN || u16::from_be_bytes([msg[4], msg[5]]) == 0 {
        return QuestionScan::Missing;
    }
    let mut name = String::new();
    if read_name_lower(msg, HEADER_LEN, &mut name).is_none() {
        // Either unrenderable or malformed; `question_end` tells the two apart,
        // and only a walkable question is worth handing to the full parser.
        return match question_end(msg) {
            Some(_) => QuestionScan::Unsupported,
            None => QuestionScan::Missing,
        };
    }
    let Some(end) = question_end(msg) else {
        return QuestionScan::Missing;
    };
    QuestionScan::Found {
        name,
        qtype: u16::from_be_bytes([msg[end - 4], msg[end - 3]]),
    }
}

// ---------------------------------------------------------------------------
// CNAME chain
// ---------------------------------------------------------------------------

/// Outcome of scanning the answer section for CNAME targets.
pub enum CnameScan {
    /// No CNAME target satisfied the predicate.
    NoMatch,
    /// The first target the predicate accepted, lowercased, no trailing dot.
    Matched(String),
    /// A target isn't a plain LDH name — an IDN (`xn--`) label, or one holding
    /// bytes that a text form has to escape. Both need the full parser's
    /// rendering to match what the rest of the system stores, so the caller
    /// falls back rather than inventing a second spelling of the same name.
    Unsupported,
}

/// Find the first CNAME target in the answer section that `pred` accepts.
///
/// Targets are rendered the way the rest of ferrite spells a domain: lowercase,
/// dot-separated, no trailing root dot. Compression pointers are followed, with
/// a jump budget so a pointer loop can't hang the query.
pub fn find_cname_target(msg: &[u8], mut pred: impl FnMut(&str) -> bool) -> CnameScan {
    let Some(mut cur) = RecordCursor::new(msg) else {
        return CnameScan::NoMatch;
    };
    let mut target = String::new();
    loop {
        match cur.next(msg) {
            Step::Record(r) if r.rtype == TYPE_CNAME && r.section == Section::Answer => {
                target.clear();
                match read_name_lower(msg, r.rdata_off, &mut target) {
                    Some(()) => {
                        if pred(&target) {
                            return CnameScan::Matched(target);
                        }
                    }
                    None => return CnameScan::Unsupported,
                }
            }
            Step::Record(_) => {}
            Step::End | Step::Malformed => return CnameScan::NoMatch,
        }
    }
}

/// Maximum compression pointers followed while reading one name. A legal name
/// has at most 127 labels; the budget only has to stop a loop.
const MAX_NAME_JUMPS: usize = 32;
/// Longest name in presentation form we'll build (RFC 1035 §2.3.4).
const MAX_NAME_LEN: usize = 255;

/// Append the domain name at `at` to `out`, lowercased, dot-separated, with no
/// trailing root dot. `None` when the name is malformed, over-long, loops, or
/// holds a label the plain rendering can't represent faithfully (see
/// [`CnameScan::Unsupported`]).
fn read_name_lower(msg: &[u8], at: usize, out: &mut String) -> Option<()> {
    let mut i = at;
    let mut jumps = 0;
    loop {
        let len = *msg.get(i)? as usize;
        match len & 0xC0 {
            0x00 => {
                if len == 0 {
                    return Some(());
                }
                let label = msg.get(i + 1..i + 1 + len)?;
                if !is_plain_label(label) {
                    return None;
                }
                if out.len() + len + 1 > MAX_NAME_LEN {
                    return None;
                }
                if !out.is_empty() {
                    out.push('.');
                }
                for b in label {
                    out.push(b.to_ascii_lowercase() as char);
                }
                i += 1 + len;
            }
            0xC0 => {
                jumps += 1;
                if jumps > MAX_NAME_JUMPS {
                    return None;
                }
                let hi = len & 0x3F;
                let lo = usize::from(*msg.get(i + 1)?);
                let dest = (hi << 8) | lo;
                // Pointers must point backwards (RFC 1035 §4.1.4); refusing a
                // forward or self pointer is what makes the budget above a
                // belt-and-braces check rather than the only guard.
                if dest >= i {
                    return None;
                }
                i = dest;
            }
            _ => return None,
        }
    }
}

/// Whether a label is one the plain lowercase rendering above spells exactly as
/// the full parser would: ASCII letters, digits, `-`, `_` and a leading `*`,
/// and not an IDN label (which the full parser decodes to Unicode).
fn is_plain_label(label: &[u8]) -> bool {
    if label.len() >= 4 && label[..4].eq_ignore_ascii_case(b"xn--") {
        return false;
    }
    label.iter().enumerate().all(|(i, b)| {
        b.is_ascii_alphanumeric() || *b == b'_' || (*b == b'-' && i > 0) || (*b == b'*' && i == 0)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builder for wire-format messages the walkers can be pointed at.
    struct Msg(Vec<u8>);

    impl Msg {
        /// Header with the given section counts and RCODE.
        fn new(counts: [u16; 4], rcode: u8) -> Self {
            let mut m = vec![0x12, 0x34, 0x81, rcode & 0x0F];
            for c in counts {
                m.extend_from_slice(&c.to_be_bytes());
            }
            Self(m)
        }

        fn name(&mut self, name: &str) -> &mut Self {
            for label in name.split('.').filter(|l| !l.is_empty()) {
                self.0.push(label.len() as u8);
                self.0.extend_from_slice(label.as_bytes());
            }
            self.0.push(0);
            self
        }

        fn question(&mut self, name: &str, qtype: u16) -> &mut Self {
            self.name(name);
            self.0.extend_from_slice(&qtype.to_be_bytes());
            self.0.extend_from_slice(&1u16.to_be_bytes()); // IN
            self
        }

        /// A record with raw RDATA.
        fn record(
            &mut self,
            name: &str,
            rtype: u16,
            class: u16,
            ttl: u32,
            rdata: &[u8],
        ) -> &mut Self {
            self.name(name);
            self.0.extend_from_slice(&rtype.to_be_bytes());
            self.0.extend_from_slice(&class.to_be_bytes());
            self.0.extend_from_slice(&ttl.to_be_bytes());
            self.0
                .extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            self.0.extend_from_slice(rdata);
            self
        }

        fn a(&mut self, name: &str, ttl: u32) -> &mut Self {
            self.record(name, 1, 1, ttl, &[93, 184, 216, 34])
        }

        /// CNAME whose target is spelled out (no compression).
        fn cname(&mut self, name: &str, ttl: u32, target: &str) -> &mut Self {
            let mut rdata = Msg(Vec::new());
            rdata.name(target);
            self.record(name, TYPE_CNAME, 1, ttl, &rdata.0)
        }

        /// SOA with the five 32-bit fields, MINIMUM last.
        fn soa(&mut self, name: &str, ttl: u32, minimum: u32) -> &mut Self {
            let mut rdata = Msg(Vec::new());
            rdata.name("ns.example.com");
            rdata.name("hostmaster.example.com");
            for v in [1u32, 7200, 3600, 1_209_600, minimum] {
                rdata.0.extend_from_slice(&v.to_be_bytes());
            }
            self.record(name, TYPE_SOA, 1, ttl, &rdata.0)
        }

        /// OPT pseudo-record: CLASS is the payload size, TTL holds
        /// extended-RCODE/version/flags.
        fn opt(&mut self, payload: u16, ext_rcode: u8, dnssec_ok: bool, rdata: &[u8]) -> &mut Self {
            let ttl = (u32::from(ext_rcode) << 24) | if dnssec_ok { 0x8000 } else { 0 };
            self.record("", TYPE_OPT, payload, ttl, rdata)
        }

        fn build(&self) -> Vec<u8> {
            self.0.clone()
        }
    }

    /// Every real record's TTL, in message order. OPT is left out — its slot
    /// holds flags, and the rewrites below are expected to leave it alone.
    fn ttls(msg: &[u8]) -> Vec<u32> {
        let mut cur = RecordCursor::new(msg).unwrap();
        let mut out = Vec::new();
        while let Step::Record(r) = cur.next(msg) {
            if r.rtype != TYPE_OPT {
                out.push(read_u32(msg, r.ttl_off));
            }
        }
        out
    }

    #[test]
    fn walks_every_section() {
        let msg = Msg::new([1, 1, 1, 1], 0)
            .question("example.com", 1)
            .a("example.com", 300)
            .soa("example.com", 60, 30)
            .opt(1232, 0, false, &[])
            .build();
        assert!(is_well_formed(&msg));
        // A, SOA — and the OPT record walked past but not counted as a TTL.
        assert_eq!(ttls(&msg), vec![300, 60]);
    }

    #[test]
    fn rejects_truncated_and_lying_counts() {
        let good = Msg::new([1, 1, 0, 0], 0)
            .question("example.com", 1)
            .a("example.com", 300)
            .build();
        assert!(is_well_formed(&good));
        // ANCOUNT claims two records, only one is present.
        let mut lying = good.clone();
        lying[7] = 2;
        assert!(!is_well_formed(&lying));
        // RDLENGTH past the end of the buffer.
        let mut chopped = good.clone();
        chopped.truncate(chopped.len() - 1);
        assert!(!is_well_formed(&chopped));
        assert!(!is_well_formed(&[]));
        assert_eq!(rcode(&chopped), None);
    }

    #[test]
    fn rcode_merges_the_extended_bits() {
        let plain = Msg::new([1, 0, 0, 0], 3).question("example.com", 1).build();
        assert_eq!(rcode(&plain), Some(3));
        // BADVERS: extended RCODE 1 in the OPT record → 16, not 0.
        let extended = Msg::new([1, 0, 0, 1], 0)
            .question("example.com", 1)
            .opt(1232, 1, false, &[])
            .build();
        assert_eq!(rcode(&extended), Some(16));
    }

    #[test]
    fn udp_payload_floors_at_512() {
        let bare = Msg::new([1, 0, 0, 0], 0).question("example.com", 1).build();
        assert_eq!(udp_payload(&bare), 512);
        let small = Msg::new([1, 0, 0, 1], 0)
            .question("example.com", 1)
            .opt(200, 0, false, &[])
            .build();
        assert_eq!(udp_payload(&small), 512);
        let large = Msg::new([1, 0, 0, 1], 0)
            .question("example.com", 1)
            .opt(4096, 0, false, &[])
            .build();
        assert_eq!(udp_payload(&large), 4096);
    }

    #[test]
    fn caps_and_sets_ttls_in_place_but_never_opt() {
        let mut msg = Msg::new([1, 2, 1, 1], 0)
            .question("example.com", 1)
            .a("example.com", 300)
            .a("example.com", 30)
            .soa("example.com", 600, 60)
            .opt(1232, 0, true, &[])
            .build();
        assert!(cap_ttls(&mut msg, 60));
        assert_eq!(ttls(&msg), vec![60, 30, 60]);
        // Already under the cap → no write, no claim of a change.
        assert!(!cap_ttls(&mut msg, 60));

        assert!(set_ttls(&mut msg, 45));
        assert_eq!(ttls(&msg), vec![45, 45, 45]);
        // The OPT "TTL" is flags, not a lifetime: both rewrites skipped it, so
        // the DO bit set above is still set.
        let EdnsScan::Opt(opt) = edns(&msg) else {
            panic!("OPT not found");
        };
        assert!(opt.dnssec_ok);
        assert!(is_well_formed(&msg));
    }

    #[test]
    fn broken_messages_are_left_alone() {
        let mut msg = Msg::new([1, 1, 0, 0], 0)
            .question("example.com", 1)
            .a("example.com", 300)
            .build();
        msg[7] = 9; // ANCOUNT lies
        let before = msg.clone();
        assert!(!cap_ttls(&mut msg, 1));
        assert!(!set_ttls(&mut msg, 1));
        assert_eq!(msg, before);
    }

    #[test]
    fn cache_ttl_prefers_answers_then_the_soa() {
        let positive = Msg::new([1, 2, 0, 0], 0)
            .question("example.com", 1)
            .a("example.com", 300)
            .a("example.com", 120)
            .build();
        assert_eq!(cache_ttl(&positive), Some(120));

        // NODATA: the lesser of the SOA's own TTL and its MINIMUM.
        let nodata = Msg::new([1, 0, 1, 0], 0)
            .question("example.com", 28)
            .soa("example.com", 3600, 300)
            .build();
        assert_eq!(cache_ttl(&nodata), Some(300));

        let zero = Msg::new([1, 1, 0, 0], 0)
            .question("example.com", 1)
            .a("example.com", 0)
            .build();
        assert_eq!(cache_ttl(&zero), None);

        // NODATA with nothing to bound it.
        let unbounded = Msg::new([1, 0, 0, 0], 0)
            .question("example.com", 28)
            .build();
        assert_eq!(cache_ttl(&unbounded), None);
    }

    #[test]
    fn edns_reports_do_and_ecs_and_patches_in_place() {
        let no_opt = Msg::new([1, 0, 0, 0], 0).question("example.com", 1).build();
        assert!(matches!(edns(&no_opt), EdnsScan::None));

        // One ECS option (code 8) after an unrelated one (code 10, cookie).
        let mut rdata = vec![0, 10, 0, 2, 0xab, 0xcd];
        rdata.extend_from_slice(&[0, 8, 0, 4, 0, 1, 24, 0]);
        let mut msg = Msg::new([1, 0, 0, 1], 0)
            .question("example.com", 1)
            .opt(512, 0, false, &rdata)
            .build();
        let EdnsScan::Opt(opt) = edns(&msg) else {
            panic!("OPT not found");
        };
        assert!(opt.has_ecs);
        assert!(!opt.dnssec_ok);
        assert_eq!(opt.payload, 512);

        set_dnssec_ok(&mut msg, &opt, true);
        set_udp_payload(&mut msg, &opt, 1232);
        let EdnsScan::Opt(opt) = edns(&msg) else {
            panic!("OPT not found");
        };
        assert!(opt.dnssec_ok);
        assert_eq!(opt.payload, 1232);
        set_dnssec_ok(&mut msg, &opt, false);
        let EdnsScan::Opt(opt) = edns(&msg) else {
            panic!("OPT not found");
        };
        assert!(!opt.dnssec_ok);
        assert!(is_well_formed(&msg));
    }

    #[test]
    fn finds_cname_targets_including_compressed_ones() {
        let msg = Msg::new([1, 2, 0, 0], 0)
            .question("example.com", 1)
            .cname("example.com", 300, "TRACK.ads.example")
            .a("track.ads.example", 300)
            .build();
        assert!(matches!(
            find_cname_target(&msg, |t| t == "track.ads.example"),
            CnameScan::Matched(t) if t == "track.ads.example"
        ));
        assert!(matches!(
            find_cname_target(&msg, |_| false),
            CnameScan::NoMatch
        ));

        // A compressed target: pointer back to the question's name.
        let compressed = Msg::new([1, 1, 0, 0], 0)
            .question("example.com", 1)
            .record("www.example.com", TYPE_CNAME, 1, 300, &[0xC0, 0x0C])
            .build();
        assert!(matches!(
            find_cname_target(&compressed, |t| t == "example.com"),
            CnameScan::Matched(_)
        ));
    }

    #[test]
    fn unrepresentable_targets_ask_for_the_full_parser() {
        // IDN label: the full parser renders it as Unicode, so byte-lowercasing
        // would spell a different name.
        let idn = Msg::new([1, 1, 0, 0], 0)
            .question("example.com", 1)
            .cname("example.com", 300, "xn--80ak6aa92e.com")
            .build();
        assert!(matches!(
            find_cname_target(&idn, |_| true),
            CnameScan::Unsupported
        ));

        // A label holding a byte the text form has to escape.
        let odd = Msg::new([1, 1, 0, 0], 0)
            .question("example.com", 1)
            .cname("example.com", 300, "we ird.com")
            .build();
        assert!(matches!(
            find_cname_target(&odd, |_| true),
            CnameScan::Unsupported
        ));
    }

    #[test]
    fn pointer_loops_terminate() {
        // RDATA is a pointer to itself (offset 52) → refused, not followed:
        // only a strictly backwards pointer can be walked.
        let looped = Msg::new([1, 1, 0, 0], 0)
            .question("example.com", 1)
            .record("example.com", TYPE_CNAME, 1, 300, &[0xC0, 0x34])
            .build();
        assert_eq!(looped.len(), 54);
        assert!(matches!(
            find_cname_target(&looped, |_| true),
            CnameScan::Unsupported
        ));
    }

    #[test]
    fn reads_the_question_off_the_wire() {
        let msg = Msg::new([1, 0, 0, 0], 0)
            .question("WWW.Example.COM", 28)
            .build();
        let QuestionScan::Found { name, qtype } = question(&msg) else {
            panic!("question not found");
        };
        assert_eq!(name, "www.example.com");
        assert_eq!(qtype, 28);
        assert_eq!(opcode(&msg), Some(0));

        // The root: one empty name, and the log spells it "".
        let root = Msg::new([1, 0, 0, 0], 0).question("", 48).build();
        assert!(matches!(
            question(&root),
            QuestionScan::Found { ref name, qtype: 48 } if name.is_empty()
        ));

        // An IDN question goes to the full parser, like an IDN CNAME target.
        let idn = Msg::new([1, 0, 0, 0], 0)
            .question("xn--80ak6aa92e.com", 1)
            .build();
        assert!(matches!(question(&idn), QuestionScan::Unsupported));

        // Nothing to read: no question at all, and a truncated one.
        let none = Msg::new([0, 0, 0, 0], 0).build();
        assert!(matches!(question(&none), QuestionScan::Missing));
        assert!(matches!(
            question(&msg[..msg.len() - 6]),
            QuestionScan::Missing
        ));
        assert!(matches!(question(&[]), QuestionScan::Missing));
        assert_eq!(opcode(&[]), None);
    }

    #[test]
    fn question_end_matches_the_walkers() {
        let msg = Msg::new([1, 0, 0, 0], 0).question("example.com", 1).build();
        assert_eq!(question_end(&msg), Some(msg.len()));
        assert_eq!(question_end(&msg[..msg.len() - 2]), None);
        assert_eq!(question_end(&[]), None);
    }
}
