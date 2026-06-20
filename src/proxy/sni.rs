//! Minimal TLS ClientHello SNI peeker.
//!
//! Reads only enough of the (untrusted) TLS handshake to extract the
//! `server_name`, without terminating TLS — so the client still completes the
//! handshake end-to-end with the real server (no MITM, no cert warning). Every
//! index is bounds-checked; malformed input yields `NotFound`, never a panic.

/// Outcome of attempting to read the SNI host from a (possibly partial) stream.
#[derive(Debug, PartialEq, Eq)]
pub enum SniResult {
    /// SNI host name found (lowercased, no trailing dot).
    Found(String),
    /// The buffer doesn't yet contain the full first TLS record — read more.
    Incomplete,
    /// Parsed a full record but it isn't a ClientHello with a usable SNI
    /// (junk, non-TLS, encrypted ClientHello, or no server_name extension).
    NotFound,
}

const TLS_HANDSHAKE: u8 = 0x16;
const CLIENT_HELLO: u8 = 0x01;
const EXT_SERVER_NAME: u16 = 0x0000;
const SNI_HOST_NAME: u8 = 0x00;

/// Try to extract the SNI host name from the start of a TLS stream.
pub fn parse_sni(buf: &[u8]) -> SniResult {
    // TLS record header: content_type(1) legacy_version(2) length(2).
    if buf.len() < 5 {
        return SniResult::Incomplete;
    }
    if buf[0] != TLS_HANDSHAKE {
        return SniResult::NotFound;
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let record_end = 5 + record_len;
    if buf.len() < record_end {
        return SniResult::Incomplete;
    }
    // We only inspect the first record. A ClientHello that legitimately spans
    // multiple records is treated as NotFound (vanishingly rare for clients).
    match parse_client_hello(&buf[5..record_end]) {
        Some(Some(host)) => SniResult::Found(host),
        _ => SniResult::NotFound,
    }
}

/// Absolute byte offset (into `buf`) and length of the SNI host name within the
/// first TLS record, if `buf` begins with a ClientHello carrying a `server_name`.
/// Used by the DPI-evasion egress to split the ClientHello *inside* the host name
/// so a SNI-matching middlebox never sees the whole name in one segment. Returns
/// `None` for anything that wouldn't parse to a host (mirrors `parse_sni`), and
/// every index is bounds-checked.
pub fn sni_host_range(buf: &[u8]) -> Option<(usize, usize)> {
    if buf.len() < 5 || buf[0] != TLS_HANDSHAKE {
        return None;
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let record_end = 5 + record_len;
    if buf.len() < record_end {
        return None;
    }
    // Single cursor over the first record so positions stay absolute.
    let rec = &buf[..record_end];
    let mut r = Reader::new(rec);
    r.skip(5)?; // record header
    if r.u8()? != CLIENT_HELLO {
        return None;
    }
    r.u24()?; // handshake length
    r.skip(2 + 32)?; // client_version + random
    let session_id_len = r.u8()? as usize;
    r.skip(session_id_len)?;
    let cipher_suites_len = r.u16()? as usize;
    r.skip(cipher_suites_len)?;
    let compression_len = r.u8()? as usize;
    r.skip(compression_len)?;
    let ext_total = r.u16()? as usize;
    let ext_end = r.pos.checked_add(ext_total)?.min(record_end);
    while r.pos + 4 <= ext_end {
        let ext_type = r.u16()?;
        let ext_len = r.u16()? as usize;
        let ext_data_start = r.pos;
        r.skip(ext_len)?;
        if ext_type == EXT_SERVER_NAME {
            return host_name_range(rec, ext_data_start, ext_len);
        }
    }
    None
}

/// Locate the first `host_name` entry inside a `server_name` extension's data,
/// returning its absolute offset and length within `rec`.
fn host_name_range(rec: &[u8], data_start: usize, data_len: usize) -> Option<(usize, usize)> {
    let end = data_start.checked_add(data_len)?.min(rec.len());
    let mut r = Reader::new(rec);
    r.pos = data_start;
    let _list_len = r.u16()?; // server_name_list length
    while r.pos + 3 <= end {
        let name_type = r.u8()?;
        let name_len = r.u16()? as usize;
        let name_start = r.pos;
        if name_start.checked_add(name_len)? > end {
            return None;
        }
        r.pos = name_start + name_len;
        if name_type == SNI_HOST_NAME && name_len > 0 {
            return Some((name_start, name_len));
        }
    }
    None
}

/// `Some(Some(host))` = found; `Some(None)` = valid ClientHello but no SNI;
/// `None` = malformed/truncated within the record.
fn parse_client_hello(rec: &[u8]) -> Option<Option<String>> {
    let mut r = Reader::new(rec);
    if r.u8()? != CLIENT_HELLO {
        return Some(None);
    }
    let _handshake_len = r.u24()?;
    r.skip(2)?; // client_version
    r.skip(32)?; // random
    let session_id_len = r.u8()? as usize;
    r.skip(session_id_len)?;
    let cipher_suites_len = r.u16()? as usize;
    r.skip(cipher_suites_len)?;
    let compression_len = r.u8()? as usize;
    r.skip(compression_len)?;
    // Extensions block.
    let ext_total = r.u16()? as usize;
    let ext_block = r.slice(ext_total)?;

    let mut er = Reader::new(ext_block);
    while er.remaining() >= 4 {
        let ext_type = er.u16()?;
        let ext_len = er.u16()? as usize;
        let ext_data = er.slice(ext_len)?;
        if ext_type == EXT_SERVER_NAME {
            return Some(parse_server_name(ext_data));
        }
    }
    Some(None)
}

fn parse_server_name(data: &[u8]) -> Option<String> {
    let mut r = Reader::new(data);
    let _list_len = r.u16()?; // server_name_list length
    while r.remaining() >= 3 {
        let name_type = r.u8()?;
        let name_len = r.u16()? as usize;
        let name = r.slice(name_len)?;
        if name_type == SNI_HOST_NAME {
            let host = std::str::from_utf8(name).ok()?;
            if host.is_empty() {
                return None;
            }
            return Some(host.trim_end_matches('.').to_ascii_lowercase());
        }
    }
    None
}

/// Bounds-checked big-endian cursor over a byte slice.
struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.pos)
    }
    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }
    fn u16(&mut self) -> Option<u16> {
        let hi = *self.b.get(self.pos)?;
        let lo = *self.b.get(self.pos + 1)?;
        self.pos += 2;
        Some(u16::from_be_bytes([hi, lo]))
    }
    fn u24(&mut self) -> Option<usize> {
        let a = *self.b.get(self.pos)? as usize;
        let b = *self.b.get(self.pos + 1)? as usize;
        let c = *self.b.get(self.pos + 2)? as usize;
        self.pos += 3;
        Some((a << 16) | (b << 8) | c)
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        let np = self.pos.checked_add(n)?;
        if np > self.b.len() {
            return None;
        }
        self.pos = np;
        Some(())
    }
    fn slice(&mut self, n: usize) -> Option<&'a [u8]> {
        let np = self.pos.checked_add(n)?;
        let s = self.b.get(self.pos..np)?;
        self.pos = np;
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal but well-formed TLS 1.2 ClientHello record carrying `sni`
    /// (empty string → no SNI extension).
    fn client_hello(sni: &str) -> Vec<u8> {
        let mut extensions = Vec::new();
        if !sni.is_empty() {
            let host = sni.as_bytes();
            let mut sni_data = Vec::new();
            let entry_len = 1 + 2 + host.len(); // name_type(1) + name_len(2) + host
            sni_data.extend_from_slice(&(entry_len as u16).to_be_bytes()); // list length
            sni_data.push(SNI_HOST_NAME);
            sni_data.extend_from_slice(&(host.len() as u16).to_be_bytes());
            sni_data.extend_from_slice(host);

            extensions.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
            extensions.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&sni_data);
        }

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client_version TLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id length
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites length
        body.extend_from_slice(&[0x00, 0x2f]); // one cipher suite
        body.push(1); // compression_methods length
        body.push(0); // null compression
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = vec![CLIENT_HELLO];
        let blen = body.len();
        handshake.push((blen >> 16) as u8);
        handshake.push((blen >> 8) as u8);
        handshake.push(blen as u8);
        handshake.extend_from_slice(&body);

        let mut record = vec![TLS_HANDSHAKE, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn extracts_sni_host() {
        assert_eq!(
            parse_sni(&client_hello("example.com")),
            SniResult::Found("example.com".to_string())
        );
    }

    #[test]
    fn lowercases_and_strips_trailing_dot() {
        assert_eq!(
            parse_sni(&client_hello("Example.COM.")),
            SniResult::Found("example.com".to_string())
        );
    }

    #[test]
    fn partial_record_is_incomplete() {
        let full = client_hello("example.com");
        assert_eq!(parse_sni(&full[..3]), SniResult::Incomplete);
        // Header present but body truncated → still incomplete.
        assert_eq!(parse_sni(&full[..full.len() - 5]), SniResult::Incomplete);
    }

    #[test]
    fn non_tls_is_not_found() {
        assert_eq!(parse_sni(b"GET / HTTP/1.1\r\n\r\n"), SniResult::NotFound);
    }

    #[test]
    fn client_hello_without_sni_is_not_found() {
        assert_eq!(parse_sni(&client_hello("")), SniResult::NotFound);
    }

    #[test]
    fn sni_host_range_points_at_the_raw_host_bytes() {
        let ch = client_hello("Example.COM");
        let (start, len) = sni_host_range(&ch).expect("range");
        // Raw bytes (case preserved — unlike parse_sni, which lowercases).
        assert_eq!(&ch[start..start + len], b"Example.COM");
    }

    #[test]
    fn sni_host_range_none_without_sni_or_for_junk() {
        assert_eq!(sni_host_range(&client_hello("")), None);
        assert_eq!(sni_host_range(b"GET / HTTP/1.1\r\n\r\n"), None);
        // Truncated record → None (no panic).
        let full = client_hello("example.com");
        assert_eq!(sni_host_range(&full[..full.len() - 4]), None);
    }

    #[test]
    fn sni_host_range_midpoint_splits_the_host() {
        let ch = client_hello("blocked.example.com");
        let (start, len) = sni_host_range(&ch).unwrap();
        let split = start + len / 2;
        // Neither side contains the whole host name.
        assert!(split > start && split < start + len);
    }
}
