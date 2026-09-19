use std::net::{IpAddr, Ipv6Addr};
use std::path::Path;

use fst::map::OpBuilder;
use fst::{Map, MapBuilder, Streamer};
use reqwest::{Client, Url};

use crate::ListPolarity;
use crate::domains::DomainSet;
use crate::parser::{self, AdblockStats};
use ferrite_core::error::{FeriteError, Result};

/// Standard error message returned when a user-submitted blocklist URL fails
/// validation. Kept as a constant so the API and tests share one wording.
const INVALID_URL_MSG: &str =
    "blocklist URL must be http(s) and must not point to a private or local address";

/// Returns `true` if `ip` is in a range that must never be reachable via a
/// user-submitted blocklist URL (loopback, private, link-local incl. cloud
/// metadata 169.254.169.254, unspecified, broadcast, multicast).
fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local() // 169.254.0.0/16 (covers 169.254.169.254)
                || v4.is_unspecified() // 0.0.0.0
                || v4.is_broadcast() // 255.255.255.255
                || v4.is_multicast()
                // RFC 6598 carrier-grade NAT 100.64.0.0/10
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 0x40)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() // ::1
                || v6.is_unspecified() // ::
                || v6.is_multicast()
                || is_unique_local_v6(v6) // fc00::/7
                || is_unicast_link_local_v6(v6) // fe80::/10
                // IPv4-mapped/compatible addresses must be re-checked as IPv4.
                || v6.to_ipv4().map(IpAddr::V4).is_some_and(is_blocked_ip)
        }
    }
}

/// fc00::/7 — IPv6 unique local addresses (the `Ipv6Addr::is_unique_local`
/// method is unstable, so check the high bits directly).
fn is_unique_local_v6(v6: Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xfe00) == 0xfc00
}

/// fe80::/10 — IPv6 unicast link-local addresses (`is_unicast_link_local` is
/// unstable, so check the high bits directly).
fn is_unicast_link_local_v6(v6: Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xffc0) == 0xfe80
}

/// Validate a blocklist URL submitted through the public API.
///
/// This guards against SSRF and local file disclosure: it rejects any scheme
/// other than `http`/`https` (so `file://`, `ftp://`, … are refused) and any
/// host that resolves to a non-public address (loopback, private LAN,
/// link-local incl. the cloud metadata IP `169.254.169.254`, unspecified,
/// broadcast, multicast).
///
/// Hostnames are resolved via DNS and *every* resolved address must be public;
/// this defends against DNS-rebinding-to-internal. `localhost` is rejected
/// outright.
///
/// NOTE: this is intentionally enforced at the API layer only. Blocklists
/// defined in the trusted local config file (which may legitimately use
/// `file://`) load through `load_list` directly and are not subject to this
/// check.
pub async fn validate_remote_list_url(url: &str) -> Result<()> {
    let parsed = Url::parse(url).map_err(|_| FeriteError::Config(INVALID_URL_MSG.to_owned()))?;

    // (1) Scheme must be http or https — this rejects file://, ftp://, etc.
    match parsed.scheme() {
        "http" | "https" => {}
        _ => return Err(FeriteError::Config(INVALID_URL_MSG.to_owned())),
    }

    // `host_str()` brackets IPv6 literals (e.g. "[::1]"); strip them so the
    // value parses cleanly as an `IpAddr`.
    let host = parsed
        .host_str()
        .ok_or_else(|| FeriteError::Config(INVALID_URL_MSG.to_owned()))?;
    let host_unbracketed = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);

    // (2) IP literal host: check the range directly, no DNS needed.
    if let Ok(ip) = host_unbracketed.parse::<IpAddr>() {
        if is_blocked_ip(ip) {
            return Err(FeriteError::Config(INVALID_URL_MSG.to_owned()));
        }
        return Ok(());
    }

    // (3)/(4) Hostname: reject `localhost` outright, then resolve and reject if
    // ANY resolved address is in a blocked range (DNS-rebinding defense).
    let name_lc = host_unbracketed.to_ascii_lowercase();
    if name_lc == "localhost" || name_lc.ends_with(".localhost") {
        return Err(FeriteError::Config(INVALID_URL_MSG.to_owned()));
    }

    let mut resolved = tokio::net::lookup_host((name_lc.as_str(), 80u16))
        .await
        .map_err(|e| {
            FeriteError::Config(format!(
                "could not resolve blocklist URL host '{}': {}",
                host, e
            ))
        })?
        .peekable();

    if resolved.peek().is_none() {
        return Err(FeriteError::Config(format!(
            "could not resolve blocklist URL host '{}'",
            host
        )));
    }

    for addr in resolved {
        if is_blocked_ip(addr.ip()) {
            return Err(FeriteError::Config(INVALID_URL_MSG.to_owned()));
        }
    }
    Ok(())
}

/// Shared HTTP client (connection pool is reused across all list fetches).
static HTTP_CLIENT: std::sync::LazyLock<Client> = std::sync::LazyLock::new(|| {
    Client::builder()
        .user_agent(concat!("ferrite/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(60))
        // Do NOT follow redirects. `validate_remote_list_url` only checks the
        // submitted URL; without this a public host could 302-redirect the
        // fetch to an internal address (cloud metadata, 127.0.0.1, LAN
        // services), bypassing the SSRF guard. Fail closed instead.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to build HTTP client")
});

/// Fetch a subscription list from `url` and return parsed domain names.
///
/// Supports:
/// - `file:///path` — read from local filesystem
/// - `http://` / `https://` — HTTP GET
///
/// Format is auto-detected from content (hosts vs. Adblock); `polarity` decides
/// how Adblock-format content is read (block rules vs `@@` exception rules).
pub async fn load_list(
    url: &str,
    polarity: ListPolarity,
) -> Result<(DomainSet, Option<AdblockStats>)> {
    // Parsed as it arrives. A big subscription is 20–40 MB of text that would
    // otherwise sit in memory next to the `Vec<String>` it parses into — and
    // this runs on a box whose whole memory target is a few tens of megabytes.
    let mut parser = ListParser::new(polarity);
    let mut lines = LineSplitter::default();

    if let Some(path) = url.strip_prefix("file://") {
        tracing::info!("reading list from file {}", path);
        use tokio::io::AsyncBufReadExt;
        let file = tokio::fs::File::open(path).await?;
        let mut reader = tokio::io::BufReader::new(file).lines();
        while let Some(line) = reader.next_line().await? {
            parser.feed(&line);
        }
    } else {
        tracing::info!("fetching list from {}", url);
        let mut resp = HTTP_CLIENT.get(url).send().await?.error_for_status()?;
        while let Some(chunk) = resp.chunk().await? {
            lines.push(&chunk, |line| parser.feed(line));
        }
        lines.finish(|line| parser.feed(line));
    }

    let (domains, stats) = parser.finish();
    tracing::info!("parsed {} domains from {}", domains.len(), url);
    Ok((domains, stats))
}

/// Splits a byte stream into lines across chunk boundaries, exactly as
/// `str::lines` would: `\n` separates, a trailing `\r` is dropped, and the last
/// line needs no terminator. Invalid UTF-8 is replaced rather than rejected — a
/// subscription with one bad byte should lose that character, not the list.
#[derive(Default)]
pub struct LineSplitter {
    pending: Vec<u8>,
}

impl LineSplitter {
    /// Feed the next chunk, calling `on_line` for every complete line in it.
    pub fn push(&mut self, chunk: &[u8], mut on_line: impl FnMut(&str)) {
        let mut rest = chunk;
        while let Some(end) = rest.iter().position(|b| *b == b'\n') {
            let (line, tail) = rest.split_at(end);
            rest = &tail[1..];
            if self.pending.is_empty() {
                on_line(&decode_line(line));
            } else {
                self.pending.extend_from_slice(line);
                on_line(&decode_line(&self.pending));
                self.pending.clear();
            }
        }
        self.pending.extend_from_slice(rest);
    }

    /// Emit whatever is left when the stream ends without a final newline.
    pub fn finish(self, mut on_line: impl FnMut(&str)) {
        if !self.pending.is_empty() {
            on_line(&decode_line(&self.pending));
        }
    }
}

fn decode_line(bytes: &[u8]) -> std::borrow::Cow<'_, str> {
    let bytes = match bytes.last() {
        Some(b'\r') => &bytes[..bytes.len() - 1],
        _ => bytes,
    };
    String::from_utf8_lossy(bytes)
}

/// The most leading comment a list may have before its format is decided. A
/// real list header is a handful of lines; the cap only stops a pathological
/// file from buffering without end.
const MAX_HEADER_BYTES: usize = 1 << 20;

/// A list parser that decides the format from the first lines and then streams
/// the rest straight into it — the same detection rules as [`parse_content`],
/// which is now this type fed a whole body.
pub struct ListParser {
    polarity: ListPolarity,
    state: ParserState,
}

enum ParserState {
    /// Still looking for the first line that reveals the format. Lines seen so
    /// far are replayed into the parser once it is chosen, so nothing is lost.
    Detecting {
        header: Vec<String>,
        bytes: usize,
    },
    Hosts(parser::HostsParser),
    Plain(parser::PlainParser),
    Adblock(parser::AdblockParser),
    AdblockAllow(parser::AdblockExceptionsParser),
}

impl ListParser {
    pub fn new(polarity: ListPolarity) -> Self {
        Self {
            polarity,
            state: ParserState::Detecting {
                header: Vec::new(),
                bytes: 0,
            },
        }
    }

    pub fn feed(&mut self, line: &str) {
        match &mut self.state {
            ParserState::Detecting { header, bytes } => {
                let trimmed = line.trim();
                let decided = if trimmed.is_empty() {
                    None
                } else if trimmed.starts_with("[Adblock") {
                    // The Adblock/uBO header is itself a definitive format
                    // marker — an EasyList file opens with e.g.
                    // `[Adblock Plus 2.0]`. Detected before the comment skip so
                    // the format is never mistaken for plain text.
                    Some(Format::Adblock)
                } else if trimmed.starts_with('!') || trimmed.starts_with('#') {
                    // Comments don't reveal the data format.
                    None
                } else if trimmed.starts_with("0.0.0.0")
                    || trimmed.starts_with("127.0.0.1")
                    || trimmed.starts_with("::1")
                {
                    // First real data line decides. The hosts marker (a leading
                    // IP) is checked first: it is the most specific signal and
                    // keeps a hosts line with a `$` in its trailing comment
                    // from being mistaken for an Adblock rule.
                    Some(Format::Hosts)
                } else if parser::is_adblock_syntax(trimmed) {
                    Some(Format::Adblock)
                } else {
                    Some(Format::Plain)
                };

                *bytes += line.len() + 1;
                header.push(line.to_string());
                match decided {
                    Some(format) => self.switch_to(format),
                    // A list that is nothing but comments never decides, and
                    // finishes empty — same as before.
                    None if *bytes > MAX_HEADER_BYTES => self.switch_to(Format::Plain),
                    None => {}
                }
            }
            ParserState::Hosts(p) => p.feed(line),
            ParserState::Plain(p) => p.feed(line),
            ParserState::Adblock(p) => p.feed(line),
            ParserState::AdblockAllow(p) => p.feed(line),
        }
    }

    /// Choose the parser and replay everything buffered during detection.
    fn switch_to(&mut self, format: Format) {
        let ParserState::Detecting { header, .. } = std::mem::replace(
            &mut self.state,
            ParserState::Plain(parser::PlainParser::default()),
        ) else {
            return;
        };
        self.state = match (format, self.polarity) {
            (Format::Hosts, _) => ParserState::Hosts(parser::HostsParser::default()),
            (Format::Plain, _) => ParserState::Plain(parser::PlainParser::default()),
            // Hosts and plain formats read the same under either polarity; only
            // the Adblock parse differs (block rules vs `@@` exception rules).
            (Format::Adblock, ListPolarity::Block) => {
                ParserState::Adblock(parser::AdblockParser::default())
            }
            (Format::Adblock, ListPolarity::Allow) => {
                ParserState::AdblockAllow(parser::AdblockExceptionsParser::default())
            }
        };
        for line in header {
            self.feed(&line);
        }
    }

    pub fn finish(self) -> (DomainSet, Option<AdblockStats>) {
        match self.state {
            // Nothing but comments: no format, no domains.
            ParserState::Detecting { .. } => (DomainSet::new(), None),
            ParserState::Hosts(p) => (p.finish(), None),
            ParserState::Plain(p) => (p.finish(), None),
            ParserState::Adblock(p) => {
                let (domains, stats) = p.finish();
                (domains, Some(stats))
            }
            ParserState::AdblockAllow(p) => {
                let (domains, stats) = p.finish();
                (domains, Some(stats))
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Format {
    Hosts,
    Plain,
    Adblock,
}

/// Detect list format and parse into domain names.
///
/// Detection rules, in order:
///
/// - A `[Adblock …]` header anywhere → adblock. This is the definitive marker
///   emitted by EasyList/uBO lists and is checked first; previously it was
///   skipped as a "comment", which let EasyList fall through to the plain
///   parser and wrongly block domains lifted from cosmetic rules.
/// - Otherwise the **first non-comment, non-empty data line** decides:
///   - Adblock filter syntax (`||`, `@@`, `##`, `$…`, …) → adblock
///   - `0.0.0.0` / `127.0.0.1` / `::1`                    → hosts format
///   - Anything else                                      → plain domain list
pub fn parse_content(content: &str, polarity: ListPolarity) -> (Vec<String>, Option<AdblockStats>) {
    let mut parser = ListParser::new(polarity);
    for line in content.lines() {
        parser.feed(line);
    }
    let (domains, stats) = parser.finish();
    (domains.to_vec(), stats)
}

/// Backing bytes for an [`fst::Map`]: an anonymous RAM buffer or a memory-mapped
/// file. Mmap is the serving default — the FST then lives in the OS page cache,
/// where the kernel can evict it under memory pressure, instead of pinning RSS.
/// `Ram` covers the empty startup map and the fallback when persisting fails
/// (e.g. read-only disk).
pub enum FstBytes {
    Ram(Vec<u8>),
    Mmap(memmap2::Mmap),
}

impl AsRef<[u8]> for FstBytes {
    fn as_ref(&self) -> &[u8] {
        match self {
            FstBytes::Ram(b) => b,
            FstBytes::Mmap(m) => m,
        }
    }
}

/// The one map type the engine holds, regardless of backing store.
pub type FstMap = Map<FstBytes>;

/// Wrap in-RAM FST bytes as an [`FstMap`].
pub fn ram_fst(bytes: Vec<u8>) -> Result<FstMap> {
    Map::new(FstBytes::Ram(bytes)).map_err(|e| FeriteError::Fst(e.to_string()))
}

/// Open an on-disk FST as a memory-mapped [`FstMap`].
///
/// Mapping a file is only sound while its inode's bytes never change. Every
/// writer of ferrite FST files must therefore replace them atomically (write a
/// tmp path, then rename) — never write in place. Rename keeps the old inode
/// alive for existing mappings.
pub fn mmap_fst(path: &Path) -> Result<FstMap> {
    let file = std::fs::File::open(path)
        .map_err(|e| FeriteError::Fst(format!("open {}: {e}", path.display())))?;
    // SAFETY: see above — FST files are immutable once renamed into place.
    let mmap = unsafe { memmap2::Mmap::map(&file) }
        .map_err(|e| FeriteError::Fst(format!("mmap {}: {e}", path.display())))?;
    Map::new(FstBytes::Mmap(mmap)).map_err(|e| FeriteError::Fst(e.to_string()))
}

/// Merge multiple per-list FSTs into one via k-way union.
///
/// Uses `fst::map::OpBuilder::union()` which streams already-sorted keys in
/// O(n log k) time — far cheaper than collecting all domains and re-sorting.
/// Inputs are read through whatever backs each map (typically mmap'd cache
/// files, so the merge peak is the output, not the sum of every input); a
/// single input is copied out as-is.
pub fn merge_fsts<D: AsRef<[u8]>>(maps: &[Map<D>]) -> Result<Vec<u8>> {
    match maps.len() {
        0 => MapBuilder::memory()
            .into_inner()
            .map_err(|e| FeriteError::Fst(e.to_string())),
        1 => Ok(maps[0].as_fst().as_bytes().to_vec()),
        _ => {
            let mut op = OpBuilder::new();
            for m in maps {
                op = op.add(m);
            }
            let mut stream = op.union();

            let mut builder = MapBuilder::memory();
            while let Some((key, _)) = stream.next() {
                builder
                    .insert(key, 1)
                    .map_err(|e| FeriteError::Fst(e.to_string()))?;
            }

            builder
                .into_inner()
                .map_err(|e| FeriteError::Fst(e.to_string()))
        }
    }
}

/// Merge per-list FSTs straight into `path`, the streaming twin of
/// [`merge_fsts`] — see [`build_fst_file`] for why the finished map shouldn't
/// also exist in memory. The caller still renames the file into place.
pub fn merge_fsts_file<D: AsRef<[u8]>>(maps: &[Map<D>], path: &Path) -> Result<BuiltFst> {
    use std::io::Write;

    let merged = (|| -> std::io::Result<usize> {
        let file = std::fs::File::create(path)?;
        let mut writer = std::io::BufWriter::new(file);
        let count = match maps.len() {
            // A single input needs no merge: its bytes are already the answer.
            1 => {
                writer.write_all(maps[0].as_fst().as_bytes())?;
                maps[0].len()
            }
            _ => {
                let mut builder = MapBuilder::new(&mut writer)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                let mut op = OpBuilder::new();
                for m in maps {
                    op = op.add(m);
                }
                let mut stream = op.union();
                let mut count = 0usize;
                while let Some((key, _)) = stream.next() {
                    builder
                        .insert(key, 1)
                        .map_err(|e| std::io::Error::other(e.to_string()))?;
                    count += 1;
                }
                builder
                    .finish()
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                count
            }
        };
        writer.flush()?;
        Ok(count)
    })();

    match merged {
        Ok(count) => Ok(BuiltFst::File(count)),
        Err(e) => {
            tracing::warn!(
                "could not merge FSTs into {}: {} — merging in memory instead",
                path.display(),
                e
            );
            let _ = std::fs::remove_file(path);
            Ok(BuiltFst::Ram(merge_fsts(maps)?))
        }
    }
}

/// Build a sorted, deduplicated FST map from domain names.
/// All values are set to 1 (the FST is used as a set).
/// Returns raw FST bytes ready to pass to `fst::Map::new()`.
pub fn build_fst(domains: impl Into<DomainSet>) -> Result<Vec<u8>> {
    let mut domains = domains.into();
    domains.prepare_keys();

    let mut builder = MapBuilder::memory();
    for domain in domains.iter() {
        builder
            .insert(domain.as_bytes(), 1)
            .map_err(|e| FeriteError::Fst(e.to_string()))?;
    }

    let bytes = builder
        .into_inner()
        .map_err(|e| FeriteError::Fst(e.to_string()))?;

    tracing::info!(
        "built FST: {} domains, {} bytes",
        domains.len(),
        bytes.len()
    );
    Ok(bytes)
}

/// Where a freshly built FST ended up.
pub enum BuiltFst {
    /// Written straight to the given path; carries the domain count.
    File(usize),
    /// The file could not be written (read-only disk, full filesystem), so the
    /// map was built in memory instead and the caller serves it from there.
    Ram(Vec<u8>),
}

/// Build the FST directly into `path`, so the finished map never exists in
/// memory as well.
///
/// A million-domain list is ~11 MB of FST, and an in-memory builder grows its
/// buffer by doubling — some 23 MB of transient allocation at the exact moment
/// the domain list is also still in memory. Since every per-list FST is written
/// to disk anyway, it is built there.
///
/// The file is the caller's temporary path: it must still be renamed into place,
/// because FST files are mmap'd and may only ever be replaced atomically.
pub fn build_fst_file(mut domains: DomainSet, path: &Path) -> Result<BuiltFst> {
    use std::io::Write;

    domains.prepare_keys();
    let count = domains.len();

    let built = (|| -> std::io::Result<()> {
        let file = std::fs::File::create(path)?;
        let mut builder = MapBuilder::new(std::io::BufWriter::new(file))
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        for domain in domains.iter() {
            builder
                .insert(domain.as_bytes(), 1)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
        }
        let mut writer = builder
            .into_inner()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        writer.flush()?;
        Ok(())
    })();

    match built {
        Ok(()) => {
            tracing::info!("built FST: {} domains, into {}", count, path.display());
            Ok(BuiltFst::File(count))
        }
        Err(e) => {
            tracing::warn!(
                "could not build FST into {}: {} — building in memory instead",
                path.display(),
                e
            );
            let _ = std::fs::remove_file(path);
            // `domains` is already prepared, so this is just the insert loop again.
            let mut builder = MapBuilder::memory();
            for domain in domains.iter() {
                builder
                    .insert(domain.as_bytes(), 1)
                    .map_err(|err| FeriteError::Fst(err.to_string()))?;
            }
            let bytes = builder
                .into_inner()
                .map_err(|err| FeriteError::Fst(err.to_string()))?;
            Ok(BuiltFst::Ram(bytes))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: validation must reject this URL.
    async fn assert_rejected(url: &str) {
        let res = validate_remote_list_url(url).await;
        assert!(res.is_err(), "expected {url} to be rejected, got Ok");
    }

    /// Helper: validation must accept this URL.
    async fn assert_accepted(url: &str) {
        let res = validate_remote_list_url(url).await;
        assert!(res.is_ok(), "expected {url} to be accepted, got {res:?}");
    }

    #[tokio::test]
    async fn rejects_file_scheme() {
        assert_rejected("file:///etc/passwd").await;
    }

    #[tokio::test]
    async fn rejects_non_http_schemes() {
        assert_rejected("ftp://example.com/list.txt").await;
        assert_rejected("gopher://example.com/").await;
    }

    #[tokio::test]
    async fn rejects_loopback_ipv4() {
        assert_rejected("http://127.0.0.1/list.txt").await;
        assert_rejected("http://127.0.0.1:8080/list.txt").await;
    }

    #[tokio::test]
    async fn rejects_loopback_ipv6() {
        assert_rejected("http://[::1]/list.txt").await;
    }

    #[tokio::test]
    async fn rejects_cloud_metadata_ip() {
        assert_rejected("http://169.254.169.254/latest/meta-data/").await;
    }

    #[tokio::test]
    async fn rejects_private_ipv4() {
        assert_rejected("http://192.168.1.1/list.txt").await;
        assert_rejected("http://10.0.0.5/list.txt").await;
        assert_rejected("http://172.16.0.1/list.txt").await;
    }

    #[tokio::test]
    async fn rejects_unspecified_and_broadcast() {
        assert_rejected("http://0.0.0.0/list.txt").await;
        assert_rejected("http://255.255.255.255/list.txt").await;
    }

    #[tokio::test]
    async fn rejects_localhost_hostname() {
        assert_rejected("http://localhost/list.txt").await;
        assert_rejected("http://localhost:9000/list.txt").await;
        assert_rejected("http://LOCALHOST/list.txt").await;
    }

    #[tokio::test]
    async fn accepts_public_ip_literal() {
        // IP literal so no DNS lookup is needed — keeps the test offline.
        assert_accepted("http://1.1.1.1/list.txt").await;
        assert_accepted("https://8.8.8.8/hosts").await;
    }

    #[test]
    fn build_fst_strips_trailing_root_dot() {
        // FQDN-form entries must be stored dot-less so they match dot-stripped
        // lookups; the dotted and undotted forms also collapse to one key.
        let bytes = build_fst(vec![
            "ads.example.com.".to_string(),
            "ads.example.com".to_string(),
            "tracker.test.".to_string(),
        ])
        .unwrap();
        let map = Map::new(bytes).unwrap();

        assert_eq!(map.len(), 2);
        assert!(map.contains_key(b"ads.example.com"));
        assert!(map.contains_key(b"tracker.test"));
        assert!(!map.contains_key(b"ads.example.com."));
    }

    #[test]
    fn easylist_detected_as_adblock_not_plain() {
        // Real EasyList shape: an `[Adblock …]` header, `!` comments, a network
        // filter whose first data line does NOT start with `||`, then cosmetic
        // rules. Regression: this used to fall through to the plain parser and
        // block google.com lifted from the `google.com##.cls` cosmetic rule.
        let content = "\
[Adblock Plus 2.0]\n\
! Title: EasyList\n\
&rb=&uuid=$third-party\n\
||doubleclick.net^\n\
google.com##.GGQPGYLCD5\n\
www.google.com##.GISRH3UDHB\n";
        let (domains, stats) = parse_content(content, ListPolarity::Block);
        assert!(stats.is_some(), "adblock list must report parse stats");
        assert!(
            domains.contains(&"doubleclick.net".to_string()),
            "real ||domain^ rules must be parsed"
        );
        assert!(
            !domains.contains(&"google.com".to_string()),
            "google.com must not be blocked"
        );
        assert!(!domains.contains(&"www.google.com".to_string()));
    }

    #[test]
    fn easylist_without_header_still_detected_via_first_rule() {
        // Same defense without the `[Adblock]` header: the first data line uses
        // option syntax (`$third-party`), which is enough to route to adblock.
        let content = "&rb=&uuid=$third-party\n||tracker.example^\ngoogle.com##.cls\n";
        let (domains, _) = parse_content(content, ListPolarity::Block);
        assert!(domains.contains(&"tracker.example".to_string()));
        assert!(!domains.contains(&"google.com".to_string()));
    }

    #[test]
    fn hosts_with_dollar_in_comment_not_misdetected_as_adblock() {
        // Regression: a `$` in a hosts comment must not route the file to the
        // adblock parser (which would find no `||` rules and load nothing).
        let content = "0.0.0.0 casino.example # costs $$$\n0.0.0.0 ads.example\n";
        let (domains, stats) = parse_content(content, ListPolarity::Block);
        assert!(stats.is_none(), "hosts list has no adblock parse stats");
        assert!(domains.contains(&"casino.example".to_string()));
        assert!(domains.contains(&"ads.example".to_string()));
    }

    #[test]
    fn allow_polarity_reads_adblock_exceptions_and_plain_lists() {
        // Adblock format under Allow polarity: the `@@` exceptions are the
        // entries, `||` block rules are not.
        let adblock = "[Adblock Plus 2.0]\n||ads.example^\n@@||good.example^\n";
        let (domains, stats) = parse_content(adblock, ListPolarity::Allow);
        assert_eq!(domains, vec!["good.example".to_string()]);
        assert!(stats.is_some());

        // Plain and hosts formats parse identically under either polarity.
        let plain = "safe.example\ncdn.example # comment\n";
        let (allow, _) = parse_content(plain, ListPolarity::Allow);
        let (block, _) = parse_content(plain, ListPolarity::Block);
        assert_eq!(allow, block);
        assert_eq!(allow, vec!["safe.example", "cdn.example"]);
    }

    #[test]
    fn ip_classification() {
        assert!(is_blocked_ip("127.0.0.1".parse().unwrap()));
        assert!(is_blocked_ip("169.254.169.254".parse().unwrap()));
        assert!(is_blocked_ip("10.1.2.3".parse().unwrap()));
        assert!(is_blocked_ip("192.168.0.1".parse().unwrap()));
        assert!(is_blocked_ip("172.16.5.5".parse().unwrap()));
        assert!(is_blocked_ip("100.64.0.1".parse().unwrap())); // CGNAT
        assert!(is_blocked_ip("::1".parse().unwrap()));
        assert!(is_blocked_ip("fc00::1".parse().unwrap()));
        assert!(is_blocked_ip("fe80::1".parse().unwrap()));

        assert!(!is_blocked_ip("1.1.1.1".parse().unwrap()));
        assert!(!is_blocked_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_blocked_ip("2606:4700:4700::1111".parse().unwrap()));
    }
}

#[cfg(test)]
mod stream_tests {
    use super::*;

    /// Bodies covering every format the detector has to tell apart, plus the
    /// shapes that only show up in a stream: CRLF, no trailing newline, a long
    /// comment header before the first data line.
    fn bodies() -> Vec<&'static str> {
        vec![
            "0.0.0.0 ads.example.com\n0.0.0.0 tracker.example.net\n",
            "# a plain list\nads.example.com\ntracker.example.net",
            "[Adblock Plus 2.0]\n! title: test\n||ads.example.com^\n@@||good.example.com^\n||good.example.com^\n",
            "! only comments\n! and nothing else\n",
            "",
            "\r\n0.0.0.0 ads.example.com\r\n0.0.0.0 tracker.example.net\r\n",
            "||ads.example.com^$domain=other.com\n||real.example.com^\ngoogle.com##.ad\n",
        ]
    }

    /// Feeding a body through the byte splitter, at any chunk size, has to
    /// produce exactly what parsing the whole thing at once produces.
    #[test]
    fn streaming_matches_whole_body_parsing() {
        for polarity in [ListPolarity::Block, ListPolarity::Allow] {
            for body in bodies() {
                let expected = parse_content(body, polarity);
                for chunk_size in [1usize, 2, 3, 7, 16, 4096] {
                    let mut parser = ListParser::new(polarity);
                    let mut splitter = LineSplitter::default();
                    for chunk in body.as_bytes().chunks(chunk_size) {
                        splitter.push(chunk, |line| parser.feed(line));
                    }
                    splitter.finish(|line| parser.feed(line));
                    let got = parser.finish();
                    assert_eq!(
                        got.0.to_vec(),
                        expected.0,
                        "domains differ at chunk size {chunk_size} for body {body:?}"
                    );
                    assert_eq!(
                        got.1.map(|s| s.kept),
                        expected.1.map(|s| s.kept),
                        "stats differ at chunk size {chunk_size} for body {body:?}"
                    );
                }
            }
        }
    }

    /// A header longer than the cap stops buffering and settles on plain —
    /// bounded memory even for a pathological file.
    #[test]
    fn an_endless_header_does_not_buffer_without_end() {
        let mut body = String::new();
        while body.len() <= MAX_HEADER_BYTES {
            body.push_str("! comment line that reveals nothing about the format\n");
        }
        body.push_str("ads.example.com\n");
        let (domains, stats) = parse_content(&body, ListPolarity::Block);
        assert_eq!(domains, vec!["ads.example.com"]);
        assert!(stats.is_none());
    }

    /// The splitter drops a trailing `\r` and needs no final newline, exactly
    /// as `str::lines` does.
    #[test]
    fn line_splitting_matches_str_lines() {
        for body in ["a\nb\n", "a\r\nb", "\n\n", "no newline at all", "\r\n"] {
            for chunk_size in [1usize, 2, 5, 64] {
                let mut got: Vec<String> = Vec::new();
                let mut splitter = LineSplitter::default();
                for chunk in body.as_bytes().chunks(chunk_size) {
                    splitter.push(chunk, |line| got.push(line.to_string()));
                }
                splitter.finish(|line| got.push(line.to_string()));
                let expected: Vec<String> = body.lines().map(String::from).collect();
                assert_eq!(got, expected, "body {body:?} at chunk size {chunk_size}");
            }
        }
    }
}
