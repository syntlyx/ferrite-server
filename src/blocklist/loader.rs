use std::net::{IpAddr, Ipv6Addr};

use fst::map::OpBuilder;
use fst::{Map, MapBuilder, Streamer};
use reqwest::{Client, Url};

use crate::blocklist::parser;
use crate::error::{FeriteError, Result};

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

/// Fetch a blocklist from `url` and return parsed domain names.
///
/// Supports:
/// - `file:///path` — read from local filesystem
/// - `http://` / `https://` — HTTP GET
///
/// Format is auto-detected from content (hosts vs. Adblock).
pub async fn load_list(url: &str) -> Result<Vec<String>> {
    let content = if let Some(path) = url.strip_prefix("file://") {
        tracing::info!("reading blocklist from file {}", path);
        tokio::fs::read_to_string(path).await?
    } else {
        tracing::info!("fetching blocklist from {}", url);
        let resp = HTTP_CLIENT.get(url).send().await?.error_for_status()?;
        resp.text().await?
    };

    let domains = parse_content(&content);
    tracing::info!("parsed {} domains from {}", domains.len(), url);
    Ok(domains)
}

/// Detect list format and parse into domain names.
///
/// Detection is based on the **first non-comment, non-empty data line**
/// (comments are lines starting with `!`, `#`, or `[Adblock`):
///
/// - Starts with `||`           → adblock (`||domain^`)
/// - Starts with `0.0.0.0` /
///   `127.0.0.1` / `::1`        → hosts format
/// - Anything else              → plain domain list (one per line)
pub fn parse_content(content: &str) -> Vec<String> {
    for line in content.lines() {
        let line = line.trim();

        // Skip comment / header lines — they don't reveal the data format.
        if line.is_empty()
            || line.starts_with('!')
            || line.starts_with('#')
            || line.starts_with("[Adblock")
        {
            continue;
        }

        // First real data line determines the format.
        if line.starts_with("||") {
            return parser::parse_adblock(content);
        }
        if line.starts_with("0.0.0.0") || line.starts_with("127.0.0.1") || line.starts_with("::1") {
            return parser::parse_hosts(content);
        }
        return parser::parse_plain(content);
    }

    vec![]
}

/// Merge multiple per-list FSTs into one via k-way union.
///
/// Uses `fst::map::OpBuilder::union()` which streams already-sorted keys in
/// O(n log k) time — far cheaper than collecting all domains and re-sorting.
/// Each input slice must be valid FST bytes; if only one slice is provided,
/// it is returned as-is without any copy.
pub fn merge_fsts(fst_slices: &[Vec<u8>]) -> Result<Vec<u8>> {
    match fst_slices.len() {
        0 => MapBuilder::memory()
            .into_inner()
            .map_err(|e| FeriteError::Fst(e.to_string())),
        1 => Ok(fst_slices[0].clone()),
        _ => {
            let maps: Vec<Map<&[u8]>> = fst_slices
                .iter()
                .map(|b| Map::new(b.as_slice()).map_err(|e| FeriteError::Fst(e.to_string())))
                .collect::<Result<_>>()?;

            let mut op = OpBuilder::new();
            for m in &maps {
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

/// Build a sorted, deduplicated FST map from domain names.
/// All values are set to 1 (the FST is used as a set).
/// Returns raw FST bytes ready to pass to `fst::Map::new()`.
pub fn build_fst(mut domains: Vec<String>) -> Result<Vec<u8>> {
    // FST requires keys in strict lexicographic order with no duplicates.
    domains.sort_unstable();
    domains.dedup();

    let mut builder = MapBuilder::memory();
    for domain in &domains {
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
