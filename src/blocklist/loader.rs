use fst::map::OpBuilder;
use fst::{Map, MapBuilder, Streamer};
use reqwest::Client;

use crate::blocklist::parser;
use crate::error::{FeriteError, Result};

/// Shared HTTP client (connection pool is reused across all list fetches).
static HTTP_CLIENT: std::sync::LazyLock<Client> = std::sync::LazyLock::new(|| {
    Client::builder()
        .user_agent(concat!("ferrite/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(60))
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
