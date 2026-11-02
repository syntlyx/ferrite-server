//! Domain-name helpers shared by the block decision, the whitelist, profiles
//! and the API: normalisation, label-boundary suffixes, the hierarchy walk
//! that stops at the registrable domain, and wildcard patterns.

use std::collections::HashSet;

use regex::Regex;

use ferrite_core::error::{FeriteError, Result};

/// Exact match on `domain`, else the first parent in the hierarchy that matches
/// (stopping at the registrable-domain boundary) — the same walk as
/// [`crate::Blocklist`]'s block check. Returns the key that matched.
pub(crate) fn matched_key(domain: &str, contains: impl Fn(&str) -> bool) -> Option<String> {
    if contains(domain) {
        return Some(domain.to_string());
    }
    let mut rest = domain;
    while let Some(dot) = rest.find('.') {
        rest = &rest[dot + 1..];
        // Membership first, public-suffix guard second: both have to hold, and
        // the guard is the more expensive of the two (see the walk in
        // `is_whitelisted_for_normalized`).
        if contains(rest) && is_registrable_or_deeper(rest) {
            return Some(rest.to_string());
        }
    }
    None
}

/// Exact match on `domain`, else a parent in the hierarchy (stopping at the
/// registrable boundary) — the shared walk used by the blacklist, whitelist, and
/// profile overrides so a rule for `evil.com` also matches `www.evil.com`.
///
/// The public-suffix guard stops the walk at the registrable-domain boundary,
/// so an entry for a multi-label suffix like `co.uk` can't cover a whole ccTLD.
pub(crate) fn domain_in_set(domain: &str, set: &HashSet<String>) -> bool {
    if set.contains(domain) {
        return true;
    }
    let mut rest = domain;
    while let Some(dot) = rest.find('.') {
        rest = &rest[dot + 1..];
        // Set lookup before the public-suffix guard: both must hold, and this
        // one is a hash (free on the empty set every unconfigured install has)
        // where the guard is a trie walk. The manual sets run uncached on every
        // single query.
        if set.contains(rest) && is_registrable_or_deeper(rest) {
            return true;
        }
    }
    false
}

pub(crate) fn normalise(domain: &str) -> String {
    domain
        .to_ascii_lowercase()
        .trim_end_matches('.')
        .to_string()
}

/// Canonical domain key used by the blocklist engine and the DNS hot path:
/// lowercase, trailing root dot stripped. Exposed so the API layer can store
/// and look up entries under the exact same key the engine uses (otherwise a
/// UI-listed value can't delete its persisted row).
pub fn normalise_domain(domain: &str) -> String {
    normalise(domain)
}

/// `true` if `name` equals `suffix` or ends with `.suffix` (label boundary —
/// `mylan` must not match suffix `lan`).
pub(crate) fn has_suffix(name: &str, suffix: &str) -> bool {
    name == suffix
        || (name.len() > suffix.len()
            && name.ends_with(suffix)
            && name.as_bytes()[name.len() - suffix.len() - 1] == b'.')
}

/// Returns `true` if `name` is a registrable domain or a subdomain of one —
/// i.e. it extends beyond its own public suffix. Used to stop the hierarchy
/// walk at the registrable boundary so an entry for a public suffix
/// (`com`, `co.uk`, `com.au`, …) never matches every domain beneath it.
///
/// Unknown suffixes are treated as registrable (fail open to the previous
/// single-dot behaviour) rather than silently dropping the check.
pub(crate) fn is_registrable_or_deeper(name: &str) -> bool {
    match psl::suffix(name.as_bytes()) {
        Some(suffix) => name.len() > suffix.as_bytes().len(),
        None => true,
    }
}

/// Compile a domain wildcard pattern (`*.example.com`) into an anchored regex.
/// Exposed to the crate so the proxy routing engine can reuse the exact same
/// wildcard semantics as the blocklist (`\*` → `.*`, anchored `^…$`).
pub fn wildcard_to_regex(pattern: &str) -> Result<Regex> {
    if pattern == "*" || pattern.trim_matches('*').is_empty() {
        return Err(FeriteError::Config(
            "wildcard pattern cannot match everything".into(),
        ));
    }
    let escaped = regex::escape(pattern);
    Regex::new(&format!("^{}$", escaped.replace("\\*", ".*")))
        .map_err(|e| FeriteError::Config(format!("invalid wildcard '{}': {}", pattern, e)))
}
