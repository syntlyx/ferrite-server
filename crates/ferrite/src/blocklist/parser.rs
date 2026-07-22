/// Parse a `/etc/hosts`-style file and return all blocked domain names.
///
/// Lines look like:
///   `0.0.0.0 ads.example.com`
///   `127.0.0.1 tracker.evil.com # comment`
pub fn parse_hosts(content: &str) -> Vec<String> {
    let mut domains = Vec::new();

    for line in content.lines() {
        // Strip inline comments.
        let line = match line.find('#') {
            Some(idx) => &line[..idx],
            None => line,
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let mut parts = line.split_whitespace();
        // First token is the IP address — skip it.
        let ip = match parts.next() {
            Some(ip) => ip,
            None => continue,
        };

        // Skip lines that are not 0.0.0.0 or 127.0.0.1 (e.g., legitimate host entries).
        if ip != "0.0.0.0" && ip != "127.0.0.1" && ip != "::1" {
            continue;
        }

        for domain in parts {
            let domain = domain.to_ascii_lowercase();
            // Skip localhost aliases.
            if domain == "localhost"
                || domain == "localhost.localdomain"
                || domain == "broadcasthost"
            {
                continue;
            }
            // Basic domain validation.
            if is_valid_domain(&domain) {
                domains.push(domain);
            }
        }
    }

    domains
}

/// Returns `true` if `line` uses Adblock/uBO filter syntax rather than being a
/// plain domain. Covers cosmetic filters (`##`, `#?#`, `#@#`, `#$#`), network
/// rules (`||…`), exception rules (`@@…`), and option modifiers (`$…`).
///
/// Used both for format auto-detection and as a guard inside `parse_plain` so
/// that a misdetected filter list (e.g. EasyList, whose first data line is
/// `&rb=&uuid=$third-party`) can never leak a bare domain such as `google.com`
/// out of a cosmetic rule like `google.com##.some-class`.
pub fn is_adblock_syntax(line: &str) -> bool {
    // Structural markers are unambiguous — check them on the raw line so a
    // cosmetic rule (`google.com##.cls`) is caught before any comment strip.
    if line.starts_with("||")
        || line.starts_with("@@")
        || line.contains("##")
        || line.contains("#?#")
        || line.contains("#@#")
        || line.contains("#$#")
    {
        return true;
    }
    // The `$` option modifier is weaker: it also appears in human comments
    // (`casino.com # costs $$$`) on otherwise-plain/hosts lines. Only treat it
    // as Adblock syntax when it sits in the rule body, before any `#` comment.
    let code = match line.find('#') {
        Some(idx) => &line[..idx],
        None => line,
    };
    code.contains('$')
}

/// Parse a plain domain list — one domain per line, `#` comments allowed.
///
///   `ads.example.com`
///   `tracker.evil.com  # optional comment`
pub fn parse_plain(content: &str) -> Vec<String> {
    let mut domains = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Defend against Adblock syntax reaching the plain parser via a
        // misdetected list. This MUST run before the `#` comment strip below:
        // a cosmetic rule like `google.com##.cls` would otherwise be truncated
        // at the first `#` and wrongly yield `google.com` as a blocked domain.
        if is_adblock_syntax(line) {
            continue;
        }

        // Strip inline `#` comments (only reached for non-Adblock lines).
        let line = match line.find('#') {
            Some(idx) => &line[..idx],
            None => line,
        }
        .trim();
        if line.is_empty() {
            continue;
        }
        let domain = line.to_ascii_lowercase();
        if is_valid_domain(&domain) {
            domains.push(domain);
        }
    }
    domains
}

/// Breakdown of how an Adblock-style list was interpreted. Surfaced through the
/// API so the gap between "rules in the file" and "domains actually blocked" is
/// explainable (e.g. EasyList is mostly cosmetic rules, not DNS-blockable
/// domains). Serialised to a sidecar cache file so it survives restarts.
#[derive(Debug, Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
pub struct AdblockStats {
    /// Domains actually emitted as blocks (after exception subtraction).
    pub kept: usize,
    /// `@@` exception rules collected from the list.
    pub exceptions: usize,
    /// Block rules cancelled because an exception exempted the same domain.
    pub unblocked_by_exception: usize,
    /// `||…^$domain=…` referrer-scoped rules skipped (would over-block).
    pub scoped_skipped: usize,
    /// Element-hiding / scriptlet cosmetic rules skipped (not DNS-blockable).
    pub cosmetic_skipped: usize,
    /// Regex / path / wildcard / option-only rules skipped.
    pub unsupported_skipped: usize,
}

/// Parse an Adblock-style filter list and return blocked domain names.
///
/// As a DNS blocklist we can only act on whole-domain network rules. Handling:
///   `||ads.example.com^`            → block domain
///   `||ads.example.com^$important`  → block domain
///   `@@||good.example.com^`         → exception: domain is exempted from this
///                                     list's blocks (see limitation below)
///   `||x.com^$domain=other.com`     → SKIPPED: referrer-scoped, only meant to
///                                     apply on `other.com`; blocking `x.com`
///                                     globally would be a false positive
///   element-hiding / regex / etc.   → ignored (handled by `is_adblock_syntax`)
///   Lines starting with `!` or `#`  → comments
///
/// Exceptions (`@@`) are subtracted from this list's own block set only. That
/// matches how EasyList authors intend them (to undo EasyList's own rules); we
/// deliberately do NOT let one list's exception cancel another list's block, as
/// that cross-list interaction is opaque and surprising.
pub fn parse_adblock(content: &str) -> (Vec<String>, AdblockStats) {
    let mut domains = Vec::new();
    let mut exceptions = std::collections::HashSet::new();
    // Diagnostics: count what we deliberately do NOT turn into block entries so
    // the volume of a filter list (e.g. EasyList) is explainable from the logs.
    let mut scoped_skipped = 0usize; // `$domain=`-scoped block rules
    let mut cosmetic_skipped = 0usize; // element-hiding / scriptlet rules
    let mut unsupported_skipped = 0usize; // regex, paths, wildcards, etc.

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
            continue;
        }

        // Exception rules (`@@||domain^…`) — checked before the `||` arm since
        // they begin with `@@`. Any modifiers are ignored: an exempted domain
        // is exempted, which errs toward NOT blocking (avoids false positives).
        if let Some(rest) = line.strip_prefix("@@||") {
            if let Some(domain) = adblock_rule_domain(rest) {
                exceptions.insert(domain);
            }
            continue;
        }

        // Network block rules — the only `||domain^` form we can act on.
        if let Some(rest) = line.strip_prefix("||") {
            // Split rule body from `$`-options: `domain^$opt1,opt2`.
            let (pattern, options) = match rest.split_once('$') {
                Some((p, o)) => (p, Some(o)),
                None => (rest, None),
            };

            // Skip referrer-scoped rules (`$domain=…`): they only apply when the
            // request originates from specific sites, so a global DNS block of
            // the target domain would over-block.
            if let Some(opts) = options
                && opts.split(',').any(|o| o.trim().starts_with("domain="))
            {
                scoped_skipped += 1;
                continue;
            }

            match adblock_rule_domain(pattern) {
                Some(domain) => domains.push(domain),
                None => unsupported_skipped += 1, // wildcard/path/invalid host
            }
            continue;
        }

        // Anything else that is recognisably a filter rule but unusable as a
        // DNS block: cosmetic filters (`##`, `#?#`, …) and regex/option-only
        // rules. Counted for visibility, not blocked.
        if is_adblock_syntax(line) {
            if line.contains("##") || line.contains("#?#") || line.contains("#@#") {
                cosmetic_skipped += 1;
            } else {
                unsupported_skipped += 1;
            }
        }
    }

    let exception_count = exceptions.len();
    let removed = if exceptions.is_empty() {
        0
    } else {
        let before = domains.len();
        domains.retain(|d| !exceptions.contains(d));
        before - domains.len()
    };

    let stats = AdblockStats {
        kept: domains.len(),
        exceptions: exception_count,
        unblocked_by_exception: removed,
        scoped_skipped,
        cosmetic_skipped,
        unsupported_skipped,
    };

    tracing::debug!(
        kept = stats.kept,
        exceptions = stats.exceptions,
        unblocked_by_exception = stats.unblocked_by_exception,
        scoped_skipped = stats.scoped_skipped,
        cosmetic_skipped = stats.cosmetic_skipped,
        unsupported_skipped = stats.unsupported_skipped,
        "parsed adblock list"
    );
    (domains, stats)
}

/// Parse an Adblock-style filter list with allowlist polarity: the `@@||domain^`
/// exception rules ARE the entries (that's what a subscribed allowlist is for —
/// exempting domains from other lists' blocks). Handling:
///   `@@||good.example.com^`           → allow domain
///   `@@||good.example.com^$important` → allow domain (non-scoping modifiers ignored)
///   `@@||x.com^$domain=site.com`      → SKIPPED: only meant to apply on
///                                       `site.com`; a global DNS allow would
///                                       over-allow (mirrors the `$domain=`
///                                       guard on block rules)
///   `||ads.example.com^`              → ignored: a block rule can't populate
///                                       an allowlist (counted unsupported)
///   cosmetic / regex / etc.           → ignored, counted as with blocklists
///
/// Stats reuse [`AdblockStats`] with allow semantics: `kept` = allow entries
/// emitted, `exceptions` = `@@` rules seen, `unblocked_by_exception` = 0.
pub fn parse_adblock_exceptions(content: &str) -> (Vec<String>, AdblockStats) {
    let mut domains = Vec::new();
    let mut exception_rules = 0usize;
    let mut scoped_skipped = 0usize;
    let mut cosmetic_skipped = 0usize;
    let mut unsupported_skipped = 0usize;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
            continue;
        }

        if let Some(rest) = line.strip_prefix("@@||") {
            exception_rules += 1;
            let (pattern, options) = match rest.split_once('$') {
                Some((p, o)) => (p, Some(o)),
                None => (rest, None),
            };
            if let Some(opts) = options
                && opts.split(',').any(|o| o.trim().starts_with("domain="))
            {
                scoped_skipped += 1;
                continue;
            }
            match adblock_rule_domain(pattern) {
                Some(domain) => domains.push(domain),
                None => unsupported_skipped += 1, // wildcard/path/invalid host
            }
            continue;
        }

        // Everything else can't produce an allow entry; keep the same
        // diagnostic buckets as the block parse so the UI stays explainable.
        if is_adblock_syntax(line) {
            if line.contains("##") || line.contains("#?#") || line.contains("#@#") {
                cosmetic_skipped += 1;
            } else {
                unsupported_skipped += 1;
            }
        }
    }

    let stats = AdblockStats {
        kept: domains.len(),
        exceptions: exception_rules,
        unblocked_by_exception: 0,
        scoped_skipped,
        cosmetic_skipped,
        unsupported_skipped,
    };

    tracing::debug!(
        kept = stats.kept,
        exceptions = stats.exceptions,
        scoped_skipped = stats.scoped_skipped,
        cosmetic_skipped = stats.cosmetic_skipped,
        unsupported_skipped = stats.unsupported_skipped,
        "parsed adblock list as allowlist"
    );
    (domains, stats)
}

/// Extract a validated, lowercased domain from the body of a `||…`/`@@||…`
/// rule (the part after the `||`, with `$`-options already stripped). Returns
/// `None` if the body is not a plain blockable domain (wildcards, paths, etc.).
fn adblock_rule_domain(body: &str) -> Option<String> {
    // The domain runs up to the `^` separator (or the end of the rule).
    let head = body.split('^').next().unwrap_or("").trim();

    // Path-scoped rules (`||google.com/pagead^`, `||cse.google.com/ads`) target a
    // specific URL path, not the whole host. A DNS blocklist can only block an
    // entire domain, so turning such a rule into a host block would over-block a
    // legitimate domain (this is exactly how `google.com` got blocked). Reject
    // anything carrying a path — only a bare `||domain^` is a whole-domain block.
    if head.contains('/') {
        return None;
    }

    let domain = head.to_ascii_lowercase();
    if !domain.is_empty() && is_valid_domain(&domain) {
        Some(domain)
    } else {
        None
    }
}

/// Very lightweight domain name sanity check.
fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    // Must contain at least one dot (not a plain hostname like "localhost").
    if !domain.contains('.') {
        return false;
    }
    domain
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '.' || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hosts() {
        let content =
            "127.0.0.1 localhost\n0.0.0.0 ads.example.com # bad ad\n0.0.0.0 tracker.evil.com\n";
        let domains = parse_hosts(content);
        assert!(domains.contains(&"ads.example.com".to_string()));
        assert!(domains.contains(&"tracker.evil.com".to_string()));
        assert!(!domains.contains(&"localhost".to_string()));
    }

    #[test]
    fn test_parse_adblock() {
        let content = "! comment\n||ads.example.com^\n||tracker.evil.com^$important\n";
        let (domains, stats) = parse_adblock(content);
        assert!(domains.contains(&"ads.example.com".to_string()));
        assert!(domains.contains(&"tracker.evil.com".to_string()));
        assert_eq!(stats.kept, 2);
    }

    #[test]
    fn adblock_exception_rules_unblock_domain() {
        // `@@||good.com^` must cancel this list's own `||good.com^` block.
        let content = "||good.com^\n||ads.evil.com^\n@@||good.com^\n";
        let (domains, stats) = parse_adblock(content);
        assert!(!domains.contains(&"good.com".to_string()));
        assert!(domains.contains(&"ads.evil.com".to_string()));
        assert_eq!(stats.exceptions, 1);
        assert_eq!(stats.unblocked_by_exception, 1);
    }

    #[test]
    fn adblock_skips_referrer_scoped_rules() {
        // `$domain=` rules apply only on specific referrers — blocking the
        // target globally would over-block. The plain rule still applies.
        let content = "||cdn.example.com^$domain=othersite.com\n||tracker.evil.com^$third-party\n";
        let (domains, stats) = parse_adblock(content);
        assert!(
            !domains.contains(&"cdn.example.com".to_string()),
            "referrer-scoped rule must not produce a global block"
        );
        assert!(domains.contains(&"tracker.evil.com".to_string()));
        assert_eq!(stats.scoped_skipped, 1);
    }

    #[test]
    fn adblock_skips_path_scoped_rules() {
        // Regression: real EasyList path rules on legitimate domains, e.g.
        // `||google.com/pagead/...` and `||google.com/adsense/...`, must NOT turn
        // into a whole-domain block of google.com. A DNS blocklist can't honour a
        // path, so these are skipped (counted unsupported); a bare `||domain^`
        // still blocks the whole host.
        let content = "\
||google.com/adsense/domains/caf.js\n\
||google.com/pagead/conversion_async.js\n\
||cse.google.com/cse_v2/ads$subdocument\n\
||doubleclick.net^\n\
||mail-ads.google.com^\n";
        let (domains, stats) = parse_adblock(content);
        assert!(
            !domains.contains(&"google.com".to_string()),
            "path rule must not block the whole google.com"
        );
        assert!(!domains.contains(&"cse.google.com".to_string()));
        // Bare whole-domain rules still block.
        assert!(domains.contains(&"doubleclick.net".to_string()));
        assert!(domains.contains(&"mail-ads.google.com".to_string()));
        assert_eq!(stats.unsupported_skipped, 3);
    }

    #[test]
    fn parse_plain_ignores_adblock_cosmetic_rules() {
        // Regression: EasyList cosmetic rules must never leak a bare domain out
        // of the plain parser. `google.com##.cls` previously truncated at the
        // first `#` and added `google.com` as a blocked domain.
        let content = "\
google.com##.GGQPGYLCD5\n\
google.com##.GGQPGYLCMCB\n\
&rb=&uuid=$third-party\n\
||doubleclick.net^\n\
ads.example.com  # a real plain entry\n";
        let domains = parse_plain(content);
        assert!(
            !domains.contains(&"google.com".to_string()),
            "google.com must not be extracted from a cosmetic rule"
        );
        assert!(!domains.contains(&"doubleclick.net".to_string()));
        // A genuine plain line with a trailing comment still parses.
        assert!(domains.contains(&"ads.example.com".to_string()));
    }

    #[test]
    fn parse_adblock_exceptions_harvests_exception_rules() {
        // Allowlist polarity: `@@||domain^` rules ARE the entries; block rules,
        // cosmetic rules, and referrer-scoped exceptions must not leak through.
        let content = "\
! comment\n\
||ads.example.com^\n\
@@||good.example.com^\n\
@@||cdn.example.com^$important\n\
@@||scoped.example.com^$domain=onlyhere.com\n\
google.com##.cosmetic\n";
        let (domains, stats) = parse_adblock_exceptions(content);
        assert_eq!(
            domains,
            vec![
                "good.example.com".to_string(),
                "cdn.example.com".to_string()
            ]
        );
        assert!(
            !domains.contains(&"ads.example.com".to_string()),
            "a block rule must not become an allow entry"
        );
        assert_eq!(stats.kept, 2);
        assert_eq!(stats.exceptions, 3);
        assert_eq!(stats.scoped_skipped, 1);
        assert_eq!(stats.cosmetic_skipped, 1);
        assert_eq!(stats.unsupported_skipped, 1); // the `||ads…^` block rule
    }

    #[test]
    fn parse_adblock_exceptions_skips_path_scoped_rules() {
        // `@@||google.com/recaptcha^` exempts a path, not the host — a DNS
        // allowlist can only exempt whole domains, so it must be skipped.
        let content = "@@||google.com/recaptcha/^\n@@||accounts.google.com^\n";
        let (domains, stats) = parse_adblock_exceptions(content);
        assert_eq!(domains, vec!["accounts.google.com".to_string()]);
        assert_eq!(stats.unsupported_skipped, 1);
    }

    #[test]
    fn is_adblock_syntax_classification() {
        assert!(is_adblock_syntax("||doubleclick.net^"));
        assert!(is_adblock_syntax("@@||good.com^"));
        assert!(is_adblock_syntax("google.com##.cls"));
        assert!(is_adblock_syntax("example.com#?#div"));
        assert!(is_adblock_syntax("&rb=&uuid=$third-party"));
        assert!(is_adblock_syntax("||example.com^$third-party"));
        assert!(!is_adblock_syntax("ads.example.com"));
        assert!(!is_adblock_syntax("tracker.evil.com  # comment"));
        // A `$` inside a trailing comment must NOT be read as a rule modifier.
        assert!(!is_adblock_syntax("casino.com # costs $$$"));
        assert!(!is_adblock_syntax("0.0.0.0 ads.example.com # blocks $ ads"));
    }
}
