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

/// Parse a plain domain list — one domain per line, `#` comments allowed.
///
///   `ads.example.com`
///   `tracker.evil.com  # optional comment`
pub fn parse_plain(content: &str) -> Vec<String> {
    let mut domains = Vec::new();
    for line in content.lines() {
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

/// Parse an Adblock-style filter list and return blocked domain names.
///
/// Supports:
///   `||ads.example.com^`           — block domain
///   `||ads.example.com^$important` — block domain
///   Lines starting with `!` or `#` are comments.
pub fn parse_adblock(content: &str) -> Vec<String> {
    let mut domains = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
            continue;
        }

        // Only handle the simple `||domain^` pattern.
        if let Some(rest) = line.strip_prefix("||") {
            let domain = rest
                .split('^')
                .next()
                .unwrap_or("")
                .split('$')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();

            if !domain.is_empty() && is_valid_domain(&domain) {
                domains.push(domain);
            }
        }
    }

    domains
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
        let domains = parse_adblock(content);
        assert!(domains.contains(&"ads.example.com".to_string()));
        assert!(domains.contains(&"tracker.evil.com".to_string()));
    }
}
