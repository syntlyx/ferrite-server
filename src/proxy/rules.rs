//! Domain → egress routing rules.
//!
//! A rule pattern is either an exact domain (matches the name and any
//! subdomain, like the blocklist hierarchy walk) or a wildcard (`*.example.com`,
//! compiled with the same [`wildcard_to_regex`] semantics as the blocklist).
//! Rules are pre-sorted most-specific-first so the first match wins.

use std::collections::HashMap;

use regex::Regex;

use crate::blocklist::engine::wildcard_to_regex;
use crate::config::RuleConfig;

pub enum Matcher {
    /// Exact domain: matches the name itself and any subdomain of it.
    Exact(String),
    /// Wildcard pattern compiled to an anchored regex.
    Wildcard(Regex),
}

pub struct CompiledRule {
    pub matcher: Matcher,
    pub egress_idx: usize,
    pub fail_closed: bool,
    /// Restrict to these clients (lowercased MAC or IP strings). Empty = all.
    pub clients: Vec<String>,
    /// Higher = more specific. Used to order rules so the most specific wins.
    pub specificity: u32,
}

impl CompiledRule {
    pub fn matches(&self, name: &str) -> bool {
        match &self.matcher {
            Matcher::Exact(p) => {
                name == p
                    || (name.len() > p.len()
                        && name.ends_with(p.as_str())
                        && name.as_bytes()[name.len() - p.len() - 1] == b'.')
            }
            Matcher::Wildcard(re) => re.is_match(name),
        }
    }

    /// Does this rule apply to the querying client? Empty client list = all
    /// clients; otherwise the client's IP or resolved MAC must be listed.
    pub fn matches_client(&self, ip: &str, mac: Option<&str>) -> bool {
        if self.clients.is_empty() {
            return true;
        }
        let ip = ip.to_ascii_lowercase();
        let mac = mac.map(|m| m.to_ascii_lowercase());
        self.clients
            .iter()
            .any(|c| *c == ip || mac.as_deref() == Some(c.as_str()))
    }
}

/// Compile rules into matchers, resolving egress ids to snapshot indices and
/// sorting most-specific-first. Rules whose egress isn't active (disabled or
/// failed to build) or whose pattern is invalid are skipped with a warning.
pub fn compile(rules: &[RuleConfig], egress_idx: &HashMap<String, usize>) -> Vec<CompiledRule> {
    let mut out = Vec::new();
    for r in rules {
        let Some(&idx) = egress_idx.get(&r.egress) else {
            tracing::warn!(
                "proxy: rule '{}' → egress '{}' is not active, skipping",
                r.pattern,
                r.egress
            );
            continue;
        };
        let labels = label_count(&r.pattern);
        let (matcher, specificity) = if r.pattern.contains('*') {
            match wildcard_to_regex(&r.pattern) {
                Ok(re) => (Matcher::Wildcard(re), labels * 2),
                Err(e) => {
                    tracing::warn!("proxy: invalid rule pattern '{}': {}", r.pattern, e);
                    continue;
                }
            }
        } else {
            // Exact beats a wildcard with the same concrete-label count.
            (Matcher::Exact(r.pattern.clone()), labels * 2 + 1)
        };
        out.push(CompiledRule {
            matcher,
            egress_idx: idx,
            fail_closed: r.fail_closed,
            clients: r
                .clients
                .iter()
                .map(|c| c.trim().to_ascii_lowercase())
                .filter(|c| !c.is_empty())
                .collect(),
            specificity,
        });
    }
    // Stable sort keeps config order among rules of equal specificity.
    out.sort_by_key(|r| std::cmp::Reverse(r.specificity));
    out
}

/// Number of concrete (non-`*`, non-empty) labels in a pattern.
fn label_count(pattern: &str) -> u32 {
    pattern
        .split('.')
        .filter(|l| !l.is_empty() && *l != "*")
        .count() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(pattern: &str, egress: &str) -> RuleConfig {
        RuleConfig {
            pattern: pattern.to_string(),
            egress: egress.to_string(),
            fail_closed: true,
            clients: Vec::new(),
        }
    }

    fn idx() -> HashMap<String, usize> {
        let mut m = HashMap::new();
        m.insert("a".to_string(), 0);
        m.insert("b".to_string(), 1);
        m
    }

    #[test]
    fn exact_matches_name_and_subdomains() {
        let m = Matcher::Exact("google.com".to_string());
        let r = CompiledRule {
            matcher: m,
            egress_idx: 0,
            fail_closed: true,
            clients: Vec::new(),
            specificity: 0,
        };
        assert!(r.matches("google.com"));
        assert!(r.matches("www.google.com"));
        assert!(r.matches("a.b.google.com"));
        assert!(!r.matches("notgoogle.com"));
        assert!(!r.matches("google.com.evil.com"));
    }

    #[test]
    fn client_scoping_restricts_to_listed_devices() {
        let scoped = CompiledRule {
            matcher: Matcher::Exact("x.test".to_string()),
            egress_idx: 0,
            fail_closed: true,
            clients: vec!["aa:bb:cc:dd:ee:ff".to_string(), "10.0.0.5".to_string()],
            specificity: 0,
        };
        assert!(scoped.matches_client("10.0.0.5", None)); // by IP
        assert!(scoped.matches_client("10.0.0.9", Some("AA:BB:CC:DD:EE:FF"))); // by MAC, case-insensitive
        assert!(!scoped.matches_client("10.0.0.9", None)); // neither IP nor MAC listed

        let all = CompiledRule {
            matcher: Matcher::Exact("x.test".to_string()),
            egress_idx: 0,
            fail_closed: true,
            clients: Vec::new(),
            specificity: 0,
        };
        assert!(all.matches_client("1.2.3.4", None)); // empty list = all clients
    }

    #[test]
    fn wildcard_matches_subdomains_only() {
        let compiled = compile(&[rule("*.google.com", "a")], &idx());
        assert!(compiled[0].matches("www.google.com"));
        // `*.google.com` regex is `^.*\.google\.com$`, so the apex does not match.
        assert!(!compiled[0].matches("google.com"));
    }

    #[test]
    fn most_specific_rule_wins() {
        // egress "a"=idx0, "b"=idx1.
        let compiled = compile(
            &[
                rule("google.com", "a"),      // exact apex (+hierarchy)
                rule("*.google.com", "a"),    // wildcard subdomains
                rule("mail.google.com", "b"), // exact, most labels → wins for itself
            ],
            &idx(),
        );
        // `find` over the most-specific-first ordering returns the winning rule.
        // mail.google.com (3 exact labels) beats the apex and the wildcard.
        let mail = compiled
            .iter()
            .find(|r| r.matches("mail.google.com"))
            .unwrap();
        assert_eq!(mail.egress_idx, 1);
        // A generic subdomain: exact apex (hierarchy, specificity 5) beats the
        // wildcard (specificity 4) → egress "a".
        let docs = compiled
            .iter()
            .find(|r| r.matches("docs.google.com"))
            .unwrap();
        assert_eq!(docs.egress_idx, 0);
    }

    #[test]
    fn rule_with_unknown_egress_is_dropped() {
        let compiled = compile(&[rule("x.test", "ghost")], &idx());
        assert!(compiled.is_empty());
    }
}
