//! The built-in service catalog: named sets of domains (YouTube, TikTok,
//! Steam…) that `[blocklist] services` and a profile's `services` block, and
//! that a tunnel rule's `service` routes. The data lives in
//! `data/services.toml` and is compiled into the binary, so it ships and
//! updates with releases — no fetch, no cache, nothing to go stale on disk.

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

/// One catalog entry.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Service {
    /// Stable id that configs reference (`"youtube"`).
    pub id: String,
    /// Display name (`"YouTube"`).
    pub name: String,
    /// One of [`CATEGORIES`]; the panel groups the catalog by it.
    pub category: String,
    /// Whether a tunnel rule may route this service. `false` for services
    /// that also speak their own protocol to a resolved name, which the
    /// HTTP/TLS-only proxy can't forward.
    #[serde(default = "routable_default")]
    pub routable: bool,
    /// Domains the service owns. Each matches itself and every subdomain.
    pub domains: Vec<String>,
}

fn routable_default() -> bool {
    true
}

/// Category ids, in the order the panel shows them.
pub const CATEGORIES: &[&str] = &[
    "video",
    "music",
    "social",
    "messaging",
    "gaming",
    "ai",
    "shopping",
];

#[derive(Deserialize)]
struct CatalogFile {
    service: Vec<Service>,
}

static CATALOG: LazyLock<Vec<Service>> = LazyLock::new(|| {
    toml::from_str::<CatalogFile>(include_str!("../data/services.toml"))
        // The file is compiled in and the tests below parse it, so this can
        // only fail in a build whose tests already failed.
        .expect("the built-in service catalog parses")
        .service
});

/// Every service, in catalog order.
pub fn catalog() -> &'static [Service] {
    &CATALOG
}

/// The service with this id, if the catalog has one.
pub fn find(id: &str) -> Option<&'static Service> {
    CATALOG.iter().find(|s| s.id == id)
}

static OWNERS: LazyLock<HashMap<&'static str, &'static Service>> = LazyLock::new(|| {
    CATALOG
        .iter()
        .flat_map(|s| s.domains.iter().map(move |d| (d.as_str(), s)))
        .collect()
});

/// The service a domain belongs to — the one listing it or a parent of it.
pub fn owner_of(domain: &str) -> Option<&'static Service> {
    let domain = domain.trim_end_matches('.');
    let mut rest = domain;
    loop {
        if let Some(s) = OWNERS.get(rest) {
            return Some(s);
        }
        rest = rest.split_once('.')?.1;
    }
}

/// Configured service ids, cleaned up: trimmed, lowercased, empties and
/// repeats dropped, order kept. Ids the catalog doesn't know come back
/// separately so the caller decides — the API rejects them, loading a config
/// warns and drops them (a service a newer build removed must not stop startup).
pub fn normalize_ids(ids: &[String]) -> (Vec<String>, Vec<String>) {
    let mut seen = HashSet::new();
    let mut known = Vec::with_capacity(ids.len());
    let mut unknown = Vec::new();
    for raw in ids {
        let id = raw.trim().to_ascii_lowercase();
        if id.is_empty() || !seen.insert(id.clone()) {
            continue;
        }
        if find(&id).is_some() {
            known.push(id);
        } else {
            unknown.push(id);
        }
    }
    (known, unknown)
}

/// The domains of every listed service the catalog knows; unknown ids are
/// skipped.
pub fn domains_of(ids: &[String]) -> impl Iterator<Item = &'static str> + '_ {
    ids.iter()
        .filter_map(|id| find(id))
        .flat_map(|s| s.domains.iter().map(String::as_str))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_domain_belongs_to_the_service_listing_it_or_a_parent() {
        assert_eq!(
            owner_of("youtube.com").map(|s| s.id.as_str()),
            Some("youtube")
        );
        assert_eq!(
            owner_of("rr3---sn-abc.googlevideo.com.").map(|s| s.id.as_str()),
            Some("youtube")
        );
        assert!(owner_of("example.com").is_none());
        assert!(owner_of("com").is_none());
    }

    #[test]
    fn catalog_parses_and_is_not_empty() {
        assert!(
            catalog().len() >= 30,
            "catalog shrank to {}",
            catalog().len()
        );
    }

    #[test]
    fn ids_are_unique_slugs() {
        let mut seen = HashSet::new();
        for s in catalog() {
            assert!(
                !s.id.is_empty()
                    && s.id
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
                "id '{}' must be a lowercase alphanumeric slug",
                s.id
            );
            assert!(seen.insert(s.id.as_str()), "duplicate id '{}'", s.id);
            assert!(!s.name.trim().is_empty(), "'{}' has no name", s.id);
        }
    }

    #[test]
    fn every_category_is_known() {
        for s in catalog() {
            assert!(
                CATEGORIES.contains(&s.category.as_str()),
                "'{}' has unknown category '{}'",
                s.id,
                s.category
            );
        }
    }

    #[test]
    fn domains_are_clean_and_listed_once() {
        let mut seen = HashSet::new();
        for s in catalog() {
            assert!(!s.domains.is_empty(), "'{}' has no domains", s.id);
            for d in &s.domains {
                assert!(
                    d.contains('.')
                        && !d.starts_with('.')
                        && !d.ends_with('.')
                        && !d.contains("..")
                        && d.chars().all(|c| c.is_ascii_lowercase()
                            || c.is_ascii_digit()
                            || c == '.'
                            || c == '-'),
                    "'{}' lists malformed domain '{}' (lowercase, no wildcard, no trailing dot)",
                    s.id,
                    d
                );
                assert!(seen.insert(d.as_str()), "domain '{}' is listed twice", d);
            }
        }
    }

    #[test]
    fn normalize_ids_cleans_and_splits_unknown() {
        let (known, unknown) = normalize_ids(&[
            " YouTube ".into(),
            "tiktok".into(),
            "youtube".into(),
            "".into(),
            "nope".into(),
        ]);
        assert_eq!(known, vec!["youtube", "tiktok"]);
        assert_eq!(unknown, vec!["nope"]);
    }

    #[test]
    fn domains_of_skips_unknown_ids() {
        let domains: Vec<&str> = domains_of(&["deepseek".into(), "nope".into()]).collect();
        assert_eq!(domains, vec!["deepseek.com"]);
    }

    #[test]
    fn messengers_and_games_are_not_routable() {
        for id in ["whatsapp", "telegram", "steam", "playstation"] {
            assert!(!find(id).unwrap().routable, "'{id}' must not be routable");
        }
        assert!(find("youtube").unwrap().routable);
    }
}
