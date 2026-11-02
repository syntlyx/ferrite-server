//! Catalog services blocked for every device (`[blocklist] services`): the
//! configured ids expanded into the domain set the block decision walks.
//! A profile's own `services` join its `block` set instead — see
//! [`crate::profiles`].

use std::collections::HashSet;

use ferrite_core::services::{self, Service};

use crate::names::{domain_in_set, matched_key};

pub(crate) struct ServiceBlock {
    /// The ids as configured (known ones only), for the API to echo back.
    ids: Vec<String>,
    /// Every domain of those services. Catalog domains are already lowercase
    /// with no trailing dot, so they compare against query names as they are.
    domains: HashSet<String>,
}

impl ServiceBlock {
    pub(crate) fn new(ids: &[String]) -> Self {
        let (ids, _unknown) = services::normalize_ids(ids);
        let domains = services::domains_of(&ids).map(str::to_string).collect();
        Self { ids, domains }
    }

    pub(crate) fn ids(&self) -> &[String] {
        &self.ids
    }

    /// Does a blocked service cover `domain` — the name itself or a parent?
    /// Expects a normalised name. Free when nothing is blocked, which is how
    /// most installs run.
    pub(crate) fn contains(&self, domain: &str) -> bool {
        !self.domains.is_empty() && domain_in_set(domain, &self.domains)
    }

    /// Each blocked service that covers `domain`, with the key that matched —
    /// for [`crate::Blocklist::explain`], off the DNS path.
    pub(crate) fn matches(&self, domain: &str) -> Vec<(&'static Service, String)> {
        self.ids
            .iter()
            .filter_map(|id| services::find(id))
            .filter_map(|svc| {
                matched_key(domain, |k| svc.domains.iter().any(|d| d == k)).map(|key| (svc, key))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn covers_service_domains_and_their_subdomains() {
        let block = ServiceBlock::new(&["tiktok".into(), "nope".into()]);
        assert_eq!(block.ids(), ["tiktok"]);
        assert!(block.contains("tiktok.com"));
        assert!(block.contains("v16-webapp.tiktok.com"));
        assert!(!block.contains("nottiktok.com"));
        assert!(!block.contains("youtube.com"));
    }

    #[test]
    fn empty_block_matches_nothing() {
        let block = ServiceBlock::new(&[]);
        assert!(!block.contains("tiktok.com"));
        assert!(block.matches("tiktok.com").is_empty());
    }

    #[test]
    fn matches_name_the_service_and_the_key() {
        let block = ServiceBlock::new(&["youtube".into()]);
        let hits = block.matches("rr3---sn-abc.googlevideo.com");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0.id, "youtube");
        assert_eq!(hits[0].1, "googlevideo.com");
    }
}
