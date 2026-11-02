//! Manual allow/block entries: exact names, matched with the hierarchy walk,
//! plus wildcard patterns. Seeded from the config and edited at runtime
//! through the API. They are global and apply inside every profile.

use std::collections::HashSet;

use parking_lot::RwLock;
use regex::Regex;

use crate::names::{domain_in_set, is_pattern, matched_key, normalise, pattern_to_regex};
use ferrite_core::error::Result;

pub(crate) struct ManualList {
    exact: RwLock<HashSet<String>>,
    /// Pattern entries — wildcards such as `*.safe.example.com` and
    /// `/regex/` ones — with their compiled regex.
    wildcards: RwLock<Vec<(String, Regex)>>,
}

impl ManualList {
    /// Seed from configured entries, normalising each. An invalid wildcard is
    /// logged and skipped rather than failing startup over one bad line.
    pub(crate) fn from_entries<'a>(entries: impl IntoIterator<Item = &'a String>) -> Self {
        let mut exact = HashSet::new();
        let mut wildcards = Vec::new();
        for entry in entries {
            let norm = normalise(entry);
            if is_pattern(&norm) {
                match pattern_to_regex(&norm) {
                    Ok(re) => wildcards.push((norm, re)),
                    Err(e) => tracing::warn!("skipping invalid pattern '{}': {}", entry, e),
                }
            } else {
                exact.insert(norm);
            }
        }
        Self {
            exact: RwLock::new(exact),
            wildcards: RwLock::new(wildcards),
        }
    }

    /// Does an entry cover `domain` — exactly, through a parent, or by
    /// wildcard? Expects a normalised name; runs uncached on every query, so
    /// the empty sets an unconfigured install has must stay free.
    pub(crate) fn contains(&self, domain: &str) -> bool {
        domain_in_set(domain, &self.exact.read())
            || self
                .wildcards
                .read()
                .iter()
                .any(|(_, re)| re.is_match(domain))
    }

    /// The exact entry that covers `domain` — the name itself or the parent
    /// where the walk matched.
    pub(crate) fn exact_match(&self, domain: &str) -> Option<String> {
        let exact = self.exact.read();
        matched_key(domain, |k| exact.contains(k))
    }

    /// Every wildcard pattern that matches `domain`, in the order added.
    pub(crate) fn matching_patterns(&self, domain: &str) -> Vec<String> {
        self.wildcards
            .read()
            .iter()
            .filter(|(_, re)| re.is_match(domain))
            .map(|(pat, _)| pat.clone())
            .collect()
    }

    pub(crate) fn add(&self, domain: &str) -> Result<()> {
        let d = normalise(domain);
        if is_pattern(&d) {
            let re = pattern_to_regex(&d)?;
            let mut wildcards = self.wildcards.write();
            // Adding the same pattern twice would only double the work.
            if !wildcards.iter().any(|(p, _)| p == &d) {
                wildcards.push((d, re));
            }
        } else {
            self.exact.write().insert(d);
        }
        Ok(())
    }

    pub(crate) fn remove(&self, domain: &str) {
        let d = normalise(domain);
        if is_pattern(&d) {
            self.wildcards.write().retain(|(pat, _)| pat != &d);
        } else {
            self.exact.write().remove(&d);
        }
    }

    /// Every entry: exact names first, then patterns.
    pub(crate) fn entries(&self) -> Vec<String> {
        let mut result: Vec<String> = self.exact.read().iter().cloned().collect();
        result.extend(self.wildcards.read().iter().map(|(p, _)| p.clone()));
        result
    }
}
