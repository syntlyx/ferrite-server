//! SafeSearch and YouTube Restricted Mode, enforced in DNS the way the engines
//! publish it: their search hosts resolve as a CNAME to a "safe" host whose
//! addresses serve filtered results. Google: `forcesafesearch.google.com`;
//! Bing: `strict.bing.com`; DuckDuckGo: `safe.duckduckgo.com`; YouTube:
//! `restrictmoderate.youtube.com` or `restrict.youtube.com`.
//!
//! This module only maps a queried name to its safe host. The DNS pipeline
//! answers with the CNAME and the safe host's records.

use ferrite_core::config::YoutubeRestrict;

/// The hosts Google lists for YouTube Restricted Mode over DNS.
const YOUTUBE_HOSTS: &[&str] = &[
    "www.youtube.com",
    "m.youtube.com",
    "youtubei.googleapis.com",
    "youtube.googleapis.com",
    "www.youtube-nocookie.com",
];

const BING_HOSTS: &[&str] = &["bing.com", "www.bing.com"];

const DUCKDUCKGO_HOSTS: &[&str] = &[
    "duckduckgo.com",
    "www.duckduckgo.com",
    "start.duckduckgo.com",
];

/// What to enforce for one client: the stricter of the network-wide setting
/// and its profile's.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SafeSearch {
    pub search: bool,
    pub youtube: YoutubeRestrict,
}

impl SafeSearch {
    pub fn is_off(&self) -> bool {
        !self.search && self.youtube == YoutubeRestrict::Off
    }

    /// The stricter of two settings.
    pub fn max(self, other: SafeSearch) -> SafeSearch {
        SafeSearch {
            search: self.search || other.search,
            youtube: self.youtube.max(other.youtube),
        }
    }

    /// The safe host `name` must resolve to, if any. Expects a normalised
    /// name (lowercase, no trailing dot).
    pub fn target(&self, name: &str) -> Option<&'static str> {
        if self.youtube != YoutubeRestrict::Off && YOUTUBE_HOSTS.contains(&name) {
            return Some(match self.youtube {
                YoutubeRestrict::Strict => "restrict.youtube.com",
                _ => "restrictmoderate.youtube.com",
            });
        }
        if !self.search {
            return None;
        }
        if BING_HOSTS.contains(&name) {
            return Some("strict.bing.com");
        }
        if DUCKDUCKGO_HOSTS.contains(&name) {
            return Some("safe.duckduckgo.com");
        }
        is_google_search_host(name).then_some("forcesafesearch.google.com")
    }
}

/// `google.<suffix>` or `www.google.<suffix>` for any public (ICANN) suffix:
/// google.com, www.google.co.uk, google.com.ua… — the search front page in
/// every country. Other Google hosts (mail, maps, the APIs) are left alone.
fn is_google_search_host(name: &str) -> bool {
    let rest = name.strip_prefix("www.").unwrap_or(name);
    let Some(suffix) = rest.strip_prefix("google.") else {
        return false;
    };
    // The remainder must be exactly a public suffix from the ICANN section, so
    // `google.example.org` or a `google.blogspot.com` blog never match.
    psl::suffix(suffix.as_bytes())
        .is_some_and(|s| s.as_bytes() == suffix.as_bytes() && s.typ() == Some(psl::Type::Icann))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEARCH: SafeSearch = SafeSearch {
        search: true,
        youtube: YoutubeRestrict::Off,
    };

    #[test]
    fn google_search_front_pages_in_every_country() {
        for host in [
            "google.com",
            "www.google.com",
            "www.google.co.uk",
            "google.com.ua",
            "www.google.de",
        ] {
            assert_eq!(
                SEARCH.target(host),
                Some("forcesafesearch.google.com"),
                "{host}"
            );
        }
        for host in [
            "mail.google.com",
            "forcesafesearch.google.com",
            "google.example.org",
            "google.blogspot.com",
            "notgoogle.com",
            "www.google",
        ] {
            assert_eq!(SEARCH.target(host), None, "{host}");
        }
    }

    #[test]
    fn bing_and_duckduckgo() {
        assert_eq!(SEARCH.target("www.bing.com"), Some("strict.bing.com"));
        assert_eq!(SEARCH.target("duckduckgo.com"), Some("safe.duckduckgo.com"));
        assert_eq!(SEARCH.target("api.bing.com"), None);
    }

    #[test]
    fn youtube_follows_its_own_setting() {
        let off = SEARCH;
        assert_eq!(off.target("www.youtube.com"), None);
        let moderate = SafeSearch {
            search: false,
            youtube: YoutubeRestrict::Moderate,
        };
        assert_eq!(
            moderate.target("m.youtube.com"),
            Some("restrictmoderate.youtube.com")
        );
        assert_eq!(moderate.target("www.google.com"), None);
        let strict = moderate.max(SafeSearch {
            search: false,
            youtube: YoutubeRestrict::Strict,
        });
        assert_eq!(
            strict.target("youtubei.googleapis.com"),
            Some("restrict.youtube.com")
        );
    }

    #[test]
    fn the_stricter_setting_wins() {
        let a = SafeSearch {
            search: true,
            youtube: YoutubeRestrict::Moderate,
        };
        let b = SafeSearch {
            search: false,
            youtube: YoutubeRestrict::Strict,
        };
        assert_eq!(
            a.max(b),
            SafeSearch {
                search: true,
                youtube: YoutubeRestrict::Strict
            }
        );
        assert!(SafeSearch::default().is_off());
    }
}
