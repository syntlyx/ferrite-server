pub mod cache;
pub mod domains;
pub mod engine;
pub mod loader;
mod manual;
mod names;
pub mod parser;
pub mod pause;
mod profiles;
mod refresh;
mod services;
mod subscriptions;

pub use domains::DomainSet;
pub use engine::Blocklist;
pub use names::{normalise_domain, wildcard_to_regex};
pub use parser::AdblockStats;
pub use profiles::CompiledProfile;
pub use subscriptions::Subscriptions;

/// Which decision set a subscription list populates. Blocklists and allowlists
/// share one fetch/parse/FST pipeline; polarity only changes how Adblock-format
/// content is read (`||` block rules vs `@@` exception rules). Hosts and plain
/// lists parse identically under either polarity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListPolarity {
    Block,
    Allow,
}

impl ListPolarity {
    /// What a list of this polarity is called in logs and errors.
    pub fn noun(self) -> &'static str {
        match self {
            ListPolarity::Block => "blocklist",
            ListPolarity::Allow => "allowlist",
        }
    }
}
