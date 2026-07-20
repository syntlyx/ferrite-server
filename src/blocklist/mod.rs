pub mod cache;
pub mod engine;
pub mod loader;
pub mod parser;
mod refresh;

pub use engine::{Blocklist, CompiledProfile, normalise_domain};
pub use parser::AdblockStats;

/// Which decision set a subscription list populates. Blocklists and allowlists
/// share one fetch/parse/FST pipeline; polarity only changes how Adblock-format
/// content is read (`||` block rules vs `@@` exception rules). Hosts and plain
/// lists parse identically under either polarity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListPolarity {
    Block,
    Allow,
}
