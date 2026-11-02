//! What following a primary has done lately — read by the panel, written by
//! the sync loop. The last change survives the restart that applies it.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncStatus {
    /// Unix seconds of the last attempt, successful or not.
    pub last_attempt: Option<i64>,
    /// Unix seconds of the last successful read of the primary.
    pub last_ok: Option<i64>,
    /// Unix seconds of the last sync that changed something here.
    pub last_change: Option<i64>,
    /// The sections that last change touched.
    pub changed: Vec<String>,
    /// Why the last attempt failed; `None` after a success.
    pub error: Option<String>,
    /// Fingerprint of what was last applied — a sync that would apply the
    /// same thing again is a loop, not a change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied: Option<String>,
}

fn path() -> PathBuf {
    ferrite_core::config::data_dir().join("sync-status.json")
}

impl SyncStatus {
    /// What the previous run left, or nothing.
    pub fn load() -> SyncStatus {
        std::fs::read(path())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Keep it for the next run (best effort).
    pub fn save(&self) {
        if let Ok(bytes) = serde_json::to_vec(self) {
            let _ = std::fs::write(path(), bytes);
        }
    }
}
