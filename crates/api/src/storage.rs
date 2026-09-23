//! Where the database can go: what is in use now, and what else this box
//! offers.
//!
//! `storage.path` is a real choice — writes on a flash card versus RAM that a
//! reboot clears — and it used to be settable only by editing the config file,
//! because nobody can be expected to recite their mount table. This endpoint
//! answers that: the RAM-backed mounts ferrite can actually write to, with
//! their free space, plus the on-disk default so the way back is as visible as
//! the way out.
//!
//! The compiled blocklist cache is placed from the same list: it faces the same
//! trade (flash writes on each refresh versus RAM and a re-download after a
//! reboot), just for data that came from list servers rather than traffic.

use axum::{Json, extract::State};
use serde::Serialize;
use serde_json::{Value, json};

use ferrite_app::AppState;
use ferrite_core::config::{StorageBackend, data_dir};
use ferrite_core::fsinfo;

/// One place the database could live.
#[derive(Serialize)]
pub struct StorageSuggestion {
    /// Full database path to use — what `storage.path` would be set to.
    pub path: String,
    /// The mount it sits on.
    pub dir: String,
    pub fstype: String,
    /// In RAM: no flash wear, and empty again after a reboot.
    pub ram_backed: bool,
    pub total_bytes: Option<u64>,
    pub available_bytes: Option<u64>,
    /// True for the location currently configured.
    pub current: bool,
}

/// GET /api/storage/locations
pub async fn list_locations(State(state): State<AppState>) -> Json<Value> {
    let cfg = state.live_config.read().clone();
    let current = cfg.storage.path.clone();

    let mut suggestions: Vec<StorageSuggestion> = Vec::new();

    // The on-disk default first: it is the answer for most boxes, and listing
    // it makes "put it back" a click rather than something to remember.
    let default_dir = data_dir();
    let default_path = default_dir.join("ferrite.db");
    suggestions.push(describe(&default_dir, "ferrite.db", None, &current));

    // Then each RAM-backed mount, most free space first.
    for location in fsinfo::ram_backed_locations() {
        let dir = location.dir.join("ferrite");
        suggestions.push(describe(
            &dir,
            "ferrite.db",
            Some(location.fstype.clone()),
            &current,
        ));
    }

    // Finally the configured path, if it is somewhere else entirely — the UI
    // should always be able to show what is in use with its free space.
    if current != default_path && !suggestions.iter().any(|s| s.current) {
        let dir = current
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| default_dir.clone());
        let name = current
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "ferrite.db".to_string());
        suggestions.push(describe(&dir, &name, None, &current));
    }

    Json(json!({
        "backend": match cfg.storage.backend {
            StorageBackend::Sqlite => "sqlite",
            StorageBackend::Memory => "memory",
        },
        "current": current.display().to_string(),
        "default": default_path.display().to_string(),
        "suggestions": suggestions,
        // The compiled blocklist picks from the same mounts — each
        // suggestion's `dir` is what `blocklist_cache_dir` would be set to.
        "blocklist_cache": {
            "current": cfg.storage.blocklist_cache_dir.display().to_string(),
            "default": default_dir.display().to_string(),
            "available_bytes": fsinfo::space_for(&cfg.storage.blocklist_cache_dir)
                .map(|s| s.available_bytes),
        },
    }))
}

fn describe(
    dir: &std::path::Path,
    filename: &str,
    fstype: Option<String>,
    current: &std::path::Path,
) -> StorageSuggestion {
    let path = dir.join(filename);
    let space = fsinfo::space_for(dir);
    StorageSuggestion {
        current: path == current,
        path: path.display().to_string(),
        dir: dir.display().to_string(),
        ram_backed: fstype
            .as_deref()
            .is_some_and(|f| f == "tmpfs" || f == "ramfs"),
        fstype: fstype.unwrap_or_else(|| "disk".to_string()),
        total_bytes: space.map(|s| s.total_bytes),
        available_bytes: space.map(|s| s.available_bytes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_app::test_support;

    /// The default location is always offered, and the one in use is marked —
    /// so the panel can render the list without a second request.
    #[tokio::test]
    async fn locations_always_include_the_default_and_flag_the_current_one() {
        let (state, db_path) = test_support::app_state("api-storage-locations").await;

        let Json(value) = list_locations(State(state.clone())).await;
        let suggestions = value["suggestions"].as_array().unwrap();
        assert!(!suggestions.is_empty());

        let default = value["default"].as_str().unwrap();
        assert!(suggestions.iter().any(|s| s["path"] == default));

        // The test state points at a temp database, so that is what is current
        // and it has to appear even though it is neither the default nor a
        // RAM mount.
        let current = value["current"].as_str().unwrap();
        assert_eq!(current, db_path.display().to_string());
        let marked: Vec<&Value> = suggestions
            .iter()
            .filter(|s| s["current"].as_bool() == Some(true))
            .collect();
        assert_eq!(marked.len(), 1, "exactly one suggestion is the current one");
        assert_eq!(marked[0]["path"], current);

        // Free space is reported for a path that does not exist yet.
        assert!(marked[0]["available_bytes"].as_u64().is_some());

        // The blocklist cache defaults to the same directory the default
        // database suggestion sits in, so one chip serves both fields.
        let cache = &value["blocklist_cache"];
        assert_eq!(cache["default"], suggestions[0]["dir"]);
        assert!(cache["current"].as_str().is_some());

        drop(state);
        test_support::cleanup_sqlite(&db_path);
    }
}
