//! Backup and restore of the whole configuration.
//!
//! `GET /api/config/export` hands back `config.toml` exactly as ferrite would
//! write it. `POST /api/config/import` takes one back: it is parsed and checked
//! the way startup would, the file it replaces is kept as `config.toml.bak`,
//! and the service restarts so every section — listeners, storage, lists —
//! applies at once.
//!
//! The export carries secrets (the API key, the password hash, WireGuard
//! private keys); it sits behind the same authentication as the rest of the
//! API, and the panel says so before the download.

use std::path::PathBuf;

use axum::{
    Json,
    extract::State,
    http::header::{CONTENT_DISPOSITION, CONTENT_TYPE},
    response::IntoResponse,
};
use serde_json::{Value, json};

use crate::ApiError;
use crate::settings::{schedule_restart, validate_blocklist_cache_dir, validate_storage_path};
use ferrite_app::AppState;
use ferrite_core::config::{Config, StorageBackend};
use ferrite_core::error::FeriteError;

/// GET /api/config/export
pub async fn export_config(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    let cfg = state.live_config.read().clone();
    let body = cfg.to_toml()?;
    Ok((
        [
            (CONTENT_TYPE, "application/toml; charset=utf-8"),
            (
                CONTENT_DISPOSITION,
                "attachment; filename=\"ferrite-config.toml\"",
            ),
        ],
        body,
    ))
}

/// POST /api/config/import — body: the TOML text of a config file.
pub async fn import_config(
    State(state): State<AppState>,
    body: String,
) -> Result<Json<Value>, ApiError> {
    let mut cfg = Config::from_toml(&body).map_err(|e| {
        ApiError(FeriteError::Config(format!(
            "not a valid ferrite config: {e}"
        )))
    })?;
    // The checks that keep a restored file from leaving the box unable to come
    // back up: the listeners already parsed as socket addresses above, and the
    // paths get the same scrutiny as when they are set from the panel.
    if cfg.storage.backend == StorageBackend::Sqlite {
        cfg.storage.path = validate_storage_path(&cfg.storage.path)?;
    }
    cfg.storage.blocklist_cache_dir =
        validate_blocklist_cache_dir(&cfg.storage.blocklist_cache_dir)?;

    let backup = keep_current_file(&state).await;
    let previous = std::mem::replace(&mut *state.live_config.write(), cfg);
    let Some(saved_to) = state.persist_config().await else {
        // Nothing reached the disk, so nothing must change in memory either.
        *state.live_config.write() = previous;
        return Err(ApiError(FeriteError::Internal(
            "could not write the config file".into(),
        )));
    };
    tracing::info!("configuration restored from an upload, restarting");
    schedule_restart(&state);
    Ok(Json(json!({
        "saved_to": saved_to,
        "backup": backup,
        "restart": true,
    })))
}

/// Copy the config file about to be replaced to `config.toml.bak`. Returns the
/// backup's path, or `None` when there was no file yet or the copy failed —
/// the restore goes ahead either way, the upload being the newer intent.
async fn keep_current_file(state: &AppState) -> Option<String> {
    let path: PathBuf = state.config_path.as_ref().clone()?;
    let bak = path.with_extension("toml.bak");
    match tokio::fs::copy(&path, &bak).await {
        Ok(_) => Some(bak.display().to_string()),
        Err(e) => {
            tracing::warn!(
                "could not keep {} as {}: {}",
                path.display(),
                bak.display(),
                e
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_app::test_support;

    #[tokio::test]
    async fn export_then_import_round_trips_and_keeps_the_old_file() {
        let (state, db_path, config_path) =
            test_support::app_state_with_config_path("api-backup").await;
        std::fs::write(&config_path, state.live_config.read().to_toml().unwrap()).unwrap();

        let res = export_config(State(state.clone()))
            .await
            .unwrap()
            .into_response();
        let disposition = res.headers()[CONTENT_DISPOSITION]
            .to_str()
            .unwrap()
            .to_string();
        assert!(disposition.starts_with("attachment"));
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let exported = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(exported.contains("[dns]"));

        // Restore a changed copy: the change lands in the file and the old file stays as .bak.
        let mut changed = Config::from_toml(&exported).unwrap();
        changed.blocklist.enabled = false;
        let res = import_config(State(state.clone()), changed.to_toml().unwrap())
            .await
            .unwrap();
        assert_eq!(res.0["restart"], true);
        let written = Config::from_toml(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert!(!written.blocklist.enabled);
        let bak = config_path.with_extension("toml.bak");
        assert!(
            Config::from_toml(&std::fs::read_to_string(&bak).unwrap())
                .unwrap()
                .blocklist
                .enabled
        );

        let _ = std::fs::remove_file(&config_path);
        let _ = std::fs::remove_file(&bak);
        drop(state);
        test_support::cleanup_sqlite(&db_path);
    }

    #[tokio::test]
    async fn a_broken_file_is_refused_and_nothing_is_written() {
        let (state, db_path, config_path) =
            test_support::app_state_with_config_path("api-backup-bad").await;
        for body in [
            "this is not toml [",
            "[dns]\nbind_addr = \"not an address\"\n",
        ] {
            let res = import_config(State(state.clone()), body.into()).await;
            assert!(res.is_err(), "{body:?} must be refused");
        }
        assert!(!config_path.exists(), "a refused import writes nothing");

        drop(state);
        test_support::cleanup_sqlite(&db_path);
    }
}
