use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::app::AppState;
use crate::config::{Config, UpstreamConfig};

pub fn temp_path(name: &str, extension: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut path =
        std::env::temp_dir().join(format!("ferrite-{name}-{}-{nanos}", std::process::id()));
    path.set_extension(extension);
    path
}

pub async fn app_state(name: &str) -> (AppState, PathBuf) {
    let db_path = temp_path(name, "db");
    let mut config = Config::default();
    config.storage.path = db_path.clone();
    config.blocklist.lists.clear();
    config.upstream = vec![UpstreamConfig::Plain {
        address: "127.0.0.1".to_string(),
        port: 53,
    }];

    let state = AppState::init(&config, config.clone()).await.unwrap();
    (state, db_path)
}

pub async fn app_state_with_config_path(name: &str) -> (AppState, PathBuf, PathBuf) {
    let (state, db_path) = app_state(name).await;
    let config_path = temp_path(name, "toml");
    let state = AppState {
        config_path: Arc::new(Some(config_path.clone())),
        ..state
    };
    (state, db_path, config_path)
}

pub fn cleanup_sqlite(path: &Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(path.with_extension("db-shm"));
    let _ = std::fs::remove_file(path.with_extension("db-wal"));
}
