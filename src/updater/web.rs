use std::path::Path;

use serde::Deserialize;

use crate::error::{FeriteError, Result};
use crate::updater::checksum;
use crate::updater::github::{
    fetch_asset_text, fetch_releases, parse_semver, resolve_asset_sha256, update_available,
    with_release_auth, HTTP_CLIENT, RELEASE_OWNER, RELEASE_REPO_WEB,
};

const WEB_RELEASE_SCAN_LIMIT: usize = 20;
const WEB_MANIFEST_ASSET: &str = "dist.manifest.json";

pub struct WebUpdateInfo {
    pub version: String,
    pub download_url: String,
    pub release_notes: String,
    pub sha256: Option<String>,
    pub server_compat: String,
}

pub struct IncompatibleWebUpdate {
    pub version: String,
    pub required_server: String,
    pub reason: String,
}

pub struct WebUpdateCheck {
    pub update: Option<WebUpdateInfo>,
    pub incompatible_latest: Option<IncompatibleWebUpdate>,
}

#[derive(Debug, Deserialize)]
struct WebReleaseManifest {
    server_compat: Option<String>,
}

/// Check GitHub Releases for the newest ferrite-web artifact compatible with
/// the running server. Newer incompatible web releases are reported separately
/// so the UI can tell the user to update the server first.
pub async fn check_web_update_for_server(
    current_version: &str,
    current_sha256: Option<&str>,
    current_server_version: &str,
) -> Result<WebUpdateCheck> {
    let current = current_version.trim_start_matches('v');
    let mut incompatible_latest = None;

    for release in fetch_releases(RELEASE_OWNER, RELEASE_REPO_WEB, WEB_RELEASE_SCAN_LIMIT).await? {
        if release.draft || release.prerelease {
            continue;
        }

        let latest = release.tag_name.trim_start_matches('v');
        let Some(asset) = release.assets.iter().find(|a| a.name.ends_with(".tar.gz")) else {
            continue;
        };

        let manifest = fetch_release_manifest(&release).await?;
        let required_server = manifest
            .as_ref()
            .and_then(|m| cleaned_compat(m.server_compat.as_deref()))
            .unwrap_or_else(|| default_server_compat(latest));

        if !server_satisfies_compat(current_server_version, &required_server) {
            if incompatible_latest.is_none() && parse_semver(latest) > parse_semver(current) {
                incompatible_latest = Some(IncompatibleWebUpdate {
                    version: latest.to_string(),
                    reason: format!(
                        "web UI v{latest} requires server {required_server}; running server is v{}",
                        current_server_version.trim_start_matches('v')
                    ),
                    required_server,
                });
            }
            continue;
        }

        let sha256 = resolve_asset_sha256(&release, asset).await?;

        if !update_available(latest, current, sha256.as_deref(), current_sha256) {
            continue;
        }

        return Ok(WebUpdateCheck {
            update: Some(WebUpdateInfo {
                version: latest.to_string(),
                download_url: asset.browser_download_url.clone(),
                release_notes: release.body.unwrap_or_default(),
                sha256,
                server_compat: required_server,
            }),
            incompatible_latest,
        });
    }

    Ok(WebUpdateCheck {
        update: None,
        incompatible_latest,
    })
}

/// Download the web UI dist archive and extract it to `dest_dir`.
/// The archive is expected to be a `dist.tar.gz` containing a `dist/` folder.
pub async fn apply_web_update(info: &WebUpdateInfo, dest_dir: &Path) -> Result<()> {
    tracing::info!(
        "downloading web UI v{} from {}",
        info.version,
        info.download_url
    );

    let bytes = with_release_auth(HTTP_CLIENT.get(&info.download_url))
        .send()
        .await
        .map_err(FeriteError::Http)?
        .error_for_status()
        .map_err(FeriteError::Http)?
        .bytes()
        .await
        .map_err(FeriteError::Http)?;

    if let Some(expected) = &info.sha256 {
        checksum::verify_bytes_sha256(&bytes, expected, "web UI update archive")?;
    }

    // Extract into a staging dir first, then move the prepared dist into place.
    let staging = dest_dir.with_extension("tmp");
    let prepared = dest_dir.with_extension("new");
    remove_dir_if_exists(&staging).await?;
    remove_dir_if_exists(&prepared).await?;
    tokio::fs::create_dir_all(&staging).await?;

    let bytes_vec = bytes.to_vec();
    let staging_clone = staging.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let cursor = std::io::Cursor::new(bytes_vec);
        let gz = flate2::read::GzDecoder::new(cursor);
        let mut archive = tar::Archive::new(gz);
        for entry in archive
            .entries()
            .map_err(|e| FeriteError::Internal(format!("archive entries: {}", e)))?
        {
            let mut entry =
                entry.map_err(|e| FeriteError::Internal(format!("archive entry: {}", e)))?;
            let entry_path = entry
                .path()
                .map_err(|e| FeriteError::Internal(format!("entry path: {}", e)))?
                .into_owned();
            // Skip entries with path traversal components (zip-slip).
            if entry_path
                .components()
                .any(|c| c == std::path::Component::ParentDir)
            {
                tracing::warn!(
                    "skipping archive entry with path traversal: {}",
                    entry_path.display()
                );
                continue;
            }
            entry.unpack_in(&staging_clone).map_err(|e| {
                FeriteError::Internal(format!("extract {}: {}", entry_path.display(), e))
            })?;
        }
        Ok(())
    })
    .await
    .map_err(|e| FeriteError::Internal(e.to_string()))??;

    // Releases may contain either the files directly or a top-level dist/ folder.
    let dist_inside_staging = staging.join("dist");
    if tokio::fs::metadata(&dist_inside_staging).await.is_ok() {
        tokio::fs::rename(&dist_inside_staging, &prepared).await?;
        remove_dir_if_exists(&staging).await?;
    } else {
        tokio::fs::rename(&staging, &prepared).await?;
    }

    remove_dir_if_exists(dest_dir).await?;
    tokio::fs::rename(&prepared, dest_dir).await?;

    tracing::info!(
        "web UI updated to v{} at {}",
        info.version,
        dest_dir.display()
    );
    Ok(())
}

pub async fn installed_sha256(web_dir: &Path) -> Result<Option<String>> {
    checksum::read_sha256_file(&sha256_path(web_dir)).await
}

pub async fn persist_installed_sha256(web_dir: &Path, sha256: Option<&str>) -> Result<()> {
    let path = sha256_path(web_dir);
    match sha256 {
        Some(sha256) => checksum::write_sha256_file(&path, sha256).await,
        None => checksum::remove_file_if_exists(&path).await,
    }
}

fn sha256_path(web_dir: &Path) -> std::path::PathBuf {
    web_dir.with_extension("sha256")
}

async fn fetch_release_manifest(
    release: &crate::updater::github::Release,
) -> Result<Option<WebReleaseManifest>> {
    let Some(raw) = fetch_asset_text(release, WEB_MANIFEST_ASSET).await? else {
        return Ok(None);
    };

    serde_json::from_str(&raw)
        .map(Some)
        .map_err(|e| FeriteError::Update(format!("{WEB_MANIFEST_ASSET} is invalid JSON: {e}")))
}

fn cleaned_compat(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn default_server_compat(web_version: &str) -> String {
    let (major, minor, _) = parse_semver(web_version);
    format!(">={major}.{minor}.0 <{major}.{}.0", minor + 1)
}

fn server_satisfies_compat(server_version: &str, compat: &str) -> bool {
    let server = parse_semver(server_version);
    compat
        .split_whitespace()
        .all(|part| version_satisfies_comparator(server, part).unwrap_or(false))
}

fn version_satisfies_comparator(version: (u32, u32, u32), comparator: &str) -> Option<bool> {
    let (op, raw) = if let Some(raw) = comparator.strip_prefix(">=") {
        (">=", raw)
    } else if let Some(raw) = comparator.strip_prefix("<=") {
        ("<=", raw)
    } else if let Some(raw) = comparator.strip_prefix('>') {
        (">", raw)
    } else if let Some(raw) = comparator.strip_prefix('<') {
        ("<", raw)
    } else if let Some(raw) = comparator.strip_prefix('=') {
        ("=", raw)
    } else {
        return None;
    };

    let target = parse_semver(raw);
    Some(match op {
        ">=" => version >= target,
        "<=" => version <= target,
        ">" => version > target,
        "<" => version < target,
        "=" => version == target,
        _ => return None,
    })
}

async fn remove_dir_if_exists(path: &Path) -> Result<()> {
    match tokio::fs::remove_dir_all(path).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_compat_uses_web_minor_line() {
        assert_eq!(default_server_compat("0.1.7"), ">=0.1.0 <0.2.0");
        assert_eq!(default_server_compat("1.4.2"), ">=1.4.0 <1.5.0");
    }

    #[test]
    fn server_compat_range_accepts_current_line() {
        assert!(server_satisfies_compat("0.1.4", ">=0.1.0 <0.2.0"));
        assert!(server_satisfies_compat("v0.1.4", ">=0.1.0 <0.2.0"));
    }

    #[test]
    fn server_compat_range_blocks_next_minor() {
        assert!(!server_satisfies_compat("0.1.9", ">=0.2.0 <0.3.0"));
        assert!(!server_satisfies_compat("0.2.0", ">=0.1.0 <0.2.0"));
    }

    #[test]
    fn invalid_compat_is_not_accepted() {
        assert!(!server_satisfies_compat("0.1.0", "~0.1"));
    }
}
