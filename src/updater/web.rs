use std::path::Path;

use crate::error::{FeriteError, Result};
use crate::updater::checksum;
use crate::updater::github::{
    fetch_latest_release, resolve_asset_sha256, update_available, with_release_auth, HTTP_CLIENT,
    RELEASE_OWNER, RELEASE_REPO_WEB,
};

pub struct WebUpdateInfo {
    pub version: String,
    pub download_url: String,
    pub release_notes: String,
    pub sha256: Option<String>,
}

/// Check GitHub Releases for a newer ferrite-web artifact.
pub async fn check_web_update(
    current_version: &str,
    current_sha256: Option<&str>,
) -> Result<Option<WebUpdateInfo>> {
    let release = match fetch_latest_release(RELEASE_OWNER, RELEASE_REPO_WEB).await? {
        Some(r) => r,
        None => return Ok(None),
    };

    let latest = release.tag_name.trim_start_matches('v');
    let current = current_version.trim_start_matches('v');

    let Some(asset) = release.assets.iter().find(|a| a.name.ends_with(".tar.gz")) else {
        return Ok(None);
    };

    let sha256 = resolve_asset_sha256(&release, asset).await?;

    if !update_available(latest, current, sha256.as_deref(), current_sha256) {
        return Ok(None);
    }

    Ok(Some(WebUpdateInfo {
        version: latest.to_string(),
        download_url: asset.browser_download_url.clone(),
        release_notes: release.body.unwrap_or_default(),
        sha256,
    }))
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

async fn remove_dir_if_exists(path: &Path) -> Result<()> {
    match tokio::fs::remove_dir_all(path).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}
