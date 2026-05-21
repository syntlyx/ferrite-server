use std::path::{Path, PathBuf};

use crate::error::{FeriteError, Result};
use crate::updater::checksum;
use crate::updater::github::{
    fetch_latest_release, resolve_asset_sha256, update_available, with_release_auth, HTTP_CLIENT,
    RELEASE_OWNER, RELEASE_REPO_SERVER,
};

/// Information about an available update.
pub struct UpdateInfo {
    pub version: String,
    pub download_url: String,
    pub release_notes: String,
    pub sha256: Option<String>,
}

/// Check GitHub Releases for a newer server artifact.
/// Returns `Ok(Some(info))` if an update is available, `Ok(None)` if up-to-date.
pub async fn check(current_version: &str) -> Result<Option<UpdateInfo>> {
    let release = match fetch_latest_release(RELEASE_OWNER, RELEASE_REPO_SERVER).await? {
        Some(r) => r,
        None => return Ok(None),
    };

    let latest = release.tag_name.trim_start_matches('v');

    let target = current_platform_target();
    let asset = release
        .assets
        .iter()
        .find(|a| a.name.ends_with(".tar.gz") && a.name.contains(target));

    let Some(asset) = asset else {
        return Ok(None);
    };

    let sha256 = resolve_asset_sha256(&release, asset).await?;
    let installed_sha256 = installed_sha256().await?;

    if !update_available(
        latest,
        current_version,
        sha256.as_deref(),
        installed_sha256.as_deref(),
    ) {
        return Ok(None);
    }

    Ok(Some(UpdateInfo {
        version: latest.to_string(),
        download_url: asset.browser_download_url.clone(),
        release_notes: release.body.unwrap_or_default(),
        sha256,
    }))
}

/// Download and apply a server update: extracts the `ferrite` binary from the
/// release tar.gz and atomically renames it over the current executable.
pub async fn apply(info: &UpdateInfo) -> Result<()> {
    let url = info.download_url.clone();
    let version = info.version.clone();
    let expected_sha256 = info.sha256.clone();
    tracing::info!("downloading server update v{}", version);

    let bytes = with_release_auth(HTTP_CLIENT.get(&url))
        .send()
        .await
        .map_err(FeriteError::Http)?
        .error_for_status()
        .map_err(FeriteError::Http)?
        .bytes()
        .await
        .map_err(FeriteError::Http)?
        .to_vec();

    if let Some(expected) = &expected_sha256 {
        checksum::verify_bytes_sha256(&bytes, expected, "server update archive")?;
    }

    let current_exe = std::env::current_exe()?;
    let checksum_path = checksum_path_for(&current_exe);

    tokio::task::spawn_blocking(move || -> Result<()> {
        let tmp = current_exe.with_extension("update.tmp");
        let _ = std::fs::remove_file(&tmp);

        // Extract the `ferrite` binary from the tar.gz archive.
        let cursor = std::io::Cursor::new(bytes);
        let gz = flate2::read::GzDecoder::new(cursor);
        let mut archive = tar::Archive::new(gz);

        let mut found = false;
        for entry in archive
            .entries()
            .map_err(|e| FeriteError::Internal(format!("archive entries: {e}")))?
        {
            let mut entry =
                entry.map_err(|e| FeriteError::Internal(format!("archive entry: {e}")))?;
            let path = entry
                .path()
                .map_err(|e| FeriteError::Internal(format!("entry path: {e}")))?
                .into_owned();

            if path.file_name().and_then(|n| n.to_str()) == Some("ferrite") {
                entry
                    .unpack(&tmp)
                    .map_err(|e| FeriteError::Internal(format!("unpack: {e}")))?;
                found = true;
                break;
            }
        }

        if !found {
            return Err(FeriteError::Update(
                "'ferrite' binary not found in update archive".into(),
            ));
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
        }

        // Atomic rename over the running binary (safe on Linux/macOS: the old
        // inode stays mapped until the process exits).
        std::fs::rename(&tmp, &current_exe)?;

        Ok(())
    })
    .await
    .map_err(|e| FeriteError::Internal(e.to_string()))??;

    if let Some(expected) = expected_sha256 {
        checksum::write_sha256_file(&checksum_path, &expected).await?;
    } else {
        checksum::remove_file_if_exists(&checksum_path).await?;
    }

    tracing::info!("server updated to v{} — restart to apply", version);
    Ok(())
}

pub async fn installed_sha256() -> Result<Option<String>> {
    let current_exe = std::env::current_exe()?;
    checksum::read_sha256_file(&checksum_path_for(&current_exe)).await
}

fn checksum_path_for(current_exe: &Path) -> PathBuf {
    current_exe.with_extension("sha256")
}

fn current_platform_target() -> &'static str {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    return "x86_64-unknown-linux-musl";
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    return "aarch64-unknown-linux-musl";
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    return "x86_64-apple-darwin";
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    return "aarch64-apple-darwin";
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    return "unknown";
}
