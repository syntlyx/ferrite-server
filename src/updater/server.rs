use std::path::{Path, PathBuf};

use crate::error::{FeriteError, Result};
use crate::updater::checksum;
use crate::updater::github::{
    current_platform_target, fetch_latest_release, resolve_asset_sha256, update_available,
    with_release_auth, HTTP_CLIENT, RELEASE_OWNER, RELEASE_REPO_SERVER,
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
    if !server_self_update_enabled() {
        tracing::debug!("server self-update is disabled by FERRITE_SERVER_SELF_UPDATE");
        return Ok(None);
    }

    let release = match fetch_latest_release(RELEASE_OWNER, RELEASE_REPO_SERVER).await? {
        Some(r) => r,
        None => return Ok(None),
    };

    let latest = release.tag_name.trim_start_matches('v');

    let Some(target) = current_platform_target() else {
        return Ok(None);
    };
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
    let expected_sha256 = require_verified_checksum(info.sha256.as_deref())?;
    let current_exe = std::env::current_exe()?;
    let checksum_path = checksum_path_for(&current_exe);
    let version_path = version_path_for(&current_exe);

    preflight_update_target(&current_exe)?;

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

    checksum::verify_bytes_sha256(&bytes, &expected_sha256, "server update archive")?;

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
                    .map_err(|e| FeriteError::Update(format!("failed to unpack ferrite: {e}")))?;
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
        std::fs::rename(&tmp, &current_exe).map_err(|e| {
            FeriteError::Update(format!("failed to replace {}: {e}", current_exe.display()))
        })?;

        Ok(())
    })
    .await
    .map_err(|e| FeriteError::Internal(e.to_string()))??;

    checksum::write_sha256_file(&checksum_path, &expected_sha256).await?;
    tokio::fs::write(&version_path, format!("{version}\n")).await?;

    tracing::info!("server updated to v{} — restart to apply", version);
    Ok(())
}

pub async fn installed_sha256() -> Result<Option<String>> {
    let current_exe = std::env::current_exe()?;
    checksum::read_sha256_file(&checksum_path_for(&current_exe)).await
}

fn server_self_update_enabled() -> bool {
    let Ok(value) = std::env::var("FERRITE_SERVER_SELF_UPDATE") else {
        return true;
    };
    env_flag_enabled(Some(&value))
}

fn env_flag_enabled(value: Option<&str>) -> bool {
    match value.map(str::trim).filter(|v| !v.is_empty()) {
        Some(value) => !matches!(
            value.to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off" | "disabled"
        ),
        None => true,
    }
}

/// Fail-closed precondition for applying a server update: a verified SHA-256
/// checksum is mandatory. Returns the checksum to verify against, or an error
/// if the release published neither an asset digest nor a `.sha256` sidecar.
fn require_verified_checksum(sha256: Option<&str>) -> Result<String> {
    match sha256.map(str::trim).filter(|s| !s.is_empty()) {
        Some(expected) => Ok(expected.to_string()),
        None => Err(FeriteError::Update(
            "refusing to apply update without a verified SHA-256 checksum".into(),
        )),
    }
}

fn checksum_path_for(current_exe: &Path) -> PathBuf {
    current_exe.with_extension("sha256")
}

fn version_path_for(current_exe: &Path) -> PathBuf {
    current_exe.with_extension("version")
}

fn preflight_update_target(current_exe: &Path) -> Result<()> {
    let parent = current_exe.parent().ok_or_else(|| {
        FeriteError::Update(format!(
            "cannot determine parent directory for {}",
            current_exe.display()
        ))
    })?;
    let probe = parent.join(format!(".ferrite-update-probe-{}", std::process::id()));

    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(file) => {
            drop(file);
            let _ = std::fs::remove_file(&probe);
            Ok(())
        }
        Err(e) => Err(FeriteError::Update(format!(
            "server self-update cannot write to {} ({e}). Install ferrite with a writable service binary path or rerun the installer as root.",
            current_exe.display()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_preflight_allows_writable_executable_directory() {
        let path = crate::test_support::temp_path("server-update-writable", "bin");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();

        preflight_update_target(&path).unwrap();
    }

    #[test]
    fn apply_requires_a_verified_checksum() {
        let err = require_verified_checksum(None).unwrap_err();
        assert!(matches!(err, FeriteError::Update(_)));
        assert!(err
            .to_string()
            .contains("refusing to apply update without a verified SHA-256 checksum"));

        // Blank/whitespace-only values are treated as absent.
        assert!(require_verified_checksum(Some("   ")).is_err());

        // A present checksum is accepted and returned trimmed.
        assert_eq!(
            require_verified_checksum(Some("  abc123  ")).unwrap(),
            "abc123"
        );
    }

    #[test]
    fn server_self_update_flag_defaults_enabled() {
        assert!(env_flag_enabled(None));
        assert!(env_flag_enabled(Some("")));
        assert!(env_flag_enabled(Some("true")));
    }

    #[test]
    fn server_self_update_flag_accepts_common_disabled_values() {
        assert!(!env_flag_enabled(Some("0")));
        assert!(!env_flag_enabled(Some("false")));
        assert!(!env_flag_enabled(Some("off")));
        assert!(!env_flag_enabled(Some("no")));
        assert!(!env_flag_enabled(Some("disabled")));
    }

    #[cfg(unix)]
    #[test]
    fn update_preflight_reports_unwritable_executable_directory_as_update_error() {
        use std::os::unix::fs::PermissionsExt;

        let dir = crate::test_support::temp_path("server-update-readonly", "dir");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        let path = dir.join("ferrite");

        let err = preflight_update_target(&path).unwrap_err();

        assert!(matches!(err, FeriteError::Update(_)));
        assert!(err.to_string().contains("server self-update cannot write"));

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }
}
