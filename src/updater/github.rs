use reqwest::{redirect::Policy, Client, RequestBuilder};
use serde::Deserialize;

use crate::error::{FeriteError, Result};
use crate::updater::checksum;

pub const RELEASE_API_BASE: &str = "https://api.github.com";
pub const RELEASE_OWNER: &str = "syntlyx";
pub const RELEASE_REPO_SERVER: &str = "ferrite-server";
pub const RELEASE_REPO_WEB: &str = "ferrite-web";

pub static HTTP_CLIENT: std::sync::LazyLock<Client> = std::sync::LazyLock::new(|| {
    Client::builder()
        .user_agent(concat!("ferrite/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .expect("failed to build updater HTTP client")
});

static NO_REDIRECT_HTTP_CLIENT: std::sync::LazyLock<Client> = std::sync::LazyLock::new(|| {
    Client::builder()
        .user_agent(concat!("ferrite/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(30))
        .redirect(Policy::none())
        .build()
        .expect("failed to build updater HTTP client")
});

pub fn with_release_auth(request: RequestBuilder) -> RequestBuilder {
    let token = std::env::var("FERRITE_RELEASE_TOKEN")
        .or_else(|_| std::env::var("GITHUB_TOKEN"))
        .or_else(|_| std::env::var("GITEA_TOKEN"));

    match token {
        Ok(token) if !token.trim().is_empty() => {
            request.header("authorization", format!("Bearer {}", token.trim()))
        }
        _ => request,
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct Release {
    pub tag_name: String,
    pub body: Option<String>,
    pub assets: Vec<ReleaseAsset>,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub prerelease: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ReleaseAsset {
    pub name: String,
    pub browser_download_url: String,
    pub digest: Option<String>,
}

pub fn parse_semver(v: &str) -> (u32, u32, u32) {
    let v = v.trim_start_matches('v');
    let mut parts = v.splitn(3, '.').map(|s| s.parse::<u32>().unwrap_or(0));
    (
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    )
}

pub fn update_available(
    latest_version: &str,
    current_version: &str,
    latest_sha256: Option<&str>,
    installed_sha256: Option<&str>,
) -> bool {
    let version_newer = parse_semver(latest_version) > parse_semver(current_version);
    let checksum_changed = match (latest_sha256, installed_sha256) {
        (Some(latest), Some(current)) => latest != current,
        (Some(_), None) => true,
        _ => false,
    };

    version_newer || checksum_changed
}

/// Fetch recent releases for the given GitHub repo. Returns an empty list if no releases exist.
pub async fn fetch_releases(owner: &str, repo: &str, limit: usize) -> Result<Vec<Release>> {
    let per_page = limit.clamp(1, 100);
    let url = format!(
        "{}/repos/{}/{}/releases?per_page={}",
        RELEASE_API_BASE.trim_end_matches('/'),
        owner,
        repo,
        per_page
    );

    let resp = with_release_auth(
        HTTP_CLIENT
            .get(&url)
            .header("accept", "application/vnd.github+json")
            .header("x-github-api-version", "2022-11-28"),
    )
    .send()
    .await
    .map_err(FeriteError::Http)?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(Vec::new());
    }

    if is_rate_limited(resp.status()) {
        tracing::warn!(
            "GitHub release API is rate limited for {}/{}; falling back to latest release only",
            owner,
            repo
        );
        return Ok(fetch_latest_release(owner, repo)
            .await?
            .into_iter()
            .collect());
    }

    resp.error_for_status()
        .map_err(FeriteError::Http)?
        .json()
        .await
        .map_err(FeriteError::Http)
}

/// Fetch the latest release for the given GitHub repo. Returns `None` if no releases exist.
pub async fn fetch_latest_release(owner: &str, repo: &str) -> Result<Option<Release>> {
    let url = format!(
        "{}/repos/{}/{}/releases/latest",
        RELEASE_API_BASE.trim_end_matches('/'),
        owner,
        repo
    );

    let resp = with_release_auth(
        HTTP_CLIENT
            .get(&url)
            .header("accept", "application/vnd.github+json")
            .header("x-github-api-version", "2022-11-28"),
    )
    .send()
    .await
    .map_err(FeriteError::Http)?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }

    if is_rate_limited(resp.status()) {
        tracing::warn!(
            "GitHub release API is rate limited for {}/{}; falling back to release download URLs",
            owner,
            repo
        );
        return fetch_latest_release_from_downloads(owner, repo).await;
    }

    let release: Release = resp
        .error_for_status()
        .map_err(FeriteError::Http)?
        .json()
        .await
        .map_err(FeriteError::Http)?;

    Ok(Some(release))
}

async fn fetch_latest_release_from_downloads(owner: &str, repo: &str) -> Result<Option<Release>> {
    let Some(tag) = fetch_latest_release_tag(owner, repo).await? else {
        return Ok(None);
    };
    let Some(asset_name) = fallback_asset_name(repo, &tag) else {
        return Ok(None);
    };

    let base = format!(
        "https://github.com/{owner}/{repo}/releases/download/{tag}/{asset_name}",
        owner = owner,
        repo = repo,
        tag = tag,
        asset_name = asset_name
    );

    Ok(Some(Release {
        tag_name: tag,
        body: None,
        draft: false,
        prerelease: false,
        assets: vec![
            ReleaseAsset {
                name: asset_name.clone(),
                browser_download_url: base.clone(),
                digest: None,
            },
            ReleaseAsset {
                name: format!("{asset_name}.sha256"),
                browser_download_url: format!("{base}.sha256"),
                digest: None,
            },
        ],
    }))
}

pub async fn fetch_asset_text(release: &Release, asset_name: &str) -> Result<Option<String>> {
    let Some(asset) = release.assets.iter().find(|a| a.name == asset_name) else {
        return Ok(None);
    };

    let resp = with_release_auth(HTTP_CLIENT.get(&asset.browser_download_url))
        .send()
        .await
        .map_err(FeriteError::Http)?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }

    resp.error_for_status()
        .map_err(FeriteError::Http)?
        .text()
        .await
        .map(Some)
        .map_err(FeriteError::Http)
}

async fn fetch_latest_release_tag(owner: &str, repo: &str) -> Result<Option<String>> {
    let url = format!("https://github.com/{owner}/{repo}/releases/latest");
    let resp = with_release_auth(NO_REDIRECT_HTTP_CLIENT.get(&url))
        .send()
        .await
        .map_err(FeriteError::Http)?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }

    if !resp.status().is_redirection() {
        return Err(FeriteError::Update(format!(
            "GitHub latest release redirect for {owner}/{repo} returned {}",
            resp.status()
        )));
    }

    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            FeriteError::Update(format!(
                "GitHub latest release redirect for {owner}/{repo} did not include Location"
            ))
        })?;

    latest_tag_from_location(location).ok_or_else(|| {
        FeriteError::Update(format!(
            "GitHub latest release redirect for {owner}/{repo} had an unexpected Location: {location}"
        ))
    }).map(Some)
}

fn latest_tag_from_location(location: &str) -> Option<String> {
    let path = location.split('?').next().unwrap_or(location);
    let marker = "/releases/tag/";
    let tag = path.split(marker).nth(1)?.trim_matches('/');
    (!tag.is_empty()).then(|| tag.to_string())
}

fn fallback_asset_name(repo: &str, tag: &str) -> Option<String> {
    if repo == RELEASE_REPO_SERVER {
        return current_platform_target().map(|target| format!("ferrite-{tag}-{target}.tar.gz"));
    }

    if repo == RELEASE_REPO_WEB {
        return Some("dist.tar.gz".to_string());
    }

    None
}

fn is_rate_limited(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::FORBIDDEN || status == reqwest::StatusCode::TOO_MANY_REQUESTS
}

pub fn current_platform_target() -> Option<&'static str> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    return Some("x86_64-unknown-linux-musl");
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    return Some("aarch64-unknown-linux-musl");
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    return Some("x86_64-apple-darwin");
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    return Some("aarch64-apple-darwin");
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    return None;
}

pub async fn resolve_asset_sha256(
    release: &Release,
    asset: &ReleaseAsset,
) -> Result<Option<String>> {
    if let Some(digest) = asset.digest.as_deref() {
        let sha256 = checksum::normalize_sha256(digest).ok_or_else(|| {
            FeriteError::Update(format!(
                "release asset {} has an invalid digest value: {}",
                asset.name, digest
            ))
        })?;
        return Ok(Some(sha256));
    }

    let checksum_name = format!("{}.sha256", asset.name);
    let Some(asset) = release.assets.iter().find(|a| a.name == checksum_name) else {
        return Ok(None);
    };

    let resp = with_release_auth(HTTP_CLIENT.get(&asset.browser_download_url))
        .send()
        .await
        .map_err(FeriteError::Http)?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }

    let text = resp
        .error_for_status()
        .map_err(FeriteError::Http)?
        .text()
        .await
        .map_err(FeriteError::Http)?;

    checksum::normalize_sha256(&text)
        .ok_or_else(|| {
            FeriteError::Update(format!(
                "checksum asset {} does not contain a valid SHA256",
                asset.name
            ))
        })
        .map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn release_with_assets(assets: Vec<ReleaseAsset>) -> Release {
        Release {
            tag_name: "v0.1.0".to_string(),
            body: None,
            draft: false,
            prerelease: false,
            assets,
        }
    }

    fn asset(name: &str, digest: Option<&str>) -> ReleaseAsset {
        ReleaseAsset {
            name: name.to_string(),
            browser_download_url: format!("https://example.test/{name}"),
            digest: digest.map(str::to_string),
        }
    }

    #[test]
    fn parses_latest_release_redirect_location() {
        assert_eq!(
            latest_tag_from_location(
                "https://github.com/syntlyx/ferrite-server/releases/tag/v0.1.0"
            )
            .as_deref(),
            Some("v0.1.0")
        );
        assert_eq!(
            latest_tag_from_location("/syntlyx/ferrite-server/releases/tag/v0.1.1").as_deref(),
            Some("v0.1.1")
        );
        assert!(latest_tag_from_location("/syntlyx/ferrite-server/releases").is_none());
    }

    #[test]
    fn builds_known_fallback_asset_names() {
        let server = fallback_asset_name(RELEASE_REPO_SERVER, "v0.1.0").unwrap();
        assert!(server.starts_with("ferrite-v0.1.0-"));
        assert!(server.ends_with(".tar.gz"));

        assert_eq!(
            fallback_asset_name(RELEASE_REPO_WEB, "v0.1.0").as_deref(),
            Some("dist.tar.gz")
        );
        assert!(fallback_asset_name("unknown", "v0.1.0").is_none());
    }

    #[test]
    fn update_available_when_same_version_has_different_checksum() {
        assert!(update_available("0.1.0", "0.1.0", Some(SHA_A), Some(SHA_B)));
    }

    #[test]
    fn update_not_available_when_version_and_checksum_match() {
        assert!(!update_available(
            "0.1.0",
            "0.1.0",
            Some(SHA_A),
            Some(SHA_A)
        ));
    }

    #[test]
    fn update_available_when_newer_version_has_no_installed_checksum() {
        assert!(update_available("0.1.1", "0.1.0", Some(SHA_A), None));
    }

    #[test]
    fn update_falls_back_to_version_when_digest_is_missing() {
        assert!(!update_available("0.1.0", "0.1.0", None, Some(SHA_A)));
        assert!(update_available("0.1.1", "0.1.0", None, Some(SHA_A)));
    }

    #[tokio::test]
    async fn resolves_github_asset_digest_without_checksum_asset() {
        let release =
            release_with_assets(vec![asset("dist.tar.gz", Some(&format!("sha256:{SHA_A}")))]);
        let result = resolve_asset_sha256(&release, &release.assets[0])
            .await
            .unwrap();

        assert_eq!(result.as_deref(), Some(SHA_A));
    }

    #[tokio::test]
    async fn invalid_github_asset_digest_is_an_error() {
        let release = release_with_assets(vec![asset("dist.tar.gz", Some("sha256:not-a-sha"))]);
        let err = resolve_asset_sha256(&release, &release.assets[0])
            .await
            .unwrap_err();

        assert!(err.to_string().contains("invalid digest"));
    }

    #[tokio::test]
    async fn missing_digest_and_checksum_asset_returns_none() {
        let release = release_with_assets(vec![asset("dist.tar.gz", None)]);
        let result = resolve_asset_sha256(&release, &release.assets[0])
            .await
            .unwrap();

        assert!(result.is_none());
    }
}
