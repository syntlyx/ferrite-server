use std::path::Path;

use crate::error::{FeriteError, Result};

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    to_lower_hex(digest.as_ref())
}

pub fn normalize_sha256(input: &str) -> Option<String> {
    input
        .split(|c: char| !c.is_ascii_hexdigit())
        .find(|part| part.len() == 64 && part.chars().all(|c| c.is_ascii_hexdigit()))
        .map(str::to_ascii_lowercase)
}

pub fn verify_bytes_sha256(bytes: &[u8], expected: &str, label: &str) -> Result<()> {
    let expected = normalize_sha256(expected).ok_or_else(|| {
        FeriteError::Update(format!("invalid SHA256 value for {label}: {expected}"))
    })?;
    let actual = sha256_hex(bytes);

    if actual != expected {
        return Err(FeriteError::Update(format!(
            "{label} checksum mismatch: expected {expected}, got {actual}"
        )));
    }

    Ok(())
}

pub async fn read_sha256_file(path: &Path) -> Result<Option<String>> {
    match tokio::fs::read_to_string(path).await {
        Ok(raw) => Ok(normalize_sha256(&raw)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub async fn write_sha256_file(path: &Path, sha256: &str) -> Result<()> {
    let sha256 = normalize_sha256(sha256).ok_or_else(|| {
        FeriteError::Update(format!(
            "refusing to persist invalid SHA256 value at {}",
            path.display()
        ))
    })?;
    tokio::fs::write(path, format!("{sha256}\n")).await?;
    Ok(())
}

pub async fn remove_file_if_exists(path: &Path) -> Result<()> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn to_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_standard_sha256sum_output() {
        let raw =
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855  ferrite.tar.gz";

        assert_eq!(
            normalize_sha256(raw).as_deref(),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
    }

    #[test]
    fn normalizes_github_asset_digest_output() {
        let raw = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        assert_eq!(
            normalize_sha256(raw).as_deref(),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
    }

    #[test]
    fn verifies_download_bytes_against_expected_sha256() {
        let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

        verify_bytes_sha256(b"hello", expected, "fixture").unwrap();
        assert!(verify_bytes_sha256(b"goodbye", expected, "fixture").is_err());
    }

    #[tokio::test]
    async fn sha256_sidecar_round_trips_and_removes_cleanly() {
        let path = temp_path("sidecar");
        let sha = "SHA256:2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824";

        assert_eq!(read_sha256_file(&path).await.unwrap(), None);

        write_sha256_file(&path, sha).await.unwrap();
        assert_eq!(
            read_sha256_file(&path).await.unwrap().as_deref(),
            Some("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        );

        remove_file_if_exists(&path).await.unwrap();
        remove_file_if_exists(&path).await.unwrap();
        assert_eq!(read_sha256_file(&path).await.unwrap(), None);
    }

    #[tokio::test]
    async fn refusing_invalid_sidecar_value_does_not_create_file() {
        let path = temp_path("invalid-sidecar");

        assert!(
            write_sha256_file(&path, "definitely-not-a-sha")
                .await
                .is_err()
        );
        assert_eq!(read_sha256_file(&path).await.unwrap(), None);
    }

    fn temp_path(name: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "ferrite-checksum-{name}-{}-{nanos}.sha256",
            std::process::id()
        ))
    }
}
