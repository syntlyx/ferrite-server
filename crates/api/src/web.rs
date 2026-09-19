use std::path::Path;
use std::time::UNIX_EPOCH;

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, StatusCode, Uri, header},
    response::Response,
};
use tokio::fs;

use ferrite_app::AppState;

/// Axum fallback handler — serves static files from the local web dir.
/// API routes are matched before this, so everything here is UI traffic.
/// Unknown paths fall back to `index.html` for SPA routing.
///
/// Every response carries a validator, and a browser that sends it back gets a
/// 304 with no body and no file read. The panel is polled and reloaded often,
/// and re-sending the same few hundred kilobytes of bundle each time is the
/// most expensive thing this process does for a page that hasn't changed.
pub async fn static_handler(
    uri: Uri,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    let web_dir = state
        .live_config
        .read()
        .web_dir
        .clone()
        .unwrap_or_else(|| ferrite_core::config::data_dir().join("web"));

    let rel = uri.path().trim_start_matches('/');
    let rel = if rel.is_empty() { "index.html" } else { rel };

    // Reject path traversal attempts (e.g. "../../etc/passwd").
    if std::path::Path::new(rel)
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::from("forbidden"))
            .expect("hardcoded response is valid");
    }

    if let Some(response) = serve_file(&web_dir.join(rel), rel, &headers).await {
        return response;
    }
    // SPA fallback: an unknown path is a client-side route, so hand back the
    // shell and let the app router sort it out.
    if let Some(response) = serve_file(&web_dir.join("index.html"), "index.html", &headers).await {
        return response;
    }
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .body(Body::from("Web UI not installed. Run: ferrite update web"))
        .expect("hardcoded response is valid")
}

/// Serve one file with a validator, or `None` if it isn't there.
async fn serve_file(path: &Path, rel: &str, headers: &HeaderMap) -> Option<Response> {
    let meta = fs::metadata(path).await.ok()?;
    if !meta.is_file() {
        return None;
    }
    let etag = etag(&meta);
    let cache_control = cache_control(rel);

    // The browser already has this exact file: say so and send nothing.
    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|sent| sent.split(',').any(|candidate| candidate.trim() == etag))
    {
        return Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header(header::ETAG, &etag)
            .header(header::CACHE_CONTROL, cache_control)
            .body(Body::empty())
            .ok();
    }

    let bytes = fs::read(path).await.ok()?;
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, guess_content_type(rel))
        .header(header::ETAG, &etag)
        .header(header::CACHE_CONTROL, cache_control)
        .body(Body::from(bytes))
        .ok()
}

/// A weak validator built from the file's size and modification time — enough
/// to tell "the same build" from "a new one" without hashing the file on every
/// request. Weak, because a rebuild that lands the same bytes at the same
/// second is indistinguishable, which is exactly what a validator may treat as
/// unchanged.
fn etag(meta: &std::fs::Metadata) -> String {
    let modified = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("W/\"{:x}-{:x}\"", meta.len(), modified)
}

/// How long a browser may keep this file without asking again.
///
/// A bundler names its output after the content it holds (`index-B2f3c4d5.js`),
/// so that file can never change under its name and is cached for a year.
/// Everything else — `index.html` above all — is revalidated on every load, or
/// an updated panel would keep showing the old one until someone cleared their
/// cache.
fn cache_control(rel: &str) -> &'static str {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    let stem = name.rsplit_once('.').map_or(name, |(stem, _)| stem);
    let is_content_addressed = stem.rsplit_once(['-', '.']).is_some_and(|(_, hash)| {
        hash.len() >= 8
            && hash
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c.is_ascii_alphanumeric())
    });
    if is_content_addressed {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    }
}

fn guess_content_type(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "html" | "htm" => "text/html; charset=utf-8",
        "js" | "mjs" => "application/javascript",
        "css" => "text/css",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "map" => "application/json",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_content_addressed_names_are_cached_forever() {
        for immutable in [
            "assets/index-B2f3c4d5.js",
            "assets/index-4a9f0c2e11.css",
            "assets/logo-0011aabbcc.svg",
        ] {
            assert_eq!(
                cache_control(immutable),
                "public, max-age=31536000, immutable",
                "{immutable}"
            );
        }
        // The shell and anything without a content hash must be revalidated, or
        // an updated panel never reaches a browser that has the old one.
        for revalidate in [
            "index.html",
            "favicon.ico",
            "assets/style.css",
            "manifest.json",
            "assets/logo-dark.svg",
        ] {
            assert_eq!(cache_control(revalidate), "no-cache", "{revalidate}");
        }
    }
}
