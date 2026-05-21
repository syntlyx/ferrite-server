use axum::{
    body::Body,
    extract::State,
    http::{header, StatusCode, Uri},
    response::Response,
};
use tokio::fs;

use crate::app::AppState;

/// Axum fallback handler — serves static files from the local web dir.
/// API routes are matched before this, so everything here is UI traffic.
/// Unknown paths fall back to `index.html` for SPA routing.
pub async fn static_handler(uri: Uri, State(state): State<AppState>) -> Response {
    let web_dir = state
        .live_config
        .read()
        .web_dir
        .clone()
        .unwrap_or_else(|| crate::config::data_dir().join("web"));

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

    let file_path = web_dir.join(rel);

    match fs::read(&file_path).await {
        Ok(bytes) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, guess_content_type(rel))
            .body(Body::from(bytes))
            .expect("hardcoded response is valid"),
        Err(_) => {
            // SPA fallback
            let index = web_dir.join("index.html");
            match fs::read(&index).await {
                Ok(bytes) => Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                    .body(Body::from(bytes))
                    .expect("hardcoded response is valid"),
                Err(_) => Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(Body::from("Web UI not installed. Run: ferrite update web"))
                    .expect("hardcoded response is valid"),
            }
        }
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
