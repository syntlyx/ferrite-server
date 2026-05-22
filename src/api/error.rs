use axum::{http::StatusCode, response::IntoResponse};

use crate::error::FeriteError;

/// Wrapper that converts `FeriteError` into an appropriate HTTP response.
/// Used as the `E` type in all `Result<Json<_>, ApiError>` handler return types.
#[derive(Debug)]
pub struct ApiError(pub FeriteError);

impl From<FeriteError> for ApiError {
    fn from(e: FeriteError) -> Self {
        ApiError(e)
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(e: serde_json::Error) -> Self {
        ApiError(FeriteError::Json(e))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        use axum::Json;
        use serde_json::json;

        let status = api_error_status(&self.0);
        let kind = api_error_kind(&self.0);
        let code = api_error_code(&self.0);
        let message = self.0.to_string();
        let details = api_error_details(&self.0);

        (
            status,
            Json(json!({
                "error": message,
                "code": code,
                "kind": kind,
                "details": details,
            })),
        )
            .into_response()
    }
}

fn api_error_status(error: &FeriteError) -> StatusCode {
    match error {
        FeriteError::Unauthorized => StatusCode::UNAUTHORIZED,
        FeriteError::Config(_) => StatusCode::BAD_REQUEST,
        FeriteError::NotFound(_) => StatusCode::NOT_FOUND,
        FeriteError::Update(_) => StatusCode::CONFLICT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn api_error_kind(error: &FeriteError) -> &'static str {
    match error {
        FeriteError::Unauthorized => "unauthorized",
        FeriteError::Config(_) => "config",
        FeriteError::NotFound(_) => "not_found",
        FeriteError::Update(_) => "update",
        _ => "internal",
    }
}

fn api_error_code(error: &FeriteError) -> &'static str {
    match error {
        FeriteError::Unauthorized => "unauthorized",
        FeriteError::Config(message) => config_error_code(message),
        FeriteError::NotFound(_) => "not_found",
        FeriteError::Update(message) => update_error_code(message),
        _ => "internal",
    }
}

fn api_error_details(error: &FeriteError) -> String {
    match error {
        FeriteError::Config(message)
        | FeriteError::NotFound(message)
        | FeriteError::Update(message) => message.clone(),
        _ => error.to_string(),
    }
}

fn config_error_code(message: &str) -> &'static str {
    if message == "password cannot be empty; use null to disable password auth" {
        "password_empty"
    } else if message.starts_with("password hash failed:") {
        "password_hash_failed"
    } else if message == "api_key cannot be empty; use null to disable key auth" {
        "api_key_empty"
    } else if message.starts_with("dns_min_ttl must be between") {
        "dns_min_ttl_range"
    } else if message.starts_with("dns_max_ttl must be between") {
        "dns_max_ttl_range"
    } else if message.starts_with("dns_min_ttl (") {
        "dns_ttl_order"
    } else if message.starts_with("invalid dns_bind_addr:") {
        "invalid_dns_bind_addr"
    } else if message == "blocklist_decision_cache_size must be greater than 0" {
        "blocklist_cache_size"
    } else if message.starts_with("invalid api_bind_addr:") {
        "invalid_api_bind_addr"
    } else if message == "upstream list cannot be empty" {
        "upstream_empty"
    } else if message.starts_with("invalid blocklist_client_bypass entry:") {
        "invalid_client_bypass"
    } else if message == "name must not be empty" {
        "client_name_empty"
    } else if message.starts_with("invalid IP:") {
        "invalid_ip"
    } else if message.starts_with("invalid MAC:") {
        "invalid_mac"
    } else if message == "provide exactly one of 'ip' or 'mac'" {
        "client_identity_required"
    } else if message.contains("is neither a valid IP nor a MAC address") {
        "invalid_client_key"
    } else {
        "config"
    }
}

fn update_error_code(message: &str) -> &'static str {
    if message.starts_with("web UI v") && message.contains("requires server") {
        "web_update_incompatible"
    } else {
        "update"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_known_config_errors() {
        assert_eq!(
            api_error_code(&FeriteError::Config(
                "api_key cannot be empty; use null to disable key auth".to_owned()
            )),
            "api_key_empty"
        );
        assert_eq!(
            api_error_code(&FeriteError::Config(
                "provide exactly one of 'ip' or 'mac'".to_owned()
            )),
            "client_identity_required"
        );
        assert_eq!(
            api_error_code(&FeriteError::Config(
                "'not-a-client' is neither a valid IP nor a MAC address".to_owned()
            )),
            "invalid_client_key"
        );
    }

    #[test]
    fn classifies_incompatible_web_update() {
        assert_eq!(
            api_error_code(&FeriteError::Update(
                "web UI v0.2.0 requires server >=0.2.0 <0.3.0".to_owned()
            )),
            "web_update_incompatible"
        );
    }
}
