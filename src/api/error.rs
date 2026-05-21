use axum::response::IntoResponse;

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
        use axum::http::StatusCode;
        use axum::Json;
        use serde_json::json;

        let (status, message) = match &self.0 {
            FeriteError::Unauthorized => (StatusCode::UNAUTHORIZED, self.0.to_string()),
            FeriteError::Config(_) => (StatusCode::BAD_REQUEST, self.0.to_string()),
            FeriteError::NotFound(_) => (StatusCode::NOT_FOUND, self.0.to_string()),
            FeriteError::Update(_) => (StatusCode::CONFLICT, self.0.to_string()),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, self.0.to_string()),
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}
