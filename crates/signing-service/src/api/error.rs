//! Uniform API error envelope.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use hsm_core::HsmError;
use serde::Serialize;
use tracing::error;

/// Public JSON error body – deliberately minimal to avoid leaking internals.
#[derive(Serialize)]
pub struct ErrorBody {
    error: &'static str,
    message: String,
    request_id: Option<String>,
}

/// Internal API error wrapper.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// Malformed request body / parameters.
    #[error("bad request: {0}")]
    BadRequest(String),

    /// Invalid base64 or similar decode failure.
    #[error("invalid encoding: {0}")]
    InvalidEncoding(String),

    /// Downstream HSM failure.
    #[error(transparent)]
    Hsm(#[from] HsmError),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, kind) = match &self {
            Self::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            Self::InvalidEncoding(_) => (StatusCode::BAD_REQUEST, "invalid_encoding"),
            Self::Hsm(e) => match e {
                HsmError::KeyNotFound(_) => (StatusCode::NOT_FOUND, "key_not_found"),
                HsmError::AlgorithmMismatch { .. } => {
                    (StatusCode::BAD_REQUEST, "algorithm_mismatch")
                }
                HsmError::InvalidInput(_) => (StatusCode::BAD_REQUEST, "invalid_input"),
                HsmError::AuthenticationFailed => (StatusCode::UNAUTHORIZED, "auth_failed"),
                HsmError::PoolExhausted => (StatusCode::SERVICE_UNAVAILABLE, "pool_exhausted"),
                HsmError::Unavailable(_) => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
                HsmError::Backend(_) => {
                    error!(error = ?e, "unexpected HSM backend failure");
                    (StatusCode::INTERNAL_SERVER_ERROR, "internal")
                }
            },
        };
        // Public message: for 5xx, mask the detail.
        let message = if status.is_server_error() {
            "internal error".to_owned()
        } else {
            self.to_string()
        };
        let body = ErrorBody {
            error: kind,
            message,
            request_id: None,
        };
        (status, Json(body)).into_response()
    }
}
