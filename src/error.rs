//! Error types for the BSV auth middleware.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Unified error type for the BSV authentication middleware.
#[derive(Debug, thiserror::Error)]
pub enum AuthMiddlewareError {
    /// Transport-level error (connection, channel, etc.).
    #[error("transport error: {0}")]
    Transport(String),

    /// Configuration error (missing required fields, invalid values).
    #[error("configuration error: {0}")]
    Config(String),

    /// Payload serialization or deserialization error.
    #[error("payload error: {0}")]
    Payload(String),

    /// Error from the BSV SDK authentication layer.
    #[error("bsv sdk error: {0}")]
    BsvSdk(#[from] bsv::auth::AuthError),

    /// Middleware-level authentication failure.
    #[error("authentication error: {0}")]
    Authentication(String),

    /// Certificate exchange timed out.
    #[error("certificate timeout: {0}")]
    CertificateTimeout(String),
}

impl IntoResponse for AuthMiddlewareError {
    fn into_response(self) -> Response {
        let status = match &self {
            Self::BsvSdk(e) => match e {
                bsv::auth::AuthError::NotAuthenticated(_)
                | bsv::auth::AuthError::AuthFailed(_)
                | bsv::auth::AuthError::InvalidSignature(_) => StatusCode::UNAUTHORIZED,
                bsv::auth::AuthError::Timeout(_) => StatusCode::REQUEST_TIMEOUT,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
            Self::Authentication(_) => StatusCode::UNAUTHORIZED,
            Self::CertificateTimeout(_) => StatusCode::REQUEST_TIMEOUT,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let code = match &self {
            Self::BsvSdk(e) => match e {
                bsv::auth::AuthError::NotAuthenticated(_) => "ERR_NOT_AUTHENTICATED",
                bsv::auth::AuthError::AuthFailed(_) => "ERR_AUTH_FAILED",
                bsv::auth::AuthError::InvalidSignature(_) => "ERR_INVALID_SIGNATURE",
                bsv::auth::AuthError::Timeout(_) => "ERR_TIMEOUT",
                _ => "ERR_BSV_SDK",
            },
            Self::Authentication(_) => "ERR_UNAUTHORIZED",
            Self::CertificateTimeout(_) => "ERR_CERTIFICATE_TIMEOUT",
            Self::Transport(_) => "ERR_TRANSPORT",
            Self::Config(_) => "ERR_CONFIG",
            Self::Payload(_) => "ERR_PAYLOAD",
        };

        let body = serde_json::json!({
            "status": "error",
            "code": code,
            "description": self.to_string()
        });

        (status, axum::Json(body)).into_response()
    }
}
