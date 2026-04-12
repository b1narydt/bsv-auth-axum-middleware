//! Error types for the BSV auth middleware.
//!
//! Defines `AuthMiddlewareError` with variants for transport, configuration,
//! payload, and BSV SDK errors. Implements `axum::response::IntoResponse` for
//! automatic HTTP response conversion with JSON error bodies matching the
//! TypeScript `auth-express-middleware` wire format exactly.
//!
//! Wire-contract notes (TS parity):
//! - 401 missing/invalid auth headers: `{"status":"error","code":"UNAUTHORIZED",
//!   "message":"Mutual-authentication failed!"}`
//! - 408 certificate request timeout: `{"status":"error","code":"CERTIFICATE_TIMEOUT",
//!   "message":"Certificate request timed out"}`
//! - 500 response signing failure: `{"status":"error","code":"ERR_RESPONSE_SIGNING_FAILED",
//!   "description":"<reason>"}` (TS uses `description` for this variant only)

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

    /// Middleware-level auth failure: request lacked valid auth headers when
    /// allow_unauthenticated=false. Emits TS body
    /// `{"code":"UNAUTHORIZED","message":"Mutual-authentication failed!"}`.
    #[error("Mutual-authentication failed!")]
    Unauthorized,

    /// Certificate exchange timed out. Emits
    /// `{"code":"CERTIFICATE_TIMEOUT","message":"Certificate request timed out"}`.
    #[error("Certificate request timed out")]
    CertificateTimeout,

    /// Response signing failed during general-message flow. Emits
    /// `{"code":"ERR_RESPONSE_SIGNING_FAILED","description":"<reason>"}`.
    #[error("{0}")]
    ResponseSigningFailed(String),
}

impl axum::response::IntoResponse for AuthMiddlewareError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;

        // Variants that diverge from the standard {status,code,description}
        // shape are emitted explicitly to match TS byte-for-byte.
        match &self {
            AuthMiddlewareError::Unauthorized => {
                return (
                    StatusCode::UNAUTHORIZED,
                    axum::Json(serde_json::json!({
                        "status": "error",
                        "code": "UNAUTHORIZED",
                        "message": "Mutual-authentication failed!",
                    })),
                )
                    .into_response();
            }
            AuthMiddlewareError::CertificateTimeout => {
                return (
                    StatusCode::REQUEST_TIMEOUT,
                    axum::Json(serde_json::json!({
                        "status": "error",
                        "code": "CERTIFICATE_TIMEOUT",
                        "message": "Certificate request timed out",
                    })),
                )
                    .into_response();
            }
            AuthMiddlewareError::ResponseSigningFailed(reason) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    axum::Json(serde_json::json!({
                        "status": "error",
                        "code": "ERR_RESPONSE_SIGNING_FAILED",
                        "description": reason,
                    })),
                )
                    .into_response();
            }
            _ => {}
        }

        let status = match &self {
            AuthMiddlewareError::BsvSdk(e) => match e {
                bsv::auth::AuthError::NotAuthenticated(_)
                | bsv::auth::AuthError::AuthFailed(_)
                | bsv::auth::AuthError::InvalidSignature(_) => StatusCode::UNAUTHORIZED,
                bsv::auth::AuthError::Timeout(_) => StatusCode::REQUEST_TIMEOUT,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let code = match &self {
            AuthMiddlewareError::BsvSdk(e) => match e {
                bsv::auth::AuthError::NotAuthenticated(_) => "ERR_NOT_AUTHENTICATED",
                bsv::auth::AuthError::AuthFailed(_) => "ERR_AUTH_FAILED",
                bsv::auth::AuthError::InvalidSignature(_) => "ERR_INVALID_SIGNATURE",
                bsv::auth::AuthError::Timeout(_) => "ERR_TIMEOUT",
                _ => "ERR_INTERNAL_SERVER_ERROR",
            },
            AuthMiddlewareError::Transport(_) => "ERR_TRANSPORT",
            AuthMiddlewareError::Config(_) => "ERR_CONFIG",
            AuthMiddlewareError::Payload(_) => "ERR_PAYLOAD",
            AuthMiddlewareError::Unauthorized
            | AuthMiddlewareError::CertificateTimeout
            | AuthMiddlewareError::ResponseSigningFailed(_) => {
                unreachable!("handled in match above")
            }
        };

        (
            status,
            axum::Json(serde_json::json!({
                "status": "error",
                "code": code,
                "description": self.to_string(),
            })),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_display() {
        let err = AuthMiddlewareError::Transport("msg".to_string());
        assert_eq!(err.to_string(), "transport error: msg");
    }

    #[test]
    fn test_config_display() {
        let err = AuthMiddlewareError::Config("msg".to_string());
        assert_eq!(err.to_string(), "configuration error: msg");
    }

    #[test]
    fn test_payload_display() {
        let err = AuthMiddlewareError::Payload("msg".to_string());
        assert_eq!(err.to_string(), "payload error: msg");
    }

    #[test]
    fn test_from_bsv_auth_error() {
        let auth_err = bsv::auth::AuthError::AuthFailed("bad".to_string());
        let err: AuthMiddlewareError = auth_err.into();
        match err {
            AuthMiddlewareError::BsvSdk(_) => {}
            _ => panic!("expected BsvSdk variant"),
        }
    }

    #[tokio::test]
    async fn test_unauthorized_error_response_matches_ts_spec() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let err = AuthMiddlewareError::Unauthorized;
        let resp = err.into_response();
        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);

        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["status"], "error");
        assert_eq!(json["code"], "UNAUTHORIZED");
        assert_eq!(json["message"], "Mutual-authentication failed!");
        assert!(json.get("description").is_none());
    }

    #[tokio::test]
    async fn test_certificate_timeout_error_response_matches_ts_spec() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let err = AuthMiddlewareError::CertificateTimeout;
        let resp = err.into_response();
        assert_eq!(resp.status(), http::StatusCode::REQUEST_TIMEOUT);

        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["status"], "error");
        assert_eq!(json["code"], "CERTIFICATE_TIMEOUT");
        assert_eq!(json["message"], "Certificate request timed out");
        assert!(json.get("description").is_none());
    }

    #[tokio::test]
    async fn test_response_signing_failed_error_response_matches_ts_spec() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let err = AuthMiddlewareError::ResponseSigningFailed("wallet HSM offline".to_string());
        let resp = err.into_response();
        assert_eq!(resp.status(), http::StatusCode::INTERNAL_SERVER_ERROR);

        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["status"], "error");
        assert_eq!(json["code"], "ERR_RESPONSE_SIGNING_FAILED");
        assert_eq!(json["description"], "wallet HSM offline");
        assert!(json.get("message").is_none());
    }

    #[test]
    fn test_unauthorized_display() {
        let err = AuthMiddlewareError::Unauthorized;
        assert_eq!(err.to_string(), "Mutual-authentication failed!");
    }

    #[test]
    fn test_certificate_timeout_display() {
        let err = AuthMiddlewareError::CertificateTimeout;
        assert_eq!(err.to_string(), "Certificate request timed out");
    }

    #[test]
    fn test_response_signing_failed_display_is_inner_reason() {
        let err = AuthMiddlewareError::ResponseSigningFailed("boom".to_string());
        assert_eq!(err.to_string(), "boom");
    }

    #[tokio::test]
    async fn test_error_response_body_format_transport() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let err = AuthMiddlewareError::Transport("connection refused".to_string());
        let resp = err.into_response();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["status"], "error");
        assert_eq!(json["code"], "ERR_TRANSPORT");
        assert_eq!(json["description"], "transport error: connection refused");
    }

    #[tokio::test]
    async fn test_error_response_body_format_not_authenticated() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let err = AuthMiddlewareError::BsvSdk(bsv::auth::AuthError::NotAuthenticated(
            "no session".to_string(),
        ));
        let resp = err.into_response();
        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);

        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["status"], "error");
        assert_eq!(json["code"], "ERR_NOT_AUTHENTICATED");
        assert_eq!(
            json["description"],
            "bsv sdk error: not authenticated: no session"
        );
    }

    #[tokio::test]
    async fn test_error_response_body_format_config() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let err = AuthMiddlewareError::Config("wallet is required".to_string());
        let resp = err.into_response();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["status"], "error");
        assert_eq!(json["code"], "ERR_CONFIG");
        assert_eq!(
            json["description"],
            "configuration error: wallet is required"
        );
    }

    #[tokio::test]
    async fn test_error_response_body_format_payload() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let err = AuthMiddlewareError::Payload("invalid bytes".to_string());
        let resp = err.into_response();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["status"], "error");
        assert_eq!(json["code"], "ERR_PAYLOAD");
        assert_eq!(json["description"], "payload error: invalid bytes");
    }
}
