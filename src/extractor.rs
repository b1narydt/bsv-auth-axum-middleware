//! Authenticated request extractor for downstream handlers.
//!
//! The `Authenticated` struct is inserted into request extensions by the auth
//! middleware after successful BRC-31 signature verification. Handlers extract
//! it via axum's `FromRequestParts` trait.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Verified identity extracted from BRC-31 auth headers.
///
/// Inserted into request extensions by the auth middleware. When
/// `allow_unauthenticated` is true and no auth headers are present,
/// `identity_key` is set to `"unknown"`.
#[derive(Clone, Debug)]
pub struct Authenticated {
    /// Compressed hex public key of the authenticated caller.
    pub identity_key: String,
}

impl<S: Send + Sync> FromRequestParts<S> for Authenticated {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Authenticated>()
            .cloned()
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    axum::Json(serde_json::json!({
                        "status": "error",
                        "code": "ERR_NOT_AUTHENTICATED",
                        "description": "Authentication required"
                    })),
                )
                    .into_response()
            })
    }
}
