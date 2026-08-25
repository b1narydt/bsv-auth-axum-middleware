//! Authenticated request extractor for downstream handlers.
//!
//! The `Authenticated` struct is inserted into request extensions by the auth
//! middleware after successful BRC-103/104 signature verification. Handlers extract
//! it via axum's `FromRequestParts` trait.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use bsv::auth::certificates::VerifiableCertificate;

/// Verified identity extracted from BRC-103/104 auth headers.
///
/// Inserted into request extensions by the auth middleware. When
/// `allow_unauthenticated` is true and no auth headers are present,
/// `identity_key` is set to `"unknown"`.
#[derive(Clone, Debug)]
pub struct Authenticated {
    /// Compressed hex public key of the authenticated caller.
    pub identity_key: String,
    /// Validated certificates presented by the caller.
    ///
    /// Populated only when the middleware is certificate-gated (non-empty
    /// `trusted_certifiers`): every certificate here has passed subject-bind,
    /// certifier-PIN, type-PIN, and certifier-signature validation. Empty on
    /// non-cert-gated paths and for `allow_unauthenticated` passthrough.
    pub certificates: Vec<VerifiableCertificate>,
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
