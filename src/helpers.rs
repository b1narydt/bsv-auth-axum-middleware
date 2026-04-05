//! Helper functions for the BRC-31 auth middleware.
//!
//! Provides header extraction, body reading, and AuthMessage construction
//! utilities that the middleware will call.

use axum::http::HeaderMap;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use bsv::auth::types::{AuthMessage, MessageType};

/// All six `x-bsv-auth-*` headers extracted from a request.
#[derive(Clone, Debug)]
pub struct AuthHeaders {
    /// Protocol version (e.g. "0.1").
    pub version: String,
    /// Compressed hex public key of the sender.
    pub identity_key: String,
    /// Base64-encoded nonce created by the sender.
    pub nonce: String,
    /// The other party's nonce (echoed back).
    pub your_nonce: String,
    /// Hex-encoded ECDSA signature over the message.
    pub signature: String,
    /// Base64-encoded request nonce bytes.
    pub request_id: String,
}

/// Extract all six `x-bsv-auth-*` headers from request headers.
///
/// Returns `None` if ANY of the six headers is missing or contains
/// non-ASCII characters.
pub fn extract_auth_headers(headers: &HeaderMap) -> Option<AuthHeaders> {
    let version = headers
        .get("x-bsv-auth-version")?
        .to_str()
        .ok()?
        .to_string();
    let identity_key = headers
        .get("x-bsv-auth-identity-key")?
        .to_str()
        .ok()?
        .to_string();
    let nonce = headers
        .get("x-bsv-auth-nonce")?
        .to_str()
        .ok()?
        .to_string();
    let your_nonce = headers
        .get("x-bsv-auth-your-nonce")?
        .to_str()
        .ok()?
        .to_string();
    let signature = headers
        .get("x-bsv-auth-signature")?
        .to_str()
        .ok()?
        .to_string();
    let request_id = headers
        .get("x-bsv-auth-request-id")?
        .to_str()
        .ok()?
        .to_string();

    Some(AuthHeaders {
        version,
        identity_key,
        nonce,
        your_nonce,
        signature,
        request_id,
    })
}

/// Construct an `AuthMessage` from request details, body bytes, and extracted headers.
///
/// Decodes the base64 request ID to raw nonce bytes, serializes the request
/// payload via `payload::serialize_request_payload`, decodes the hex
/// signature, and assembles the `AuthMessage`.
pub fn build_auth_message(
    method: &str,
    path: &str,
    query: &str,
    all_headers: &[(String, String)],
    body_bytes: &[u8],
    auth_hdrs: &AuthHeaders,
) -> AuthMessage {
    let request_nonce_bytes = BASE64.decode(&auth_hdrs.request_id).unwrap_or_default();

    let filtered_headers = crate::payload::filter_and_sort_request_headers(all_headers);

    let payload = crate::payload::serialize_request_payload(
        &request_nonce_bytes,
        method,
        path,
        query,
        &filtered_headers,
        if body_bytes.is_empty() {
            None
        } else {
            Some(body_bytes)
        },
    );

    tracing::debug!(
        "build_auth_message: method={} path={} query={} body_len={} payload_len={}",
        method,
        path,
        query,
        body_bytes.len(),
        payload.len(),
    );

    let signature_bytes = hex::decode(&auth_hdrs.signature).unwrap_or_default();

    AuthMessage {
        version: auth_hdrs.version.clone(),
        message_type: MessageType::General,
        identity_key: auth_hdrs.identity_key.clone(),
        nonce: Some(auth_hdrs.nonce.clone()),
        your_nonce: Some(auth_hdrs.your_nonce.clone()),
        initial_nonce: None,
        certificates: None,
        requested_certificates: None,
        payload: Some(payload),
        signature: Some(signature_bytes),
    }
}
