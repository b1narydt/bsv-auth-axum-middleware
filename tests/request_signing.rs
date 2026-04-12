//! Authenticated request round-trip integration tests.
//!
//! These tests exercise the middleware's "Branch 2" path
//! (authenticated request) in `src/middleware.rs` end-to-end:
//! handshake + signed request + response signing. They assert that
//! - the full `AuthFetch` round-trip works for GET and POST-with-JSON-body,
//! - the `Authenticated` extractor delivers the correct client identity to
//!   the handler (not a placeholder),
//! - the middleware's body re-injection path preserves the exact request
//!   body bytes when the handler extracts via `Json<T>`,
//! - unsigned requests are rejected with 401 when `allow_unauthenticated=false`,
//! - unsigned requests pass through with identity `"unknown"` when
//!   `allow_unauthenticated=true`.

mod common;

use std::collections::HashMap;

use bsv::auth::clients::AuthFetch;
use bsv::primitives::private_key::PrivateKey;

use common::test_server::{spawn_test_server, TestServerConfig, TestWallet};

/// Test 1 — full GET round-trip via AuthFetch.
#[tokio::test(flavor = "multi_thread")]
async fn test_authenticated_get_round_trip() {
    let server = spawn_test_server(TestServerConfig::default()).await;

    let client_wallet = TestWallet::new(PrivateKey::from_random().expect("gen client key"));
    let mut auth_fetch = AuthFetch::new(client_wallet);

    let url = format!("{}/other-endpoint", server.base_url);
    let response = auth_fetch
        .fetch(&url, "GET", None, None)
        .await
        .expect("GET /other-endpoint");

    assert_eq!(response.status, 200, "expected 200");
    assert_eq!(
        String::from_utf8_lossy(&response.body),
        "This is another endpoint.",
        "body should match handler output"
    );
}

/// Test 2 — POST with a JSON body, handler extracts via `Json<T>`.
///
/// This proves the middleware's body re-injection path delivers the exact
/// request bytes to `inner.call(request)` in middleware.rs:229. If the
/// middleware mutated or truncated the body during `handle_response_signing`'s
/// buffering path, `Json<EchoPayload>` would return 422 and the test would
/// fail.
#[tokio::test(flavor = "multi_thread")]
async fn test_authenticated_post_json_body_preserved() {
    let server = spawn_test_server(TestServerConfig::default()).await;

    let client_wallet = TestWallet::new(PrivateKey::from_random().expect("gen client key"));
    let mut auth_fetch = AuthFetch::new(client_wallet);

    let payload = b"{\"value\":\"axum-parity\"}".to_vec();
    let headers = HashMap::from([("content-type".to_string(), "application/json".to_string())]);

    let url = format!("{}/json-echo", server.base_url);
    let response = auth_fetch
        .fetch(&url, "POST", Some(payload), Some(headers))
        .await
        .expect("POST /json-echo");

    assert_eq!(
        response.status, 200,
        "handler should accept the round-tripped body"
    );
    let echoed: serde_json::Value =
        serde_json::from_slice(&response.body).expect("parse echoed JSON");
    assert_eq!(
        echoed["value"], "axum-parity",
        "echoed value must equal the value the client sent"
    );
}

/// Test 3 — POST with a generic (non-JSON) body still round-trips.
///
/// Confirms the middleware handles POST bodies that aren't extracted via
/// `Json<T>`. Uses `/other-endpoint`'s POST handler which takes
/// `axum::body::Bytes`.
#[tokio::test(flavor = "multi_thread")]
async fn test_authenticated_post_bytes_round_trip() {
    let server = spawn_test_server(TestServerConfig::default()).await;

    let client_wallet = TestWallet::new(PrivateKey::from_random().expect("gen client key"));
    let mut auth_fetch = AuthFetch::new(client_wallet);

    let payload = b"Hello from binary!".to_vec();
    let headers = HashMap::from([(
        "content-type".to_string(),
        "application/octet-stream".to_string(),
    )]);

    let url = format!("{}/other-endpoint", server.base_url);
    let response = auth_fetch
        .fetch(&url, "POST", Some(payload), Some(headers))
        .await
        .expect("POST /other-endpoint");

    assert_eq!(response.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&response.body).expect("parse body");
    assert_eq!(body["message"], "This is another endpoint.");
}

/// Test 4 — unsigned request with `allow_unauthenticated=false` yields 401.
///
/// An unauthenticated reqwest GET hits Branch 3 in `AuthService::call` and
/// must return a structured 401 JSON error matching middleware.rs:247-256.
#[tokio::test(flavor = "multi_thread")]
async fn test_missing_headers_returns_401() {
    let server = spawn_test_server(TestServerConfig::default()).await;

    let http = reqwest::Client::new();
    let url = format!("{}/", server.base_url);

    let resp = http.get(&url).send().await.expect("unauthenticated GET /");

    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    let body: serde_json::Value = resp.json().await.expect("parse error JSON");
    assert_eq!(body["status"], "error");
    assert_eq!(body["code"], "ERR_UNAUTHORIZED");
    assert!(body.get("description").is_some());
}

/// Test 5 — `allow_unauthenticated=true` passes through with identity
/// `"unknown"` and the handler runs.
#[tokio::test(flavor = "multi_thread")]
async fn test_allow_unauthenticated_passthrough() {
    let server = spawn_test_server(TestServerConfig {
        allow_unauthenticated: true,
    })
    .await;

    let http = reqwest::Client::new();
    let url = format!("{}/identity-echo", server.base_url);

    let resp = http
        .get(&url)
        .send()
        .await
        .expect("unauthenticated GET /identity-echo");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "allow_unauthenticated should let the handler run"
    );
    let body: serde_json::Value = resp.json().await.expect("parse handler JSON");
    assert_eq!(
        body["identity_key"], "unknown",
        "Authenticated extractor should see identity \"unknown\""
    );
}

/// Test 6 — `Authenticated` extractor exposes the client's real identity key
/// when the request is authenticated.
#[tokio::test(flavor = "multi_thread")]
async fn test_extractor_exposes_identity_key_to_handler() {
    let server = spawn_test_server(TestServerConfig::default()).await;

    let client_key = PrivateKey::from_random().expect("gen client key");
    let client_wallet = TestWallet::new(client_key);
    let client_identity_hex = client_wallet.identity_key_hex().await;
    let mut auth_fetch = AuthFetch::new(client_wallet);

    let url = format!("{}/identity-echo", server.base_url);
    let response = auth_fetch
        .fetch(&url, "GET", None, None)
        .await
        .expect("GET /identity-echo");

    assert_eq!(response.status, 200);
    let body: serde_json::Value =
        serde_json::from_slice(&response.body).expect("parse identity-echo body");
    assert_eq!(
        body["identity_key"], client_identity_hex,
        "handler should see the client's real identity key, not a placeholder"
    );
}

/// Test 7 — handler returning 500 still has its response signed.
///
/// The middleware's response-signing path runs regardless of the handler's
/// status code, so an error response should still carry the six x-bsv-auth-*
/// headers on the final HTTP response.
#[tokio::test(flavor = "multi_thread")]
async fn test_error_500_response_is_still_signed() {
    let server = spawn_test_server(TestServerConfig::default()).await;

    let client_wallet = TestWallet::new(PrivateKey::from_random().expect("gen client key"));
    let mut auth_fetch = AuthFetch::new(client_wallet);

    let url = format!("{}/error-500", server.base_url);
    let payload = b"{}".to_vec();
    let headers = HashMap::from([("content-type".to_string(), "application/json".to_string())]);

    let response = auth_fetch
        .fetch(&url, "POST", Some(payload), Some(headers))
        .await
        .expect("POST /error-500 should succeed even at HTTP 500");

    assert_eq!(response.status, 500);
    let body: serde_json::Value =
        serde_json::from_slice(&response.body).expect("parse error-500 body");
    assert_eq!(body["code"], "ERR_BAD_THING");
    assert_eq!(body["status"], "error");
}
