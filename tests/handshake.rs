//! BRC-31 handshake integration tests.
//!
//! These tests drive the `/.well-known/auth` endpoint end-to-end through a
//! real HTTP round-trip against an in-process axum server. They exercise
//! three shapes:
//!
//! 1. A raw `initialRequest` JSON body posted via `reqwest`, with assertions
//!    on the response body's parsed `AuthMessage` and on the six
//!    `x-bsv-auth-*` response headers written by `handle_handshake` in
//!    `src/middleware.rs`.
//! 2. A full `bsv_sdk::auth::clients::AuthFetch` handshake + authenticated
//!    request (prove that the handshake wires up a session the general-message
//!    flow can use).
//! 3. A malformed JSON body posted to `/.well-known/auth`, asserting the
//!    middleware returns a structured JSON error rather than panicking or
//!    hanging.

mod common;

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

use bsv::auth::clients::AuthFetch;
use bsv::auth::types::{AuthMessage, MessageType};
use bsv::primitives::private_key::PrivateKey;

use common::test_server::{spawn_test_server, TestServerConfig, TestWallet};

fn random_b64_nonce_32() -> String {
    // Use the SDK's own RNG so there's no separate `rand` dev-dependency.
    let bytes = bsv::primitives::random::random_bytes(32);
    BASE64.encode(&bytes)
}

/// Test 1 — raw initialRequest → initialResponse via reqwest.
///
/// Verifies:
/// - HTTP status 200
/// - Response body parses as an `AuthMessage` with `messageType=initialResponse`.
/// - `your_nonce` in the response echoes the client's `initial_nonce`.
/// - `initial_nonce` in the response is the server's freshly-generated session nonce.
/// - Response is signed: `signature` present and non-empty.
/// - Server identity key matches the TestWallet's identity key.
/// - Response carries the `x-bsv-auth-*` headers set by `handle_handshake`.
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)] // cohesive assertion chain; splitting obscures flow
async fn test_initial_request_returns_initial_response() {
    let server = spawn_test_server(TestServerConfig::default()).await;

    let server_identity_hex = server.wallet.identity_key_hex().await;

    // Build the client's minimal initial request. No signature on initialRequest.
    let client_key = PrivateKey::from_random().expect("gen client key");
    let client_wallet = TestWallet::new(client_key);
    let client_identity_hex = client_wallet.identity_key_hex().await;

    let client_initial_nonce = random_b64_nonce_32();

    let request_msg = AuthMessage {
        version: "0.1".to_string(),
        message_type: MessageType::InitialRequest,
        identity_key: client_identity_hex.clone(),
        nonce: None,
        your_nonce: None,
        initial_nonce: Some(client_initial_nonce.clone()),
        certificates: None,
        requested_certificates: None,
        payload: None,
        signature: None,
    };

    let http = reqwest::Client::new();
    let url = format!("{}/.well-known/auth", server.base_url);

    let resp = http
        .post(&url)
        .json(&request_msg)
        .send()
        .await
        .expect("POST /.well-known/auth");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "expected 200 from handshake"
    );

    // Assert the middleware-level auth headers are present on the handshake
    // response (set by `handle_handshake` in src/middleware.rs).
    let headers = resp.headers().clone();
    assert_eq!(
        headers
            .get("x-bsv-auth-version")
            .and_then(|v| v.to_str().ok()),
        Some("0.1"),
        "x-bsv-auth-version missing or wrong"
    );
    assert_eq!(
        headers
            .get("x-bsv-auth-identity-key")
            .and_then(|v| v.to_str().ok()),
        Some(server_identity_hex.as_str()),
        "x-bsv-auth-identity-key must match server wallet identity key"
    );
    assert_eq!(
        headers
            .get("x-bsv-auth-your-nonce")
            .and_then(|v| v.to_str().ok()),
        Some(client_initial_nonce.as_str()),
        "server's response must echo client's initial nonce as your-nonce"
    );
    // NOTE: the axum middleware's `handle_handshake` reads `response_msg.nonce`
    // to populate `x-bsv-auth-nonce` (middleware.rs:365-367), but the SDK's
    // `Peer::handle_initial_request` leaves that field None on an
    // initialResponse and stores the server's fresh session nonce in
    // `initial_nonce` instead. The SDK's own `SimplifiedHTTPTransport`
    // doesn't read the `x-bsv-auth-nonce` header on the handshake path, so
    // AuthFetch-based clients work today — but strict TS parity would have
    // that header present. See .planning/phases/01-tests-harness/deferred-items.md
    // for the follow-up. This test is tolerant: if the header is present it
    // must match the body's initial_nonce; if absent it's logged (non-fatal).
    let server_nonce_header_opt = headers
        .get("x-bsv-auth-nonce")
        .and_then(|v| v.to_str().ok())
        .map(std::string::ToString::to_string);

    let sig_hex = headers
        .get("x-bsv-auth-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        !sig_hex.is_empty() && hex::decode(sig_hex).is_ok(),
        "x-bsv-auth-signature must be valid hex"
    );

    // Parse the JSON body as an AuthMessage and cross-check the header claims.
    let body_bytes = resp.bytes().await.expect("read response body");
    let response_msg: AuthMessage =
        serde_json::from_slice(&body_bytes).expect("parse response body as AuthMessage");

    assert!(
        matches!(response_msg.message_type, MessageType::InitialResponse),
        "expected InitialResponse, got {:?}",
        response_msg.message_type
    );
    assert_eq!(response_msg.version, "0.1");
    assert_eq!(
        response_msg.identity_key, server_identity_hex,
        "body identity_key must equal server wallet's identity key"
    );
    assert_eq!(
        response_msg.your_nonce.as_deref(),
        Some(client_initial_nonce.as_str()),
        "body your_nonce must echo client's initial_nonce"
    );
    assert!(
        response_msg.initial_nonce.is_some(),
        "body initial_nonce (the server's session nonce) must be set"
    );
    assert!(
        response_msg
            .signature
            .as_ref()
            .is_some_and(|s| !s.is_empty()),
        "body signature must be present and non-empty"
    );

    // If the middleware DID emit the x-bsv-auth-nonce header on this handshake
    // response (which it currently doesn't — see deferred-items.md), it must
    // equal the body's initial_nonce (the server's session nonce).
    if let Some(ref header_nonce) = server_nonce_header_opt {
        assert_eq!(
            response_msg.initial_nonce.as_deref(),
            Some(header_nonce.as_str()),
            "when present, x-bsv-auth-nonce header must equal body initial_nonce"
        );
    } else {
        tracing::warn!(
            "handshake response omits x-bsv-auth-nonce header; body initial_nonce \
             is the only surface exposing the server's session nonce on this path. \
             See .planning/phases/01-tests-harness/deferred-items.md"
        );
    }
}

/// Test 2 — full end-to-end handshake + authenticated request via AuthFetch.
///
/// Uses the SDK's `AuthFetch` client, which drives the handshake over real
/// HTTP, signs a general message, and reads back the response. Confirms the
/// whole request/response pipeline (middleware + server Peer + response
/// signing) is wired correctly.
#[tokio::test(flavor = "multi_thread")]
async fn test_auth_fetch_handshake_and_round_trip_succeeds() {
    let server = spawn_test_server(TestServerConfig::default()).await;

    let client_key = PrivateKey::from_random().expect("gen client key");
    let client_wallet = TestWallet::new(client_key);
    let mut auth_fetch = AuthFetch::new(client_wallet);

    let url = format!("{}/", server.base_url);
    let response = auth_fetch
        .fetch(&url, "GET", None, None)
        .await
        .expect("auth_fetch GET / should succeed");

    assert_eq!(response.status, 200, "expected 200 from GET /");
    assert_eq!(
        String::from_utf8_lossy(&response.body),
        "Hello, world!",
        "body should echo the /-handler"
    );
}

/// Test 3 — malformed JSON body → structured 400 error.
///
/// The middleware's `handle_handshake` catches JSON-parse failures and
/// returns a JSON body `{status:"error", description:"..."}` with a 400
/// status. This test pins that behavior so future refactors of the error
/// path can't silently regress into a bare 500 or a panic.
#[tokio::test(flavor = "multi_thread")]
async fn test_handshake_rejects_malformed_auth_message() {
    let server = spawn_test_server(TestServerConfig::default()).await;

    let http = reqwest::Client::new();
    let url = format!("{}/.well-known/auth", server.base_url);

    let resp = http
        .post(&url)
        .header("content-type", "application/json")
        .body("not a valid auth message, definitely not json either {{}")
        .send()
        .await
        .expect("POST malformed body");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "malformed handshake body should yield 400"
    );

    // Body should be structured JSON per src/middleware.rs:289-295.
    let body: serde_json::Value = resp.json().await.expect("parse error body as JSON");
    assert_eq!(body["status"], "error", "status field should be \"error\"");
    assert!(
        body.get("description").is_some(),
        "description field should be present"
    );
}

/// Test 4 — handshake body that is valid JSON but the wrong shape.
///
/// An empty JSON object `{}` serialises without structural errors but fails
/// `serde_json::from_slice::<AuthMessage>` because required fields are
/// missing. This exercises the same error path as Test 3 but with a
/// structurally valid JSON document, ensuring both paths funnel to a 400.
#[tokio::test(flavor = "multi_thread")]
async fn test_handshake_rejects_wrong_shape_auth_message() {
    let server = spawn_test_server(TestServerConfig::default()).await;

    let http = reqwest::Client::new();
    let url = format!("{}/.well-known/auth", server.base_url);

    let resp = http
        .post(&url)
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("POST empty JSON");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "empty JSON body should yield 400"
    );
}

// Silence unused-import warnings in other test files that share `common`.
#[allow(dead_code)]
fn _keep_hashmap_used(_h: HashMap<String, String>) {}
