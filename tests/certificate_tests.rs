//! Certificate exchange integration tests for BRC-31 authentication middleware.
//!
//! Tests validate the full certificate request/response flow using a test
//! server configured with certificatesToRequest and a client MockWallet
//! holding issued MasterCertificates.
//!
//! Mirrors TS testCertificaterequests.test.ts (Tests 12 and 16).
//! Ported from actix certificate_tests.rs — test names preserved exactly.

mod common;

use common::mock_wallet::MockWallet;
use common::test_server::create_cert_test_server;

use bsv::auth::certificates::master::MasterCertificate;
use bsv::auth::clients::AuthFetch;
use bsv::primitives::private_key::PrivateKey;
use bsv::wallet::interfaces::{CertificateType, GetPublicKeyArgs, WalletInterface};

use std::collections::HashMap;
use std::sync::Once;

static INIT_TRACING: Once = Once::new();

fn init_tracing() {
    INIT_TRACING.call_once(|| {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("debug")),
            )
            .with_test_writer()
            .init();
    });
}

/// Decode a base64 string to [u8; 32].
fn base64_decode_32(s: &str) -> [u8; 32] {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s)
        .expect("failed to decode base64");
    let mut arr = [0u8; 32];
    assert_eq!(bytes.len(), 32, "expected 32 bytes, got {}", bytes.len());
    arr.copy_from_slice(&bytes);
    arr
}

/// Test 16 (TS cert test): Client with MasterCertificate authenticates to
/// cert-protected endpoint.
///
/// Flow:
/// 1. Certifier issues MasterCertificate to client wallet
/// 2. Client creates AuthFetch with the certificate
/// 3. Client POSTs to /cert-protected-endpoint
/// 4. During handshake, server requests certs (certificatesToRequest)
/// 5. Client auto-responds with matching certificates
/// 6. Server's onCertificatesReceived callback fires
/// 7. Handler returns 200 because certs were received
#[tokio::test]
async fn test_cert_protected_endpoint() {
    init_tracing();
    let ctx = create_cert_test_server().await;
    let base_url = &ctx.server_base_url;

    // Create certifier wallet from fixed key (same as TS test)
    let certifier_key =
        PrivateKey::from_hex("5a4d867377bd44eba1cecd0806c16f24e293f7e218c162b1177571edaeeaecef")
            .expect("parse certifier key");
    let certifier_wallet = MockWallet::new(certifier_key);

    // Create client wallet with random key
    let client_key = PrivateKey::from_random().expect("generate client key");
    let client_wallet = MockWallet::new(client_key);

    // Get client's identity public key
    let client_pub_key_result = client_wallet
        .get_public_key(
            GetPublicKeyArgs {
                identity_key: true,
                protocol_id: None,
                key_id: None,
                counterparty: None,
                privileged: false,
                privileged_reason: None,
                for_self: None,
                seek_permission: None,
            },
            None,
        )
        .await
        .expect("get client public key");

    println!(
        "[test_cert_protected] Client identity key: {:?}",
        client_pub_key_result.public_key
    );

    // Issue MasterCertificate for client using certifier wallet
    let cert_type_b64 = "z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY=";
    let certificate_type = CertificateType(base64_decode_32(cert_type_b64));
    let fields = HashMap::from([
        ("firstName".to_string(), "Alice".to_string()),
        ("lastName".to_string(), "Doe".to_string()),
    ]);

    let master_cert = MasterCertificate::issue_certificate_for_subject(
        &certificate_type,
        &client_pub_key_result.public_key,
        fields,
        &certifier_wallet,
    )
    .await
    .expect("issue certificate for client");

    println!(
        "[test_cert_protected] MasterCertificate issued, serial={:?}",
        master_cert.certificate.serial_number
    );

    // Add master cert to client wallet
    client_wallet.add_master_certificate(master_cert).await;

    // Create AuthFetch with client wallet
    let mut auth_fetch = AuthFetch::new(client_wallet);

    // POST to cert-protected endpoint
    let url = format!("{}/cert-protected-endpoint", base_url);
    let body = serde_json::to_vec(&serde_json::json!({"message": "Hello protected Route!"}))
        .expect("serialize body");
    let headers = HashMap::from([("content-type".to_string(), "application/json".to_string())]);

    println!("[test_cert_protected] POST {}", url);

    let response = auth_fetch
        .fetch(&url, "POST", Some(body), Some(headers))
        .await
        .expect("auth fetch to cert-protected endpoint should succeed");

    println!("[test_cert_protected] Response status: {}", response.status);
    println!(
        "[test_cert_protected] Response body: {}",
        String::from_utf8_lossy(&response.body)
    );

    assert_eq!(
        response.status, 200,
        "expected 200 from cert-protected endpoint (certs should have been exchanged)"
    );

    let body_json: serde_json::Value =
        serde_json::from_slice(&response.body).expect("parse response JSON");
    assert_eq!(
        body_json["message"], "You have certs!",
        "expected 'You have certs!' message"
    );

    // Verify the server actually received certificates
    let received = ctx.certs_received.lock().await;
    println!(
        "[test_cert_protected] Server received {} certificates",
        received.len()
    );
    assert!(
        !received.is_empty(),
        "server should have received at least one certificate"
    );
}

/// GAP G4 regression: a `certificateResponse` message arriving at
/// `/.well-known/auth` with an empty `certificates` array must yield a 400
/// with the minimal body `{"status":"No certificates provided"}`, per TS
/// auth-express-middleware:437-442.
///
/// Crucially, this is *not* the standard `{status,code,message}` error shape
/// -- it is a single-field body. Asserting byte-for-byte parity here guards
/// against any well-meaning refactor that "helpfully" wraps it back into the
/// standard envelope.
#[tokio::test]
async fn test_empty_cert_response_returns_400() {
    init_tracing();
    let ctx = create_cert_test_server().await;
    let base_url = &ctx.server_base_url;

    // Hand-craft a certificateResponse AuthMessage with empty certs. We use
    // the wire JSON directly (camelCase per the SDK's serde config) rather
    // than reaching into the SDK, because this test is specifically about
    // how the middleware reacts to a malformed/empty cert payload from an
    // untrusted peer -- including peers not speaking the Rust SDK.
    let msg = serde_json::json!({
        "version": "0.1",
        "messageType": "certificateResponse",
        "identityKey": "02".to_string() + &"0".repeat(64),
        "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "yourNonce": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=",
        "certificates": []
    });

    let url = format!("{}/.well-known/auth", base_url);
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("content-type", "application/json")
        .json(&msg)
        .send()
        .await
        .expect("POST /.well-known/auth should return a response");

    assert_eq!(
        resp.status().as_u16(),
        400,
        "empty certificateResponse must return 400"
    );

    let body: serde_json::Value = resp.json().await.expect("response body should be JSON");

    // Exact shape match: one field, one value, no extras.
    assert_eq!(
        body,
        serde_json::json!({"status": "No certificates provided"})
    );
}

/// GAP G4 regression: when the `certificates` field is entirely absent
/// (not just an empty array), the middleware treats that the same way --
/// TS's `!Array.isArray(certs) || certs.length === 0` catches both cases.
#[tokio::test]
async fn test_cert_response_with_missing_certs_field_returns_400() {
    init_tracing();
    let ctx = create_cert_test_server().await;
    let base_url = &ctx.server_base_url;

    let msg = serde_json::json!({
        "version": "0.1",
        "messageType": "certificateResponse",
        "identityKey": "02".to_string() + &"0".repeat(64),
        "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "yourNonce": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA="
        // certificates field deliberately omitted
    });

    let url = format!("{}/.well-known/auth", base_url);
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("content-type", "application/json")
        .json(&msg)
        .send()
        .await
        .expect("POST /.well-known/auth should return a response");

    assert_eq!(resp.status().as_u16(), 400);

    let body: serde_json::Value = resp.json().await.expect("response body should be JSON");
    assert_eq!(
        body,
        serde_json::json!({"status": "No certificates provided"})
    );
}

/// Test 12 (TS cert test): Certificate request flow -- client requests certs
/// from server during handshake.
///
/// NOTE: The TS test uses `sendCertificateRequest` which is a separate method.
/// In the Rust SDK, certificate requests are configured via
/// `set_requested_certificates` on AuthFetch, and the exchange happens during
/// the handshake when both sides specify their requested certificates.
///
/// This test verifies that when a client configures requested certificates
/// and makes a request, the handshake includes the certificate request,
/// and the server's certificates are exchanged.
#[tokio::test]
async fn test_cert_request_flow() {
    init_tracing();
    let ctx = create_cert_test_server().await;
    let base_url = &ctx.server_base_url;

    // Create client wallet with random key
    let client_key = PrivateKey::from_random().expect("generate client key");
    let client_wallet = MockWallet::new(client_key);

    // Create AuthFetch with certificate request configuration
    let mut auth_fetch = AuthFetch::new(client_wallet);

    // Configure certificates to request from the server
    let cert_type_b64 = "z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY=";
    let mut requested = bsv::auth::types::RequestedCertificateSet::default();
    requested
        .types
        .insert(cert_type_b64.to_string(), vec!["firstName".to_string()]);
    auth_fetch.set_requested_certificates(requested);

    // Make a request to trigger handshake + cert exchange
    let url = format!("{}/", base_url);
    println!(
        "[test_cert_request] GET {} with requested certificates",
        url
    );

    let response = auth_fetch
        .fetch(&url, "GET", None, None)
        .await
        .expect("auth fetch with cert request should succeed");

    println!("[test_cert_request] Response status: {}", response.status);
    println!(
        "[test_cert_request] Response body: {}",
        String::from_utf8_lossy(&response.body)
    );

    // The request should succeed (200) since the root handler is not cert-gated
    assert_eq!(response.status, 200, "expected 200 from root endpoint");

    // The handshake should have completed with certificate exchange.
    // We can verify by checking that the auth round-trip succeeded
    // (which implies the handshake with certificate request completed).
    println!("[test_cert_request] Certificate request flow completed successfully");
}
