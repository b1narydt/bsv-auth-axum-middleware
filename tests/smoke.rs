//! Smoke test: the shared `tests/common/` module compiles and a test server
//! can be spawned, bound, and torn down. Every integration test file in this
//! crate depends on `tests/common/`, so this file exists primarily to ensure
//! the infrastructure compiles in isolation as part of Task 2's verify step.
//!
//! More substantive tests live in:
//! - `tests/handshake.rs` — BRC-31 handshake path
//! - `tests/request_signing.rs` — authenticated request round-trip
//! - `tests/response_signing.rs` — response signing + `your_nonce` regression
//! - `tests/certificate_gate.rs` — certificate gate primitive

mod common;

use common::test_server::{spawn_test_server, TestServerConfig};

#[tokio::test(flavor = "multi_thread")]
async fn smoke_test_server_binds_and_exposes_base_url() {
    let server = spawn_test_server(TestServerConfig::default()).await;
    assert!(
        server.base_url.starts_with("http://127.0.0.1:"),
        "expected loopback base URL, got {}",
        server.base_url
    );
    assert_ne!(server.addr.port(), 0, "bound port should be non-zero");

    // Verify we can read the server's identity key from the wallet — this
    // requires `TestWallet::identity_key_hex` to round-trip through
    // ProtoWallet's `get_public_key` without panicking.
    let id_key = server.wallet.identity_key_hex().await;
    assert!(
        !id_key.is_empty(),
        "server identity key should be non-empty"
    );
    assert_eq!(
        id_key.len(),
        66,
        "compressed secp256k1 hex key should be 66 chars, got {}",
        id_key.len()
    );
}
