//! In-process axum server bootstrapper for integration tests.
//!
//! Mirrors actix test_server.rs routes exactly. Each spawned server binds
//! to a random OS port, returns its base URL, and is torn down when the
//! returned handle is dropped (or the test process exits for leaked servers).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post, put},
    Router,
};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use bsv::auth::certificates::master::MasterCertificate;
use bsv::auth::peer::Peer;
use bsv::primitives::private_key::PrivateKey;
use bsv::wallet::interfaces::{Certificate, CertificateType, GetPublicKeyArgs, WalletInterface};
use bsv_auth_axum_middleware::{
    ActixTransport, AuthLayer, AuthMiddlewareConfigBuilder, Authenticated, OnCertificatesReceived,
};

use super::mock_wallet::MockWallet;

// ---------------------------------------------------------------------------
// TestServerHandle
// ---------------------------------------------------------------------------

/// Handle to a running test server.
///
/// The spawned task is aborted when this handle is dropped, so in-process
/// servers are cleaned up even if tests fail. For servers that should persist
/// for the lifetime of the test process, use `std::mem::forget` (leak) just
/// as actix's test_server does.
pub struct TestServerHandle {
    pub base_url: String,
    task: JoinHandle<()>,
}

impl Drop for TestServerHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

// ---------------------------------------------------------------------------
// Integration test server (mirrors create_test_server from actix)
// ---------------------------------------------------------------------------

/// Create an axum test server and return its base URL.
///
/// Mirrors the actix `create_test_server()` API: a single server with
/// `allow_unauthenticated(false)` and the same set of routes as the actix
/// implementation.
///
/// The server runs in a dedicated background thread with its own Tokio
/// multi-thread runtime. This means it outlives any individual `#[tokio::test]`
/// runtime — each `#[tokio::test]` creates a fresh runtime on each invocation,
/// so spawning into the test runtime would not persist the server across tests.
/// Running in a dedicated thread avoids that lifetime problem while keeping the
/// axum::serve loop alive for the process lifetime (the thread is leaked via
/// `std::thread::spawn` without joining, matching the actix `std::mem::forget`
/// pattern).
pub async fn create_test_server() -> String {
    // Bind the port *now* in the current async context so the port is reserved
    // before we return the URL.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind test listener");
    listener.set_nonblocking(true).expect("set_nonblocking");
    let addr: SocketAddr = listener.local_addr().expect("local_addr");
    let base_url = format!("http://{}", addr);

    let server_key = PrivateKey::from_random().expect("failed to generate server key");
    let server_wallet = MockWallet::new(server_key);

    // Build config + layer in the calling async context so we don't have to
    // send `ActixTransport` across threads without proper setup.
    let transport = Arc::new(ActixTransport::new());
    let peer = Arc::new(tokio::sync::Mutex::new(Peer::new(
        server_wallet.clone(),
        transport.clone(),
    )));

    let config = AuthMiddlewareConfigBuilder::new()
        .wallet(server_wallet)
        .allow_unauthenticated(false)
        .build()
        .expect("failed to build middleware config");

    let layer = AuthLayer::from_config(config, peer.clone(), transport.clone()).await;

    let app = Router::new()
        .route("/", get(handler_root))
        .route("/other-endpoint", post(handler_other_endpoint_post))
        .route("/other-endpoint", get(handler_other_endpoint_get))
        .route("/error-500", post(handler_error_500))
        .route("/put-endpoint", put(handler_put))
        .route("/delete-endpoint", delete(handler_delete))
        .route("/large-upload", post(handler_large_upload))
        .route("/query-endpoint", get(handler_query))
        .route("/custom-headers", get(handler_custom_headers))
        .layer(layer);

    println!("Test server started at {}", base_url);

    // Spawn a background thread with its own Tokio runtime. The thread is
    // leaked (never joined) so the server lives for the process lifetime,
    // matching the actix `std::mem::forget(server)` pattern.
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("create server runtime");
        rt.block_on(async move {
            let tokio_listener =
                TcpListener::from_std(listener).expect("convert to tokio listener");
            axum::serve(tokio_listener, app)
                .await
                .expect("test server serve");
        });
    });

    base_url
}

// ---------------------------------------------------------------------------
// Route handlers (matching actix test_server.rs handlers)
// ---------------------------------------------------------------------------

async fn handler_root(_auth: Authenticated) -> impl IntoResponse {
    println!("[handler] GET / -- Hello, world!");
    (StatusCode::OK, "Hello, world!")
}

async fn handler_other_endpoint_post(_auth: Authenticated, body: Bytes) -> impl IntoResponse {
    println!(
        "[handler] POST /other-endpoint -- body length: {}",
        body.len()
    );
    axum::Json(serde_json::json!({"message": "This is another endpoint."}))
}

async fn handler_other_endpoint_get(_auth: Authenticated) -> impl IntoResponse {
    println!("[handler] GET /other-endpoint");
    (StatusCode::OK, "This is another endpoint.")
}

async fn handler_error_500(_auth: Authenticated) -> impl IntoResponse {
    println!("[handler] POST /error-500 -- returning 500");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        axum::Json(serde_json::json!({
            "status": "error",
            "code": "ERR_BAD_THING",
            "description": "A bad thing has happened."
        })),
    )
}

async fn handler_put(_auth: Authenticated, body: Bytes) -> impl IntoResponse {
    println!("[handler] PUT /put-endpoint -- body length: {}", body.len());
    axum::Json(serde_json::json!({"status": "updated"}))
}

async fn handler_delete(_auth: Authenticated) -> impl IntoResponse {
    println!("[handler] DELETE /delete-endpoint");
    axum::Json(serde_json::json!({"status": "deleted"}))
}

async fn handler_large_upload(_auth: Authenticated, body: Bytes) -> impl IntoResponse {
    println!(
        "[handler] POST /large-upload -- body length: {}",
        body.len()
    );
    axum::Json(serde_json::json!({
        "status": "upload received",
        "size": body.len()
    }))
}

async fn handler_query(_auth: Authenticated, req: Request) -> impl IntoResponse {
    let query = req.uri().query().unwrap_or("");
    println!("[handler] GET /query-endpoint -- query: {}", query);
    axum::Json(serde_json::json!({
        "status": "query received",
        "query": query
    }))
}

async fn handler_custom_headers(_auth: Authenticated, headers: HeaderMap) -> impl IntoResponse {
    println!("[handler] GET /custom-headers");
    for (name, value) in headers.iter() {
        println!("  header: {} = {:?}", name, value);
    }
    axum::Json(serde_json::json!({"status": "headers received"}))
}

// ---------------------------------------------------------------------------
// Certificate test server (mirrors create_cert_test_server from actix)
// ---------------------------------------------------------------------------

/// Context returned by create_cert_test_server for test assertions.
pub struct CertTestContext {
    /// Base URL of the cert test server (e.g., "http://127.0.0.1:54321").
    pub server_base_url: String,
    /// Shared storage for certificates received via the onCertificatesReceived callback.
    pub certs_received: Arc<tokio::sync::Mutex<Vec<Certificate>>>,
}

/// Create a certificate-protected axum test server mirroring actix create_cert_test_server.
///
/// The server:
/// 1. Has a server wallet with a MasterCertificate issued by a known certifier
/// 2. Configures certificatesToRequest to request certs from clients
/// 3. Has an onCertificatesReceived callback that stores received certs
/// 4. Serves /cert-protected-endpoint that checks if certs were received
///
/// The server task is leaked (like create_test_server) for static lifetime.
pub async fn create_cert_test_server() -> CertTestContext {
    let server_key = PrivateKey::from_random().expect("failed to generate server key");
    let server_wallet = MockWallet::new(server_key);

    // Issue a MasterCertificate to the server wallet.
    // Uses the same certifier key as the TS test suite.
    let certifier_key =
        PrivateKey::from_hex("5a4d867377bd44eba1cecd0806c16f24e293f7e218c162b1177571edaeeaecef")
            .expect("failed to parse certifier key");
    let certifier_wallet = MockWallet::new(certifier_key);

    // Decode the base64 certificate type to [u8; 32]
    let cert_type_b64 = "z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY=";
    let cert_type_bytes = base64_decode_32(cert_type_b64);
    let certificate_type = CertificateType(cert_type_bytes);

    let fields = HashMap::from([
        ("firstName".to_string(), "Alice".to_string()),
        ("lastName".to_string(), "Doe".to_string()),
    ]);

    // Get server wallet's public key for cert issuance
    let server_pub_key_result = server_wallet
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
        .expect("failed to get server public key");

    let master_cert = MasterCertificate::issue_certificate_for_subject(
        &certificate_type,
        &server_pub_key_result.public_key,
        fields,
        &certifier_wallet,
    )
    .await
    .expect("failed to issue server certificate");

    server_wallet.add_master_certificate(master_cert).await;
    println!("[cert_server] Server wallet seeded with MasterCertificate");

    // Configure certificatesToRequest
    let mut certs_to_request = bsv::auth::types::RequestedCertificateSet::default();
    certs_to_request
        .types
        .insert(cert_type_b64.to_string(), vec!["firstName".to_string()]);

    // Shared storage for received certificates
    let certs_received = Arc::new(tokio::sync::Mutex::new(Vec::<Certificate>::new()));
    let certs_received_cb = certs_received.clone();

    // Build the onCertificatesReceived callback
    let on_certs_received: OnCertificatesReceived =
        Box::new(move |sender_key: String, certs: Vec<Certificate>| {
            let certs_store = certs_received_cb.clone();
            Box::pin(async move {
                println!(
                    "[cert_server] Certificates received from {}: count={}",
                    sender_key,
                    certs.len()
                );
                let mut store = certs_store.lock().await;
                store.extend(certs);
            })
        });

    let transport = Arc::new(ActixTransport::new());
    let peer = Arc::new(tokio::sync::Mutex::new(Peer::new(
        server_wallet.clone(),
        transport.clone(),
    )));

    let config = AuthMiddlewareConfigBuilder::new()
        .wallet(server_wallet)
        .allow_unauthenticated(false)
        .certificates_to_request(certs_to_request)
        .on_certificates_received(on_certs_received)
        .build()
        .expect("failed to build cert middleware config");

    let layer = AuthLayer::from_config(config, peer.clone(), transport.clone()).await;

    let certs_received_state = certs_received.clone();

    let app = Router::new()
        .route("/", get(handler_root))
        .route("/cert-protected-endpoint", post(handler_cert_protected))
        .with_state(certs_received_state)
        .layer(layer);

    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind cert test listener");
    std_listener.set_nonblocking(true).expect("set_nonblocking");
    let addr: SocketAddr = std_listener.local_addr().expect("local_addr");
    let base_url = format!("http://{}", addr);

    println!(
        "[cert_server] Certificate test server started at {}",
        base_url
    );

    // Spawn a dedicated background thread with its own Tokio runtime,
    // matching the pattern from create_test_server. The thread is leaked
    // so the server lives for the process lifetime.
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("create cert server runtime");
        rt.block_on(async move {
            let listener = TcpListener::from_std(std_listener).expect("convert to tokio listener");
            axum::serve(listener, app)
                .await
                .expect("cert test server serve");
        });
    });

    CertTestContext {
        server_base_url: base_url,
        certs_received,
    }
}

// ---------------------------------------------------------------------------
// Certificate server handlers
// ---------------------------------------------------------------------------

/// Handler for /cert-protected-endpoint.
///
/// Waits briefly for certificates to arrive (via the background listener),
/// then checks if any certificates were received. Returns 200 if yes, 401 if no.
async fn handler_cert_protected(
    _auth: Authenticated,
    State(certs): State<Arc<tokio::sync::Mutex<Vec<Certificate>>>>,
    body: Bytes,
) -> impl IntoResponse {
    println!(
        "[handler] POST /cert-protected-endpoint -- body length: {}",
        body.len()
    );

    // Wait briefly for certificate callback to fire
    // (the callback runs in a spawned task and may not have completed yet)
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let store = certs.lock().await;
    if !store.is_empty() {
        println!(
            "[handler] Certificates present: {} certs received",
            store.len()
        );
        (
            StatusCode::OK,
            axum::Json(serde_json::json!({"message": "You have certs!"})),
        )
            .into_response()
    } else {
        println!("[handler] No certificates received yet");
        (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({"message": "You must have certs!"})),
        )
            .into_response()
    }
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/// Decode a base64 string to a [u8; 32] array.
/// Panics if the decoded length is not 32 bytes.
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
