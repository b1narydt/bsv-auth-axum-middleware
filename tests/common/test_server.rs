//! In-process axum test-server factory for the BRC-31 integration harness.
//!
//! A fresh server is spawned per test (`spawn_test_server()`), bound to
//! `127.0.0.1:0` so every test gets its own random ephemeral port. Each server
//! carries its own `Peer<TestWallet>` state, so sessions in one test never
//! leak into another.
//!
//! The server owns a single `AuthLayer<TestWallet>` wrapped around a small
//! `Router` of handlers that mirror the shapes the sibling actix test suite
//! exercises (GET, POST JSON, POST bytes, error-500, query-echo). Handlers
//! use the `Authenticated` extractor so each request's identity key is
//! verifiable from the handler.
//!
//! `TestWallet` is an `Arc<ProtoWallet>` wrapper implementing
//! `WalletInterface` — `ProtoWallet` doesn't derive `Clone` (its
//! `PrivateKey`/`KeyDeriver` don't), so the wrapper lets us satisfy
//! `AuthLayer<W: ... + Clone + 'static>`.
//!
//! This file is `#[allow(dead_code)]` at the module level — not every test
//! file consumes every helper (e.g. a handshake-only test doesn't need the
//! JSON POST handler). That is intentional for Rust's per-integration-test
//! crate model, where each `tests/*.rs` file is its own binary and unused
//! items in `common` surface as dead-code warnings.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::{Arc, Once};

use async_trait::async_trait;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};

use bsv::auth::peer::Peer;
use bsv::primitives::private_key::PrivateKey;
use bsv::wallet::error::WalletError;
use bsv::wallet::interfaces::{
    AbortActionArgs, AbortActionResult, AcquireCertificateArgs, AuthenticatedResult, Certificate,
    CreateActionArgs, CreateActionResult, CreateHmacArgs, CreateHmacResult, CreateSignatureArgs,
    CreateSignatureResult, DecryptArgs, DecryptResult, DiscoverByAttributesArgs,
    DiscoverByIdentityKeyArgs, DiscoverCertificatesResult, EncryptArgs, EncryptResult,
    GetHeaderArgs, GetHeaderResult, GetHeightResult, GetNetworkResult, GetPublicKeyArgs,
    GetPublicKeyResult, GetVersionResult, InternalizeActionArgs, InternalizeActionResult,
    ListActionsArgs, ListActionsResult, ListCertificatesArgs, ListCertificatesResult,
    ListOutputsArgs, ListOutputsResult, ProveCertificateArgs, ProveCertificateResult,
    RelinquishCertificateArgs, RelinquishCertificateResult, RelinquishOutputArgs,
    RelinquishOutputResult, RevealCounterpartyKeyLinkageArgs, RevealCounterpartyKeyLinkageResult,
    RevealSpecificKeyLinkageArgs, RevealSpecificKeyLinkageResult, SignActionArgs, SignActionResult,
    VerifyHmacArgs, VerifyHmacResult, VerifySignatureArgs, VerifySignatureResult, WalletInterface,
};
use bsv::wallet::proto_wallet::ProtoWallet;

use bsv_auth_axum_middleware::transport::ActixTransport;
use bsv_auth_axum_middleware::{AuthLayer, Authenticated};

// ---------------------------------------------------------------------------
// TestWallet — Arc<ProtoWallet> with WalletInterface + Clone
// ---------------------------------------------------------------------------

/// Test wallet: a `Clone`-able `Arc<ProtoWallet>`.
///
/// `ProtoWallet` itself is not `Clone` because `PrivateKey` and `KeyDeriver`
/// aren't. Wrapping in `Arc` gives us `Clone` without touching the inner
/// state. All `WalletInterface` calls delegate to the inner `ProtoWallet`'s
/// trait impl.
#[derive(Clone)]
pub struct TestWallet {
    inner: Arc<ProtoWallet>,
}

impl TestWallet {
    pub fn new(private_key: PrivateKey) -> Self {
        Self {
            inner: Arc::new(ProtoWallet::new(private_key)),
        }
    }

    /// Look up this wallet's identity public key (hex-compressed).
    pub async fn identity_key_hex(&self) -> String {
        let result = WalletInterface::get_public_key(
            &*self.inner,
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
        .expect("failed to read identity public key from TestWallet");
        result.public_key.to_der_hex()
    }
}

#[async_trait]
impl WalletInterface for TestWallet {
    async fn create_action(
        &self,
        args: CreateActionArgs,
        originator: Option<&str>,
    ) -> Result<CreateActionResult, WalletError> {
        WalletInterface::create_action(&*self.inner, args, originator).await
    }
    async fn sign_action(
        &self,
        args: SignActionArgs,
        originator: Option<&str>,
    ) -> Result<SignActionResult, WalletError> {
        WalletInterface::sign_action(&*self.inner, args, originator).await
    }
    async fn abort_action(
        &self,
        args: AbortActionArgs,
        originator: Option<&str>,
    ) -> Result<AbortActionResult, WalletError> {
        WalletInterface::abort_action(&*self.inner, args, originator).await
    }
    async fn list_actions(
        &self,
        args: ListActionsArgs,
        originator: Option<&str>,
    ) -> Result<ListActionsResult, WalletError> {
        WalletInterface::list_actions(&*self.inner, args, originator).await
    }
    async fn internalize_action(
        &self,
        args: InternalizeActionArgs,
        originator: Option<&str>,
    ) -> Result<InternalizeActionResult, WalletError> {
        WalletInterface::internalize_action(&*self.inner, args, originator).await
    }
    async fn list_outputs(
        &self,
        args: ListOutputsArgs,
        originator: Option<&str>,
    ) -> Result<ListOutputsResult, WalletError> {
        WalletInterface::list_outputs(&*self.inner, args, originator).await
    }
    async fn relinquish_output(
        &self,
        args: RelinquishOutputArgs,
        originator: Option<&str>,
    ) -> Result<RelinquishOutputResult, WalletError> {
        WalletInterface::relinquish_output(&*self.inner, args, originator).await
    }
    async fn get_public_key(
        &self,
        args: GetPublicKeyArgs,
        originator: Option<&str>,
    ) -> Result<GetPublicKeyResult, WalletError> {
        WalletInterface::get_public_key(&*self.inner, args, originator).await
    }
    async fn reveal_counterparty_key_linkage(
        &self,
        args: RevealCounterpartyKeyLinkageArgs,
        originator: Option<&str>,
    ) -> Result<RevealCounterpartyKeyLinkageResult, WalletError> {
        WalletInterface::reveal_counterparty_key_linkage(&*self.inner, args, originator).await
    }
    async fn reveal_specific_key_linkage(
        &self,
        args: RevealSpecificKeyLinkageArgs,
        originator: Option<&str>,
    ) -> Result<RevealSpecificKeyLinkageResult, WalletError> {
        WalletInterface::reveal_specific_key_linkage(&*self.inner, args, originator).await
    }
    async fn encrypt(
        &self,
        args: EncryptArgs,
        originator: Option<&str>,
    ) -> Result<EncryptResult, WalletError> {
        WalletInterface::encrypt(&*self.inner, args, originator).await
    }
    async fn decrypt(
        &self,
        args: DecryptArgs,
        originator: Option<&str>,
    ) -> Result<DecryptResult, WalletError> {
        WalletInterface::decrypt(&*self.inner, args, originator).await
    }
    async fn create_hmac(
        &self,
        args: CreateHmacArgs,
        originator: Option<&str>,
    ) -> Result<CreateHmacResult, WalletError> {
        WalletInterface::create_hmac(&*self.inner, args, originator).await
    }
    async fn verify_hmac(
        &self,
        args: VerifyHmacArgs,
        originator: Option<&str>,
    ) -> Result<VerifyHmacResult, WalletError> {
        WalletInterface::verify_hmac(&*self.inner, args, originator).await
    }
    async fn create_signature(
        &self,
        args: CreateSignatureArgs,
        originator: Option<&str>,
    ) -> Result<CreateSignatureResult, WalletError> {
        WalletInterface::create_signature(&*self.inner, args, originator).await
    }
    async fn verify_signature(
        &self,
        args: VerifySignatureArgs,
        originator: Option<&str>,
    ) -> Result<VerifySignatureResult, WalletError> {
        WalletInterface::verify_signature(&*self.inner, args, originator).await
    }
    async fn acquire_certificate(
        &self,
        args: AcquireCertificateArgs,
        originator: Option<&str>,
    ) -> Result<Certificate, WalletError> {
        WalletInterface::acquire_certificate(&*self.inner, args, originator).await
    }
    async fn list_certificates(
        &self,
        args: ListCertificatesArgs,
        originator: Option<&str>,
    ) -> Result<ListCertificatesResult, WalletError> {
        WalletInterface::list_certificates(&*self.inner, args, originator).await
    }
    async fn prove_certificate(
        &self,
        args: ProveCertificateArgs,
        originator: Option<&str>,
    ) -> Result<ProveCertificateResult, WalletError> {
        WalletInterface::prove_certificate(&*self.inner, args, originator).await
    }
    async fn relinquish_certificate(
        &self,
        args: RelinquishCertificateArgs,
        originator: Option<&str>,
    ) -> Result<RelinquishCertificateResult, WalletError> {
        WalletInterface::relinquish_certificate(&*self.inner, args, originator).await
    }
    async fn discover_by_identity_key(
        &self,
        args: DiscoverByIdentityKeyArgs,
        originator: Option<&str>,
    ) -> Result<DiscoverCertificatesResult, WalletError> {
        WalletInterface::discover_by_identity_key(&*self.inner, args, originator).await
    }
    async fn discover_by_attributes(
        &self,
        args: DiscoverByAttributesArgs,
        originator: Option<&str>,
    ) -> Result<DiscoverCertificatesResult, WalletError> {
        WalletInterface::discover_by_attributes(&*self.inner, args, originator).await
    }
    async fn is_authenticated(
        &self,
        originator: Option<&str>,
    ) -> Result<AuthenticatedResult, WalletError> {
        WalletInterface::is_authenticated(&*self.inner, originator).await
    }
    async fn wait_for_authentication(
        &self,
        originator: Option<&str>,
    ) -> Result<AuthenticatedResult, WalletError> {
        WalletInterface::wait_for_authentication(&*self.inner, originator).await
    }
    async fn get_height(&self, originator: Option<&str>) -> Result<GetHeightResult, WalletError> {
        WalletInterface::get_height(&*self.inner, originator).await
    }
    async fn get_header_for_height(
        &self,
        args: GetHeaderArgs,
        originator: Option<&str>,
    ) -> Result<GetHeaderResult, WalletError> {
        WalletInterface::get_header_for_height(&*self.inner, args, originator).await
    }
    async fn get_network(&self, originator: Option<&str>) -> Result<GetNetworkResult, WalletError> {
        WalletInterface::get_network(&*self.inner, originator).await
    }
    async fn get_version(&self, originator: Option<&str>) -> Result<GetVersionResult, WalletError> {
        WalletInterface::get_version(&*self.inner, originator).await
    }
}

// ---------------------------------------------------------------------------
// Tracing init (idempotent)
// ---------------------------------------------------------------------------

static INIT_TRACING: Once = Once::new();

/// Initialise tracing-subscriber once per process.
///
/// Picks up `RUST_LOG` from the env when set, otherwise defaults to `info`.
/// Safe to call from every test; subsequent calls are no-ops.
pub fn init_tracing() {
    INIT_TRACING.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .with_test_writer()
            .try_init();
    });
}

// ---------------------------------------------------------------------------
// TestServer — axum::serve running in a spawned task
// ---------------------------------------------------------------------------

/// Handle for a running in-process axum test server.
///
/// The server keeps running as long as this handle is alive; when dropped, the
/// internal `JoinHandle` is detached and the socket is closed on the next
/// scheduler tick. Each `TestServer` holds a direct `Arc<Mutex<Peer>>`
/// reference so integration tests can inspect server-side session state
/// (notably for the `your_nonce` regression test).
pub struct TestServer {
    /// Bound socket address (useful for building test URLs).
    pub addr: SocketAddr,
    /// Base URL (e.g. `http://127.0.0.1:54321`) — convenience for clients.
    pub base_url: String,
    /// Shared server `Peer` — integration tests can lock this to read the
    /// `SessionManager` directly.
    pub peer: Arc<Mutex<Peer<TestWallet>>>,
    /// Server-side wallet handle (used to learn the server's identity key).
    pub wallet: TestWallet,
    /// Detached join handle — dropped with the struct.
    _handle: tokio::task::JoinHandle<()>,
}

/// Configuration for `spawn_test_server`.
#[derive(Clone, Default)]
pub struct TestServerConfig {
    /// Whether unauthenticated requests pass through (identity `"unknown"`).
    pub allow_unauthenticated: bool,
}

/// Spawn an axum test server with `AuthLayer` wrapping a minimal router.
///
/// The server binds to `127.0.0.1:0` — the OS assigns a free ephemeral port —
/// so every concurrent test uses its own server with its own `Peer` state.
///
/// Routes mounted:
/// - `GET  /`                 → `Hello, world!` (200, plain text)
/// - `GET  /other-endpoint`   → `This is another endpoint.` (200, plain text)
/// - `POST /other-endpoint`   → `{"message":"This is another endpoint."}` (200)
/// - `POST /error-500`        → `{"status":"error","code":"ERR_BAD_THING",...}` (500)
/// - `PUT  /put-endpoint`     → `{"status":"updated"}` (200)
/// - `DELETE /delete-endpoint` → `{"status":"deleted"}` (200)
/// - `GET  /query-endpoint`   → `{"status":"query received","query":"..."}` (200)
/// - `POST /json-echo`        → echoes the received `{"value":"..."}` JSON body (200)
/// - `GET  /identity-echo`    → `{"identity_key":"<auth.identity_key>"}` (200)
///
/// Every handler takes the `Authenticated` extractor, so a request that
/// reaches the handler is by construction (a) authenticated via `AuthLayer`
/// or (b) flagged `identity_key == "unknown"` when `allow_unauthenticated=true`.
pub async fn spawn_test_server(config: TestServerConfig) -> TestServer {
    init_tracing();

    // Fresh server identity key per test run.
    let server_key = PrivateKey::from_random().expect("generate server private key");
    let server_wallet = TestWallet::new(server_key);

    // Build transport + peer pair.
    let transport = Arc::new(ActixTransport::new());
    let peer = Arc::new(Mutex::new(Peer::new(
        server_wallet.clone(),
        transport.clone(),
    )));

    // Build the AuthLayer around the router.
    let auth_layer = AuthLayer::new(peer.clone(), transport, config.allow_unauthenticated);

    let app = Router::new()
        .route("/", get(handler_root))
        .route("/other-endpoint", get(handler_other_endpoint_get))
        .route("/other-endpoint", post(handler_other_endpoint_post))
        .route("/error-500", post(handler_error_500))
        .route("/put-endpoint", put(handler_put))
        .route("/delete-endpoint", delete(handler_delete))
        .route("/query-endpoint", get(handler_query))
        .route("/json-echo", post(handler_json_echo))
        .route("/identity-echo", get(handler_identity_echo))
        .layer(auth_layer);

    // Bind a random ephemeral port.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind 127.0.0.1:0");
    let addr = listener.local_addr().expect("local_addr");
    let base_url = format!("http://{addr}");

    // Spawn the server in the background. We deliberately ignore the result of
    // `axum::serve`: it runs forever until the task is aborted or all handles
    // close, and drop-propagation via the JoinHandle is what shuts it down when
    // the TestServer struct is dropped at end of test.
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    TestServer {
        addr,
        base_url,
        peer,
        wallet: server_wallet,
        _handle: handle,
    }
}

// ---------------------------------------------------------------------------
// Route handlers — all gated by the Authenticated extractor
// ---------------------------------------------------------------------------

async fn handler_root(auth: Authenticated) -> impl IntoResponse {
    tracing::debug!(identity_key = %auth.identity_key, "handler GET /");
    (StatusCode::OK, "Hello, world!")
}

async fn handler_other_endpoint_get(auth: Authenticated) -> impl IntoResponse {
    tracing::debug!(identity_key = %auth.identity_key, "handler GET /other-endpoint");
    (StatusCode::OK, "This is another endpoint.")
}

async fn handler_other_endpoint_post(
    auth: Authenticated,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    tracing::debug!(
        identity_key = %auth.identity_key,
        body_len = body.len(),
        "handler POST /other-endpoint"
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({"message": "This is another endpoint."})),
    )
}

async fn handler_error_500(auth: Authenticated) -> impl IntoResponse {
    tracing::debug!(identity_key = %auth.identity_key, "handler POST /error-500");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({
            "status": "error",
            "code": "ERR_BAD_THING",
            "description": "A bad thing has happened."
        })),
    )
}

async fn handler_put(auth: Authenticated, body: axum::body::Bytes) -> impl IntoResponse {
    tracing::debug!(
        identity_key = %auth.identity_key,
        body_len = body.len(),
        "handler PUT /put-endpoint"
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({"status": "updated"})),
    )
}

async fn handler_delete(auth: Authenticated) -> impl IntoResponse {
    tracing::debug!(identity_key = %auth.identity_key, "handler DELETE /delete-endpoint");
    (
        StatusCode::OK,
        Json(serde_json::json!({"status": "deleted"})),
    )
}

async fn handler_query(
    auth: Authenticated,
    req: axum::http::Request<axum::body::Body>,
) -> impl IntoResponse {
    let query = req.uri().query().unwrap_or("").to_string();
    tracing::debug!(
        identity_key = %auth.identity_key,
        query = %query,
        "handler GET /query-endpoint"
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "query received",
            "query": query,
        })),
    )
}

/// POST `{"value": "x"}` → 200 with the same JSON body echoed back unchanged.
///
/// This handler uses `Json<T>` extraction, which proves that the middleware's
/// body re-injection path delivers the original request bytes to the handler
/// unchanged. If the middleware corrupted the body, `Json<Echo>` would fail
/// to deserialize and return a 422 instead of 200.
async fn handler_json_echo(
    auth: Authenticated,
    Json(payload): Json<EchoPayload>,
) -> impl IntoResponse {
    tracing::debug!(
        identity_key = %auth.identity_key,
        value = %payload.value,
        "handler POST /json-echo"
    );
    (StatusCode::OK, Json(payload))
}

/// GET `/identity-echo` → `{"identity_key": "<auth.identity_key>"}`.
///
/// Used to prove the `Authenticated` extractor surfaces the client's real
/// identity key to the handler (not a hard-coded placeholder).
async fn handler_identity_echo(auth: Authenticated) -> impl IntoResponse {
    let key = auth.identity_key.clone();
    tracing::debug!(identity_key = %key, "handler GET /identity-echo");
    (
        StatusCode::OK,
        Json(serde_json::json!({"identity_key": key})),
    )
}

/// Simple JSON envelope for `/json-echo`.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct EchoPayload {
    pub value: String,
}

// Keep `State` import alive for future extensions without tripping unused-import.
// Some handlers might use `State` once we wire in per-test shared state.
#[allow(dead_code)]
fn _use_state_marker<T>(_s: State<T>) {}
