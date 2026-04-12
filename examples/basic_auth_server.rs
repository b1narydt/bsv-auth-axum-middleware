//! Basic BRC-31 authentication server example.
//!
//! Demonstrates how to set up an axum server with `AuthLayer::from_config`
//! for mutual authentication using the BRC-31 Authrite protocol.
//!
//! # Overview
//!
//! This example creates a minimal HTTP server on `127.0.0.1:8080` that requires
//! BRC-31 authentication on all routes. It includes:
//!
//! - An `ExampleWallet` implementing `WalletInterface` (for demonstration only)
//! - Server setup with `AuthLayer::from_config`
//! - A protected route using the `Authenticated` extractor
//!
//! # Running
//!
//! ```bash
//! cargo run --example basic_auth_server
//! ```
//!
//! # Note
//!
//! The `ExampleWallet` in this example is a minimal stub for demonstration
//! purposes. In production, implement `WalletInterface` with proper key
//! management, certificate storage, and transaction handling.

use std::sync::Arc;

use async_trait::async_trait;
use axum::{Router, routing::get};
use tokio::net::TcpListener;

use bsv::auth::peer::Peer;
use bsv::primitives::private_key::PrivateKey;
use bsv::wallet::error::WalletError;
use bsv::wallet::interfaces::*;
use bsv::wallet::proto_wallet::ProtoWallet;

use bsv_auth_axum_middleware::{
    ActixTransport, AuthLayer, AuthMiddlewareConfigBuilder, Authenticated,
};

// ---------------------------------------------------------------------------
// ExampleWallet -- minimal WalletInterface implementation for demonstration
// ---------------------------------------------------------------------------

/// A minimal wallet wrapping `ProtoWallet` for demonstration purposes.
///
/// This wallet delegates cryptographic operations (signing, verification,
/// encryption, HMAC) to `ProtoWallet` and returns stub results for
/// certificate and action methods that are not needed for basic auth.
///
/// **Do not use in production.** Implement `WalletInterface` with proper
/// key management and certificate storage for real applications.
#[derive(Clone)]
struct ExampleWallet {
    inner: Arc<ProtoWallet>,
}

impl ExampleWallet {
    fn new(private_key: PrivateKey) -> Self {
        Self {
            inner: Arc::new(ProtoWallet::new(private_key)),
        }
    }
}

#[async_trait]
impl WalletInterface for ExampleWallet {
    // -- Crypto methods: delegate to ProtoWallet --

    async fn get_public_key(
        &self,
        args: GetPublicKeyArgs,
        originator: Option<&str>,
    ) -> Result<GetPublicKeyResult, WalletError> {
        WalletInterface::get_public_key(&*self.inner, args, originator).await
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

    // -- Stub methods: return simple defaults --

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

    async fn internalize_action(
        &self,
        _args: InternalizeActionArgs,
        _originator: Option<&str>,
    ) -> Result<InternalizeActionResult, WalletError> {
        Ok(InternalizeActionResult { accepted: true })
    }

    async fn list_certificates(
        &self,
        _args: ListCertificatesArgs,
        _originator: Option<&str>,
    ) -> Result<ListCertificatesResult, WalletError> {
        Ok(ListCertificatesResult {
            total_certificates: 0,
            certificates: vec![],
        })
    }

    async fn prove_certificate(
        &self,
        _args: ProveCertificateArgs,
        _originator: Option<&str>,
    ) -> Result<ProveCertificateResult, WalletError> {
        Err(WalletError::Internal(
            "prove_certificate not implemented in ExampleWallet".to_string(),
        ))
    }

    async fn acquire_certificate(
        &self,
        args: AcquireCertificateArgs,
        originator: Option<&str>,
    ) -> Result<Certificate, WalletError> {
        WalletInterface::acquire_certificate(&*self.inner, args, originator).await
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
// Route handlers
// ---------------------------------------------------------------------------

/// A protected handler that requires BRC-31 authentication.
///
/// The `Authenticated` extractor provides access to the authenticated
/// identity key of the caller.
async fn protected_handler(auth: Authenticated) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "message": "Hello, authenticated user!",
        "identity_key": auth.identity_key,
    }))
}

/// A simple health check endpoint (also protected by middleware).
async fn health_handler(_auth: Authenticated) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "ok",
    }))
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Generate a random server key for this example.
    // In production, load a persistent key from secure storage.
    let server_key = PrivateKey::from_random().expect("failed to generate server key");
    let wallet = ExampleWallet::new(server_key);

    // Create the transport and peer for BRC-31 protocol handling.
    let transport = Arc::new(ActixTransport::new());
    let peer = Arc::new(tokio::sync::Mutex::new(Peer::new(
        wallet.clone(),
        transport.clone(),
    )));

    // Build the middleware configuration.
    // Set allow_unauthenticated(false) to require auth on all routes.
    let config = AuthMiddlewareConfigBuilder::new()
        .wallet(wallet)
        .allow_unauthenticated(false)
        .build()
        .expect("failed to build middleware config");

    // Create the AuthLayer from config (async because it extracts Peer receivers).
    let layer = AuthLayer::from_config(config, peer.clone(), transport.clone()).await;

    println!("Starting BRC-31 auth server on 127.0.0.1:8080");

    // Build the axum Router with routes wrapped by the auth layer.
    let app = Router::new()
        .route("/", get(protected_handler))
        .route("/health", get(health_handler))
        .layer(layer);

    // Bind the listener and start serving.
    let listener = TcpListener::bind("127.0.0.1:8080")
        .await
        .map_err(|e| std::io::Error::other(format!("failed to bind: {}", e)))?;

    axum::serve(listener, app)
        .await
        .map_err(|e| std::io::Error::other(format!("server error: {}", e)))?;

    Ok(())
}
