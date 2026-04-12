//! Core BRC-31 authentication middleware for axum.
//!
//! Implements the tower `Layer`/`Service` pattern to intercept all
//! requests and handle three branches:
//!
//! 1. **Handshake** (`/.well-known/auth`) -- feed incoming AuthMessage to Peer,
//!    wait for signed response, return with `x-bsv-auth-*` headers.
//! 2. **Authenticated** (requests with `x-bsv-auth-*` headers) -- verify
//!    request signature via Peer, call handler, buffer response, sign response.
//! 3. **Unauthenticated** (no auth headers) -- reject with 401 when
//!    `allow_unauthenticated` is false, or pass through with identity "unknown".

use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use axum::response::IntoResponse;
use http_body_util::BodyExt;
use tower::{Layer, Service};
use tracing::{debug, error, warn};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use bsv::auth::peer::Peer;
use bsv::auth::types::AuthMessage;
use bsv::wallet::interfaces::WalletInterface;

use crate::certificate::CertificateGate;
use crate::error::AuthMiddlewareError;
use crate::extractor::Authenticated;
use crate::helpers::{build_auth_message, extract_auth_headers};
use crate::payload::headers_from_map;
use crate::transport::ActixTransport;

// ---------------------------------------------------------------------------
// AuthLayer (tower Layer)
// ---------------------------------------------------------------------------

/// Tower Layer that wraps services with BRC-31 authentication.
///
/// Users register this via `.layer()` on their axum Router.
#[derive(Clone)]
pub struct AuthLayer<W: WalletInterface> {
    peer: Arc<tokio::sync::Mutex<Peer<W>>>,
    transport: Arc<ActixTransport>,
    allow_unauthenticated: bool,
    pub(crate) certificate_gate: Option<CertificateGate>,
}

impl<W: WalletInterface + Clone + 'static> AuthLayer<W> {
    /// Create a new auth layer.
    ///
    /// # Arguments
    /// * `peer` - Shared Peer instance for BRC-31 protocol processing.
    /// * `transport` - Channel-based transport for message correlation.
    /// * `allow_unauthenticated` - Whether to allow requests without auth headers.
    pub fn new(
        peer: Arc<tokio::sync::Mutex<Peer<W>>>,
        transport: Arc<ActixTransport>,
        allow_unauthenticated: bool,
    ) -> Self {
        Self {
            peer,
            transport,
            allow_unauthenticated,
            certificate_gate: None,
        }
    }

    /// Set a certificate gate for per-identity request gating.
    pub fn with_certificate_gate(mut self, gate: CertificateGate) -> Self {
        self.certificate_gate = Some(gate);
        self
    }

    /// Create an auth layer from configuration.
    ///
    /// When `config.certificates_to_request` is `Some`, this constructor:
    /// 1. Configures the Peer with the requested certificate set.
    /// 2. Takes the certificate receivers from the Peer (one-shot take).
    /// 3. Spawns a background `certificate_listener_task` that consumes
    ///    certificate events and releases the per-identity gate.
    pub async fn from_config(
        config: crate::config::AuthMiddlewareConfig<W>,
        peer: Arc<tokio::sync::Mutex<Peer<W>>>,
        transport: Arc<ActixTransport>,
    ) -> Self {
        let certificate_gate = if let Some(certs_to_request) = config.certificates_to_request.clone() {
            let (cert_rx, cert_req_rx) = {
                let mut peer_guard = peer.lock().await;
                peer_guard.set_certificates_to_request(certs_to_request);
                let cert_rx = peer_guard.on_certificates();
                let cert_req_rx = peer_guard.on_certificate_request();

                if cert_rx.is_none() {
                    warn!("Peer::on_certificates() returned None -- receiver already taken");
                }
                if cert_req_rx.is_none() {
                    warn!("Peer::on_certificate_request() returned None -- receiver already taken");
                }

                (cert_rx, cert_req_rx)
            };

            match (cert_rx, cert_req_rx) {
                (Some(cert_rx), Some(cert_req_rx)) => {
                    let gate = crate::certificate::CertificateGate::new();
                    let gate_clone = gate.clone();
                    let callback = config.on_certificates_received.clone();
                    tokio::spawn(crate::certificate::certificate_listener_task(
                        cert_rx,
                        cert_req_rx,
                        gate_clone,
                        callback,
                    ));
                    debug!("certificate listener task spawned");
                    Some(gate)
                }
                _ => {
                    warn!("certificate exchange configured but receivers unavailable -- gate disabled");
                    None
                }
            }
        } else {
            None
        };

        Self {
            peer,
            transport,
            allow_unauthenticated: config.allow_unauthenticated,
            certificate_gate,
        }
    }
}

impl<S, W> Layer<S> for AuthLayer<W>
where
    W: WalletInterface + Clone + 'static,
{
    type Service = AuthService<S, W>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthService {
            inner,
            peer: self.peer.clone(),
            transport: self.transport.clone(),
            allow_unauthenticated: self.allow_unauthenticated,
            certificate_gate: self.certificate_gate.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// AuthService (tower Service)
// ---------------------------------------------------------------------------

/// Per-request middleware service that intercepts requests.
#[derive(Clone)]
pub struct AuthService<S, W: WalletInterface> {
    inner: S,
    peer: Arc<tokio::sync::Mutex<Peer<W>>>,
    transport: Arc<ActixTransport>,
    allow_unauthenticated: bool,
    certificate_gate: Option<CertificateGate>,
}

impl<S, W> Service<Request<Body>> for AuthService<S, W>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    W: WalletInterface + Clone + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let mut inner = self.inner.clone();
        let peer = self.peer.clone();
        let transport = self.transport.clone();
        let allow_unauth = self.allow_unauthenticated;
        let certificate_gate = self.certificate_gate.clone();

        Box::pin(async move {
            let path = req.uri().path().to_string();

            // Branch 1: Handshake at /.well-known/auth
            if path == "/.well-known/auth" {
                debug!("BRC-31 handshake request at /.well-known/auth");
                return Ok(handle_handshake(req, peer, transport).await);
            }

            // Check for auth headers
            let auth_headers = extract_auth_headers(req.headers());

            match auth_headers {
                Some(headers) => {
                    // Branch 2: Authenticated request
                    debug!(
                        "Authenticated request detected (identity_key={})",
                        headers.identity_key
                    );

                    // 1. Read request body
                    let (parts, body) = req.into_parts();
                    let body_bytes = body
                        .collect()
                        .await
                        .map(|c| c.to_bytes())
                        .unwrap_or_default();

                    // 2. Build AuthMessage from request
                    let raw_headers = headers_from_map(&parts.headers);
                    let query = parts.uri.query().map(|q| format!("?{q}")).unwrap_or_default();
                    let auth_msg = build_auth_message(
                        parts.method.as_str(),
                        parts.uri.path(),
                        &query,
                        &raw_headers,
                        &body_bytes,
                        &headers,
                    );

                    // 3. Verify request signature via Peer
                    {
                        let mut peer_guard = peer.lock().await;
                        if let Err(e) = peer_guard.dispatch_message(auth_msg).await {
                            warn!("Signature verification failed: {}", e);
                            return Ok(AuthMiddlewareError::BsvSdk(e).into_response());
                        }
                    }

                    // 4. Insert identity into extensions
                    let mut parts = parts;
                    parts.extensions.insert(Authenticated {
                        identity_key: headers.identity_key.clone(),
                    });

                    // 4b. Certificate gating
                    if let Some(ref gate) = certificate_gate {
                        let has_session = {
                            let peer_guard = peer.lock().await;
                            peer_guard
                                .session_manager()
                                .has_session_by_identifier(&headers.identity_key)
                        };
                        if !has_session {
                            let notify = gate.register(&headers.identity_key);
                            if tokio::time::timeout(Duration::from_secs(30), notify.notified())
                                .await
                                .is_err()
                            {
                                warn!(identity_key = %headers.identity_key, "certificate request timed out");
                                return Ok((
                                    StatusCode::REQUEST_TIMEOUT,
                                    axum::Json(serde_json::json!({
                                        "status": "error",
                                        "code": "CERTIFICATE_TIMEOUT",
                                        "message": "Certificate request timed out"
                                    })),
                                )
                                    .into_response());
                            }
                        }
                    }

                    // 5. Re-inject body and call inner service
                    let request = Request::from_parts(parts, Body::from(body_bytes.clone()));
                    let service_resp = inner.call(request).await?;

                    // 6. Buffer response, sign, and return with auth headers
                    Ok(handle_response_signing(service_resp, peer, &headers, &body_bytes).await)
                }
                None => {
                    // Branch 3: No auth headers
                    if allow_unauth {
                        debug!("No auth headers, passing through with identity 'unknown'");
                        let (mut parts, body) = req.into_parts();
                        parts.extensions.insert(Authenticated {
                            identity_key: "unknown".to_string(),
                        });
                        let req = Request::from_parts(parts, body);
                        inner.call(req).await
                    } else {
                        debug!("No auth headers, rejecting with 401");
                        Ok((
                            StatusCode::UNAUTHORIZED,
                            axum::Json(serde_json::json!({
                                "status": "error",
                                "code": "ERR_UNAUTHORIZED",
                                "description": "Mutual authentication required"
                            })),
                        )
                            .into_response())
                    }
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Handshake handler
// ---------------------------------------------------------------------------

async fn handle_handshake<W>(
    req: Request<Body>,
    peer: Arc<tokio::sync::Mutex<Peer<W>>>,
    transport: Arc<ActixTransport>,
) -> Response<Body>
where
    W: WalletInterface + 'static,
{
    // Read body
    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => {
            warn!("Failed to read handshake body: {}", e);
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    // Parse as AuthMessage
    let auth_msg: AuthMessage = match serde_json::from_slice(&body_bytes) {
        Ok(m) => m,
        Err(e) => {
            warn!("Failed to parse handshake body: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "status": "error",
                    "description": format!("Invalid auth message: {e}")
                })),
            )
                .into_response();
        }
    };

    debug!(
        "Auth message at /.well-known/auth: type={:?}, identity_key={}",
        auth_msg.message_type, auth_msg.identity_key
    );

    // Certificate messages: just process and return 200
    match auth_msg.message_type {
        bsv::auth::types::MessageType::CertificateResponse
        | bsv::auth::types::MessageType::CertificateRequest => {
            if let Err(e) = transport.feed_incoming(auth_msg).await {
                error!("Failed to feed certificate message: {}", e);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            if let Err(e) = peer.lock().await.process_pending().await {
                error!("Peer processing failed for certificate: {}", e);
            }
            return axum::Json(serde_json::json!({"status": "ok"})).into_response();
        }
        _ => {}
    }

    // Handshake flow
    let nonce = auth_msg.initial_nonce.clone().unwrap_or_default();
    let rx = transport.register_pending(nonce).await;

    if let Err(e) = transport.feed_incoming(auth_msg).await {
        error!("Failed to feed handshake message: {}", e);
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    {
        let mut peer_guard = peer.lock().await;
        if let Err(e) = peer_guard.process_pending().await {
            error!("Peer processing failed during handshake: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    // Wait for signed response
    let response_msg = match tokio::time::timeout(Duration::from_secs(30), rx).await {
        Ok(Ok(msg)) => msg,
        Ok(Err(_)) => {
            error!("Handshake response channel dropped");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Err(_) => {
            error!("Handshake response timed out");
            return StatusCode::REQUEST_TIMEOUT.into_response();
        }
    };

    debug!("Handshake response ready: identity_key={}", response_msg.identity_key);

    // Build response with auth headers
    let resp_json = serde_json::to_vec(&response_msg).unwrap_or_default();

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("x-bsv-auth-version", &response_msg.version)
        .header("x-bsv-auth-identity-key", &response_msg.identity_key);

    if let Some(ref n) = response_msg.nonce {
        builder = builder.header("x-bsv-auth-nonce", n);
    }
    if let Some(ref yn) = response_msg.your_nonce {
        builder = builder.header("x-bsv-auth-your-nonce", yn);
    }
    if let Some(ref sig) = response_msg.signature {
        builder = builder.header("x-bsv-auth-signature", hex::encode(sig));
    }

    builder
        .body(Body::from(resp_json))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

// ---------------------------------------------------------------------------
// Response signing
// ---------------------------------------------------------------------------

async fn handle_response_signing<W>(
    service_resp: Response<Body>,
    peer: Arc<tokio::sync::Mutex<Peer<W>>>,
    request_headers: &crate::helpers::AuthHeaders,
    _request_body: &[u8],
) -> Response<Body>
where
    W: WalletInterface + 'static,
{
    // 1. Buffer the response
    let status = service_resp.status();
    let response_headers = service_resp.headers().clone();
    let body_bytes = match service_resp.into_body().collect().await {
        Ok(c) => c.to_bytes().to_vec(),
        Err(_) => {
            error!("Failed to buffer response body for signing");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // 2. Serialize response payload
    let request_nonce_bytes = BASE64
        .decode(&request_headers.request_id)
        .unwrap_or_default();
    let response_payload = crate::payload::serialize_from_http_response(
        &request_nonce_bytes,
        status,
        &response_headers,
        &body_bytes,
    );

    // 3. Sign via Peer
    let signed_msg = {
        let peer_guard = peer.lock().await;
        match peer_guard
            .create_general_message(&request_headers.your_nonce, response_payload)
            .await
        {
            Ok(msg) => msg,
            Err(e) => {
                error!("Response signing failed: {}", e);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    };

    debug!("Response signed for identity_key={}", signed_msg.identity_key);

    // 4. Rebuild response with original headers + auth headers
    let mut builder = Response::builder().status(status);

    for (key, value) in response_headers.iter() {
        builder = builder.header(key, value);
    }

    builder = builder
        .header("x-bsv-auth-version", &signed_msg.version)
        .header("x-bsv-auth-identity-key", &signed_msg.identity_key)
        .header("x-bsv-auth-request-id", &request_headers.request_id);

    if let Some(ref n) = signed_msg.nonce {
        builder = builder.header("x-bsv-auth-nonce", n);
    }
    if let Some(ref yn) = signed_msg.your_nonce {
        builder = builder.header("x-bsv-auth-your-nonce", yn);
    }
    if let Some(ref sig) = signed_msg.signature {
        builder = builder.header("x-bsv-auth-signature", hex::encode(sig));
    }

    builder
        .body(Body::from(body_bytes))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthMiddlewareConfigBuilder;
    use bsv::auth::peer::Peer;
    use bsv::auth::types::RequestedCertificateSet;

    // Minimal MockWallet for middleware tests.
    // All methods return unimplemented!() since we only test constructor logic.
    use async_trait::async_trait;
    use bsv::wallet::error::WalletError;
    use bsv::wallet::interfaces::*;

    struct MockWallet;

    #[async_trait]
    impl WalletInterface for MockWallet {
        async fn create_action(&self, _: CreateActionArgs, _: Option<&str>) -> Result<CreateActionResult, WalletError> { unimplemented!() }
        async fn sign_action(&self, _: SignActionArgs, _: Option<&str>) -> Result<SignActionResult, WalletError> { unimplemented!() }
        async fn abort_action(&self, _: AbortActionArgs, _: Option<&str>) -> Result<AbortActionResult, WalletError> { unimplemented!() }
        async fn list_actions(&self, _: ListActionsArgs, _: Option<&str>) -> Result<ListActionsResult, WalletError> { unimplemented!() }
        async fn internalize_action(&self, _: InternalizeActionArgs, _: Option<&str>) -> Result<InternalizeActionResult, WalletError> { unimplemented!() }
        async fn list_outputs(&self, _: ListOutputsArgs, _: Option<&str>) -> Result<ListOutputsResult, WalletError> { unimplemented!() }
        async fn relinquish_output(&self, _: RelinquishOutputArgs, _: Option<&str>) -> Result<RelinquishOutputResult, WalletError> { unimplemented!() }
        async fn get_public_key(&self, _: GetPublicKeyArgs, _: Option<&str>) -> Result<GetPublicKeyResult, WalletError> { unimplemented!() }
        async fn reveal_counterparty_key_linkage(&self, _: RevealCounterpartyKeyLinkageArgs, _: Option<&str>) -> Result<RevealCounterpartyKeyLinkageResult, WalletError> { unimplemented!() }
        async fn reveal_specific_key_linkage(&self, _: RevealSpecificKeyLinkageArgs, _: Option<&str>) -> Result<RevealSpecificKeyLinkageResult, WalletError> { unimplemented!() }
        async fn encrypt(&self, _: EncryptArgs, _: Option<&str>) -> Result<EncryptResult, WalletError> { unimplemented!() }
        async fn decrypt(&self, _: DecryptArgs, _: Option<&str>) -> Result<DecryptResult, WalletError> { unimplemented!() }
        async fn create_hmac(&self, _: CreateHmacArgs, _: Option<&str>) -> Result<CreateHmacResult, WalletError> { unimplemented!() }
        async fn verify_hmac(&self, _: VerifyHmacArgs, _: Option<&str>) -> Result<VerifyHmacResult, WalletError> { unimplemented!() }
        async fn create_signature(&self, _: CreateSignatureArgs, _: Option<&str>) -> Result<CreateSignatureResult, WalletError> { unimplemented!() }
        async fn verify_signature(&self, _: VerifySignatureArgs, _: Option<&str>) -> Result<VerifySignatureResult, WalletError> { unimplemented!() }
        async fn acquire_certificate(&self, _: AcquireCertificateArgs, _: Option<&str>) -> Result<Certificate, WalletError> { unimplemented!() }
        async fn list_certificates(&self, _: ListCertificatesArgs, _: Option<&str>) -> Result<ListCertificatesResult, WalletError> { unimplemented!() }
        async fn prove_certificate(&self, _: ProveCertificateArgs, _: Option<&str>) -> Result<ProveCertificateResult, WalletError> { unimplemented!() }
        async fn relinquish_certificate(&self, _: RelinquishCertificateArgs, _: Option<&str>) -> Result<RelinquishCertificateResult, WalletError> { unimplemented!() }
        async fn discover_by_identity_key(&self, _: DiscoverByIdentityKeyArgs, _: Option<&str>) -> Result<DiscoverCertificatesResult, WalletError> { unimplemented!() }
        async fn discover_by_attributes(&self, _: DiscoverByAttributesArgs, _: Option<&str>) -> Result<DiscoverCertificatesResult, WalletError> { unimplemented!() }
        async fn is_authenticated(&self, _: Option<&str>) -> Result<AuthenticatedResult, WalletError> { unimplemented!() }
        async fn wait_for_authentication(&self, _: Option<&str>) -> Result<AuthenticatedResult, WalletError> { unimplemented!() }
        async fn get_height(&self, _: Option<&str>) -> Result<GetHeightResult, WalletError> { unimplemented!() }
        async fn get_header_for_height(&self, _: GetHeaderArgs, _: Option<&str>) -> Result<GetHeaderResult, WalletError> { unimplemented!() }
        async fn get_network(&self, _: Option<&str>) -> Result<GetNetworkResult, WalletError> { unimplemented!() }
        async fn get_version(&self, _: Option<&str>) -> Result<GetVersionResult, WalletError> { unimplemented!() }
    }

    // MockWallet must be Clone for Peer<W: Clone> bounds
    impl Clone for MockWallet {
        fn clone(&self) -> Self { MockWallet }
    }

    #[tokio::test]
    async fn test_from_config_without_certs_has_no_gate() {
        let transport = Arc::new(ActixTransport::new());
        let peer = Arc::new(tokio::sync::Mutex::new(Peer::new(MockWallet, transport.clone())));

        let config = AuthMiddlewareConfigBuilder::new()
            .wallet(MockWallet)
            .allow_unauthenticated(false)
            .build()
            .unwrap();

        let layer = AuthLayer::from_config(config, peer, transport).await;
        assert!(layer.certificate_gate.is_none());
    }

    #[tokio::test]
    async fn test_from_config_with_certs_spawns_gate() {
        let transport = Arc::new(ActixTransport::new());
        let peer = Arc::new(tokio::sync::Mutex::new(Peer::new(MockWallet, transport.clone())));

        let mut certs = RequestedCertificateSet::default();
        certs.types.insert("certifier1".to_string(), vec!["field1".to_string()]);

        let config = AuthMiddlewareConfigBuilder::new()
            .wallet(MockWallet)
            .certificates_to_request(certs)
            .build()
            .unwrap();

        let layer = AuthLayer::from_config(config, peer, transport).await;
        assert!(layer.certificate_gate.is_some());
    }
}
