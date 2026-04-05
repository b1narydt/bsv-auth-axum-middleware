//! Channel-based Transport implementation for Actix-web middleware.
//!
//! `ActixTransport` implements the BSV SDK `Transport` trait using tokio
//! channels for message passing. Oneshot channels provide per-request
//! message correlation (replacing the TS callback map pattern), and an
//! mpsc channel feeds incoming messages to the `Peer`.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{mpsc, oneshot};

use bsv::auth::error::AuthError;
use bsv::auth::transports::Transport;
use bsv::auth::types::AuthMessage;

use crate::error::AuthMiddlewareError;

/// Channel-based transport bridging Actix-web requests and the BSV SDK Peer.
///
/// Stores a map of pending oneshot senders keyed by nonce for per-request
/// message correlation. The `subscribe()` method returns an mpsc receiver
/// for the Peer to consume incoming messages.
pub struct ActixTransport {
    /// Pending response senders keyed by nonce/request_id.
    pending: Arc<tokio::sync::Mutex<HashMap<String, oneshot::Sender<AuthMessage>>>>,
    /// Sender for feeding incoming messages to the Peer's subscription channel.
    incoming_tx: mpsc::Sender<AuthMessage>,
    /// Receiver taken once by the Peer via `subscribe()`.
    /// Uses std::sync::Mutex because `subscribe()` is a sync fn that may be
    /// called from within an async runtime (Peer::new calls it).
    incoming_rx: std::sync::Mutex<Option<mpsc::Receiver<AuthMessage>>>,
}

impl Default for ActixTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl ActixTransport {
    /// Create a new transport with an internal mpsc channel.
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(1024);
        Self {
            pending: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            incoming_tx: tx,
            incoming_rx: std::sync::Mutex::new(Some(rx)),
        }
    }

    /// Register a pending request by nonce, returning a oneshot receiver
    /// that will resolve when the Peer sends a response for this nonce.
    pub async fn register_pending(&self, nonce: String) -> oneshot::Receiver<AuthMessage> {
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(nonce, tx);
        rx
    }

    /// Feed an incoming auth message to the Peer's subscription channel.
    pub async fn feed_incoming(&self, message: AuthMessage) -> Result<(), AuthMiddlewareError> {
        self.incoming_tx.send(message).await.map_err(|e| {
            AuthMiddlewareError::Transport(format!("failed to send incoming message: {}", e))
        })
    }
}

#[async_trait]
impl Transport for ActixTransport {
    async fn send(&self, message: AuthMessage) -> Result<(), AuthError> {
        // Extract the correlation key from the message.
        // The Peer sets your_nonce on outgoing messages to correlate with the
        // original request nonce. Fall back to initial_nonce if your_nonce is absent.
        let key = message
            .your_nonce
            .as_deref()
            .or(message.initial_nonce.as_deref())
            .ok_or_else(|| {
                AuthError::TransportError(
                    "message has no your_nonce or initial_nonce for correlation".to_string(),
                )
            })?
            .to_string();

        let sender = self.pending.lock().await.remove(&key).ok_or_else(|| {
            AuthError::TransportError(format!("no pending request for nonce: {}", key))
        })?;

        // Deliver the message. If the receiver was dropped, ignore the error.
        let _ = sender.send(message);
        Ok(())
    }

    fn subscribe(&self) -> mpsc::Receiver<AuthMessage> {
        self.incoming_rx
            .lock()
            .expect("incoming_rx mutex poisoned")
            .take()
            .expect("subscribe() can only be called once")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv::auth::peer::Peer;
    use bsv::auth::types::MessageType;
    use bsv::wallet::error::WalletError;
    use bsv::wallet::interfaces::*;

    /// Minimal mock wallet for transport tests.
    struct MockWallet;

    #[async_trait]
    impl WalletInterface for MockWallet {
        async fn create_action(
            &self,
            _args: CreateActionArgs,
            _originator: Option<&str>,
        ) -> Result<CreateActionResult, WalletError> {
            unimplemented!()
        }
        async fn sign_action(
            &self,
            _args: SignActionArgs,
            _originator: Option<&str>,
        ) -> Result<SignActionResult, WalletError> {
            unimplemented!()
        }
        async fn abort_action(
            &self,
            _args: AbortActionArgs,
            _originator: Option<&str>,
        ) -> Result<AbortActionResult, WalletError> {
            unimplemented!()
        }
        async fn list_actions(
            &self,
            _args: ListActionsArgs,
            _originator: Option<&str>,
        ) -> Result<ListActionsResult, WalletError> {
            unimplemented!()
        }
        async fn internalize_action(
            &self,
            _args: InternalizeActionArgs,
            _originator: Option<&str>,
        ) -> Result<InternalizeActionResult, WalletError> {
            unimplemented!()
        }
        async fn list_outputs(
            &self,
            _args: ListOutputsArgs,
            _originator: Option<&str>,
        ) -> Result<ListOutputsResult, WalletError> {
            unimplemented!()
        }
        async fn relinquish_output(
            &self,
            _args: RelinquishOutputArgs,
            _originator: Option<&str>,
        ) -> Result<RelinquishOutputResult, WalletError> {
            unimplemented!()
        }
        async fn get_public_key(
            &self,
            _args: GetPublicKeyArgs,
            _originator: Option<&str>,
        ) -> Result<GetPublicKeyResult, WalletError> {
            unimplemented!()
        }
        async fn reveal_counterparty_key_linkage(
            &self,
            _args: RevealCounterpartyKeyLinkageArgs,
            _originator: Option<&str>,
        ) -> Result<RevealCounterpartyKeyLinkageResult, WalletError> {
            unimplemented!()
        }
        async fn reveal_specific_key_linkage(
            &self,
            _args: RevealSpecificKeyLinkageArgs,
            _originator: Option<&str>,
        ) -> Result<RevealSpecificKeyLinkageResult, WalletError> {
            unimplemented!()
        }
        async fn encrypt(
            &self,
            _args: EncryptArgs,
            _originator: Option<&str>,
        ) -> Result<EncryptResult, WalletError> {
            unimplemented!()
        }
        async fn decrypt(
            &self,
            _args: DecryptArgs,
            _originator: Option<&str>,
        ) -> Result<DecryptResult, WalletError> {
            unimplemented!()
        }
        async fn create_hmac(
            &self,
            _args: CreateHmacArgs,
            _originator: Option<&str>,
        ) -> Result<CreateHmacResult, WalletError> {
            unimplemented!()
        }
        async fn verify_hmac(
            &self,
            _args: VerifyHmacArgs,
            _originator: Option<&str>,
        ) -> Result<VerifyHmacResult, WalletError> {
            unimplemented!()
        }
        async fn create_signature(
            &self,
            _args: CreateSignatureArgs,
            _originator: Option<&str>,
        ) -> Result<CreateSignatureResult, WalletError> {
            unimplemented!()
        }
        async fn verify_signature(
            &self,
            _args: VerifySignatureArgs,
            _originator: Option<&str>,
        ) -> Result<VerifySignatureResult, WalletError> {
            unimplemented!()
        }
        async fn acquire_certificate(
            &self,
            _args: AcquireCertificateArgs,
            _originator: Option<&str>,
        ) -> Result<Certificate, WalletError> {
            unimplemented!()
        }
        async fn list_certificates(
            &self,
            _args: ListCertificatesArgs,
            _originator: Option<&str>,
        ) -> Result<ListCertificatesResult, WalletError> {
            unimplemented!()
        }
        async fn prove_certificate(
            &self,
            _args: ProveCertificateArgs,
            _originator: Option<&str>,
        ) -> Result<ProveCertificateResult, WalletError> {
            unimplemented!()
        }
        async fn relinquish_certificate(
            &self,
            _args: RelinquishCertificateArgs,
            _originator: Option<&str>,
        ) -> Result<RelinquishCertificateResult, WalletError> {
            unimplemented!()
        }
        async fn discover_by_identity_key(
            &self,
            _args: DiscoverByIdentityKeyArgs,
            _originator: Option<&str>,
        ) -> Result<DiscoverCertificatesResult, WalletError> {
            unimplemented!()
        }
        async fn discover_by_attributes(
            &self,
            _args: DiscoverByAttributesArgs,
            _originator: Option<&str>,
        ) -> Result<DiscoverCertificatesResult, WalletError> {
            unimplemented!()
        }
        async fn is_authenticated(
            &self,
            _originator: Option<&str>,
        ) -> Result<AuthenticatedResult, WalletError> {
            unimplemented!()
        }
        async fn wait_for_authentication(
            &self,
            _originator: Option<&str>,
        ) -> Result<AuthenticatedResult, WalletError> {
            unimplemented!()
        }
        async fn get_height(
            &self,
            _originator: Option<&str>,
        ) -> Result<GetHeightResult, WalletError> {
            unimplemented!()
        }
        async fn get_header_for_height(
            &self,
            _args: GetHeaderArgs,
            _originator: Option<&str>,
        ) -> Result<GetHeaderResult, WalletError> {
            unimplemented!()
        }
        async fn get_network(
            &self,
            _originator: Option<&str>,
        ) -> Result<GetNetworkResult, WalletError> {
            unimplemented!()
        }
        async fn get_version(
            &self,
            _originator: Option<&str>,
        ) -> Result<GetVersionResult, WalletError> {
            unimplemented!()
        }
    }

    /// Helper: create a minimal AuthMessage with given your_nonce.
    fn make_message(your_nonce: Option<&str>) -> AuthMessage {
        AuthMessage {
            version: "0.1".to_string(),
            message_type: MessageType::General,
            identity_key: "test-key".to_string(),
            nonce: Some("my-nonce".to_string()),
            your_nonce: your_nonce.map(|s| s.to_string()),
            initial_nonce: None,
            certificates: None,
            requested_certificates: None,
            payload: None,
            signature: None,
        }
    }

    #[tokio::test]
    async fn test_transport_send_subscribe() {
        let transport = ActixTransport::new();
        let mut rx = transport.subscribe();

        let msg = make_message(None);
        transport.feed_incoming(msg.clone()).await.unwrap();

        let received = rx.recv().await.unwrap();
        assert_eq!(received.identity_key, "test-key");
    }

    #[tokio::test]
    async fn test_oneshot_correlation() {
        let transport = ActixTransport::new();
        let oneshot_rx = transport.register_pending("nonce1".to_string()).await;

        let msg = make_message(Some("nonce1"));
        transport.send(msg).await.unwrap();

        let received = oneshot_rx.await.unwrap();
        assert_eq!(received.your_nonce.as_deref(), Some("nonce1"));
    }

    #[tokio::test]
    async fn test_send_no_pending() {
        let transport = ActixTransport::new();
        let msg = make_message(Some("unknown-nonce"));
        let result = transport.send(msg).await;
        assert!(result.is_err());
    }

    #[test]
    #[should_panic(expected = "subscribe() can only be called once")]
    fn test_subscribe_once() {
        let transport = ActixTransport::new();
        let _rx1 = transport.subscribe();
        let _rx2 = transport.subscribe(); // should panic
    }

    #[tokio::test]
    async fn test_peer_shared_state() {
        let transport = Arc::new(ActixTransport::new());
        let peer = Peer::new(MockWallet, transport.clone());
        let shared_peer = Arc::new(tokio::sync::Mutex::new(peer));

        // Clone into a spawned task to prove Send + Sync
        let peer_clone = shared_peer.clone();
        let handle = tokio::spawn(async move {
            let _lock = peer_clone.lock().await;
            // If this compiles and runs, Peer is shareable via Arc<Mutex<Peer>>
            true
        });

        assert!(handle.await.unwrap());
    }

    #[tokio::test]
    async fn test_send_no_nonce_returns_error() {
        let transport = ActixTransport::new();
        // Message with no your_nonce and no initial_nonce
        let msg = AuthMessage {
            version: "0.1".to_string(),
            message_type: MessageType::General,
            identity_key: "test".to_string(),
            nonce: None,
            your_nonce: None,
            initial_nonce: None,
            certificates: None,
            requested_certificates: None,
            payload: None,
            signature: None,
        };
        let result = transport.send(msg).await;
        assert!(result.is_err());
    }
}
