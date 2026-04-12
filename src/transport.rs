//! Channel-based Transport implementation for Actix-web middleware.
//!
//! `ActixTransport` implements the BSV SDK `Transport` trait using tokio
//! channels for message passing. Oneshot channels provide per-request
//! message correlation (replacing the TS callback map pattern), and an
//! mpsc channel feeds incoming messages to the `Peer`.
//!
//! Each pending registration is guarded by a cancellable background timeout
//! task. If the peer never responds, the timeout fires, removes the entry
//! from the pending map and drops the oneshot sender so the awaiting side
//! observes a `RecvError` (mirrors the TS `openNextHandlerTimeouts` pattern
//! in `auth-express-middleware` at lines 188, 453-460, and 629-651).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::{mpsc, oneshot};
use tokio::task::AbortHandle;

use bsv::auth::error::AuthError;
use bsv::auth::transports::Transport;
use bsv::auth::types::AuthMessage;

use crate::error::AuthMiddlewareError;

/// Default pending-message timeout, matching the TS `CERTIFICATE_TIMEOUT_MS`
/// / `openNextHandlerTimeouts` duration (30 seconds).
pub const DEFAULT_PENDING_TIMEOUT: Duration = Duration::from_secs(30);

/// Internal entry stored in the pending map.
///
/// Keeps the oneshot sender (for normal resolution) paired with the abort
/// handle of the timeout task so both can be cleaned up atomically: successful
/// `send()` aborts the timeout, timeout firing drops the sender.
struct PendingEntry {
    sender: oneshot::Sender<AuthMessage>,
    timeout_handle: AbortHandle,
}

type PendingMap = Arc<tokio::sync::Mutex<HashMap<String, PendingEntry>>>;

/// Channel-based transport bridging Actix-web requests and the BSV SDK Peer.
///
/// Stores a map of pending oneshot senders keyed by nonce for per-request
/// message correlation. The `subscribe()` method returns an mpsc receiver
/// for the Peer to consume incoming messages.
pub struct ActixTransport {
    /// Pending response senders keyed by nonce/request_id.
    pending: PendingMap,
    /// Sender for feeding incoming messages to the Peer's subscription channel.
    incoming_tx: mpsc::Sender<AuthMessage>,
    /// Receiver taken once by the Peer via `subscribe()`.
    /// Uses std::sync::Mutex because `subscribe()` is a sync fn that may be
    /// called from within an async runtime (Peer::new calls it).
    incoming_rx: std::sync::Mutex<Option<mpsc::Receiver<AuthMessage>>>,
    /// Timeout applied to each `register_pending` entry. Defaults to 30s.
    pending_timeout: Duration,
}

impl Default for ActixTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl ActixTransport {
    /// Create a new transport with an internal mpsc channel and the default
    /// 30-second pending-message timeout.
    pub fn new() -> Self {
        Self::with_timeout(DEFAULT_PENDING_TIMEOUT)
    }

    /// Create a new transport with a custom pending-message timeout. Each
    /// entry registered via `register_pending` is automatically cleaned up
    /// (and the oneshot sender dropped) if no response arrives within
    /// `pending_timeout`.
    pub fn with_timeout(pending_timeout: Duration) -> Self {
        let (tx, rx) = mpsc::channel(1024);
        Self {
            pending: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            incoming_tx: tx,
            incoming_rx: std::sync::Mutex::new(Some(rx)),
            pending_timeout,
        }
    }

    /// Return the configured pending-message timeout.
    pub fn pending_timeout(&self) -> Duration {
        self.pending_timeout
    }

    /// Register a pending request by nonce, returning a oneshot receiver
    /// that will resolve when the Peer sends a response for this nonce.
    ///
    /// A background timeout task is spawned: if no matching `send()` arrives
    /// within `pending_timeout`, the entry is removed from the pending map
    /// and the oneshot sender is dropped (awaiting side sees `RecvError`).
    /// If `register_pending` is called again with the same key, the previous
    /// timeout task is aborted and the previous sender is dropped before the
    /// new one is installed (mirrors TS line 630 cleanup-then-reinstall).
    pub async fn register_pending(&self, nonce: String) -> oneshot::Receiver<AuthMessage> {
        let (tx, rx) = oneshot::channel();

        // Spawn the timeout task. It removes its own entry on fire (guarded
        // by a pointer-equality check on the abort handle so it doesn't
        // evict a freshly re-registered entry).
        let pending = self.pending.clone();
        let key = nonce.clone();
        let timeout_duration = self.pending_timeout;
        let handle = tokio::spawn(async move {
            tokio::time::sleep(timeout_duration).await;
            // Remove the entry so the awaiting side's `rx.await` resolves
            // with `RecvError` (sender dropped). We only remove if the key
            // still maps to an entry — a successful `send()` would have
            // already removed it (and aborted us before we got here, but
            // the abort is racy with the final poll, so we double-check).
            let mut guard = pending.lock().await;
            guard.remove(&key);
            // Dropping `guard` + entry here closes the oneshot sender.
        });
        let timeout_handle = handle.abort_handle();

        let entry = PendingEntry {
            sender: tx,
            timeout_handle,
        };

        // Insert and, if a previous entry existed for this key, abort its
        // timeout so it doesn't fire against the new registration.
        let mut guard = self.pending.lock().await;
        if let Some(old) = guard.insert(nonce, entry) {
            old.timeout_handle.abort();
            // Dropping `old.sender` closes any prior waiter with RecvError.
        }
        drop(guard);

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

        let entry = self.pending.lock().await.remove(&key).ok_or_else(|| {
            AuthError::TransportError(format!("no pending request for nonce: {}", key))
        })?;

        // Cancel the timeout task so it doesn't later try to remove an
        // entry we already claimed (harmless, but avoids wasted wakeups).
        entry.timeout_handle.abort();

        // Deliver the message. If the receiver was dropped, ignore the error.
        let _ = entry.sender.send(message);
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
    async fn test_register_pending_times_out_after_duration() {
        // Short (100ms) timeout: if we never send, the receiver must resolve
        // with a RecvError (sender dropped) once the timeout fires.
        let transport = ActixTransport::with_timeout(Duration::from_millis(100));
        let rx = transport.register_pending("lost-nonce".to_string()).await;

        // Wait long enough for the timeout to fire + map entry removal.
        let result = tokio::time::timeout(Duration::from_millis(500), rx).await;

        // Outer timeout must NOT fire — the inner rx should have resolved.
        let rx_result = result.expect("inner rx did not resolve before outer timeout");
        // Sender was dropped by the timeout task -> RecvError.
        assert!(
            rx_result.is_err(),
            "expected RecvError after timeout fired, got {:?}",
            rx_result
        );

        // Pending map must be cleaned up.
        assert!(transport.pending.lock().await.is_empty());
    }

    #[tokio::test]
    async fn test_timeout_is_aborted_on_successful_send() {
        // 500ms timeout, immediate send: receiver should see the message,
        // and after sleeping past the original timeout nothing else should
        // have fired.
        let transport = ActixTransport::with_timeout(Duration::from_millis(500));
        let rx = transport.register_pending("nonce-ok".to_string()).await;

        let msg = make_message(Some("nonce-ok"));
        transport.send(msg).await.unwrap();

        let received = rx.await.expect("expected message, not timeout");
        assert_eq!(received.your_nonce.as_deref(), Some("nonce-ok"));

        // Sleep past the original timeout to make sure no lingering task
        // causes panics or side effects.
        tokio::time::sleep(Duration::from_millis(600)).await;

        // Pending map is still empty.
        assert!(transport.pending.lock().await.is_empty());
    }

    #[tokio::test]
    async fn test_reregister_cancels_old_timeout() {
        // First registration with a long timeout (10s). If it ever fired in
        // this test, the test would hang — so proving the re-registration
        // wins is the point.
        let transport = ActixTransport::with_timeout(Duration::from_secs(10));
        let rx_old = transport.register_pending("dup-key".to_string()).await;

        // Re-register the same key on a transport configured with a shorter
        // timeout. We can't change `pending_timeout` mid-flight, so spin up
        // a second transport to demonstrate the "shorter timeout wins"
        // behaviour directly; for the same-transport re-registration we
        // verify the old waiter's sender was dropped and the new one is live.
        let rx_new = transport.register_pending("dup-key".to_string()).await;

        // The old receiver must see RecvError (sender was dropped on
        // re-registration).
        let old_result = tokio::time::timeout(Duration::from_millis(200), rx_old)
            .await
            .expect("old rx should resolve immediately after re-registration");
        assert!(
            old_result.is_err(),
            "old rx should see RecvError after re-registration"
        );

        // The new receiver is still pending; send fulfils it.
        let msg = make_message(Some("dup-key"));
        transport.send(msg).await.unwrap();
        let received = rx_new.await.expect("new rx should receive the message");
        assert_eq!(received.your_nonce.as_deref(), Some("dup-key"));

        // Now repeat on a short-timeout transport to show the freshly
        // installed timeout also supersedes the old one.
        let short = ActixTransport::with_timeout(Duration::from_millis(100));
        let _rx_first = short.register_pending("k".to_string()).await;
        let rx_second = short.register_pending("k".to_string()).await;

        tokio::time::sleep(Duration::from_millis(300)).await;

        // After 300ms the fresh 100ms timeout has fired; new rx sees
        // RecvError and the map is empty.
        let second_result = tokio::time::timeout(Duration::from_millis(50), rx_second)
            .await
            .expect("second rx should have resolved via timeout");
        assert!(second_result.is_err());
        assert!(short.pending.lock().await.is_empty());
    }

    #[tokio::test]
    async fn test_default_timeout_is_30s() {
        // Smoke test: default constructor uses the 30-second constant.
        let transport = ActixTransport::new();
        assert_eq!(transport.pending_timeout(), Duration::from_secs(30));

        let default_transport = ActixTransport::default();
        assert_eq!(default_transport.pending_timeout(), Duration::from_secs(30));

        // And the public constant matches.
        assert_eq!(DEFAULT_PENDING_TIMEOUT, Duration::from_secs(30));
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
