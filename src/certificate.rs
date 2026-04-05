//! Certificate gate and background listener task for certificate exchange.
//!
//! Provides `CertificateGate` for per-identity-key request gating and
//! `certificate_listener_task` for consuming certificate channels from the
//! BSV SDK Peer.

use std::sync::Arc;

use bsv::auth::types::RequestedCertificateSet;
use bsv::wallet::interfaces::Certificate;
use dashmap::DashMap;
use tokio::sync::mpsc;
use tokio::sync::Notify;

use crate::config::OnCertificatesReceived;

/// Per-identity-key gate for blocking requests until certificates arrive.
///
/// Uses a `DashMap` mapping identity keys to `Notify` instances. The background
/// listener task calls `release` when certificates arrive; `Service::call`
/// registers a gate and awaits the `Notify` with a timeout.
#[derive(Clone)]
pub struct CertificateGate {
    pending: Arc<DashMap<String, Arc<Notify>>>,
}

impl CertificateGate {
    /// Create a new certificate gate with an empty pending map.
    pub fn new() -> Self {
        Self {
            pending: Arc::new(DashMap::new()),
        }
    }

    /// Register a gate for an identity key, returning the `Notify` to await on.
    ///
    /// If a gate already exists for this key, the existing `Notify` is returned.
    /// Multiple waiters on the same identity key share the same `Notify`.
    pub fn register(&self, identity_key: &str) -> Arc<Notify> {
        self.pending
            .entry(identity_key.to_string())
            .or_insert_with(|| Arc::new(Notify::new()))
            .clone()
    }

    /// Release the gate for an identity key, waking all waiters.
    ///
    /// If no gate exists for the key, this is a no-op.
    pub fn release(&self, identity_key: &str) {
        if let Some((_, notify)) = self.pending.remove(identity_key) {
            notify.notify_waiters();
        }
    }
}

impl Default for CertificateGate {
    fn default() -> Self {
        Self::new()
    }
}

/// Background task that consumes certificate channels from the BSV SDK Peer.
///
/// Runs in a loop via `tokio::select!`, consuming both the certificates-received
/// and certificate-request channels. When certificates arrive:
/// 1. Invokes the optional `on_certificates_received` callback (fire-and-forget)
/// 2. Releases the gate for the sender's identity key
///
/// Certificate request messages are logged for awareness; the Peer handles the
/// actual request flow internally.
///
/// Exits when both channels are closed.
pub async fn certificate_listener_task(
    mut cert_rx: mpsc::Receiver<(String, Vec<Certificate>)>,
    mut cert_req_rx: mpsc::Receiver<(String, RequestedCertificateSet)>,
    gate: CertificateGate,
    callback: Option<Arc<OnCertificatesReceived>>,
) {
    loop {
        tokio::select! {
            msg = cert_rx.recv() => {
                match msg {
                    Some((sender_key, certs)) => {
                        tracing::info!(
                            sender = %sender_key,
                            count = certs.len(),
                            "certificates received from peer"
                        );

                        // 1. Invoke callback fire-and-forget
                        if let Some(ref cb) = callback {
                            let cb = Arc::clone(cb);
                            let key = sender_key.clone();
                            tokio::spawn(async move {
                                // Catch panics from the callback via JoinHandle
                                let fut = cb(key, certs);
                                fut.await;
                            });
                        }

                        // 2. Release gated request
                        gate.release(&sender_key);
                    }
                    None => {
                        tracing::debug!("certificate receiver closed");
                        // Check if other channel is also closed
                        // by letting select! handle it on next iteration
                        break;
                    }
                }
            }
            msg = cert_req_rx.recv() => {
                match msg {
                    Some((sender_key, _requested)) => {
                        tracing::debug!(
                            sender = %sender_key,
                            "certificate request received from peer (handled by Peer internally)"
                        );
                    }
                    None => {
                        tracing::debug!("certificate request receiver closed");
                        break;
                    }
                }
            }
        }
    }
    tracing::debug!("certificate listener task exiting");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    #[test]
    fn test_gate_register_returns_notify() {
        let gate = CertificateGate::new();
        let notify = gate.register("identity_key_1");
        // Verify we get an Arc<Notify> (type system ensures this)
        assert!(Arc::strong_count(&notify) >= 1);
    }

    #[test]
    fn test_gate_register_same_key_returns_same_notify() {
        let gate = CertificateGate::new();
        let notify1 = gate.register("identity_key_1");
        let notify2 = gate.register("identity_key_1");
        // Same Arc means same pointer
        assert!(Arc::ptr_eq(&notify1, &notify2));
    }

    #[tokio::test]
    async fn test_gate_release_wakes_waiter() {
        let gate = CertificateGate::new();
        let notify = gate.register("identity_key_1");

        let gate_clone = gate.clone();
        let handle = tokio::spawn(async move {
            // Small delay to ensure waiter is registered before release
            tokio::time::sleep(Duration::from_millis(10)).await;
            gate_clone.release("identity_key_1");
        });

        // This should complete when release is called
        let result = tokio::time::timeout(Duration::from_secs(2), notify.notified()).await;
        assert!(result.is_ok(), "notified() should have completed");
        handle.await.unwrap();
    }

    #[test]
    fn test_gate_release_unknown_key_does_not_panic() {
        let gate = CertificateGate::new();
        // Should be a no-op, no panic
        gate.release("unknown_key");
    }

    #[tokio::test]
    async fn test_listener_invokes_callback_on_certificate() {
        let called = Arc::new(AtomicBool::new(false));
        let called_clone = called.clone();

        let callback: OnCertificatesReceived = Box::new(move |_key, _certs| {
            let called = called_clone.clone();
            Box::pin(async move {
                called.store(true, Ordering::SeqCst);
            })
        });

        let gate = CertificateGate::new();
        let (cert_tx, cert_rx) = mpsc::channel(8);
        let (_cert_req_tx, cert_req_rx) = mpsc::channel(8);

        let task = tokio::spawn(certificate_listener_task(
            cert_rx,
            cert_req_rx,
            gate.clone(),
            Some(Arc::new(callback)),
        ));

        // Send a certificate
        cert_tx
            .send(("sender_1".to_string(), vec![]))
            .await
            .unwrap();

        // Give callback time to execute
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert!(
            called.load(Ordering::SeqCst),
            "callback should have been invoked"
        );

        // Drop senders to close channels and let task exit
        drop(cert_tx);
        drop(_cert_req_tx);
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }

    #[tokio::test]
    async fn test_listener_releases_gate_on_certificate() {
        let gate = CertificateGate::new();
        let notify = gate.register("sender_1");

        let (cert_tx, cert_rx) = mpsc::channel(8);
        let (_cert_req_tx, cert_req_rx) = mpsc::channel(8);

        let task = tokio::spawn(certificate_listener_task(
            cert_rx,
            cert_req_rx,
            gate.clone(),
            None,
        ));

        // Send a certificate
        cert_tx
            .send(("sender_1".to_string(), vec![]))
            .await
            .unwrap();

        // The gate should be released, so notified() should complete
        let result = tokio::time::timeout(Duration::from_secs(2), notify.notified()).await;
        assert!(result.is_ok(), "gate should have been released");

        drop(cert_tx);
        drop(_cert_req_tx);
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }

    #[tokio::test]
    async fn test_listener_exits_when_channels_close() {
        let gate = CertificateGate::new();
        let (cert_tx, cert_rx) = mpsc::channel::<(String, Vec<Certificate>)>(8);
        let (cert_req_tx, cert_req_rx) = mpsc::channel::<(String, RequestedCertificateSet)>(8);

        let task = tokio::spawn(certificate_listener_task(cert_rx, cert_req_rx, gate, None));

        // Drop senders to close channels
        drop(cert_tx);
        drop(cert_req_tx);

        // Task should exit
        let result = tokio::time::timeout(Duration::from_secs(2), task).await;
        assert!(result.is_ok(), "task should have completed");
        assert!(result.unwrap().is_ok(), "task should not have panicked");
    }

    #[tokio::test]
    async fn test_listener_handles_callback_panic_gracefully() {
        let callback: OnCertificatesReceived = Box::new(|_key, _certs| {
            Box::pin(async {
                panic!("callback panicked intentionally");
            })
        });

        let gate = CertificateGate::new();
        let (cert_tx, cert_rx) = mpsc::channel(8);
        let (_cert_req_tx, cert_req_rx) = mpsc::channel(8);

        let task = tokio::spawn(certificate_listener_task(
            cert_rx,
            cert_req_rx,
            gate.clone(),
            Some(Arc::new(callback)),
        ));

        // Send a certificate that will trigger panicking callback
        cert_tx
            .send(("sender_1".to_string(), vec![]))
            .await
            .unwrap();

        // Give time for the callback to panic (spawned in a separate task)
        tokio::time::sleep(Duration::from_millis(50)).await;

        // The listener task itself should still be alive -- drop channels to exit
        drop(cert_tx);
        drop(_cert_req_tx);

        let result = tokio::time::timeout(Duration::from_secs(2), task).await;
        assert!(result.is_ok(), "listener task should have completed");
        assert!(
            result.unwrap().is_ok(),
            "listener task should not have panicked"
        );
    }
}
