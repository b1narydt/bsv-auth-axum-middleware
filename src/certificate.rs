//! Certificate gate, validation, and background listener for certificate exchange.
//!
//! Provides `CertificateGate` for per-identity-key request gating (keyed on
//! *validated-certificate presence*, never on mere session existence),
//! `validate_certificate` for BRC-31 certificate validation, and
//! `certificate_listener_task` for consuming certificate channels from the
//! BSV SDK Peer and releasing the gate only after validation succeeds.
//!
//! ## Validation (TS parity + strictly-better)
//!
//! For every incoming certificate the listener enforces, BEFORE releasing the
//! gate (mirrors `ts-sdk` `validateCertificates.ts` / `Peer.ts:873-914`):
//!
//! 1. **Subject-bind** — `cert.subject == sender.identityKey`
//!    (ts `validateCertificates.ts:25-29`).
//! 2. **Certifier PIN** — `cert.certifier ∈ configured trusted set`. This is
//!    *strictly better* than TS, which skips the pin on the server path
//!    (`Peer.ts:824-829`): we always pin against our own configured set.
//! 3. **Type PIN** — when requested types are configured, `cert.type` must be a
//!    member (ts `validateCertificates.ts:50-67`).
//! 4. **Certifier signature** — verified via the SDK's
//!    [`AuthCertificate::verify`], which serialises the certificate with the
//!    exact `Certificate.toBinary(false)` field ordering used by the TS SDK and
//!    verifies with counterparty = certifier, protocol `[2,'certificate
//!    signature']`, keyID `"<type> <serialNumber>"`. We call the SDK rather than
//!    re-implementing certificate crypto.

use std::collections::HashMap;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use bsv::auth::certificates::AuthCertificate;
use bsv::auth::types::RequestedCertificateSet;
use bsv::primitives::public_key::PublicKey;
use bsv::wallet::interfaces::Certificate;
use bsv::wallet::proto_wallet::ProtoWallet;
use dashmap::DashMap;
use tokio::sync::mpsc;
use tokio::sync::Notify;

use crate::config::OnCertificatesReceived;

// ---------------------------------------------------------------------------
// Validation policy + result
// ---------------------------------------------------------------------------

/// Server-side certificate validation policy.
///
/// A **non-empty** `trusted_certifiers` set makes certificate validation
/// MANDATORY and engages the per-identity gate. An **empty** set means
/// certificates are not required (the gate is not engaged at all).
#[derive(Clone, Debug, Default)]
pub struct CertificateValidationPolicy {
    /// Certifier identity keys (compressed DER hex) the server trusts. A
    /// certificate whose `certifier` is not a member is rejected on every path.
    pub trusted_certifiers: Vec<String>,
    /// Requested certificate types (base64 32-byte type id → field names). When
    /// non-empty, an incoming certificate's type must be a member.
    pub requested_types: HashMap<String, Vec<String>>,
}

impl CertificateValidationPolicy {
    /// Whether this policy engages certificate validation (non-empty trusted set).
    pub fn is_engaged(&self) -> bool {
        !self.trusted_certifiers.is_empty()
    }
}

/// Reason a certificate failed validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertRejectReason {
    /// The sender identity key could not be parsed as a public key.
    MalformedSenderKey,
    /// `cert.subject` did not equal the sender's identity key.
    SubjectMismatch,
    /// `cert.certifier` was not in the configured trusted set.
    UntrustedCertifier,
    /// The certificate type was not in the configured requested types.
    UnrequestedType,
    /// The certifier signature failed to verify.
    BadSignature,
}

/// Validate a single incoming certificate against the sender identity + policy.
///
/// Returns `Ok(())` only when subject-bind, certifier PIN, type PIN (when
/// configured), and the certifier signature all pass. See the module docs for
/// the exact checks and their TS-parity references. `verifier_wallet` MUST be an
/// "anyone" wallet ([`ProtoWallet::anyone`]) — certificate signatures are
/// produced against the anonymous counterparty.
pub async fn validate_certificate(
    cert: &Certificate,
    sender_identity_key: &str,
    policy: &CertificateValidationPolicy,
    verifier_wallet: &ProtoWallet,
) -> Result<(), CertRejectReason> {
    // 1. Subject-bind: cert.subject must equal the sender identity key.
    let sender_pk = PublicKey::from_string(sender_identity_key)
        .map_err(|_| CertRejectReason::MalformedSenderKey)?;
    if cert.subject != sender_pk {
        return Err(CertRejectReason::SubjectMismatch);
    }

    // 2. Certifier PIN: certifier must be in the configured trusted set.
    //    Compare on compressed-DER hex, case-insensitively.
    let certifier_hex = cert.certifier.to_der_hex();
    let trusted = policy
        .trusted_certifiers
        .iter()
        .any(|c| c.eq_ignore_ascii_case(&certifier_hex));
    if !trusted {
        return Err(CertRejectReason::UntrustedCertifier);
    }

    // 3. Type PIN: when requested types are configured, the cert type must match.
    if !policy.requested_types.is_empty() {
        let type_b64 = BASE64.encode(cert.cert_type.0);
        if !policy.requested_types.contains_key(&type_b64) {
            return Err(CertRejectReason::UnrequestedType);
        }
    }

    // 4. Certifier signature over the canonical cert binary (SDK; byte-matches TS).
    match AuthCertificate::verify(cert, verifier_wallet).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(CertRejectReason::BadSignature),
        Err(e) => {
            tracing::warn!("certificate signature verification errored: {e}");
            Err(CertRejectReason::BadSignature)
        }
    }
}

// ---------------------------------------------------------------------------
// CertificateGate
// ---------------------------------------------------------------------------

/// Per-identity-key gate for blocking requests until *validated* certificates
/// arrive.
///
/// Two maps back the gate:
/// - `pending`: identity key → `Notify` waiters registered by in-flight requests.
/// - `validated`: identity key → the validated certificates recorded by the
///   background listener.
///
/// A request is authorised only when `validated_for` returns certificates for
/// its identity — session existence alone never releases the gate (F1 fix).
#[derive(Clone)]
pub struct CertificateGate {
    pending: Arc<DashMap<String, Arc<Notify>>>,
    validated: Arc<DashMap<String, Vec<Certificate>>>,
}

impl CertificateGate {
    /// Create a new certificate gate with empty maps.
    pub fn new() -> Self {
        Self {
            pending: Arc::new(DashMap::new()),
            validated: Arc::new(DashMap::new()),
        }
    }

    /// Register a waiter for an identity key, returning the `Notify` to await on.
    ///
    /// Multiple waiters on the same identity key share the same `Notify`.
    pub fn register(&self, identity_key: &str) -> Arc<Notify> {
        self.pending
            .entry(identity_key.to_string())
            .or_insert_with(|| Arc::new(Notify::new()))
            .clone()
    }

    /// Record validated certificates for an identity and wake all waiters.
    ///
    /// This is the ONLY path that authorises a cert-gated identity. Call it only
    /// after every certificate for `identity_key` has passed
    /// [`validate_certificate`].
    pub fn mark_validated(&self, identity_key: &str, certs: Vec<Certificate>) {
        self.validated.insert(identity_key.to_string(), certs);
        if let Some((_, notify)) = self.pending.remove(identity_key) {
            notify.notify_waiters();
        }
    }

    /// The validated certificates recorded for an identity, if any.
    pub fn validated_for(&self, identity_key: &str) -> Option<Vec<Certificate>> {
        self.validated.get(identity_key).map(|e| e.value().clone())
    }

    /// Wake any waiters for an identity WITHOUT recording certificates.
    ///
    /// Does not authorise the identity (`validated_for` stays `None`); a woken
    /// waiter re-checks `validated_for` and rejects when it is still empty.
    /// Retained for callers that need to unblock a waiter explicitly.
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

// ---------------------------------------------------------------------------
// Background listener task
// ---------------------------------------------------------------------------

/// Background task that consumes certificate channels from the BSV SDK Peer.
///
/// On each certificates-received event it **validates every certificate** for
/// the sender against `policy` (subject-bind + certifier PIN + type PIN +
/// certifier signature). Only if the batch is non-empty and *all* certificates
/// pass does it:
/// 1. Invoke the optional `on_certificates_received` callback (fire-and-forget),
///    with the validated certificates.
/// 2. Record the validated certificates and release the per-identity gate
///    ([`CertificateGate::mark_validated`]).
///
/// On any validation failure (or an empty batch) the gate is NOT released — the
/// waiting request times out and is rejected.
///
/// Exits when both channels are closed.
pub async fn certificate_listener_task(
    mut cert_rx: mpsc::Receiver<(String, Vec<Certificate>)>,
    mut cert_req_rx: mpsc::Receiver<(String, RequestedCertificateSet)>,
    gate: CertificateGate,
    policy: Arc<CertificateValidationPolicy>,
    callback: Option<Arc<OnCertificatesReceived>>,
) {
    // Certificate signatures are produced against the anonymous ("anyone")
    // counterparty, so verification uses the anyone wallet.
    let verifier = ProtoWallet::anyone();

    loop {
        tokio::select! {
            msg = cert_rx.recv() => {
                match msg {
                    Some((sender_key, certs)) => {
                        tracing::info!(
                            sender = %sender_key,
                            count = certs.len(),
                            "certificates received from peer; validating"
                        );

                        if certs.is_empty() {
                            tracing::warn!(
                                sender = %sender_key,
                                "no certificates provided -- gate NOT released"
                            );
                            continue;
                        }

                        // Validate EVERY certificate; reject the whole batch on
                        // the first failure (do not release the gate).
                        let mut all_valid = true;
                        for cert in &certs {
                            if let Err(reason) =
                                validate_certificate(cert, &sender_key, &policy, &verifier).await
                            {
                                tracing::warn!(
                                    sender = %sender_key,
                                    ?reason,
                                    "certificate REJECTED -- gate NOT released"
                                );
                                all_valid = false;
                                break;
                            }
                        }
                        if !all_valid {
                            continue;
                        }

                        tracing::info!(
                            sender = %sender_key,
                            count = certs.len(),
                            "all certificates validated -- releasing gate"
                        );

                        // 1. Invoke callback fire-and-forget with validated certs.
                        if let Some(ref cb) = callback {
                            let cb = Arc::clone(cb);
                            let key = sender_key.clone();
                            let certs_for_cb = certs.clone();
                            tokio::spawn(async move {
                                let fut = cb(key, certs_for_cb);
                                fut.await;
                            });
                        }

                        // 2. Record validated certs + release the gate.
                        gate.mark_validated(&sender_key, certs);
                    }
                    None => {
                        tracing::debug!("certificate receiver closed");
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

    use bsv::auth::certificates::master::MasterCertificate;
    use bsv::primitives::private_key::PrivateKey;
    use bsv::wallet::interfaces::{
        CertificateType, GetPublicKeyArgs, WalletInterface,
    };

    // -- gate mechanics --------------------------------------------------

    #[test]
    fn test_gate_register_returns_notify() {
        let gate = CertificateGate::new();
        let notify = gate.register("identity_key_1");
        assert!(Arc::strong_count(&notify) >= 1);
    }

    #[test]
    fn test_gate_register_same_key_returns_same_notify() {
        let gate = CertificateGate::new();
        let notify1 = gate.register("identity_key_1");
        let notify2 = gate.register("identity_key_1");
        assert!(Arc::ptr_eq(&notify1, &notify2));
    }

    #[tokio::test]
    async fn test_mark_validated_wakes_waiter_and_records_certs() {
        let gate = CertificateGate::new();
        let notify = gate.register("identity_key_1");

        let gate_clone = gate.clone();
        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            gate_clone.mark_validated("identity_key_1", Vec::new());
        });

        let result = tokio::time::timeout(Duration::from_secs(2), notify.notified()).await;
        assert!(result.is_ok(), "mark_validated should wake the waiter");
        assert!(gate.validated_for("identity_key_1").is_some());
        handle.await.unwrap();
    }

    #[test]
    fn test_validated_for_unknown_key_is_none() {
        let gate = CertificateGate::new();
        assert!(gate.validated_for("unknown_key").is_none());
    }

    #[test]
    fn test_release_unknown_key_does_not_panic() {
        let gate = CertificateGate::new();
        gate.release("unknown_key");
    }

    // -- validation helpers ----------------------------------------------

    async fn identity_hex(w: &ProtoWallet) -> String {
        let r = w
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
            .unwrap();
        r.public_key.to_der_hex()
    }

    async fn issue(
        certifier: &ProtoWallet,
        subject: &PublicKey,
        cert_type: [u8; 32],
    ) -> Certificate {
        let mut fields = HashMap::new();
        fields.insert("firstName".to_string(), "Alice".to_string());
        MasterCertificate::issue_certificate_for_subject(
            &CertificateType(cert_type),
            subject,
            fields,
            certifier,
        )
        .await
        .unwrap()
        .certificate
        .clone()
    }

    #[tokio::test]
    async fn test_validate_accepts_valid_trusted_cert() {
        let certifier = ProtoWallet::new(PrivateKey::from_random().unwrap());
        let subject = PrivateKey::from_random().unwrap().to_public_key();
        let cert = issue(&certifier, &subject, [3u8; 32]).await;
        let pol = CertificateValidationPolicy {
            trusted_certifiers: vec![identity_hex(&certifier).await],
            requested_types: HashMap::new(),
        };
        let verifier = ProtoWallet::anyone();
        assert_eq!(
            validate_certificate(&cert, &subject.to_der_hex(), &pol, &verifier).await,
            Ok(())
        );
    }

    #[tokio::test]
    async fn test_validate_rejects_untrusted_certifier() {
        let certifier = ProtoWallet::new(PrivateKey::from_random().unwrap());
        let subject = PrivateKey::from_random().unwrap().to_public_key();
        let cert = issue(&certifier, &subject, [3u8; 32]).await;
        let pol = CertificateValidationPolicy {
            trusted_certifiers: vec![PrivateKey::from_random()
                .unwrap()
                .to_public_key()
                .to_der_hex()],
            requested_types: HashMap::new(),
        };
        let verifier = ProtoWallet::anyone();
        assert_eq!(
            validate_certificate(&cert, &subject.to_der_hex(), &pol, &verifier).await,
            Err(CertRejectReason::UntrustedCertifier)
        );
    }

    #[tokio::test]
    async fn test_validate_rejects_malformed_sender_key() {
        let certifier = ProtoWallet::new(PrivateKey::from_random().unwrap());
        let subject = PrivateKey::from_random().unwrap().to_public_key();
        let cert = issue(&certifier, &subject, [3u8; 32]).await;
        let pol = CertificateValidationPolicy {
            trusted_certifiers: vec![identity_hex(&certifier).await],
            requested_types: HashMap::new(),
        };
        let verifier = ProtoWallet::anyone();
        assert_eq!(
            validate_certificate(&cert, "not-a-key", &pol, &verifier).await,
            Err(CertRejectReason::MalformedSenderKey)
        );
    }

    // -- listener behaviour ----------------------------------------------

    #[tokio::test]
    async fn test_listener_releases_only_after_validation() {
        let certifier = ProtoWallet::new(PrivateKey::from_random().unwrap());
        let subject = PrivateKey::from_random().unwrap().to_public_key();
        let sender = subject.to_der_hex();
        let cert = issue(&certifier, &subject, [4u8; 32]).await;

        let pol = Arc::new(CertificateValidationPolicy {
            trusted_certifiers: vec![identity_hex(&certifier).await],
            requested_types: HashMap::new(),
        });

        let gate = CertificateGate::new();
        let _n = gate.register(&sender);
        let (cert_tx, cert_rx) = mpsc::channel(8);
        let (_req_tx, req_rx) = mpsc::channel::<(String, RequestedCertificateSet)>(8);

        let task = tokio::spawn(certificate_listener_task(
            cert_rx,
            req_rx,
            gate.clone(),
            pol,
            None,
        ));

        cert_tx.send((sender.clone(), vec![cert])).await.unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(gate.validated_for(&sender).is_some());

        drop(cert_tx);
        drop(_req_tx);
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }

    #[tokio::test]
    async fn test_listener_does_not_release_on_empty_batch() {
        let pol = Arc::new(CertificateValidationPolicy {
            trusted_certifiers: vec!["02aa".to_string()],
            requested_types: HashMap::new(),
        });
        let gate = CertificateGate::new();
        let _n = gate.register("sender_1");
        let (cert_tx, cert_rx) = mpsc::channel(8);
        let (_req_tx, req_rx) = mpsc::channel::<(String, RequestedCertificateSet)>(8);

        let task = tokio::spawn(certificate_listener_task(
            cert_rx,
            req_rx,
            gate.clone(),
            pol,
            None,
        ));

        cert_tx.send(("sender_1".to_string(), vec![])).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            gate.validated_for("sender_1").is_none(),
            "empty batch must not release the gate"
        );

        drop(cert_tx);
        drop(_req_tx);
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }

    #[tokio::test]
    async fn test_listener_invokes_callback_only_on_validated() {
        let certifier = ProtoWallet::new(PrivateKey::from_random().unwrap());
        let subject = PrivateKey::from_random().unwrap().to_public_key();
        let sender = subject.to_der_hex();
        let cert = issue(&certifier, &subject, [4u8; 32]).await;

        let called = Arc::new(AtomicBool::new(false));
        let called_clone = called.clone();
        let callback: OnCertificatesReceived = Box::new(move |_key, _certs| {
            let called = called_clone.clone();
            Box::pin(async move {
                called.store(true, Ordering::SeqCst);
            })
        });

        let pol = Arc::new(CertificateValidationPolicy {
            trusted_certifiers: vec![identity_hex(&certifier).await],
            requested_types: HashMap::new(),
        });
        let gate = CertificateGate::new();
        let _n = gate.register(&sender);
        let (cert_tx, cert_rx) = mpsc::channel(8);
        let (_req_tx, req_rx) = mpsc::channel::<(String, RequestedCertificateSet)>(8);

        let task = tokio::spawn(certificate_listener_task(
            cert_rx,
            req_rx,
            gate.clone(),
            pol,
            Some(Arc::new(callback)),
        ));

        cert_tx.send((sender.clone(), vec![cert])).await.unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(called.load(Ordering::SeqCst), "callback should fire on validated certs");

        drop(cert_tx);
        drop(_req_tx);
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }

    #[tokio::test]
    async fn test_listener_exits_when_channels_close() {
        let gate = CertificateGate::new();
        let (cert_tx, cert_rx) = mpsc::channel::<(String, Vec<Certificate>)>(8);
        let (cert_req_tx, cert_req_rx) =
            mpsc::channel::<(String, RequestedCertificateSet)>(8);
        let pol = Arc::new(CertificateValidationPolicy::default());

        let task = tokio::spawn(certificate_listener_task(
            cert_rx, cert_req_rx, gate, pol, None,
        ));

        drop(cert_tx);
        drop(cert_req_tx);

        let result = tokio::time::timeout(Duration::from_secs(2), task).await;
        assert!(result.is_ok(), "task should have completed");
        assert!(result.unwrap().is_ok(), "task should not have panicked");
    }
}
