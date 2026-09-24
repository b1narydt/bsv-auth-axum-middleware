//! Certificate gate, validation, and background listener for certificate exchange.
//!
//! Provides `CertificateGate` for session-bound HTTP authorization (keyed on
//! *validated-certificate presence*, never on identity or mere session existence),
//! `validate_certificate` for BRC-103/104 certificate validation, and
//! `certificate_listener_task` for consuming certificate channels from the
//! BSV SDK Peer and releasing the gate only after validation succeeds.
//!
//! ## Validation (TS parity + strictly-better)
//!
//! For every incoming certificate, synchronous session admission and the
//! post-admission listener enforce (mirrors `ts-sdk`
//! `validateCertificates.ts` / `Peer.ts:873-914`):
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use bsv::auth::certificates::{AuthCertificate, VerifiableCertificate};
use bsv::primitives::public_key::PublicKey;
use bsv::wallet::interfaces::Certificate;
use bsv::wallet::proto_wallet::ProtoWallet;
use dashmap::DashMap;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::Notify;

use crate::config::OnCertificatesReceived;

/// Maximum number of identities retained by each compatibility-only observer
/// map. Exact-session HTTP authority is held separately and is not affected.
pub const OBSERVATION_IDENTITY_CAPACITY: usize = 1024;

/// Maximum idle age for compatibility-only identity observations.
pub const OBSERVATION_IDENTITY_TTL: Duration = Duration::from_secs(15 * 60);

/// Maximum number of post-admission certificate events queued for legacy
/// identity observation and application callbacks.
pub const CERTIFICATE_OBSERVER_EVENT_CAPACITY: usize = 1024;

/// Maximum duration of one post-admission application callback. Callbacks run
/// sequentially, so concurrency is fixed at one and never grows with load.
pub const CERTIFICATE_OBSERVER_CALLBACK_TIMEOUT: Duration = Duration::from_secs(30);

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

/// Session-bound certificate authority plus legacy identity observation APIs.
///
/// HTTP authorization reads only `sessions`, populated by synchronous proof
/// dispatch against the exact active local BRC session. Its first validated
/// batch is immutable. `pending`/`validated` retain the public identity APIs
/// for compatibility; those maps and listener callbacks cannot authorize HTTP.
#[derive(Clone)]
pub struct CertificateGate {
    pending: Arc<DashMap<String, PendingObservation>>,
    validated: Arc<DashMap<String, ValidatedObservation>>,
    observation_limits: ObservationLimits,
    observation_mutation: Arc<std::sync::Mutex<()>>,
    // Identity-only maps above are legacy observation APIs, never HTTP authority.
    sessions: Arc<DashMap<String, Arc<SessionCertificates>>>,
    policy: Option<Arc<CertificateValidationPolicy>>,
    admission: Arc<tokio::sync::Mutex<()>>,
    next_provisional_owner: Arc<AtomicU64>,
}

#[derive(Clone)]
struct PendingObservation {
    notify: Arc<Notify>,
    touched_at: Instant,
}

#[derive(Clone)]
struct ValidatedObservation {
    certificates: Vec<VerifiableCertificate>,
    touched_at: Instant,
}

#[derive(Clone, Copy)]
struct ObservationLimits {
    capacity: usize,
    ttl: Duration,
}

struct SessionCertificates {
    identity_key: String,
    // Short synchronous critical sections let a dropped SDK commit callback
    // roll back its exact provisional owner without spawning fallible cleanup.
    batch: std::sync::Mutex<Option<SessionCertificateBatch>>,
}

enum SessionCertificateBatch {
    Provisional {
        owner: u64,
        certificates: Vec<VerifiableCertificate>,
    },
    Committed(Vec<VerifiableCertificate>),
}

struct ProvisionalSessionBatch {
    record: Arc<SessionCertificates>,
    owner: u64,
    armed: bool,
}

impl ProvisionalSessionBatch {
    fn promote(mut self) -> Result<(), bsv::auth::error::AuthError> {
        use bsv::auth::error::AuthError;
        let mut batch = self
            .record
            .batch
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let current = batch.take();
        match current {
            Some(SessionCertificateBatch::Provisional {
                owner,
                certificates,
            }) if owner == self.owner => {
                *batch = Some(SessionCertificateBatch::Committed(certificates));
                self.armed = false;
                Ok(())
            }
            other => {
                *batch = other;
                Err(AuthError::CertificateValidation(
                    "provisional certificate admission ownership changed before commit".to_string(),
                ))
            }
        }
    }
}

impl Drop for ProvisionalSessionBatch {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut batch = self
            .record
            .batch
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if matches!(
            batch.as_ref(),
            Some(SessionCertificateBatch::Provisional { owner, .. }) if *owner == self.owner
        ) {
            *batch = None;
        }
        // Deliberately keep the empty record. A later attempt reuses it, and
        // ownership matching above guarantees this rollback can never erase a
        // replacement provisional or committed batch.
    }
}

impl CertificateGate {
    /// Create a new certificate gate with empty maps.
    pub fn new() -> Self {
        Self {
            pending: Arc::new(DashMap::new()),
            validated: Arc::new(DashMap::new()),
            observation_limits: ObservationLimits {
                capacity: OBSERVATION_IDENTITY_CAPACITY,
                ttl: OBSERVATION_IDENTITY_TTL,
            },
            observation_mutation: Arc::new(std::sync::Mutex::new(())),
            sessions: Arc::new(DashMap::new()),
            policy: None,
            admission: Arc::new(tokio::sync::Mutex::new(())),
            next_provisional_owner: Arc::new(AtomicU64::new(1)),
        }
    }

    #[cfg(test)]
    fn with_observation_limits(mut self, capacity: usize, ttl: Duration) -> Self {
        self.observation_limits = ObservationLimits {
            capacity: capacity.max(1),
            ttl,
        };
        self
    }

    fn prune_observations_locked(&self, now: Instant) {
        let ttl = self.observation_limits.ttl;
        let expired_pending: Vec<_> = self
            .pending
            .iter()
            .filter(|entry| now.saturating_duration_since(entry.touched_at) >= ttl)
            .map(|entry| entry.key().clone())
            .collect();
        for key in expired_pending {
            if let Some((_, pending)) = self.pending.remove(&key) {
                pending.notify.notify_waiters();
            }
        }
        self.validated
            .retain(|_, entry| now.saturating_duration_since(entry.touched_at) < ttl);
    }

    fn evict_oldest_pending_locked(&self) {
        if self.pending.len() < self.observation_limits.capacity {
            return;
        }
        let oldest = self
            .pending
            .iter()
            .min_by_key(|entry| entry.touched_at)
            .map(|entry| entry.key().clone());
        if let Some(key) = oldest {
            if let Some((_, pending)) = self.pending.remove(&key) {
                pending.notify.notify_waiters();
            }
        }
    }

    fn evict_oldest_validated_locked(&self) {
        if self.validated.len() < self.observation_limits.capacity {
            return;
        }
        let oldest = self
            .validated
            .iter()
            .min_by_key(|entry| entry.touched_at)
            .map(|entry| entry.key().clone());
        if let Some(key) = oldest {
            self.validated.remove(&key);
        }
    }

    pub(crate) fn with_policy(mut self, policy: Arc<CertificateValidationPolicy>) -> Self {
        self.policy = Some(policy);
        self
    }

    // Snapshot keys before awaiting SDK liveness; never hold a DashMap guard
    // across an await. Pointer-checked removal cannot delete a new record that
    // was installed after this sweep's snapshot.
    async fn prune_sessions_using<F, Fut>(&self, mut active_identity: F)
    where
        F: FnMut(String) -> Fut,
        Fut: std::future::Future<Output = Option<String>>,
    {
        let entries: Vec<_> = self
            .sessions
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect();
        for (nonce, record) in entries {
            if active_identity(nonce.clone()).await.as_deref() != Some(record.identity_key.as_str())
            {
                self.sessions
                    .remove_if(&nonce, |_, current| Arc::ptr_eq(current, &record));
            }
        }
    }

    async fn prune_sessions<W>(&self, peer: &bsv::auth::peer::Peer<W>)
    where
        W: bsv::wallet::interfaces::WalletInterface + Clone + 'static,
    {
        self.prune_sessions_using(
            |nonce| async move { peer.session_peer_identity_for(&nonce).await },
        )
        .await;
    }

    pub(crate) fn start_session_pruner<W>(&self, peer: std::sync::Weak<bsv::auth::peer::Peer<W>>)
    where
        W: bsv::wallet::interfaces::WalletInterface + Clone + 'static,
    {
        let gate = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let Some(peer) = peer.upgrade() else {
                    break;
                };
                // The SDK accessor honors both its cap eviction and idle TTL,
                // even when the SDK has not physically reaped expired entries.
                gate.prune_sessions(&peer).await;
            }
        });
    }

    /// Read only the batch validated for this exact local BRC session and peer.
    /// Identity-only listener updates cannot populate or replace this record.
    /// This is a snapshot lookup; the HTTP middleware separately verifies the
    /// request signature and checks SDK session liveness before and after it.
    pub async fn validated_for_session(
        &self,
        session_nonce: &str,
        identity_key: &str,
    ) -> Option<Vec<VerifiableCertificate>> {
        let session = self.sessions.get(session_nonce)?.clone();
        if !session.identity_key.eq_ignore_ascii_case(identity_key) {
            return None;
        }
        let batch = session
            .batch
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match batch.as_ref() {
            Some(SessionCertificateBatch::Committed(certificates)) => Some(certificates.clone()),
            Some(SessionCertificateBatch::Provisional { .. }) | None => None,
        }
    }

    /// Stage the locally validated batch while the SDK's blocking authorizer
    /// still holds this session in `Pending` state.
    ///
    /// The returned attempt-owned guard is registered with the SDK, which
    /// promotes it under the session write lock only when acceptance becomes
    /// terminal. Cancellation, rejection, or timeout drops the guard and rolls
    /// back only this provisional owner.
    async fn stage_authorized_session_batch<W>(
        &self,
        peer: &bsv::auth::peer::Peer<W>,
        context: &bsv::auth::CertificateAuthorizationContext,
    ) -> Result<ProvisionalSessionBatch, bsv::auth::error::AuthError>
    where
        W: bsv::wallet::interfaces::WalletInterface + Clone + 'static,
    {
        use bsv::auth::error::AuthError;
        let reject = || {
            AuthError::CertificateValidation(
                "certificate response is not bound to the pending authenticated session"
                    .to_string(),
            )
        };
        let policy = self.policy.as_ref().ok_or_else(reject)?;
        // An empty batch is staged like any other: the SDK routes it here only
        // for a session that still requires certificates, and the blocking
        // authorizer has already accepted it (certificate-less admission).
        let requested = context.requested_certificates.as_ref().ok_or_else(reject)?;

        // The SDK decrypts supplied keys on the nonempty path, but does not
        // enforce that they equal the retained field request. A valid key for
        // another field is not evidence for the field we requested.
        for cert in &context.certificates {
            let fields = requested
                .types
                .get(&BASE64.encode(cert.cert_type.0))
                .ok_or_else(reject)?;
            let expected: std::collections::BTreeSet<_> = fields.iter().collect();
            let disclosed: std::collections::BTreeSet<_> = cert.keyring.keys().collect();
            if expected != disclosed {
                return Err(reject());
            }
        }

        let verifier = ProtoWallet::anyone();
        for cert in &context.certificates {
            validate_certificate(cert, &context.peer_identity_key, policy, &verifier)
                .await
                .map_err(|_| reject())?;
        }

        // The context is SDK-created from its selected session. Bind the local
        // record to that same still-live authenticated session before commit.
        let session = peer
            .session_by_identifier(&context.session_nonce)
            .await
            .ok_or_else(reject)?;
        if session.session_nonce != context.session_nonce
            || !session.is_authenticated
            || session.certificates_validated
            || !session.certificates_required
            || !session
                .peer_identity_key
                .eq_ignore_ascii_case(&context.peer_identity_key)
            || session.requested_certificates.is_none()
            || peer
                .session_peer_identity_for(&context.session_nonce)
                .await
                .as_deref()
                != Some(context.peer_identity_key.as_str())
        {
            return Err(reject());
        }

        // Bound persistent records to the SDK's active session set during
        // admission as well as while idle. Serialize prune+insert so a burst of
        // concurrent handshakes cannot accumulate a lifetime-sized stale map.
        let admission = self.admission.lock().await;
        self.prune_sessions(peer).await;
        let record = self
            .sessions
            .entry(context.session_nonce.clone())
            .or_insert_with(|| {
                Arc::new(SessionCertificates {
                    identity_key: context.peer_identity_key.clone(),
                    batch: std::sync::Mutex::new(None),
                })
            })
            .clone();
        drop(admission);

        // Recheck immediately before taking ownership of the empty slot. All
        // remaining work is synchronous, so cancellation cannot strand the
        // provisional value outside its rollback guard.
        let before_commit = peer
            .session_by_identifier(&context.session_nonce)
            .await
            .ok_or_else(reject)?;
        if !before_commit.is_authenticated
            || before_commit.certificates_validated
            || !before_commit
                .peer_identity_key
                .eq_ignore_ascii_case(&context.peer_identity_key)
        {
            return Err(reject());
        }
        let mut batch = record
            .batch
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !record
            .identity_key
            .eq_ignore_ascii_case(&context.peer_identity_key)
            || batch.is_some()
        {
            return Err(reject());
        }

        let owner = self.next_provisional_owner.fetch_add(1, Ordering::Relaxed);
        *batch = Some(SessionCertificateBatch::Provisional {
            owner,
            certificates: context.certificates.clone(),
        });
        drop(batch);
        Ok(ProvisionalSessionBatch {
            record,
            owner,
            armed: true,
        })
    }

    /// Stage and register an exact-session batch for atomic SDK admission.
    /// Dropping the authorization attempt before SDK commit rolls back only
    /// this attempt's provisional owner.
    pub(crate) async fn register_authorized_session_batch<W>(
        &self,
        peer: &bsv::auth::peer::Peer<W>,
        context: &bsv::auth::CertificateAuthorizationContext,
    ) -> Result<(), bsv::auth::error::AuthError>
    where
        W: bsv::wallet::interfaces::WalletInterface + Clone + 'static,
    {
        let provisional = self.stage_authorized_session_batch(peer, context).await?;
        context.register_certificate_admission_commit(move || provisional.promote())
    }

    /// Process a proof against the exact authenticated, locally nonce-selected
    /// session. A frame's identity/nonce is a selector, never evidence: the SDK
    /// verifies the nonce, signature, replay and retained certificate request.
    /// Completion and policy checks happen here, not in an identity callback.
    pub(crate) async fn validate_session_response<W>(
        &self,
        peer: &bsv::auth::peer::Peer<W>,
        message: bsv::auth::types::AuthMessage,
    ) -> Result<(), bsv::auth::error::AuthError>
    where
        W: bsv::wallet::interfaces::WalletInterface + Clone + 'static,
    {
        use bsv::auth::error::AuthError;
        let reject = || {
            AuthError::CertificateValidation(
                "certificate response is not bound to a pending authenticated session".to_string(),
            )
        };
        let nonce = message.your_nonce.clone().ok_or_else(reject)?;
        let identity = peer
            .session_peer_identity_for(&nonce)
            .await
            .ok_or_else(reject)?;
        let session = peer
            .session_by_identifier(&nonce)
            .await
            .ok_or_else(reject)?;
        if session.session_nonce != nonce
            || !session.is_authenticated
            || !identity.eq_ignore_ascii_case(&message.identity_key)
            || !session.certificates_required
            || session.requested_certificates.is_none()
        {
            return Err(reject());
        }
        // A missing `certificates` field is malformed; an empty one is a
        // proof batch the blocking authorizer decides.
        let certs = message.certificates.as_ref().ok_or_else(reject)?;
        // The SDK decrypts the supplied keys on the nonempty path, but does
        // not enforce that they equal the retained field request. A valid key
        // for a different field is not evidence for the field we requested.
        let requested = session.requested_certificates.as_ref().ok_or_else(reject)?;
        for cert in certs {
            let fields = requested
                .types
                .get(&BASE64.encode(cert.cert_type.0))
                .ok_or_else(reject)?;
            let expected: std::collections::BTreeSet<_> = fields.iter().collect();
            let disclosed: std::collections::BTreeSet<_> = cert.keyring.keys().collect();
            if expected != disclosed {
                return Err(reject());
            }
        }
        // Direct dispatch performs structural validation and blocks in the SDK
        // authorizer. That wrapper commits the local exact-session batch before
        // returning `Accept`, so SDK authority cannot become visible first.
        peer.dispatch_message(message).await?;
        let after = peer
            .session_by_identifier(&nonce)
            .await
            .ok_or_else(reject)?;
        if peer.session_peer_identity_for(&nonce).await.as_deref() != Some(identity.as_str())
            || after.session_nonce != nonce
            || after.peer_nonce != session.peer_nonce
            || !after.is_authenticated
            || !after.certificates_validated
        {
            return Err(reject());
        }
        if self
            .validated_for_session(&nonce, &identity)
            .await
            .is_none()
        {
            return Err(reject());
        }
        Ok(())
    }

    /// Register a waiter for an identity key, returning the `Notify` to await on.
    ///
    /// Multiple waiters on the same identity key share the same `Notify`.
    pub fn register(&self, identity_key: &str) -> Arc<Notify> {
        let _mutation = self
            .observation_mutation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        self.prune_observations_locked(now);
        if let Some(mut existing) = self.pending.get_mut(identity_key) {
            existing.touched_at = now;
            return existing.notify.clone();
        }
        self.evict_oldest_pending_locked();
        let notify = Arc::new(Notify::new());
        self.pending.insert(
            identity_key.to_string(),
            PendingObservation {
                notify: notify.clone(),
                touched_at: now,
            },
        );
        notify
    }

    /// Record validated certificates for an identity and wake all waiters.
    ///
    /// Legacy observation API only: this does not authorize HTTP or populate a
    /// session batch. Call it only after every certificate has passed
    /// [`validate_certificate`].
    pub fn mark_validated(&self, identity_key: &str, certs: Vec<VerifiableCertificate>) {
        let _mutation = self
            .observation_mutation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        self.prune_observations_locked(now);
        if !self.validated.contains_key(identity_key) {
            self.evict_oldest_validated_locked();
        }
        self.validated.insert(
            identity_key.to_string(),
            ValidatedObservation {
                certificates: certs,
                touched_at: now,
            },
        );
        if let Some((_, pending)) = self.pending.remove(identity_key) {
            pending.notify.notify_waiters();
        }
    }

    /// Legacy identity observation, not evidence of any particular session.
    pub fn validated_for(&self, identity_key: &str) -> Option<Vec<VerifiableCertificate>> {
        let _mutation = self
            .observation_mutation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        self.prune_observations_locked(now);
        let mut entry = self.validated.get_mut(identity_key)?;
        entry.touched_at = now;
        Some(entry.certificates.clone())
    }

    /// Wake any waiters for an identity WITHOUT recording certificates.
    ///
    /// Does not authorise the identity (`validated_for` stays `None`); a woken
    /// waiter re-checks `validated_for` and rejects when it is still empty.
    /// Retained for callers that need to unblock a waiter explicitly.
    pub fn release(&self, identity_key: &str) {
        let _mutation = self
            .observation_mutation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.prune_observations_locked(Instant::now());
        if let Some((_, pending)) = self.pending.remove(identity_key) {
            pending.notify.notify_waiters();
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
/// 1. Record the validated certificates and release the compatibility-only
///    per-identity observation ([`CertificateGate::mark_validated`]).
/// 2. Await the optional `on_certificates_received` callback sequentially for
///    at most [`CERTIFICATE_OBSERVER_CALLBACK_TIMEOUT`]. No callback task is
///    spawned, so callback concurrency is always one.
///
/// On any listener validation failure (or an empty batch), no legacy identity
/// observation or application callback is emitted. The SDK's earlier
/// session-bound admission decision is never rolled back or changed here.
///
/// Exits when the certificate channel is closed.
pub async fn certificate_listener_task(
    mut cert_rx: mpsc::Receiver<(String, Vec<VerifiableCertificate>)>,
    gate: CertificateGate,
    policy: Arc<CertificateValidationPolicy>,
    callback: Option<Arc<OnCertificatesReceived>>,
) {
    // Certificate signatures are produced against the anonymous ("anyone")
    // counterparty, so verification uses the anyone wallet.
    let verifier = ProtoWallet::anyone();

    loop {
        match cert_rx.recv().await {
            Some((sender_key, certs)) => {
                tracing::info!(
                    sender = %sender_key,
                    count = certs.len(),
                    "certificates received from peer; validating"
                );

                if certs.is_empty() {
                    tracing::warn!(
                        sender = %sender_key,
                        "no certificates provided -- observation dropped"
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
                            "certificate observation rejected"
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
                    "all certificates validated -- recording observation"
                );

                // This identity-only observation is not HTTP authority and has
                // already passed SDK admission before reaching this queue.
                gate.mark_validated(&sender_key, certs.clone());

                // Await one callback at a time with a fixed deadline. Keeping
                // it in this task (rather than spawning) bounds concurrency.
                if let Some(ref cb) = callback {
                    if !invoke_certificate_observer(
                        cb,
                        sender_key.clone(),
                        certs,
                        CERTIFICATE_OBSERVER_CALLBACK_TIMEOUT,
                    )
                    .await
                    {
                        tracing::warn!(
                            sender = %sender_key,
                            "post-admission certificate observer timed out"
                        );
                    }
                }
            }
            None => {
                tracing::debug!("certificate receiver closed");
                break;
            }
        }
    }
    tracing::debug!("certificate listener task exiting");
}

async fn invoke_certificate_observer(
    callback: &Arc<OnCertificatesReceived>,
    sender_key: String,
    certificates: Vec<VerifiableCertificate>,
    timeout: Duration,
) -> bool {
    tokio::time::timeout(timeout, callback(sender_key, certificates))
        .await
        .is_ok()
}

/// Enqueue one compatibility-only observer event without applying backpressure
/// to SDK admission. A full or closed queue drops the observation; admission
/// has already completed and is never rolled back or changed by this result.
pub(crate) fn try_enqueue_certificate_observation(
    cert_tx: &mpsc::Sender<(String, Vec<VerifiableCertificate>)>,
    event: (String, Vec<VerifiableCertificate>),
) -> bool {
    match cert_tx.try_send(event) {
        Ok(()) => true,
        Err(TrySendError::Full((sender_key, _))) => {
            tracing::warn!(
                sender = %sender_key,
                capacity = cert_tx.max_capacity(),
                "post-admission certificate observer queue full; dropping observation"
            );
            false
        }
        Err(TrySendError::Closed((sender_key, _))) => {
            tracing::warn!(
                sender = %sender_key,
                "post-admission certificate observer closed; dropping observation"
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use bsv::auth::certificates::master::MasterCertificate;
    use bsv::primitives::private_key::PrivateKey;
    use bsv::wallet::interfaces::{CertificateType, GetPublicKeyArgs, WalletInterface};
    use indexmap::IndexMap;

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
    fn provisional_batch_rollback_is_owner_scoped_and_retryable() {
        let record = Arc::new(SessionCertificates {
            identity_key: "peer".to_string(),
            batch: std::sync::Mutex::new(Some(SessionCertificateBatch::Provisional {
                owner: 1,
                certificates: Vec::new(),
            })),
        });
        let cancelled = ProvisionalSessionBatch {
            record: record.clone(),
            owner: 1,
            armed: true,
        };
        drop(cancelled);
        assert!(record.batch.lock().unwrap().is_none());

        // A later retry owns a distinct token. Even if an old rollback guard
        // is dropped late, it cannot erase the replacement attempt.
        *record.batch.lock().unwrap() = Some(SessionCertificateBatch::Provisional {
            owner: 2,
            certificates: Vec::new(),
        });
        drop(ProvisionalSessionBatch {
            record: record.clone(),
            owner: 1,
            armed: true,
        });
        assert!(matches!(
            record.batch.lock().unwrap().as_ref(),
            Some(SessionCertificateBatch::Provisional { owner: 2, .. })
        ));

        ProvisionalSessionBatch {
            record: record.clone(),
            owner: 2,
            armed: true,
        }
        .promote()
        .unwrap();
        assert!(matches!(
            record.batch.lock().unwrap().as_ref(),
            Some(SessionCertificateBatch::Committed(_))
        ));
    }

    #[test]
    fn test_release_unknown_key_does_not_panic() {
        let gate = CertificateGate::new();
        gate.release("unknown_key");
    }

    #[test]
    fn compatibility_identity_maps_are_capacity_bounded() {
        let gate = CertificateGate::new().with_observation_limits(2, Duration::from_secs(60));

        gate.register("pending-1");
        gate.register("pending-2");
        gate.register("pending-3");
        assert_eq!(gate.pending.len(), 2);

        gate.mark_validated("validated-1", Vec::new());
        gate.mark_validated("validated-2", Vec::new());
        gate.mark_validated("validated-3", Vec::new());
        assert_eq!(gate.validated.len(), 2);
    }

    #[test]
    fn compatibility_identity_maps_expire_by_ttl() {
        let gate = CertificateGate::new().with_observation_limits(4, Duration::from_millis(1));
        gate.register("pending");
        gate.mark_validated("validated", Vec::new());
        std::thread::sleep(Duration::from_millis(5));

        gate.register("trigger-prune");
        assert!(!gate.pending.contains_key("pending"));
        assert!(gate.validated_for("validated").is_none());
    }

    #[test]
    fn observer_event_queue_drops_over_capacity_without_growing() {
        let (cert_tx, mut cert_rx) = mpsc::channel(2);
        assert!(try_enqueue_certificate_observation(
            &cert_tx,
            ("one".to_string(), Vec::new())
        ));
        assert!(try_enqueue_certificate_observation(
            &cert_tx,
            ("two".to_string(), Vec::new())
        ));
        assert!(!try_enqueue_certificate_observation(
            &cert_tx,
            ("dropped".to_string(), Vec::new())
        ));

        assert_eq!(cert_rx.try_recv().unwrap().0, "one");
        assert_eq!(cert_rx.try_recv().unwrap().0, "two");
        assert!(matches!(
            cert_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn observer_callback_is_cancelled_at_fixed_deadline() {
        let callback: OnCertificatesReceived = Box::new(|_, _| Box::pin(std::future::pending()));
        assert!(
            !invoke_certificate_observer(
                &Arc::new(callback),
                "identity".to_string(),
                Vec::new(),
                Duration::from_millis(10),
            )
            .await
        );
    }

    #[tokio::test]
    async fn session_pruning_tracks_sdk_cap_idle_expiry_and_current_batches() {
        use bsv::auth::session_manager::SessionManager;
        use bsv::auth::types::PeerSession;
        // Use the actual SDK lifecycle implementation with explicit test time,
        // not a wall-clock sleep or an expanded SDK API. The wire test separately
        // drives Peer through its real 1024-session cap.
        const CAP: usize = 1024;
        let mut manager = SessionManager::with_config(100, 100);
        let gate = CertificateGate::new();
        let issuer = ProtoWallet::new(PrivateKey::from_random().unwrap());
        let subject = PrivateKey::from_random().unwrap().to_public_key();
        let identity = subject.to_der_hex();
        let certs = [
            issue(&issuer, &subject, [4; 32]).await,
            issue(&issuer, &subject, [4; 32]).await,
        ];
        for index in 0..CAP + 2 {
            let nonce = index.to_string();
            manager.add_session_capped(
                PeerSession {
                    session_nonce: nonce.clone(),
                    peer_identity_key: identity.clone(),
                    peer_nonce: format!("peer-{index}"),
                    is_authenticated: true,
                    requested_certificates: None,
                    certificates_required: true,
                    certificates_validated: true,
                },
                0,
                CAP,
            );
            gate.sessions.insert(
                nonce,
                Arc::new(SessionCertificates {
                    identity_key: identity.clone(),
                    batch: std::sync::Mutex::new(Some(SessionCertificateBatch::Committed(vec![
                        certs[index % 2].clone(),
                    ]))),
                }),
            );
        }
        gate.prune_sessions_using(|nonce| {
            std::future::ready(
                manager
                    .get_active_session(&nonce, 0)
                    .map(|s| s.peer_identity_key.clone()),
            )
        })
        .await;
        assert_eq!(gate.sessions.len(), CAP);
        assert!(gate.validated_for_session("0", &identity).await.is_none());
        assert!(gate.validated_for_session("1", &identity).await.is_none());
        for index in CAP..CAP + 2 {
            manager.touch(&index.to_string(), 50);
        }
        // All but the two touched concurrent sessions expire at t=101.
        gate.prune_sessions_using(|nonce| {
            std::future::ready(
                manager
                    .get_active_session(&nonce, 101)
                    .map(|s| s.peer_identity_key.clone()),
            )
        })
        .await;
        assert_eq!(gate.sessions.len(), 2);
        for index in CAP..CAP + 2 {
            assert_eq!(
                gate.validated_for_session(&index.to_string(), &identity)
                    .await
                    .unwrap()[0]
                    .serial_number,
                certs[index % 2].serial_number
            );
        }
        gate.prune_sessions_using(|nonce| {
            std::future::ready(
                manager
                    .get_active_session(&nonce, 151)
                    .map(|s| s.peer_identity_key.clone()),
            )
        })
        .await;
        assert!(gate.sessions.is_empty());
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
    ) -> VerifiableCertificate {
        let mut fields = IndexMap::new();
        fields.insert("firstName".to_string(), "Alice".to_string());
        let certificate = MasterCertificate::issue_certificate_for_subject(
            &CertificateType(cert_type),
            subject,
            fields,
            certifier,
            // bsv-sdk 0.2.89 restored the TS `getRevocationOutpoint(serial)`
            // callback: the SDK does not mint a revocation token, the caller does.
            // Test certs use the SDK default (the all-zeros sentinel = not
            // revocable), which is fine here — nothing exercises revocation.
            bsv::auth::certificates::master::default_get_revocation_outpoint,
            None,
        )
        .await
        .unwrap()
        .certificate
        .clone();
        VerifiableCertificate::new(certificate, IndexMap::new())
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
        let (cert_tx, cert_rx) = mpsc::channel(4);

        let task = tokio::spawn(certificate_listener_task(cert_rx, gate.clone(), pol, None));

        cert_tx.send((sender.clone(), vec![cert])).await.unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(gate.validated_for(&sender).is_some());

        drop(cert_tx);
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
        let (cert_tx, cert_rx) = mpsc::channel(4);

        let task = tokio::spawn(certificate_listener_task(cert_rx, gate.clone(), pol, None));

        cert_tx
            .send(("sender_1".to_string(), vec![]))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            gate.validated_for("sender_1").is_none(),
            "empty batch must not release the gate"
        );

        drop(cert_tx);
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
        let (cert_tx, cert_rx) = mpsc::channel(4);

        let task = tokio::spawn(certificate_listener_task(
            cert_rx,
            gate.clone(),
            pol,
            Some(Arc::new(callback)),
        ));

        cert_tx.send((sender.clone(), vec![cert])).await.unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(
            called.load(Ordering::SeqCst),
            "callback should fire on validated certs"
        );

        drop(cert_tx);
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }

    #[tokio::test]
    async fn test_listener_exits_when_certificate_channel_closes() {
        let gate = CertificateGate::new();
        let (cert_tx, cert_rx) = mpsc::channel::<(String, Vec<VerifiableCertificate>)>(4);
        let pol = Arc::new(CertificateValidationPolicy::default());

        let task = tokio::spawn(certificate_listener_task(cert_rx, gate, pol, None));

        drop(cert_tx);

        let result = tokio::time::timeout(Duration::from_secs(2), task).await;
        assert!(result.is_ok(), "task should have completed");
        assert!(result.unwrap().is_ok(), "task should not have panicked");
    }
}
