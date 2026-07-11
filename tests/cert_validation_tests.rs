//! TDD tests for server-side certificate validation (CUSTODY-AUTH).
//!
//! These tests pin the security-critical behaviour of the certificate gate:
//! a certificate must (1) bind to the sender's identity key, (2) be signed by a
//! certifier in the server's configured trusted set, (3) match a requested type,
//! and (4) carry a valid certifier signature — BEFORE the per-identity gate is
//! released and the certs surfaced to the handler. A live session with no valid
//! certificate must NOT pass a cert-required endpoint (F1 fix).

mod common;

use std::collections::HashMap;
use std::time::Duration;

use bsv::auth::certificates::master::MasterCertificate;
use bsv::primitives::private_key::PrivateKey;
use bsv::primitives::public_key::PublicKey;
use bsv::wallet::interfaces::{Certificate, CertificateType};
use bsv::wallet::proto_wallet::ProtoWallet;

use bsv_auth_axum_middleware::certificate::{
    certificate_listener_task, validate_certificate, CertRejectReason, CertificateGate,
    CertificateValidationPolicy,
};

use bsv::auth::types::RequestedCertificateSet;
use std::sync::Arc;
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Issue a real, certifier-signed certificate for `subject`.
async fn issue_cert(
    certifier: &ProtoWallet,
    subject_pubkey: &PublicKey,
    cert_type: [u8; 32],
) -> Certificate {
    let mut fields = HashMap::new();
    fields.insert("firstName".to_string(), "Alice".to_string());
    let mc = MasterCertificate::issue_certificate_for_subject(
        &CertificateType(cert_type),
        subject_pubkey,
        fields,
        certifier,
    )
    .await
    .expect("issue cert");
    mc.certificate.clone()
}

fn policy(trusted: Vec<String>, types: HashMap<String, Vec<String>>) -> CertificateValidationPolicy {
    CertificateValidationPolicy {
        trusted_certifiers: trusted,
        requested_types: types,
    }
}

/// Drive one cert batch through the listener task and return the gate afterwards.
/// Registers a waiter for `sender` first so the release path is exercised.
async fn run_listener_once(
    sender: &str,
    certs: Vec<Certificate>,
    policy: CertificateValidationPolicy,
) -> CertificateGate {
    let gate = CertificateGate::new();
    let _notify = gate.register(sender);
    let (cert_tx, cert_rx) = mpsc::channel(8);
    let (_req_tx, req_rx) = mpsc::channel::<(String, RequestedCertificateSet)>(8);

    let task = tokio::spawn(certificate_listener_task(
        cert_rx,
        req_rx,
        gate.clone(),
        Arc::new(policy),
        None,
    ));

    cert_tx.send((sender.to_string(), certs)).await.unwrap();
    // Give the listener time to validate + (maybe) release.
    tokio::time::sleep(Duration::from_millis(80)).await;

    drop(cert_tx);
    drop(_req_tx);
    let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    gate
}

// ---------------------------------------------------------------------------
// Test 1 — cert from an UNTRUSTED certifier is rejected (gate NOT released)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_untrusted_certifier_is_rejected() {
    let certifier = ProtoWallet::new(PrivateKey::from_random().unwrap());
    let subject_pk = PrivateKey::from_random().unwrap();
    let subject_pub = subject_pk.to_public_key();
    let sender = subject_pub.to_der_hex();
    let cert = issue_cert(&certifier, &subject_pub, [5u8; 32]).await;

    // Trusted set contains a DIFFERENT certifier.
    let other = PrivateKey::from_random().unwrap().to_public_key().to_der_hex();
    let pol = policy(vec![other], HashMap::new());
    let verifier = ProtoWallet::anyone();

    let res = validate_certificate(&cert, &sender, &pol, &verifier).await;
    assert_eq!(res, Err(CertRejectReason::UntrustedCertifier));

    // And through the listener: the gate must NOT be released.
    let gate = run_listener_once(&sender, vec![cert], pol).await;
    assert!(
        gate.validated_for(&sender).is_none(),
        "untrusted certifier must not release the gate"
    );
}

// ---------------------------------------------------------------------------
// Test 2 — cert failing subject-bind is rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_subject_bind_mismatch_is_rejected() {
    let certifier = ProtoWallet::new(PrivateKey::from_random().unwrap());
    let subject_pk = PrivateKey::from_random().unwrap();
    let subject_pub = subject_pk.to_public_key();
    let cert = issue_cert(&certifier, &subject_pub, [6u8; 32]).await;

    // Sender identity differs from the certificate subject.
    let wrong_sender = PrivateKey::from_random().unwrap().to_public_key().to_der_hex();
    let trusted = vec![certifier_hex(&certifier).await];
    let pol = policy(trusted, HashMap::new());
    let verifier = ProtoWallet::anyone();

    let res = validate_certificate(&cert, &wrong_sender, &pol, &verifier).await;
    assert_eq!(res, Err(CertRejectReason::SubjectMismatch));

    let gate = run_listener_once(&wrong_sender, vec![cert], pol).await;
    assert!(gate.validated_for(&wrong_sender).is_none());
}

// ---------------------------------------------------------------------------
// Test 3 — cert with a bad certifier signature is rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_bad_certifier_signature_is_rejected() {
    let certifier = ProtoWallet::new(PrivateKey::from_random().unwrap());
    let subject_pk = PrivateKey::from_random().unwrap();
    let subject_pub = subject_pk.to_public_key();
    let sender = subject_pub.to_der_hex();
    let mut cert = issue_cert(&certifier, &subject_pub, [7u8; 32]).await;

    // Tamper the signature bytes.
    if let Some(sig) = cert.signature.as_mut() {
        for b in sig.iter_mut() {
            *b ^= 0xFF;
        }
    }

    let trusted = vec![certifier_hex(&certifier).await];
    let pol = policy(trusted, HashMap::new());
    let verifier = ProtoWallet::anyone();

    let res = validate_certificate(&cert, &sender, &pol, &verifier).await;
    assert_eq!(res, Err(CertRejectReason::BadSignature));

    let gate = run_listener_once(&sender, vec![cert], pol).await;
    assert!(gate.validated_for(&sender).is_none());
}

// ---------------------------------------------------------------------------
// Test 4 — valid cert from a TRUSTED certifier releases the gate + is surfaced
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_valid_trusted_cert_releases_and_surfaces() {
    let certifier = ProtoWallet::new(PrivateKey::from_random().unwrap());
    let subject_pk = PrivateKey::from_random().unwrap();
    let subject_pub = subject_pk.to_public_key();
    let sender = subject_pub.to_der_hex();
    let cert = issue_cert(&certifier, &subject_pub, [8u8; 32]).await;

    let trusted = vec![certifier_hex(&certifier).await];
    let pol = policy(trusted, HashMap::new());
    let verifier = ProtoWallet::anyone();

    let res = validate_certificate(&cert, &sender, &pol, &verifier).await;
    assert_eq!(res, Ok(()));

    let gate = run_listener_once(&sender, vec![cert.clone()], pol).await;
    let surfaced = gate
        .validated_for(&sender)
        .expect("valid cert must release the gate and be surfaced");
    assert_eq!(surfaced.len(), 1);
    assert_eq!(surfaced[0].subject, subject_pub);
}

// ---------------------------------------------------------------------------
// Test 4b — type PIN: valid cert whose type is NOT requested is rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_unrequested_type_is_rejected() {
    let certifier = ProtoWallet::new(PrivateKey::from_random().unwrap());
    let subject_pk = PrivateKey::from_random().unwrap();
    let subject_pub = subject_pk.to_public_key();
    let sender = subject_pub.to_der_hex();
    let cert = issue_cert(&certifier, &subject_pub, [9u8; 32]).await;

    // Requested types contains a DIFFERENT type id.
    let mut types = HashMap::new();
    use base64::Engine;
    let other_type = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
    types.insert(other_type, vec!["firstName".to_string()]);

    let pol = policy(vec![certifier_hex(&certifier).await], types);
    let verifier = ProtoWallet::anyone();

    let res = validate_certificate(&cert, &sender, &pol, &verifier).await;
    assert_eq!(res, Err(CertRejectReason::UnrequestedType));
}

// ---------------------------------------------------------------------------
// Test 5 — empty trusted set = cert-gate not engaged (certs not required)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_empty_trusted_set_means_gate_not_engaged() {
    use bsv_auth_axum_middleware::config::AuthMiddlewareConfigBuilder;
    use bsv_auth_axum_middleware::middleware::AuthLayer;
    use bsv_auth_axum_middleware::transport::ActixTransport;

    let transport = std::sync::Arc::new(ActixTransport::new());
    let wallet = common::mock_wallet::MockWallet::new(PrivateKey::from_random().unwrap());
    let peer = std::sync::Arc::new(bsv::auth::peer::Peer::new(wallet.clone(), transport.clone()));

    // No trusted_certifiers configured -> no cert gate, even with types set.
    let mut certs = RequestedCertificateSet::default();
    certs.types.insert("someType".to_string(), vec!["f".to_string()]);
    let config = AuthMiddlewareConfigBuilder::new()
        .wallet(wallet)
        .certificates_to_request(certs)
        .build()
        .unwrap();

    let layer = AuthLayer::from_config(config, peer, transport)
        .await
        .expect("from_config");
    assert!(
        layer.certificate_gate_ref().is_none(),
        "empty trusted set must not engage the certificate gate"
    );
}

// ---------------------------------------------------------------------------
// Test 6 — F1 fix: a live session with NO valid cert does NOT pass the gate
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_f1_session_without_valid_cert_does_not_pass() {
    // A self-generated identity registers a waiter (as the middleware would),
    // but no validated certificate is ever recorded. Prior to the fix the gate
    // released on session existence; now it must stay closed.
    let gate = CertificateGate::new();
    let self_identity = PrivateKey::from_random().unwrap().to_public_key().to_der_hex();

    let notify = gate.register(&self_identity);

    // No mark_validated -> nothing to authorize this identity.
    assert!(
        gate.validated_for(&self_identity).is_none(),
        "an identity with only a session (no validated cert) must not be authorized"
    );

    // The middleware awaits the gate; with no cert it must time out (blocked).
    let waited = tokio::time::timeout(Duration::from_millis(150), notify.notified()).await;
    assert!(
        waited.is_err(),
        "gate must remain closed for a session that presented no valid certificate"
    );
}

// ---------------------------------------------------------------------------

/// The compressed-hex identity key of a ProtoWallet certifier.
async fn certifier_hex(certifier: &ProtoWallet) -> String {
    use bsv::wallet::interfaces::{GetPublicKeyArgs, WalletInterface};
    let r = certifier
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
