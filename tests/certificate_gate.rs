//! Integration tests for `CertificateGate` + `certificate_listener_task`.
//!
//! The same types are already covered by 8 unit tests inside
//! `src/certificate.rs`. This file exists to pin the PUBLIC surface of the
//! same primitives, accessed through the crate's re-exports, so a future
//! breaking-visibility refactor (e.g. moving `certificate_listener_task`
//! behind a private module) surfaces as an integration-test failure rather
//! than being caught only by the internal unit tests.
//!
//! Plus one test the unit layer can't: a combined "register → timeout → a
//! late certificate arrival still doesn't crash the listener" scenario that
//! spans several async tasks and would be awkward inside a `#[cfg(test)]`
//! module.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bsv::auth::types::RequestedCertificateSet;
use bsv::wallet::interfaces::Certificate;
use bsv_auth_axum_middleware::certificate::certificate_listener_task;
use bsv_auth_axum_middleware::CertificateGate;
use tokio::sync::mpsc;

/// Test 1 — a certificate delivery to the listener's channel releases the
/// gate for the matching identity key.
#[tokio::test(flavor = "multi_thread")]
async fn test_certificate_arrival_releases_gate() {
    let gate = CertificateGate::new();
    let notify = gate.register("identity_key_A");

    let (cert_tx, cert_rx) = mpsc::channel(4);
    let (_cert_req_tx, cert_req_rx) = mpsc::channel::<(String, RequestedCertificateSet)>(4);

    let task = tokio::spawn(certificate_listener_task(
        cert_rx,
        cert_req_rx,
        gate.clone(),
        None,
    ));

    // Feed a certificate for the registered identity.
    cert_tx
        .send(("identity_key_A".to_string(), Vec::<Certificate>::new()))
        .await
        .expect("send certificate");

    // Gate should be released within a short window.
    let waited = tokio::time::timeout(Duration::from_secs(2), notify.notified()).await;
    assert!(waited.is_ok(), "gate should be released by cert arrival");

    // Close channels and let the listener exit cleanly.
    drop(cert_tx);
    let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
}

/// Test 2 — awaiting on a gate that is never released times out via
/// `tokio::time::timeout`; the surrounding code returns control instead of
/// hanging forever.
#[tokio::test(flavor = "multi_thread")]
async fn test_certificate_gate_timeout() {
    let gate = CertificateGate::new();
    let notify = gate.register("identity_key_B");

    // We deliberately do NOT spawn a listener task — no cert will arrive.
    let waited = tokio::time::timeout(Duration::from_millis(200), notify.notified()).await;
    assert!(waited.is_err(), "waiter should time out");

    // `release` on an untouched gate is safe (the key is still registered but
    // nobody is waiting anymore — verify we can still call it without panic).
    gate.release("identity_key_B");
}

/// Test 3 — a certificate callback that panics does NOT crash the listener.
///
/// This duplicates the in-module unit test to pin the public surface: a
/// consumer registering an `OnCertificatesReceived` callback via
/// `AuthMiddlewareConfigBuilder` can rely on the listener being
/// panic-resistant. If the listener ever started aborting on callback
/// panics, middleware consumers would silently drop all future certs.
#[tokio::test(flavor = "multi_thread")]
async fn test_listener_handles_callback_panic_gracefully() {
    let invoke_count = Arc::new(AtomicUsize::new(0));
    let invoke_count_cb = invoke_count.clone();

    let callback: bsv_auth_axum_middleware::OnCertificatesReceived =
        Box::new(move |_key, _certs| {
            let ic = invoke_count_cb.clone();
            Box::pin(async move {
                ic.fetch_add(1, Ordering::SeqCst);
                panic!("intentional panic in callback");
            })
        });

    let gate = CertificateGate::new();
    let (cert_tx, cert_rx) = mpsc::channel(4);
    let (_cert_req_tx, cert_req_rx) = mpsc::channel::<(String, RequestedCertificateSet)>(4);

    let task = tokio::spawn(certificate_listener_task(
        cert_rx,
        cert_req_rx,
        gate.clone(),
        Some(Arc::new(callback)),
    ));

    // First cert triggers the panic inside the spawned callback task.
    cert_tx
        .send(("identity_key_C".to_string(), Vec::<Certificate>::new()))
        .await
        .expect("send first cert");

    // Give the spawned callback a moment to panic.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Listener must still be alive: a SECOND cert should still be processed.
    cert_tx
        .send(("identity_key_D".to_string(), Vec::<Certificate>::new()))
        .await
        .expect("send second cert (listener should still be alive)");

    // Give the second callback a moment to try to run (it will also panic,
    // but in a different spawned task).
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(
        invoke_count.load(Ordering::SeqCst),
        2,
        "callback should have been invoked twice even though both invocations panicked"
    );

    // Shut down cleanly.
    drop(cert_tx);
    let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
}

/// Test 4 — late certificate arrival after the waiter has already given up.
///
/// Registers a gate, awaits with a short timeout that expires, THEN feeds a
/// cert into the listener. The listener should process it without panicking
/// even though nobody is listening on the `notify` anymore. This covers an
/// edge case unit tests don't touch cleanly: the transition from "waiter
/// waiting" → "waiter timed out" → "cert arrives late".
#[tokio::test(flavor = "multi_thread")]
async fn test_late_certificate_after_waiter_timeout_is_safe() {
    let gate = CertificateGate::new();
    let notify = gate.register("identity_key_E");

    let (cert_tx, cert_rx) = mpsc::channel(4);
    let (_cert_req_tx, cert_req_rx) = mpsc::channel::<(String, RequestedCertificateSet)>(4);

    let task = tokio::spawn(certificate_listener_task(
        cert_rx,
        cert_req_rx,
        gate.clone(),
        None,
    ));

    // The waiter gives up quickly.
    let waited = tokio::time::timeout(Duration::from_millis(100), notify.notified()).await;
    assert!(waited.is_err(), "waiter should time out");

    // Late cert arrives.
    cert_tx
        .send(("identity_key_E".to_string(), Vec::<Certificate>::new()))
        .await
        .expect("late cert send");

    // Give the listener a tick to process.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // The listener should still be alive and the gate should be cleaned up.
    // Registering the same key again returns a fresh Notify (not Arc-equal to
    // the first one because `release` removed the entry).
    let notify_again = gate.register("identity_key_E");
    assert!(
        !Arc::ptr_eq(&notify, &notify_again),
        "release + re-register should produce a fresh Notify"
    );

    drop(cert_tx);
    let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
}
