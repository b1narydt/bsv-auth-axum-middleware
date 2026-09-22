//! Same-wallet credentials belong to the session that proved them.
#[path = "common/mock_wallet.rs"]
mod mock_wallet;

use axum::{routing::get, Json, Router};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use bsv::auth::{
    certificates::master::{default_get_revocation_outpoint, MasterCertificate},
    clients::AuthFetch,
    peer::Peer,
    types::RequestedCertificateSet,
};
use bsv::primitives::private_key::PrivateKey;
use bsv::wallet::interfaces::CertificateType;
use bsv_auth_axum_middleware::{
    ActixTransport, AuthLayer, AuthMiddlewareConfigBuilder, Authenticated,
    CertificateAuthorizationDecision, CertificateAuthorizer, CertificateGate,
};
use indexmap::IndexMap;
use mock_wallet::MockWallet;
use std::sync::Arc;

async fn read(fetch: &AuthFetch<MockWallet>, url: &str) -> String {
    let response = fetch.fetch(url, "GET", None, None).await.unwrap();
    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    serde_json::from_slice(&response.body).unwrap()
}

#[tokio::test]
async fn same_wallet_distinct_sessions_keep_their_own_certificates() {
    for fields in [vec![], vec!["name".to_string()]] {
        for reverse in [false, true] {
            let issuer_key = PrivateKey::from_random().unwrap();
            let issuer_id = issuer_key.to_public_key().to_der_hex();
            let issuer = MockWallet::new(issuer_key);
            let holder_key = PrivateKey::from_random().unwrap();
            let holder_hex = holder_key.to_hex();
            let subject = holder_key.to_public_key();
            let first = MockWallet::new(PrivateKey::from_hex(&holder_hex).unwrap());
            let second = MockWallet::new(PrivateKey::from_hex(&holder_hex).unwrap());
            let mut serials = Vec::new();
            for wallet in [&first, &second] {
                let cert = MasterCertificate::issue_certificate_for_subject(
                    &CertificateType([42; 32]),
                    &subject,
                    IndexMap::from([("name".to_string(), "Alice".to_string())]),
                    &issuer,
                    default_get_revocation_outpoint,
                    None,
                )
                .await
                .unwrap();
                serials.push(B64.encode(cert.certificate.serial_number.0));
                wallet.add_master_certificate(cert).await;
            }
            assert_ne!(serials[0], serials[1]);
            let server = MockWallet::new(PrivateKey::from_random().unwrap());
            let transport = Arc::new(ActixTransport::new());
            let peer = Arc::new(Peer::new(server.clone(), transport.clone()));
            let requested = RequestedCertificateSet {
                certifiers: vec![issuer_id.clone()],
                types: IndexMap::from([(B64.encode([42; 32]), fields.clone())]),
            };
            let config = AuthMiddlewareConfigBuilder::new()
                .wallet(server)
                .trusted_certifiers(vec![issuer_id])
                .certificate_authorizer(Box::new(|_, _| {
                    Box::pin(async {
                        bsv_auth_axum_middleware::CertificateAuthorizationDecision::Accept
                    })
                }))
                .certificates_to_request(requested)
                .build()
                .unwrap();
            let layer = AuthLayer::from_config(config, peer, transport)
                .await
                .unwrap();
            let app = Router::new()
                .route(
                    "/",
                    get(|auth: Authenticated| async move {
                        Json(B64.encode(auth.certificates[0].serial_number.0))
                    }),
                )
                .layer(layer);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/", listener.local_addr().unwrap());
            let task = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            let clients = [AuthFetch::new(first), AuthFetch::new(second)];
            let order = if reverse { [1, 0] } else { [0, 1] };
            for index in order {
                assert_eq!(read(&clients[index], &url).await, serials[index]);
            }
            for _ in 0..3 {
                let (a, b) = tokio::join!(read(&clients[0], &url), read(&clients[1], &url));
                assert_eq!(a, serials[0], "first session borrowed successor authority");
                assert_eq!(
                    b, serials[1],
                    "second session borrowed predecessor authority"
                );
            }
            task.abort();
        }
    }
}

// Low-level frames let hostile tests vary sender-selected metadata without
// relying on AuthFetch to construct only honest exchanges.
async fn handshake(http: &reqwest::Client, url: &str, holder: &str) -> String {
    let response = http
        .post(format!("{url}.well-known/auth"))
        .json(&serde_json::json!({
            "version":"0.1", "messageType":"initialRequest", "identityKey":holder,
            "initialNonce": B64.encode([9;32])
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let message: bsv::auth::types::AuthMessage = response.json().await.unwrap();
    message.initial_nonce.unwrap()
}

async fn proof_message(
    wallet: &MockWallet,
    identity: &str,
    verifier: &str,
    session: &str,
    cert: bsv::auth::certificates::VerifiableCertificate,
    tag: u8,
) -> bsv::auth::types::AuthMessage {
    use bsv::primitives::public_key::PublicKey;
    use bsv::wallet::interfaces::{CreateSignatureArgs, WalletInterface};
    use bsv::wallet::types::{Counterparty, CounterpartyType, Protocol};
    let nonce = B64.encode([tag; 32]);
    let certs = vec![cert];
    let signature = wallet
        .create_signature(
            CreateSignatureArgs {
                data: Some(serde_json::to_vec(&certs).unwrap()),
                hash_to_directly_sign: None,
                protocol_id: Protocol {
                    security_level: 2,
                    protocol: bsv::auth::types::AUTH_PROTOCOL_ID.to_string(),
                },
                key_id: format!("{nonce} {session}"),
                counterparty: Counterparty {
                    counterparty_type: CounterpartyType::Other,
                    public_key: Some(PublicKey::from_string(verifier).unwrap()),
                },
                privileged: false,
                privileged_reason: None,
                seek_permission: None,
            },
            None,
        )
        .await
        .unwrap()
        .signature;
    bsv::auth::types::AuthMessage {
        version: "0.1".to_string(),
        message_type: bsv::auth::types::MessageType::CertificateResponse,
        identity_key: identity.to_string(),
        nonce: Some(nonce),
        your_nonce: Some(session.to_string()),
        initial_nonce: None,
        certificates: Some(certs),
        requested_certificates: None,
        payload: None,
        signature: Some(signature),
    }
}

async fn general_headers(
    wallet: &MockWallet,
    identity: &str,
    verifier: &str,
    session: &str,
    tag: u8,
    valid_signature: bool,
) -> reqwest::header::HeaderMap {
    use bsv::primitives::public_key::PublicKey;
    use bsv::wallet::interfaces::{CreateSignatureArgs, WalletInterface};
    use bsv::wallet::types::{Counterparty, CounterpartyType, Protocol};
    use reqwest::header::{HeaderMap, HeaderValue};

    let message_nonce = B64.encode([tag; 32]);
    let request_id = B64.encode([tag.wrapping_add(1); 32]);
    let payload = bsv_auth_axum_middleware::payload::serialize_request_payload(
        &B64.decode(&request_id).unwrap(),
        "GET",
        "/",
        "",
        &[],
        None,
    );
    let signature = wallet
        .create_signature(
            CreateSignatureArgs {
                data: Some(payload),
                hash_to_directly_sign: None,
                protocol_id: Protocol {
                    security_level: 2,
                    protocol: bsv::auth::types::AUTH_PROTOCOL_ID.to_string(),
                },
                key_id: format!("{message_nonce} {session}"),
                counterparty: Counterparty {
                    counterparty_type: CounterpartyType::Other,
                    public_key: Some(PublicKey::from_string(verifier).unwrap()),
                },
                privileged: false,
                privileged_reason: None,
                seek_permission: None,
            },
            None,
        )
        .await
        .unwrap()
        .signature;
    let header_request_id = if valid_signature {
        request_id
    } else {
        B64.encode([tag.wrapping_add(2); 32])
    };

    let mut headers = HeaderMap::new();
    for (name, value) in [
        ("x-bsv-auth-version", "0.1".to_string()),
        ("x-bsv-auth-identity-key", identity.to_string()),
        ("x-bsv-auth-nonce", message_nonce),
        ("x-bsv-auth-your-nonce", session.to_string()),
        ("x-bsv-auth-signature", hex::encode(signature)),
        ("x-bsv-auth-request-id", header_request_id),
    ] {
        headers.insert(name, HeaderValue::from_str(&value).unwrap());
    }
    headers
}

async fn start_policy_server(
    authorizer: CertificateAuthorizer,
) -> (
    String,
    tokio::task::JoinHandle<()>,
    MockWallet,
    String,
    String,
    bsv::auth::certificates::VerifiableCertificate,
    CertificateGate,
    Arc<std::sync::atomic::AtomicBool>,
    Arc<Peer<MockWallet>>,
) {
    use bsv::auth::certificates::VerifiableCertificate;
    use std::sync::atomic::{AtomicBool, Ordering};

    let issuer_key = PrivateKey::from_random().unwrap();
    let issuer_id = issuer_key.to_public_key().to_der_hex();
    let issuer = MockWallet::new(issuer_key);
    let holder_key = PrivateKey::from_random().unwrap();
    let subject = holder_key.to_public_key();
    let holder = subject.to_der_hex();
    let wallet = MockWallet::new(holder_key);
    let certificate = MasterCertificate::issue_certificate_for_subject(
        &CertificateType([42; 32]),
        &subject,
        IndexMap::from([("name".to_string(), "Alice".to_string())]),
        &issuer,
        default_get_revocation_outpoint,
        None,
    )
    .await
    .unwrap();
    let certificate = VerifiableCertificate::new(certificate.certificate, IndexMap::new());
    let server_key = PrivateKey::from_random().unwrap();
    let verifier = server_key.to_public_key().to_der_hex();
    let server = MockWallet::new(server_key);
    let transport = Arc::new(ActixTransport::new());
    let peer = Arc::new(Peer::new(server.clone(), transport.clone()));
    let requested = RequestedCertificateSet {
        certifiers: vec![issuer_id.clone()],
        types: IndexMap::from([(B64.encode([42; 32]), vec![])]),
    };
    let config = AuthMiddlewareConfigBuilder::new()
        .wallet(server)
        .trusted_certifiers(vec![issuer_id])
        .certificate_authorizer(authorizer)
        .certificates_to_request(requested)
        .build()
        .unwrap();
    let layer = AuthLayer::from_config(config, peer.clone(), transport)
        .await
        .unwrap();
    let gate = layer.certificate_gate_ref().unwrap().clone();
    let handler_called = Arc::new(AtomicBool::new(false));
    let handler_called_for_route = handler_called.clone();
    let app = Router::new()
        .route(
            "/",
            get(move || {
                let handler_called = handler_called_for_route.clone();
                async move {
                    handler_called.store(true, Ordering::SeqCst);
                    "ok"
                }
            }),
        )
        .layer(layer);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (
        url,
        task,
        wallet,
        holder,
        verifier,
        certificate,
        gate,
        handler_called,
        peer,
    )
}

#[tokio::test]
async fn rejected_authorizer_yields_signed_403_but_invalid_request_stays_unsigned() {
    use std::sync::atomic::Ordering;

    let authorizer: CertificateAuthorizer = Box::new(|_, _| {
        Box::pin(async { CertificateAuthorizationDecision::Reject("revoked".to_string()) })
    });
    let (url, task, wallet, holder, verifier, certificate, gate, handler_called, _peer) =
        start_policy_server(authorizer).await;
    let http = reqwest::Client::new();
    let session = handshake(&http, &url, &holder).await;
    let proof = proof_message(&wallet, &holder, &verifier, &session, certificate, 60).await;
    let proof_response = http
        .post(format!("{url}.well-known/auth"))
        .json(&proof)
        .send()
        .await
        .unwrap();
    assert_ne!(proof_response.status(), 200);
    assert!(proof_response
        .headers()
        .get("x-bsv-auth-signature")
        .is_none());
    assert!(gate
        .validated_for_session(&session, &holder)
        .await
        .is_none());

    let response = http
        .get(&url)
        .headers(general_headers(&wallet, &holder, &verifier, &session, 61, true).await)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    assert!(response.headers().get("x-bsv-auth-signature").is_some());
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["code"], "ERR_CERTIFICATE_REJECTED");
    assert_eq!(body["description"], "revoked");
    assert!(!handler_called.load(Ordering::SeqCst));

    let invalid = http
        .get(&url)
        .headers(general_headers(&wallet, &holder, &verifier, &session, 62, false).await)
        .send()
        .await
        .unwrap();
    assert!(!invalid.status().is_success());
    assert_ne!(invalid.status(), 403);
    assert_ne!(invalid.status(), 408);
    assert!(invalid.headers().get("x-bsv-auth-signature").is_none());
    assert!(!handler_called.load(Ordering::SeqCst));
    task.abort();
}

#[tokio::test(start_paused = true)]
async fn pending_and_timed_out_authorizer_yield_signed_408() {
    use std::sync::atomic::Ordering;

    let started = Arc::new(tokio::sync::Notify::new());
    let started_for_authorizer = started.clone();
    let authorizer: CertificateAuthorizer = Box::new(move |_, _| {
        let started = started_for_authorizer.clone();
        Box::pin(async move {
            started.notify_waiters();
            std::future::pending::<CertificateAuthorizationDecision>().await
        })
    });
    let (url, task, wallet, holder, verifier, certificate, gate, handler_called, _peer) =
        start_policy_server(authorizer).await;
    let http = reqwest::Client::new();
    let session = handshake(&http, &url, &holder).await;
    let proof = proof_message(&wallet, &holder, &verifier, &session, certificate, 70).await;
    let started_wait = started.notified();
    let proof_http = http.clone();
    let proof_url = url.clone();
    let proof_request = tokio::spawn(async move {
        proof_http
            .post(format!("{proof_url}.well-known/auth"))
            .json(&proof)
            .send()
            .await
            .unwrap()
    });
    started_wait.await;

    let pending = http
        .get(&url)
        .headers(general_headers(&wallet, &holder, &verifier, &session, 71, true).await)
        .send()
        .await
        .unwrap();
    assert_eq!(pending.status(), 408);
    assert!(pending.headers().get("x-bsv-auth-signature").is_some());
    assert_eq!(
        pending.json::<serde_json::Value>().await.unwrap()["code"],
        "CERTIFICATE_TIMEOUT"
    );

    tokio::time::advance(std::time::Duration::from_secs(31)).await;
    let proof_response = proof_request.await.unwrap();
    assert_eq!(proof_response.status(), 408);
    assert!(proof_response
        .headers()
        .get("x-bsv-auth-signature")
        .is_none());
    let timed_out = http
        .get(&url)
        .headers(general_headers(&wallet, &holder, &verifier, &session, 72, true).await)
        .send()
        .await
        .unwrap();
    assert_eq!(timed_out.status(), 408);
    assert!(timed_out.headers().get("x-bsv-auth-signature").is_some());
    assert!(gate
        .validated_for_session(&session, &holder)
        .await
        .is_none());
    assert!(!handler_called.load(Ordering::SeqCst));
    task.abort();
}

#[tokio::test]
async fn authorized_sdk_session_never_precedes_its_local_certificate_batch() {
    use std::sync::atomic::Ordering;

    let authorizer: CertificateAuthorizer =
        Box::new(|_, _| Box::pin(async { CertificateAuthorizationDecision::Accept }));
    let (url, task, wallet, holder, verifier, certificate, gate, handler_called, peer) =
        start_policy_server(authorizer).await;

    // Hold dispatch after SDK admission but before the proof endpoint returns.
    // Before the ordering fix, local policy validation/storage happened after
    // this listener, exposing an SDK-Authorized/local-empty interval in which
    // a valid general request received a bare unsigned 408.
    let observer_entered = Arc::new(tokio::sync::Notify::new());
    let observer_release = Arc::new(tokio::sync::Notify::new());
    let entered_for_listener = observer_entered.clone();
    let release_for_listener = observer_release.clone();
    peer.listen_for_certificates_received(Arc::new(move |_, _| {
        let entered = entered_for_listener.clone();
        let release = release_for_listener.clone();
        Box::pin(async move {
            entered.notify_one();
            release.notified().await;
            Ok(())
        })
    }));

    let http = reqwest::Client::new();
    let session = handshake(&http, &url, &holder).await;
    let proof = proof_message(&wallet, &holder, &verifier, &session, certificate, 80).await;
    let proof_http = http.clone();
    let proof_url = url.clone();
    let proof_request = tokio::spawn(async move {
        proof_http
            .post(format!("{proof_url}.well-known/auth"))
            .json(&proof)
            .send()
            .await
            .unwrap()
    });

    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        observer_entered.notified(),
    )
    .await
    .expect("certificate observer did not reach the post-admission hold point");
    assert!(gate
        .validated_for_session(&session, &holder)
        .await
        .is_some());

    let general = http
        .get(&url)
        .headers(general_headers(&wallet, &holder, &verifier, &session, 81, true).await)
        .send()
        .await
        .unwrap();
    assert_eq!(general.status(), 200);
    assert!(general.headers().get("x-bsv-auth-signature").is_some());
    assert!(handler_called.load(Ordering::SeqCst));

    observer_release.notify_one();
    let proof_response = tokio::time::timeout(std::time::Duration::from_secs(2), proof_request)
        .await
        .expect("proof dispatch stayed blocked after observer release")
        .unwrap();
    assert_eq!(proof_response.status(), 200);
    task.abort();
}

#[tokio::test]
async fn hostile_frames_and_late_identity_callbacks_cannot_replace_session_authority() {
    use bsv::auth::certificates::VerifiableCertificate;
    let issuer_key = PrivateKey::from_random().unwrap();
    let issuer_id = issuer_key.to_public_key().to_der_hex();
    let issuer = MockWallet::new(issuer_key);
    let key = PrivateKey::from_random().unwrap();
    let subject = key.to_public_key();
    let holder = subject.to_der_hex();
    let wallet = MockWallet::new(key);
    let mut certs = Vec::new();
    for _ in 0..2 {
        let cert = MasterCertificate::issue_certificate_for_subject(
            &CertificateType([42; 32]),
            &subject,
            IndexMap::from([("name".to_string(), "Alice".to_string())]),
            &issuer,
            default_get_revocation_outpoint,
            None,
        )
        .await
        .unwrap();
        certs.push(VerifiableCertificate::new(
            cert.certificate.clone(),
            IndexMap::new(),
        ));
    }
    let server_key = PrivateKey::from_random().unwrap();
    let verifier = server_key.to_public_key().to_der_hex();
    let server = MockWallet::new(server_key);
    let transport = Arc::new(ActixTransport::new());
    let peer = Arc::new(Peer::new(server.clone(), transport.clone()));
    // SDK callbacks may be delayed and delivered through a shared queue.
    // Their completion order carries no session authority.
    peer.listen_for_certificates_received(Arc::new(|_, _| {
        Box::pin(async {
            tokio::time::sleep(std::time::Duration::from_millis(40)).await;
            Ok(())
        })
    }));
    let requested = RequestedCertificateSet {
        certifiers: vec![issuer_id.clone()],
        types: IndexMap::from([(B64.encode([42; 32]), vec![])]),
    };
    let config = AuthMiddlewareConfigBuilder::new()
        .wallet(server)
        .trusted_certifiers(vec![issuer_id])
        .certificate_authorizer(Box::new(|_, _| {
            Box::pin(async { bsv_auth_axum_middleware::CertificateAuthorizationDecision::Accept })
        }))
        .certificates_to_request(requested)
        .build()
        .unwrap();
    let layer = AuthLayer::from_config(config, peer, transport)
        .await
        .unwrap();
    let gate = layer.certificate_gate_ref().unwrap().clone();
    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(layer);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let http = reqwest::Client::new();
    let a = handshake(&http, &url, &holder).await;
    let b = handshake(&http, &url, &holder).await;
    assert_ne!(a, b);
    let endpoint = format!("{url}.well-known/auth");
    // A sender-chosen request cannot make an unrequested certificate admissible.
    let mut forged = proof_message(&wallet, &holder, &verifier, &a, certs[0].clone(), 1).await;
    forged.signature = Some(vec![0; 64]);
    forged.requested_certificates = Some(RequestedCertificateSet::default());
    assert_ne!(
        http.post(&endpoint)
            .json(&forged)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    // A correctly signed proof cannot override the server's retained request.
    let wrong_type = MasterCertificate::issue_certificate_for_subject(
        &CertificateType([43; 32]),
        &subject,
        IndexMap::from([("name".to_string(), "Alice".to_string())]),
        &issuer,
        default_get_revocation_outpoint,
        None,
    )
    .await
    .unwrap();
    let mut request_forgery = proof_message(
        &wallet,
        &holder,
        &verifier,
        &a,
        VerifiableCertificate::new(wrong_type.certificate, IndexMap::new()),
        11,
    )
    .await;
    request_forgery.requested_certificates = Some(RequestedCertificateSet {
        certifiers: vec![],
        types: IndexMap::from([(B64.encode([43; 32]), vec![])]),
    });
    assert_ne!(
        http.post(&endpoint)
            .json(&request_forgery)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let attacker_key = PrivateKey::from_random().unwrap();
    let attacker_id = attacker_key.to_public_key().to_der_hex();
    let attacker = MockWallet::new(attacker_key);
    let stolen_nonce =
        proof_message(&attacker, &attacker_id, &verifier, &a, certs[0].clone(), 12).await;
    assert_ne!(
        http.post(&endpoint)
            .json(&stolen_nonce)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert!(gate.validated_for_session(&a, &holder).await.is_none());
    // Valid holder proof for the second session must not validate the first.
    let valid_b = proof_message(&wallet, &holder, &verifier, &b, certs[1].clone(), 2).await;
    assert_eq!(
        http.post(&endpoint)
            .json(&valid_b)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert!(gate.validated_for_session(&a, &holder).await.is_none());
    assert_eq!(
        gate.validated_for_session(&b, &holder).await.unwrap()[0].serial_number,
        certs[1].serial_number
    );
    let valid_a = proof_message(&wallet, &holder, &verifier, &a, certs[0].clone(), 3).await;
    assert_eq!(
        http.post(&endpoint)
            .json(&valid_a)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    // Delayed identity-only callbacks must be powerless over either session.
    gate.mark_validated(&holder, vec![certs[1].clone()]);
    assert_eq!(
        gate.validated_for_session(&a, &holder).await.unwrap()[0].serial_number,
        certs[0].serial_number
    );
    gate.mark_validated(&holder, vec![certs[0].clone()]);
    assert_eq!(
        gate.validated_for_session(&b, &holder).await.unwrap()[0].serial_number,
        certs[1].serial_number
    );
    // Replacement and replay on the existing generation are refused.
    let replacement = proof_message(&wallet, &holder, &verifier, &a, certs[1].clone(), 4).await;
    assert_ne!(
        http.post(&endpoint)
            .json(&replacement)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_ne!(
        http.post(&endpoint)
            .json(&valid_a)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        gate.validated_for_session(&a, &holder).await.unwrap()[0].serial_number,
        certs[0].serial_number
    );
    assert!(gate.validated_for_session(&a, &verifier).await.is_none());
    // Two concurrent genuine proofs for one new session cannot overwrite the
    // winner, regardless of SDK listener scheduling/completion order.
    let c = handshake(&http, &url, &holder).await;
    let c1 = proof_message(&wallet, &holder, &verifier, &c, certs[0].clone(), 21).await;
    let c2 = proof_message(&wallet, &holder, &verifier, &c, certs[1].clone(), 22).await;
    let (r1, r2) = tokio::join!(
        http.post(&endpoint).json(&c1).send(),
        http.post(&endpoint).json(&c2).send()
    );
    let first_won = r1.unwrap().status() == 200;
    assert_ne!(first_won, r2.unwrap().status() == 200);
    let index = if first_won { 0 } else { 1 };
    assert_eq!(
        gate.validated_for_session(&c, &holder).await.unwrap()[0].serial_number,
        certs[index].serial_number
    );
    task.abort();
}

#[tokio::test]
async fn retained_nonempty_fields_reject_missing_substituted_and_extra_proofs() {
    use bsv::auth::certificates::VerifiableCertificate;
    let issuer_key = PrivateKey::from_random().unwrap();
    let issuer_id = issuer_key.to_public_key().to_der_hex();
    let issuer = MockWallet::new(issuer_key);
    let key = PrivateKey::from_random().unwrap();
    let subject = key.to_public_key();
    let holder = subject.to_der_hex();
    let wallet = MockWallet::new(key);
    let master = MasterCertificate::issue_certificate_for_subject(
        &CertificateType([42; 32]),
        &subject,
        IndexMap::from([
            ("name".into(), "Alice".into()),
            ("email".into(), "a@example.test".into()),
            ("other".into(), "private".into()),
        ]),
        &issuer,
        default_get_revocation_outpoint,
        None,
    )
    .await
    .unwrap();
    let server_key = PrivateKey::from_random().unwrap();
    let verifier_key = server_key.to_public_key();
    let verifier = verifier_key.to_der_hex();
    let server = MockWallet::new(server_key);
    let transport = Arc::new(ActixTransport::new());
    let peer = Arc::new(Peer::new(server.clone(), transport.clone()));
    let requested = RequestedCertificateSet {
        certifiers: vec![issuer_id.clone()],
        types: IndexMap::from([(B64.encode([42; 32]), vec!["name".into(), "email".into()])]),
    };
    let config = AuthMiddlewareConfigBuilder::new()
        .wallet(server)
        .trusted_certifiers(vec![issuer_id])
        .certificate_authorizer(Box::new(|_, _| {
            Box::pin(async { bsv_auth_axum_middleware::CertificateAuthorizationDecision::Accept })
        }))
        .certificates_to_request(requested)
        .build()
        .unwrap();
    let layer = AuthLayer::from_config(config, peer, transport)
        .await
        .unwrap();
    let gate = layer.certificate_gate_ref().unwrap().clone();
    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(layer);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let http = reqwest::Client::new();
    for (tag, (fields, accepted)) in [
        (vec!["name"], false),
        (vec!["other"], false),
        (vec!["name", "email", "other"], false),
        (vec![], false),
        (vec!["name", "email"], true),
        (vec!["email", "name"], true),
    ]
    .into_iter()
    .enumerate()
    {
        let nonce = handshake(&http, &url, &holder).await;
        let fields: Vec<String> = fields.into_iter().map(str::to_string).collect();
        let keyring = if fields.is_empty() {
            IndexMap::new()
        } else {
            master
                .create_keyring_for_verifier(
                    &verifier_key,
                    &fields,
                    &master.certificate.certifier,
                    &wallet,
                )
                .await
                .unwrap()
        };
        let cert = VerifiableCertificate::new(master.certificate.clone(), keyring);
        let mut proof =
            proof_message(&wallet, &holder, &verifier, &nonce, cert, tag as u8 + 50).await;
        // The sender cannot redefine the retained request to match its keyring.
        proof.requested_certificates = Some(RequestedCertificateSet {
            certifiers: vec![],
            types: IndexMap::from([(B64.encode([42; 32]), fields.clone())]),
        });
        let response = http
            .post(format!("{url}.well-known/auth"))
            .json(&proof)
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status() == 200,
            accepted,
            "disclosed fields {fields:?}"
        );
        assert_eq!(
            gate.validated_for_session(&nonce, &holder).await.is_some(),
            accepted
        );
    }
    task.abort();
}

#[tokio::test]
async fn sdk_eviction_removes_the_corresponding_certificate_batch() {
    use bsv::auth::certificates::VerifiableCertificate;
    let issuer_key = PrivateKey::from_random().unwrap();
    let issuer_id = issuer_key.to_public_key().to_der_hex();
    let issuer = MockWallet::new(issuer_key);
    let key = PrivateKey::from_random().unwrap();
    let subject = key.to_public_key();
    let holder = subject.to_der_hex();
    let wallet = MockWallet::new(key);
    let mut certs = Vec::new();
    for _ in 0..2 {
        let cert = MasterCertificate::issue_certificate_for_subject(
            &CertificateType([42; 32]),
            &subject,
            IndexMap::from([("name".to_string(), "Alice".to_string())]),
            &issuer,
            default_get_revocation_outpoint,
            None,
        )
        .await
        .unwrap();
        certs.push(VerifiableCertificate::new(
            cert.certificate.clone(),
            IndexMap::new(),
        ));
    }
    let server_key = PrivateKey::from_random().unwrap();
    let verifier = server_key.to_public_key().to_der_hex();
    let server = MockWallet::new(server_key);
    let transport = Arc::new(ActixTransport::new());
    let peer = Arc::new(Peer::new(server.clone(), transport.clone()));
    // SDK callbacks may be delayed and delivered through a shared queue.
    // Their completion order carries no session authority.
    peer.listen_for_certificates_received(Arc::new(|_, _| {
        Box::pin(async {
            tokio::time::sleep(std::time::Duration::from_millis(40)).await;
            Ok(())
        })
    }));
    let requested = RequestedCertificateSet {
        certifiers: vec![issuer_id.clone()],
        types: IndexMap::from([(B64.encode([42; 32]), vec![])]),
    };
    let config = AuthMiddlewareConfigBuilder::new()
        .wallet(server)
        .trusted_certifiers(vec![issuer_id])
        .certificate_authorizer(Box::new(|_, _| {
            Box::pin(async { bsv_auth_axum_middleware::CertificateAuthorizationDecision::Accept })
        }))
        .certificates_to_request(requested)
        .build()
        .unwrap();
    let layer = AuthLayer::from_config(config, peer.clone(), transport)
        .await
        .unwrap();
    let gate = layer.certificate_gate_ref().unwrap().clone();
    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(layer);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let http = reqwest::Client::new();

    let old = handshake(&http, &url, &holder).await;
    let proof = proof_message(&wallet, &holder, &verifier, &old, certs[0].clone(), 90).await;
    let endpoint = format!("{url}.well-known/auth");
    assert_eq!(
        http.post(&endpoint)
            .json(&proof)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert!(gate.validated_for_session(&old, &holder).await.is_some());
    // Exercise the pinned SDK's real 1024-session cap without test-only SDK APIs.
    let mut newest = String::new();
    for _ in 0..1025 {
        newest = handshake(&http, &url, &holder).await;
    }
    assert!(peer.session_peer_identity_for(&old).await.is_none());
    assert_eq!(peer.sessions_for_identity(&holder).await.len(), 1024);
    // No further certificate exchange: the periodic lifecycle cleanup must
    // reclaim the evicted batch even when the server becomes idle now.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
    while gate.validated_for_session(&old, &holder).await.is_some()
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        gate.validated_for_session(&old, &holder).await.is_none(),
        "evicted session retained its certificate batch"
    );
    let proof = proof_message(&wallet, &holder, &verifier, &newest, certs[1].clone(), 91).await;
    assert_eq!(
        http.post(&endpoint)
            .json(&proof)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        gate.validated_for_session(&newest, &holder).await.unwrap()[0].serial_number,
        certs[1].serial_number
    );
    task.abort();
}
