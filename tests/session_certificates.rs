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
