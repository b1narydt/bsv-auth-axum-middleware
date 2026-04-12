//! Response signing integration tests, including the Phase 1 `your_nonce` regression.
//!
//! See `.planning/bsv-parity-FINDING-your-nonce.md` for the full investigation
//! that motivates [`response_signing_uses_request_session_when_identity_has_multiple_sessions`].
//!
//! That test pins the first argument of
//! `Peer::create_general_message` in `src/middleware.rs::handle_response_signing`:
//! it must be `&request_headers.your_nonce` (the server session nonce that
//! authenticated this specific request), NOT `&request_headers.identity_key`
//! (which resolves via `SessionManager::identity_to_nonces` and picks a
//! non-deterministic "best" session when one identity has multiple concurrent
//! sessions). If anyone ever flips that argument, the regression test's
//! alternating-clients loop will fail because AF2's requests will be signed
//! with AF1's session nonce, the response will fail verification in the
//! client's `handle_general_message`, and `AuthFetch::fetch` will time out.

mod common;

use std::collections::HashMap;
use std::time::Duration;

use bsv::auth::clients::AuthFetch;
use bsv::primitives::private_key::PrivateKey;

use common::test_server::{spawn_test_server, TestServerConfig, TestWallet};

/// Test 1 — successful general response carries all six `x-bsv-auth-*` headers
/// and the original body (per the response-signing path buffering+rebuilding).
///
/// Uses AuthFetch for the full round-trip, then re-runs an independent raw
/// reqwest request inside the same AuthFetch-initiated session to observe the
/// actual HTTP response headers (AuthFetch's `AuthFetchResponse.headers`
/// excludes `x-bsv-auth-*`, so we need a second vantage point). We make the
/// raw request using AuthFetch's just-completed session state by issuing a
/// second AuthFetch call and inspecting that the body was correctly signed
/// (no error) — then independently fetch `GET /` via plain reqwest to
/// observe the 401 path headers for completeness.
#[tokio::test(flavor = "multi_thread")]
async fn test_response_signing_attaches_all_six_headers() {
    let server = spawn_test_server(TestServerConfig::default()).await;

    let client_wallet = TestWallet::new(PrivateKey::from_random().expect("gen client key"));
    let mut auth_fetch = AuthFetch::new(client_wallet);

    // AuthFetch's own round-trip exercises the response-signing path. If the
    // middleware failed to attach any of the six auth headers, the client's
    // `SimplifiedHTTPTransport::send_general` would error at
    // `bsv-rust-sdk/src/auth/transports/http.rs:213-225` ("HTTP .. without
    // valid BSV authentication").
    let url = format!("{}/", server.base_url);
    let resp = auth_fetch
        .fetch(&url, "GET", None, None)
        .await
        .expect("response signing should attach all six auth headers");

    assert_eq!(resp.status, 200);
    assert_eq!(String::from_utf8_lossy(&resp.body), "Hello, world!");

    // And confirm the unauthenticated path's error also reaches us as
    // structured JSON (the 401 branch is NOT signed — that's branch 3 of
    // AuthService::call — but we use it here as a negative control that
    // the server is still alive and the middleware isn't returning bare
    // 500s for unknown reasons).
    let http = reqwest::Client::new();
    let raw_resp = http
        .get(&url)
        .send()
        .await
        .expect("raw unauthenticated GET");
    assert_eq!(raw_resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

/// Test 2 — response body bytes are preserved through the middleware's
/// buffer+sign+rebuild path.
///
/// Sends a POST that the handler echoes verbatim as JSON, checks that the
/// response body delivered to the client decodes to exactly the sent value.
/// If `handle_response_signing`'s `body_bytes.to_vec()` ever lost bytes or
/// re-encoded them, this assertion fails.
#[tokio::test(flavor = "multi_thread")]
async fn test_response_signing_preserves_json_body() {
    let server = spawn_test_server(TestServerConfig::default()).await;

    let client_wallet = TestWallet::new(PrivateKey::from_random().expect("gen client key"));
    let mut auth_fetch = AuthFetch::new(client_wallet);

    let sent = b"{\"value\":\"body-preservation-check-\xe2\x9c\x93\"}".to_vec();
    let headers = HashMap::from([("content-type".to_string(), "application/json".to_string())]);

    let url = format!("{}/json-echo", server.base_url);
    let response = auth_fetch
        .fetch(&url, "POST", Some(sent.clone()), Some(headers))
        .await
        .expect("POST /json-echo");

    assert_eq!(response.status, 200);
    // /json-echo returns Json<EchoPayload>, so serde re-serialises the payload
    // once. Parse both sent and returned back to JSON values and compare.
    let sent_val: serde_json::Value = serde_json::from_slice(&sent).expect("parse sent payload");
    let got_val: serde_json::Value =
        serde_json::from_slice(&response.body).expect("parse returned payload");
    assert_eq!(
        got_val, sent_val,
        "echo handler's output must exactly equal the sent JSON"
    );
}

// ---------------------------------------------------------------------------
// Regression test — your_nonce vs identity_key
// ---------------------------------------------------------------------------

/// **REGRESSION**: response signing must resolve the server-side session by
/// the `your_nonce` header value (the exact session nonce that authenticated
/// this incoming request), NOT by the client's identity key.
///
/// Setup: one client identity key, two authenticated sessions against one
/// server (two independent `AuthFetch` instances, both using the same client
/// private key, each driving its own handshake). The server's
/// `SessionManager` now carries two `PeerSession`s indexed under the same
/// `identity_key` in its secondary `identity_to_nonces` index.
///
/// Action: issue an alternating burst of requests — AF1, AF2, AF1, AF2, ...
/// — each through its own `AuthFetch`, each sending
/// `x-bsv-auth-your-nonce = <that session's server nonce>`.
///
/// Pin: `src/middleware.rs::handle_response_signing` calls
/// `peer.create_general_message(&request_headers.your_nonce, payload)` at
/// line 426. That first argument resolves the server's session via
/// `nonce_to_session[your_nonce]` — deterministic, exact. If someone ever
/// flips it to `&request_headers.identity_key`, resolution falls through
/// to `SessionManager::identity_to_nonces` which picks a non-deterministic
/// "best" authenticated session. When AF2 sends a request but the server
/// signs using AF1's session, the response's `your_nonce` and `initial_nonce`
/// fields point at AF1's session state, which doesn't exist in AF2's client
/// peer. AF2's `handle_general_message` then fails the
/// `SessionManager::get_session_by_identifier` lookup at
/// `bsv-rust-sdk/src/auth/peer.rs:688-694` and returns
/// `SessionNotFound`, which propagates up through `AuthFetch::fetch` as
/// either a direct error or a 30-second timeout as the client's
/// `general_rx` receiver never sees a valid response.
///
/// Under the *correct* code, every request in the burst succeeds in a few
/// milliseconds. Under the buggy code, roughly half the requests will
/// either error or time out — the probability that a 10-request alternating
/// burst all succeeds is ≲ 0.5^10 ≈ 0.1 %, and even that only if the
/// non-deterministic "best session" pick happens to match every time.
///
/// This test also checks:
/// - two separate sessions exist on the server side (via
///   `peer.session_manager().get_sessions_for_identity(...)`),
/// - each individual request has the same `body` the handler returned,
///   proving the signing path routed through the correct session.
///
/// See `.planning/bsv-parity-FINDING-your-nonce.md` for the Phase 1
/// investigation that identified the dual-mode semantics of
/// `Peer::create_general_message` and the non-determinism hazard.
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)]
async fn response_signing_uses_request_session_when_identity_has_multiple_sessions() {
    let server = spawn_test_server(TestServerConfig::default()).await;

    // One client private key shared between two AuthFetch clients. Each
    // AuthFetch instance creates its own Peer + SimplifiedHTTPTransport and
    // runs its own handshake, so the server will record two distinct
    // PeerSession entries under the same `peer_identity_key`.
    let client_key = PrivateKey::from_random().expect("gen client key");
    let client_wallet_1 = TestWallet::new(client_key.clone());
    let client_wallet_2 = TestWallet::new(client_key.clone());
    let client_identity_hex = client_wallet_1.identity_key_hex().await;

    let mut af1 = AuthFetch::new(client_wallet_1);
    let mut af2 = AuthFetch::new(client_wallet_2);

    // Drive two independent handshakes. Each `fetch` call triggers a full
    // handshake on first use for its AuthFetch instance.
    let url = format!("{}/", server.base_url);
    let r1 = af1
        .fetch(&url, "GET", None, None)
        .await
        .expect("af1 initial handshake + request");
    assert_eq!(r1.status, 200);

    let r2 = af2
        .fetch(&url, "GET", None, None)
        .await
        .expect("af2 initial handshake + request");
    assert_eq!(r2.status, 200);

    // Snapshot the server-side SessionManager. It MUST now carry exactly two
    // sessions for this identity. If this fails, the test precondition isn't
    // met and the subsequent burst assertion would be meaningless.
    let (sessions_s1, sessions_s2) = {
        let peer = server.peer.lock().await;
        let mgr = peer.session_manager();
        let sessions = mgr.get_sessions_for_identity(&client_identity_hex);
        assert_eq!(
            sessions.len(),
            2,
            "expected two distinct server-side sessions for the shared client identity, got {}",
            sessions.len()
        );
        // Snapshot their (session_nonce, peer_nonce) pairs so we can assert
        // that the direct Peer::create_general_message call returns the
        // correct per-nonce response below.
        let s0 = sessions[0].clone();
        let s1 = sessions[1].clone();
        assert!(
            s0.is_authenticated && s1.is_authenticated,
            "both sessions should be authenticated"
        );
        assert_ne!(
            s0.session_nonce, s1.session_nonce,
            "server session nonces should differ between concurrent sessions"
        );
        assert_ne!(
            s0.peer_nonce, s1.peer_nonce,
            "server-side peer_nonce (client's initial_nonce) should differ between sessions"
        );
        (s0, s1)
    };

    // -----------------------------------------------------------------------
    // Direct SDK-level pin: Peer::create_general_message resolves by nonce,
    // not identity key. This is the unit-level assertion — it pins the SDK
    // contract that the middleware relies on.
    // -----------------------------------------------------------------------
    {
        let peer = server.peer.lock().await;
        let payload = b"test".to_vec();

        let signed_s1 = peer
            .create_general_message(&sessions_s1.session_nonce, payload.clone())
            .await
            .expect("create_general_message with S1 session nonce");
        assert_eq!(
            signed_s1.your_nonce.as_deref(),
            Some(sessions_s1.peer_nonce.as_str()),
            "S1 lookup by session_nonce must return S1's peer_nonce as your_nonce"
        );

        let signed_s2 = peer
            .create_general_message(&sessions_s2.session_nonce, payload.clone())
            .await
            .expect("create_general_message with S2 session nonce");
        assert_eq!(
            signed_s2.your_nonce.as_deref(),
            Some(sessions_s2.peer_nonce.as_str()),
            "S2 lookup by session_nonce must return S2's peer_nonce as your_nonce"
        );

        // The two your_nonce values MUST differ — proving the lookup is
        // session-specific and not collapsing both sessions to one "best".
        assert_ne!(
            signed_s1.your_nonce, signed_s2.your_nonce,
            "two distinct sessions must produce two distinct your_nonce values"
        );
    }

    // -----------------------------------------------------------------------
    // Middleware-level pin: alternate between AF1 and AF2 for 10 requests.
    // Each fetch wraps in a 5-second timeout so a wrong-session response
    // (which would cause the client's handle_general_message to error and
    // leave AuthFetch polling for a response that never arrives) fails fast
    // instead of taking the SDK's built-in 30-second timeout.
    //
    // Under correct code, each fetch completes in ~50ms. Under the bug,
    // each fetch has a ~50% chance of failing, so all 10 passing is
    // ≲ 0.5^10 probability.
    // -----------------------------------------------------------------------
    for i in 0..5 {
        let r = tokio::time::timeout(Duration::from_secs(5), af1.fetch(&url, "GET", None, None))
            .await
            .unwrap_or_else(|_| panic!("af1 request #{i} timed out — regression bug triggered?"))
            .unwrap_or_else(|e| {
                panic!("af1 request #{i} failed: {e:?} — regression bug triggered?")
            });
        assert_eq!(r.status, 200, "af1 request #{i} status");
        assert_eq!(String::from_utf8_lossy(&r.body), "Hello, world!");

        let r = tokio::time::timeout(Duration::from_secs(5), af2.fetch(&url, "GET", None, None))
            .await
            .unwrap_or_else(|_| panic!("af2 request #{i} timed out — regression bug triggered?"))
            .unwrap_or_else(|e| {
                panic!("af2 request #{i} failed: {e:?} — regression bug triggered?")
            });
        assert_eq!(r.status, 200, "af2 request #{i} status");
        assert_eq!(String::from_utf8_lossy(&r.body), "Hello, world!");
    }

    // Sanity: server accumulated one session per AuthFetch::fetch() call.
    //
    // NOTE: the bsv-rust-sdk AuthFetch implementation opens a fresh handshake
    // on every `fetch()` call (auth_fetch.rs:138 calls
    // `get_authenticated_session("")` with an empty identity key, which never
    // matches a stored session because `complete_handshake` overwrites the
    // empty-string key with the learned server identity). So the server
    // receives: 2 initial handshakes + 10 burst handshakes = 12 sessions
    // under the shared client identity. This is orthogonal to the regression
    // test's pin — the point is that EACH of the 12 sessions must be
    // addressable independently, and EACH request must route to the exact
    // session whose `session_nonce` appears in `x-bsv-auth-your-nonce`. Under
    // the buggy `identity_key` lookup, resolution among 12 candidates would
    // be even MORE non-deterministic than among 2.
    //
    // This AuthFetch behaviour is a pre-existing quirk of the SDK and is
    // noted in `.planning/phases/01-tests-harness/deferred-items.md` — not
    // a fault of the axum middleware.
    let peer = server.peer.lock().await;
    let final_sessions = peer
        .session_manager()
        .get_sessions_for_identity(&client_identity_hex);
    assert!(
        final_sessions.len() >= 2,
        "expected at least 2 concurrent server-side sessions after the burst, got {}",
        final_sessions.len()
    );
}
