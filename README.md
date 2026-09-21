# bsv-auth-axum-middleware

[![Crates.io](https://img.shields.io/crates/v/bsv-auth-axum-middleware.svg)](https://crates.io/crates/bsv-auth-axum-middleware)
[![Documentation](https://docs.rs/bsv-auth-axum-middleware/badge.svg)](https://docs.rs/bsv-auth-axum-middleware)
[![CI](https://github.com/b1narydt/bsv-auth-axum-middleware/actions/workflows/ci.yml/badge.svg)](https://github.com/b1narydt/bsv-auth-axum-middleware/actions)
[![License: Open BSV](https://img.shields.io/badge/license-Open%20BSV-blue.svg)](https://github.com/b1narydt/bsv-auth-axum-middleware/blob/main/LICENSE)

BSV BRC-104 (BRC-103 over HTTP) mutual authentication middleware for axum. This crate is a
port of [`bsv-auth-actix-middleware`](https://crates.io/crates/bsv-auth-actix-middleware)
to axum 0.8 + tower 0.5. Its core wire format follows the actix sibling and
the TypeScript `@bsv/auth-express-middleware` reference implementation, with a
fail-closed Rust certificate-policy extension described below.

## What is BRC-103/104?

[BRC-103](https://github.com/bitcoin-sv/BRCs/blob/master/peer-to-peer/0103.md)
defines the transport-agnostic peer-to-peer mutual authentication and
certificate exchange protocol for BSV applications, and
[BRC-104](https://github.com/bitcoin-sv/BRCs/blob/master/transports/0104.md) is
its HTTP binding — the `x-bsv-auth-*` headers and the `/.well-known/auth`
handshake endpoint this middleware implements. (BRC-103/104 supersede the older
BRC-31 "Authrite" protocol, which this stack does NOT speak.) It enables both
client and server to prove their identity through public key cryptography
without shared secrets or session cookies. Each request is signed by the sender
and verified by the receiver, and each response is signed in return, providing
end-to-end authentication for every HTTP exchange.

The protocol is framework-agnostic: the same handshake and signature scheme works
identically in the TypeScript Express middleware and in this Rust axum middleware.

## Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
bsv-auth-axum-middleware = "0.1"
bsv-sdk = { version = "0.3", features = ["network"] }
axum = "0.8"
tokio = { version = "1", features = ["full"] }
```

## Quick Start

```rust,ignore
use std::sync::Arc;
use axum::{Router, routing::post, response::IntoResponse, Json};
use bsv::auth::peer::Peer;
use bsv::primitives::private_key::PrivateKey;
use bsv::wallet::proto_wallet::ProtoWallet;
use bsv_auth_axum_middleware::{
    AuthMiddlewareConfigBuilder, AuthLayer, Authenticated, ActixTransport,
};

#[tokio::main]
async fn main() {
    // 1. Create a wallet (ProtoWallet is an in-process key wallet; production
    //    code implements WalletInterface over real key management).
    let wallet = ProtoWallet::new(PrivateKey::from_random().unwrap());

    // 2. Build middleware configuration.
    let config = AuthMiddlewareConfigBuilder::new()
        .wallet(wallet.clone())
        .allow_unauthenticated(false)
        .build()
        .expect("valid config");

    // 3. Create transport and peer.
    let transport = Arc::new(ActixTransport::new());
    let peer = Arc::new(Peer::new(wallet, transport.clone()));

    // 4. Build the auth layer (spawns certificate listener if configured).
    let auth_layer = AuthLayer::from_config(config, peer, transport)
        .await
        .expect("valid auth layer");

    // 5. Apply to router.
    let app = Router::new()
        .route("/api/data", post(protected_handler))
        .layer(auth_layer);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn protected_handler(auth: Authenticated) -> impl IntoResponse {
    Json(serde_json::json!({
        "message": "Hello, authenticated user!",
        "identity_key": auth.identity_key,
    }))
}
```

## Configuration

Use `AuthMiddlewareConfigBuilder` to configure the middleware:

```rust,ignore
let config = AuthMiddlewareConfigBuilder::new()
    .wallet(wallet)                              // Required: WalletInterface impl
    .allow_unauthenticated(false)                // Optional: reject unauth requests (default)
    .certificates_to_request(certificate_set)    // Optional: request certs from peers
    .trusted_certifiers(certifier_keys)           // Nonempty: engage certificate gate
    .certificate_authorizer(authorizer)           // Required with trusted certifiers
    .session_manager(session_mgr)                // Optional: track authenticated sessions
    .on_certificates_received(callback)          // Optional: post-admission observation
    .log_level(tracing::Level::INFO)             // Optional: install default tracing subscriber
    .build()
    .expect("valid config");
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `wallet` | `W: WalletInterface` | *required* | Wallet used for signing, verification, and key operations |
| `allow_unauthenticated` | `bool` | `false` | When `true`, requests without auth headers pass through to the handler |
| `certificates_to_request` | `RequestedCertificateSet` | `None` | Certificate types to request from peers after handshake |
| `trusted_certifiers` | `Vec<String>` | empty | Trusted certifier public keys; a nonempty set engages mandatory certificate admission |
| `certificate_authorizer` | `CertificateAuthorizer` | `None` | Blocking async policy decision; required when `trusted_certifiers` is nonempty |
| `session_manager` | `SessionManager` | `None` | Manages authenticated sessions for repeat connections |
| `on_certificates_received` | `OnCertificatesReceived` | `None` | Post-admission async observation callback; it cannot grant or veto authority |
| `log_level` | `tracing::Level` | `None` | When set, installs a default `tracing_subscriber::fmt` subscriber at that level |

## Authentication Flow

The middleware implements the full BRC-103/104 mutual authentication handshake:

1. **Client initiates handshake** -- sends a request to `/.well-known/auth` with
   its public key and a nonce. The middleware responds with the server's public
   key and nonce, establishing a session.

2. **Client sends authenticated request** -- includes `x-bsv-auth-*` headers
   containing the identity key, nonce, and a cryptographic signature over the
   request body.

3. **Middleware verifies request** -- checks the signature against the request
   body and headers, confirming the sender's identity. If verification fails,
   the request is rejected with a 401 response.

4. **Handler receives identity** -- the `Authenticated` extractor provides the
   verified `identity_key` and optional `certificate_set` to route handlers.

5. **Middleware signs response** -- before sending the response back, the
   middleware signs it with the server's key, completing mutual authentication.

## Certificate Exchange

For advanced identity verification, BRC-103/104 supports certificate exchange after
the initial handshake. Use `CertificateGate` and the `certificates_to_request`
configuration option to require specific certificates from peers:

```rust,ignore
use bsv::auth::types::RequestedCertificateSet;
use bsv_auth_axum_middleware::CertificateAuthorizationDecision;

let mut certs = RequestedCertificateSet::default();
certs.types.insert("certifier_id".into(), vec!["field_name".into()]);

let config = AuthMiddlewareConfigBuilder::new()
    .wallet(wallet)
    .certificates_to_request(certs)
    .trusted_certifiers(vec![certifier_identity_key])
    .certificate_authorizer(Box::new(|identity_key, certificates| {
        Box::pin(async move {
            // Apply application policy such as revocation/currentness here.
            if application_admits(&identity_key, &certificates).await {
                CertificateAuthorizationDecision::Accept
            } else {
                CertificateAuthorizationDecision::Reject("certificate is not current".into())
            }
        })
    }))
    .on_certificates_received(Box::new(|identity_key, certificates| {
        Box::pin(async move {
            // Observe only after structural + application admission succeeds.
            println!("Received {} certs from {}", certificates.len(), identity_key);
        })
    }))
    .build()
    .expect("valid config");
```

Configure a nonempty `trusted_certifiers` set to engage certificate gating.
Construction then requires a `certificate_authorizer`; omitting it is a
configuration error. The SDK awaits this authorizer after structural proof
validation and before marking the exact session certificate-valid. `Accept`
opens that session, `Reject(reason)` keeps it closed, and an undecided callback
times out after 30 seconds. The observation callback runs only after admission
and cannot disable or release the HTTP gate.

The well-known handler awaits SDK proof validation against the exact local
session and its retained request, validates issuer/type/subject/signature policy,
requires each proof keyring to match the exact retained field set (no missing,
substituted or extra fields), and stores the first accepted batch immutably for
that session. The empty-field case requires an empty keyring. A new credential
requires a new handshake. General HTTP requests read only that exact session's
batch, so simultaneous sessions with the same wallet key cannot borrow each
other's certificates. Nonempty-field proofs remain supported.

Session records are pruned against the SDK's active-session lookup before new
record insertion and every second while the middleware is running. This honors
SDK cap eviction and idle expiry even without later HTTP traffic. The pruning
task holds only a weak peer reference and stops after that peer is dropped;
expired records never supply HTTP authority while awaiting the next sweep.

`Authenticated` retains its two-field public shape; `certificates` now means the
batch proved by this exact request's authenticated BRC session. A separate
`AuthenticatedSession` extension exposes the server-generated `session_nonce`.
`CertificateGate::validated_for_session(nonce, identity).await` reads a snapshot;
callers must separately establish session liveness and their application policy.
The old identity-only gate methods and `on_certificates_received` callback remain
available for observation, but never authorize HTTP requests. Their compatibility
maps are independently capped at 1024 identities and expire after 15 minutes.
In particular, calling `mark_validated(identity, certs)` cannot release a
session's HTTP gate.

An authentic general request blocked by a rejected authorizer receives a signed
`403 ERR_CERTIFICATE_REJECTED`; a pending or timed-out decision receives a signed
`408 CERTIFICATE_TIMEOUT`. The SDK issues the refusal-only signing capability
only after session, identity, signature, request-payload, and replay validation.
Malformed, forged, replayed, or session-mismatched requests remain unsigned.

This source uses maintained `bsv-sdk` 0.8.1 at the revision pinned in
`Cargo.toml` via `[patch.crates-io]`.
Cargo ignores dependency-local patches: consuming workspaces must apply that
same graph-wide patch. No registry publication is implied. Certificate currentness,
revocation, grant policy and application authorization remain the consumer's
responsibility.

## License

Open BSV License Version 5. See [LICENSE](https://github.com/b1narydt/bsv-auth-axum-middleware/blob/main/LICENSE).
