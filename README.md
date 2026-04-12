# bsv-auth-axum-middleware

[![Crates.io](https://img.shields.io/crates/v/bsv-auth-axum-middleware.svg)](https://crates.io/crates/bsv-auth-axum-middleware)
[![Documentation](https://docs.rs/bsv-auth-axum-middleware/badge.svg)](https://docs.rs/bsv-auth-axum-middleware)
[![CI](https://github.com/b1narydt/bsv-auth-axum-middleware/actions/workflows/ci.yml/badge.svg)](https://github.com/b1narydt/bsv-auth-axum-middleware/actions)
[![License: Open BSV](https://img.shields.io/badge/license-Open%20BSV-blue.svg)](https://github.com/b1narydt/bsv-auth-axum-middleware/blob/main/LICENSE)

BSV BRC-31 (Authrite) mutual authentication middleware for axum. This crate is a
port of [`bsv-auth-actix-middleware`](https://crates.io/crates/bsv-auth-actix-middleware)
to axum 0.8 + tower 0.5. The wire format, config surface, and error response
bodies are identical to the actix sibling and to the TypeScript
`@bsv/auth-express-middleware` reference implementation.

## What is BRC-31?

[BRC-31](https://github.com/bitcoin-sv/BRCs/blob/master/peer-to-peer/0031.md)
defines the Authrite mutual authentication protocol for BSV applications. It
enables both client and server to prove their identity through public key
cryptography without shared secrets or session cookies. Each request is signed
by the sender and verified by the receiver, and each response is signed in
return, providing end-to-end authentication for every HTTP exchange.

The protocol is framework-agnostic: the same handshake and signature scheme works
identically in the TypeScript Express middleware and in this Rust axum middleware.

## Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
bsv-auth-axum-middleware = "0.1"
bsv-sdk = { version = "0.2", features = ["network"] }
axum = "0.8"
tokio = { version = "1", features = ["full"] }
```

## Quick Start

```rust,ignore
use std::sync::Arc;
use axum::{Router, routing::post, response::IntoResponse, Json};
use bsv::auth::peer::Peer;
use bsv::wallet::ProtoWallet;
use bsv_auth_axum_middleware::{
    AuthMiddlewareConfigBuilder, AuthLayer, Authenticated, ActixTransport,
};

#[tokio::main]
async fn main() {
    // 1. Create a wallet (ProtoWallet connects to a BRC-100 wallet service).
    let wallet = ProtoWallet::new("http://localhost:3301").await.unwrap();

    // 2. Build middleware configuration.
    let config = AuthMiddlewareConfigBuilder::new()
        .wallet(wallet.clone())
        .allow_unauthenticated(false)
        .build()
        .expect("valid config");

    // 3. Create transport and peer.
    let transport = Arc::new(ActixTransport::new());
    let peer = Arc::new(tokio::sync::Mutex::new(
        Peer::new(wallet, transport.clone()),
    ));

    // 4. Build the auth layer (spawns certificate listener if configured).
    let auth_layer = AuthLayer::from_config(config, peer, transport).await;

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
    .session_manager(session_mgr)                // Optional: track authenticated sessions
    .on_certificates_received(callback)          // Optional: handle received certificates
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
| `session_manager` | `SessionManager` | `None` | Manages authenticated sessions for repeat connections |
| `on_certificates_received` | `OnCertificatesReceived` | `None` | Async callback invoked when certificates arrive from a peer |
| `log_level` | `tracing::Level` | `None` | When set, installs a default `tracing_subscriber::fmt` subscriber at that level |

## Authentication Flow

The middleware implements the full BRC-31 mutual authentication handshake:

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

For advanced identity verification, BRC-31 supports certificate exchange after
the initial handshake. Use `CertificateGate` and the `certificates_to_request`
configuration option to require specific certificates from peers:

```rust,ignore
use bsv::auth::types::RequestedCertificateSet;

let mut certs = RequestedCertificateSet::default();
certs.types.insert("certifier_id".into(), vec!["field_name".into()]);

let config = AuthMiddlewareConfigBuilder::new()
    .wallet(wallet)
    .certificates_to_request(certs)
    .on_certificates_received(Box::new(|identity_key, certificates| {
        Box::pin(async move {
            // Process received certificates
            println!("Received {} certs from {}", certificates.len(), identity_key);
        })
    }))
    .build()
    .expect("valid config");
```

The middleware will gate authenticated requests until the required certificates
are received, using `CertificateGate` to coordinate the asynchronous exchange.

## License

Open BSV License Version 5. See [LICENSE](https://github.com/b1narydt/bsv-auth-axum-middleware/blob/main/LICENSE).
