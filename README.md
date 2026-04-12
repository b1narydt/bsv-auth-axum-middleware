# bsv-auth-axum-middleware

BRC-31 mutual authentication middleware for axum, ported from [b1narydt/auth-actix-middleware](https://github.com/b1narydt/auth-actix-middleware). Uses `bsv-sdk` `Peer` for the BRC-31 handshake, request signature verification, and response signing.

## What it provides

- **`AuthLayer`** -- tower `Layer` that wraps any axum `Router` with BRC-31 authentication.
- **`AuthService`** -- the tower `Service` created by `AuthLayer`. Intercepts every request and handles three branches:
  1. **Handshake** (`POST /.well-known/auth`) -- feeds the incoming `AuthMessage` to `Peer`, waits for the signed response, returns it with `x-bsv-auth-*` headers.
  2. **Authenticated request** (has `x-bsv-auth-*` headers) -- verifies the request signature via `Peer`, calls the inner handler, buffers the response, signs it, and returns with auth headers.
  3. **Unauthenticated request** (no auth headers) -- rejects with 401 when `allow_unauthenticated` is false, or passes through with identity `"unknown"`.
- **`Authenticated`** -- axum `FromRequestParts` extractor. Inserted into request extensions by the middleware after successful verification. Contains the caller's `identity_key` (compressed hex public key).
- **`ActixTransport`** -- channel-based transport adapter that bridges `bsv-sdk` Peer's async message passing to the request/response HTTP model.
- **`CertificateGate`** -- optional per-identity certificate gating. Blocks requests until a certificate exchange completes (with configurable timeout).

## Usage

```rust,ignore
use std::sync::Arc;
use axum::{Router, routing::post, response::IntoResponse};
use bsv::auth::peer::Peer;
use bsv_auth_axum_middleware::{AuthLayer, Authenticated, ActixTransport};

// Set up transport and peer
let transport = Arc::new(ActixTransport::new());
let peer = Arc::new(tokio::sync::Mutex::new(
    Peer::new(wallet, transport.clone())
));

// Create auth layer
let auth_layer = AuthLayer::new(peer, transport, false);

// Apply to router
let app = Router::new()
    .route("/api/data", post(handler))
    .layer(auth_layer);

// Extract authenticated identity in handlers
async fn handler(auth: Authenticated) -> impl IntoResponse {
    format!("Hello, {}", auth.identity_key)
}
```

## Modules

| Module | Purpose |
|--------|---------|
| `middleware` | `AuthLayer` and `AuthService` -- the core tower Layer/Service implementation |
| `extractor` | `Authenticated` axum extractor |
| `transport` | `ActixTransport` -- channel-based adapter for `bsv-sdk` Peer message passing |
| `certificate` | `CertificateGate` -- per-identity certificate request tracking with `Notify`-based wake |
| `config` | `AuthMiddlewareConfig` builder for advanced configuration |
| `helpers` | `extract_auth_headers`, `build_auth_message` -- header parsing and AuthMessage construction |
| `payload` | Serialization of request/response payloads for signature computation |
| `error` | `AuthMiddlewareError` enum with `IntoResponse` impl |

## Auth headers

All authenticated requests and responses carry these headers:

| Header | Description |
|--------|-------------|
| `x-bsv-auth-version` | Protocol version |
| `x-bsv-auth-identity-key` | Compressed hex public key of the sender |
| `x-bsv-auth-nonce` | Sender's nonce for this message |
| `x-bsv-auth-your-nonce` | Receiver's nonce (from the last received message) |
| `x-bsv-auth-signature` | Hex-encoded ECDSA signature over the serialized payload |
| `x-bsv-auth-request-id` | Request correlation ID (response only) |

## Origin

This crate is a port of `b1narydt/auth-actix-middleware` (actix-web) to axum's tower-based middleware system. The core BRC-31 protocol logic is identical; the adaptation is in how request/response bodies are intercepted and how the `Peer` message flow maps to tower `Service::call`.
