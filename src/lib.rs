//! BSV BRC-31 authentication middleware for axum.
//!
//! Ported from `bsv-auth-actix-middleware` — provides the same BRC-31 mutual
//! authentication using the bsv-sdk Peer, adapted for axum's tower-based
//! middleware system.
//!
//! # Usage
//!
//! ```ignore
//! use bsv_auth_axum_middleware::{AuthLayer, Authenticated};
//!
//! let auth_layer = AuthLayer::new(peer, transport, false);
//! let app = Router::new()
//!     .route("/api/data", post(handler))
//!     .layer(auth_layer);
//!
//! async fn handler(auth: Authenticated) -> impl IntoResponse {
//!     format!("Hello, {}", auth.identity_key)
//! }
//! ```

pub mod certificate;
pub mod config;
pub mod error;
pub mod extractor;
pub mod helpers;
pub mod middleware;
pub mod payload;
pub mod transport;

pub use certificate::CertificateGate;
pub use config::{AuthMiddlewareConfig, AuthMiddlewareConfigBuilder, OnCertificatesReceived};
pub use error::AuthMiddlewareError;
pub use extractor::Authenticated;
pub use helpers::{extract_auth_headers, AuthHeaders};
pub use middleware::{AuthLayer, AuthService};
pub use transport::ActixTransport;
