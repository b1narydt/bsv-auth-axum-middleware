#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

pub mod certificate;
pub mod config;
pub mod error;
pub mod extractor;
pub mod helpers;
pub mod middleware;
pub mod payload;
pub mod transport;

pub use certificate::{certificate_listener_task, CertificateGate};
pub use config::{AuthMiddlewareConfig, AuthMiddlewareConfigBuilder, OnCertificatesReceived};
pub use error::AuthMiddlewareError;
pub use extractor::Authenticated;
pub use helpers::{extract_auth_headers, AuthHeaders};
pub use middleware::{AuthLayer, AuthService};
pub use transport::{ActixTransport, DEFAULT_PENDING_TIMEOUT};
