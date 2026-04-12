//! Shared fixtures for integration and certificate tests.

#[allow(dead_code)]
pub mod mock_wallet;
#[allow(dead_code)]
pub mod test_server;

#[allow(unused_imports)]
pub use mock_wallet::MockWallet;
#[allow(unused_imports)]
pub use test_server::{create_cert_test_server, create_test_server, CertTestContext};
