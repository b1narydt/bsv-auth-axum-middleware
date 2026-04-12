//! Configuration types and builder for the BSV auth middleware.
//!
//! Provides `AuthMiddlewareConfig` and its builder for constructing the
//! middleware with a required wallet and optional fields. The config is
//! generic over `W: WalletInterface` for zero-cost static dispatch.

use std::sync::Arc;

use bsv::auth::session_manager::SessionManager;
use bsv::auth::types::RequestedCertificateSet;
use bsv::wallet::interfaces::{Certificate, WalletInterface};
use futures_util::future::BoxFuture;

use crate::error::AuthMiddlewareError;

/// Callback type invoked when certificates are received from a peer.
///
/// Receives `(sender_identity_key, certificates)`. The callback is invoked
/// fire-and-forget: panics are caught and logged but do not affect request flow.
pub type OnCertificatesReceived =
    Box<dyn Fn(String, Vec<Certificate>) -> BoxFuture<'static, ()> + Send + Sync>;

impl<W: WalletInterface> std::fmt::Debug for AuthMiddlewareConfig<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthMiddlewareConfig")
            .field("allow_unauthenticated", &self.allow_unauthenticated)
            .field(
                "certificates_to_request",
                &self.certificates_to_request.is_some(),
            )
            .field("session_manager", &self.session_manager.is_some())
            .field(
                "on_certificates_received",
                &self.on_certificates_received.is_some(),
            )
            .field("log_level", &self.log_level)
            .finish()
    }
}

/// Configuration for the BSV authentication middleware.
///
/// Generic over `W: WalletInterface` for zero-cost static dispatch.
/// WalletInterface uses `#[async_trait]` and is object-safe, but generics
/// are preferred to avoid dynamic dispatch overhead.
pub struct AuthMiddlewareConfig<W: WalletInterface> {
    /// The wallet implementation used for authentication operations.
    #[allow(dead_code)]
    pub wallet: W,
    /// Whether to allow unauthenticated requests to pass through.
    /// Defaults to `false`.
    pub allow_unauthenticated: bool,
    /// Optional set of certificates to request from peers during authentication.
    pub certificates_to_request: Option<RequestedCertificateSet>,
    /// Optional session manager for tracking authenticated sessions.
    pub session_manager: Option<SessionManager>,
    /// Optional callback invoked when certificates are received from a peer.
    pub on_certificates_received: Option<Arc<OnCertificatesReceived>>,
    /// Optional verbosity for a default `tracing` subscriber.
    ///
    /// When `None` (the default), this crate does not install any tracing
    /// subscriber — the caller is expected to configure tracing itself, which
    /// is the idiomatic pattern for library consumers.
    ///
    /// When `Some(level)`, a default subscriber can be installed via
    /// [`AuthMiddlewareConfig::try_init_tracing`] that filters log records at
    /// or above `level`. Mirrors the `logLevel` option in the TypeScript
    /// `auth-express-middleware`: `Level::ERROR` means only errors log,
    /// `Level::DEBUG` means everything logs, and so on.
    pub log_level: Option<tracing::Level>,
}

impl<W: WalletInterface> AuthMiddlewareConfig<W> {
    /// Initialize a default `tracing_subscriber` using this config's `log_level`.
    ///
    /// - If `log_level` is `None`, this is a no-op and returns `Ok(())`. This
    ///   matches the idiomatic library pattern where the caller owns tracing
    ///   setup.
    /// - If `log_level` is `Some(level)`, installs a default
    ///   `tracing_subscriber::fmt` subscriber with a `LevelFilter` at `level`.
    ///
    /// Safe to call at most once per process: returns `Err(_)` if a global
    /// subscriber has already been installed.
    pub fn try_init_tracing(&self) -> Result<(), tracing_subscriber::util::TryInitError> {
        use tracing_subscriber::util::SubscriberInitExt;

        let Some(level) = self.log_level else {
            return Ok(());
        };

        tracing_subscriber::fmt()
            .with_max_level(level)
            .finish()
            .try_init()
    }
}

/// Builder for `AuthMiddlewareConfig`.
///
/// The wallet field is required; all other fields are optional with sensible
/// defaults. Call `build()` to produce the final configuration, which returns
/// an error if the wallet has not been set.
pub struct AuthMiddlewareConfigBuilder<W: WalletInterface> {
    wallet: Option<W>,
    allow_unauthenticated: bool,
    certificates_to_request: Option<RequestedCertificateSet>,
    session_manager: Option<SessionManager>,
    on_certificates_received: Option<Arc<OnCertificatesReceived>>,
    log_level: Option<tracing::Level>,
}

impl<W: WalletInterface> AuthMiddlewareConfigBuilder<W> {
    /// Create a new builder with default values.
    ///
    /// Defaults:
    /// - `wallet`: None (must be set before `build()`)
    /// - `allow_unauthenticated`: false
    /// - `certificates_to_request`: None
    /// - `session_manager`: None
    /// - `on_certificates_received`: None
    /// - `log_level`: None (caller owns tracing setup)
    pub fn new() -> Self {
        Self {
            wallet: None,
            allow_unauthenticated: false,
            certificates_to_request: None,
            session_manager: None,
            on_certificates_received: None,
            log_level: None,
        }
    }

    /// Set the wallet implementation (required).
    pub fn wallet(mut self, wallet: W) -> Self {
        self.wallet = Some(wallet);
        self
    }

    /// Set whether unauthenticated requests are allowed through.
    pub fn allow_unauthenticated(mut self, value: bool) -> Self {
        self.allow_unauthenticated = value;
        self
    }

    /// Set the certificates to request from peers.
    pub fn certificates_to_request(mut self, certs: RequestedCertificateSet) -> Self {
        self.certificates_to_request = Some(certs);
        self
    }

    /// Set the session manager.
    pub fn session_manager(mut self, manager: SessionManager) -> Self {
        self.session_manager = Some(manager);
        self
    }

    /// Set the callback invoked when certificates are received from a peer.
    pub fn on_certificates_received(mut self, cb: OnCertificatesReceived) -> Self {
        self.on_certificates_received = Some(Arc::new(cb));
        self
    }

    /// Set the tracing verbosity for an optional default subscriber.
    ///
    /// Setting this field only records the desired level on the built config —
    /// it does not itself install a subscriber. Call
    /// [`AuthMiddlewareConfig::try_init_tracing`] after `build()` if you want
    /// this crate to install a default `tracing_subscriber::fmt` subscriber
    /// filtered at the given level. If you omit this call (or leave
    /// `log_level` unset), the caller is expected to configure tracing
    /// themselves, which is the idiomatic Rust library pattern.
    pub fn log_level(mut self, level: tracing::Level) -> Self {
        self.log_level = Some(level);
        self
    }

    /// Build the configuration.
    ///
    /// Returns `AuthMiddlewareError::Config` if the wallet has not been set.
    pub fn build(self) -> Result<AuthMiddlewareConfig<W>, AuthMiddlewareError> {
        let wallet = self
            .wallet
            .ok_or_else(|| AuthMiddlewareError::Config("wallet is required".to_string()))?;

        let config = AuthMiddlewareConfig {
            wallet,
            allow_unauthenticated: self.allow_unauthenticated,
            certificates_to_request: self.certificates_to_request,
            session_manager: self.session_manager,
            on_certificates_received: self.on_certificates_received,
            log_level: self.log_level,
        };

        tracing::info!(
            allow_unauthenticated = config.allow_unauthenticated,
            log_level = ?config.log_level,
            "auth middleware configured"
        );

        Ok(config)
    }
}

impl<W: WalletInterface> Default for AuthMiddlewareConfigBuilder<W> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use bsv::wallet::error::WalletError;
    use bsv::wallet::interfaces::*;

    /// Minimal mock wallet that satisfies `WalletInterface` trait bounds.
    /// All methods return `unimplemented!()` since we only test config building.
    struct MockWallet;

    #[async_trait]
    impl WalletInterface for MockWallet {
        async fn create_action(
            &self,
            _args: CreateActionArgs,
            _originator: Option<&str>,
        ) -> Result<CreateActionResult, WalletError> {
            unimplemented!()
        }

        async fn sign_action(
            &self,
            _args: SignActionArgs,
            _originator: Option<&str>,
        ) -> Result<SignActionResult, WalletError> {
            unimplemented!()
        }

        async fn abort_action(
            &self,
            _args: AbortActionArgs,
            _originator: Option<&str>,
        ) -> Result<AbortActionResult, WalletError> {
            unimplemented!()
        }

        async fn list_actions(
            &self,
            _args: ListActionsArgs,
            _originator: Option<&str>,
        ) -> Result<ListActionsResult, WalletError> {
            unimplemented!()
        }

        async fn internalize_action(
            &self,
            _args: InternalizeActionArgs,
            _originator: Option<&str>,
        ) -> Result<InternalizeActionResult, WalletError> {
            unimplemented!()
        }

        async fn list_outputs(
            &self,
            _args: ListOutputsArgs,
            _originator: Option<&str>,
        ) -> Result<ListOutputsResult, WalletError> {
            unimplemented!()
        }

        async fn relinquish_output(
            &self,
            _args: RelinquishOutputArgs,
            _originator: Option<&str>,
        ) -> Result<RelinquishOutputResult, WalletError> {
            unimplemented!()
        }

        async fn get_public_key(
            &self,
            _args: GetPublicKeyArgs,
            _originator: Option<&str>,
        ) -> Result<GetPublicKeyResult, WalletError> {
            unimplemented!()
        }

        async fn reveal_counterparty_key_linkage(
            &self,
            _args: RevealCounterpartyKeyLinkageArgs,
            _originator: Option<&str>,
        ) -> Result<RevealCounterpartyKeyLinkageResult, WalletError> {
            unimplemented!()
        }

        async fn reveal_specific_key_linkage(
            &self,
            _args: RevealSpecificKeyLinkageArgs,
            _originator: Option<&str>,
        ) -> Result<RevealSpecificKeyLinkageResult, WalletError> {
            unimplemented!()
        }

        async fn encrypt(
            &self,
            _args: EncryptArgs,
            _originator: Option<&str>,
        ) -> Result<EncryptResult, WalletError> {
            unimplemented!()
        }

        async fn decrypt(
            &self,
            _args: DecryptArgs,
            _originator: Option<&str>,
        ) -> Result<DecryptResult, WalletError> {
            unimplemented!()
        }

        async fn create_hmac(
            &self,
            _args: CreateHmacArgs,
            _originator: Option<&str>,
        ) -> Result<CreateHmacResult, WalletError> {
            unimplemented!()
        }

        async fn verify_hmac(
            &self,
            _args: VerifyHmacArgs,
            _originator: Option<&str>,
        ) -> Result<VerifyHmacResult, WalletError> {
            unimplemented!()
        }

        async fn create_signature(
            &self,
            _args: CreateSignatureArgs,
            _originator: Option<&str>,
        ) -> Result<CreateSignatureResult, WalletError> {
            unimplemented!()
        }

        async fn verify_signature(
            &self,
            _args: VerifySignatureArgs,
            _originator: Option<&str>,
        ) -> Result<VerifySignatureResult, WalletError> {
            unimplemented!()
        }

        async fn acquire_certificate(
            &self,
            _args: AcquireCertificateArgs,
            _originator: Option<&str>,
        ) -> Result<Certificate, WalletError> {
            unimplemented!()
        }

        async fn list_certificates(
            &self,
            _args: ListCertificatesArgs,
            _originator: Option<&str>,
        ) -> Result<ListCertificatesResult, WalletError> {
            unimplemented!()
        }

        async fn prove_certificate(
            &self,
            _args: ProveCertificateArgs,
            _originator: Option<&str>,
        ) -> Result<ProveCertificateResult, WalletError> {
            unimplemented!()
        }

        async fn relinquish_certificate(
            &self,
            _args: RelinquishCertificateArgs,
            _originator: Option<&str>,
        ) -> Result<RelinquishCertificateResult, WalletError> {
            unimplemented!()
        }

        async fn discover_by_identity_key(
            &self,
            _args: DiscoverByIdentityKeyArgs,
            _originator: Option<&str>,
        ) -> Result<DiscoverCertificatesResult, WalletError> {
            unimplemented!()
        }

        async fn discover_by_attributes(
            &self,
            _args: DiscoverByAttributesArgs,
            _originator: Option<&str>,
        ) -> Result<DiscoverCertificatesResult, WalletError> {
            unimplemented!()
        }

        async fn is_authenticated(
            &self,
            _originator: Option<&str>,
        ) -> Result<AuthenticatedResult, WalletError> {
            unimplemented!()
        }

        async fn wait_for_authentication(
            &self,
            _originator: Option<&str>,
        ) -> Result<AuthenticatedResult, WalletError> {
            unimplemented!()
        }

        async fn get_height(
            &self,
            _originator: Option<&str>,
        ) -> Result<GetHeightResult, WalletError> {
            unimplemented!()
        }

        async fn get_header_for_height(
            &self,
            _args: GetHeaderArgs,
            _originator: Option<&str>,
        ) -> Result<GetHeaderResult, WalletError> {
            unimplemented!()
        }

        async fn get_network(
            &self,
            _originator: Option<&str>,
        ) -> Result<GetNetworkResult, WalletError> {
            unimplemented!()
        }

        async fn get_version(
            &self,
            _originator: Option<&str>,
        ) -> Result<GetVersionResult, WalletError> {
            unimplemented!()
        }
    }

    #[test]
    fn test_builder_with_wallet_succeeds() {
        let config = AuthMiddlewareConfigBuilder::new()
            .wallet(MockWallet)
            .build();
        assert!(config.is_ok());
    }

    #[test]
    fn test_builder_without_wallet_returns_error() {
        let result = AuthMiddlewareConfigBuilder::<MockWallet>::new().build();
        assert!(result.is_err());
        let err = result.unwrap_err();
        match &err {
            AuthMiddlewareError::Config(msg) => {
                assert_eq!(msg, "wallet is required");
            }
            _ => panic!("expected Config error, got: {:?}", err),
        }
    }

    #[test]
    fn test_allow_unauthenticated_defaults_to_false() {
        let config = AuthMiddlewareConfigBuilder::new()
            .wallet(MockWallet)
            .build()
            .unwrap();
        assert!(!config.allow_unauthenticated);
    }

    #[test]
    fn test_allow_unauthenticated_can_be_set_to_true() {
        let config = AuthMiddlewareConfigBuilder::new()
            .wallet(MockWallet)
            .allow_unauthenticated(true)
            .build()
            .unwrap();
        assert!(config.allow_unauthenticated);
    }

    #[test]
    fn test_certificates_to_request_can_be_set() {
        let mut certs = RequestedCertificateSet::default();
        certs
            .types
            .insert("certifier1".to_string(), vec!["field1".to_string()]);

        let config = AuthMiddlewareConfigBuilder::new()
            .wallet(MockWallet)
            .certificates_to_request(certs)
            .build()
            .unwrap();
        assert!(config.certificates_to_request.is_some());
        let certs = config.certificates_to_request.unwrap();
        assert!(certs.types.contains_key("certifier1"));
    }

    #[test]
    fn test_session_manager_can_be_set() {
        let manager = SessionManager::new();
        let config = AuthMiddlewareConfigBuilder::new()
            .wallet(MockWallet)
            .session_manager(manager)
            .build()
            .unwrap();
        assert!(config.session_manager.is_some());
    }

    #[test]
    fn test_tracing_compiles() {
        // This test validates that tracing::info! compiles in this module (CONF-02).
        // If tracing is misconfigured, this test fails at compile time.
        tracing::info!("config test tracing integration check");
    }

    #[test]
    fn test_on_certificates_received_can_be_set() {
        let cb: OnCertificatesReceived = Box::new(|_identity_key, _certs| Box::pin(async {}));
        let config = AuthMiddlewareConfigBuilder::new()
            .wallet(MockWallet)
            .on_certificates_received(cb)
            .build()
            .unwrap();
        assert!(config.on_certificates_received.is_some());
    }

    #[test]
    fn test_on_certificates_received_defaults_to_none() {
        let config = AuthMiddlewareConfigBuilder::new()
            .wallet(MockWallet)
            .build()
            .unwrap();
        assert!(config.on_certificates_received.is_none());
    }

    #[test]
    fn test_default_builder() {
        // Validate that Default trait impl works
        let builder = AuthMiddlewareConfigBuilder::<MockWallet>::default();
        let result = builder.build();
        assert!(result.is_err()); // no wallet set
    }

    #[test]
    fn test_log_level_defaults_to_none() {
        let config = AuthMiddlewareConfigBuilder::new()
            .wallet(MockWallet)
            .build()
            .unwrap();
        assert!(config.log_level.is_none());
    }

    #[test]
    fn test_log_level_can_be_set_via_builder() {
        let config = AuthMiddlewareConfigBuilder::new()
            .wallet(MockWallet)
            .log_level(tracing::Level::DEBUG)
            .build()
            .unwrap();
        assert_eq!(config.log_level, Some(tracing::Level::DEBUG));

        let config = AuthMiddlewareConfigBuilder::new()
            .wallet(MockWallet)
            .log_level(tracing::Level::WARN)
            .build()
            .unwrap();
        assert_eq!(config.log_level, Some(tracing::Level::WARN));
    }

    #[test]
    fn test_try_init_tracing_noop_when_level_is_none() {
        // When `log_level` is None, `try_init_tracing` must not install a
        // subscriber and must return Ok(()) — the caller owns tracing setup.
        // Because this is a no-op, it is safe to call in any test regardless
        // of global subscriber state.
        let config = AuthMiddlewareConfigBuilder::new()
            .wallet(MockWallet)
            .build()
            .unwrap();
        assert!(config.log_level.is_none());
        assert!(config.try_init_tracing().is_ok());
    }
}
