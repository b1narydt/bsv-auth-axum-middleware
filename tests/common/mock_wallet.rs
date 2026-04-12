//! MockWallet wrapping Arc<ProtoWallet> for Clone + WalletInterface.
//!
//! Delegates all crypto methods to ProtoWallet's WalletInterface impl and
//! provides in-memory certificate storage for list_certificates and prove_certificate.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use bsv::auth::certificates::master::MasterCertificate;
use bsv::primitives::private_key::PrivateKey;
use bsv::wallet::error::WalletError;
use bsv::wallet::interfaces::*;
use bsv::wallet::proto_wallet::ProtoWallet;

/// Test wallet wrapping ProtoWallet in Arc for Clone support.
///
/// ProtoWallet does not implement Clone (PrivateKey/KeyDeriver lack Clone).
/// MockWallet wraps it in Arc so that AuthFetch<W: Clone> is satisfied.
/// Certificate storage is provided via Arc<Mutex<Vec<MasterCertificate>>>.
#[derive(Clone)]
pub struct MockWallet {
    inner: Arc<ProtoWallet>,
    certificates: Arc<Mutex<Vec<MasterCertificate>>>,
}

impl MockWallet {
    pub fn new(private_key: PrivateKey) -> Self {
        MockWallet {
            inner: Arc::new(ProtoWallet::new(private_key)),
            certificates: Arc::new(Mutex::new(Vec::new())),
        }
    }

    #[allow(dead_code)]
    pub async fn add_master_certificate(&self, cert: MasterCertificate) {
        self.certificates.lock().await.push(cert);
    }
}

#[async_trait]
impl WalletInterface for MockWallet {
    // -----------------------------------------------------------------------
    // Crypto methods -- delegate to inner ProtoWallet via WalletInterface trait
    // -----------------------------------------------------------------------

    async fn get_public_key(
        &self,
        args: GetPublicKeyArgs,
        originator: Option<&str>,
    ) -> Result<GetPublicKeyResult, WalletError> {
        WalletInterface::get_public_key(&*self.inner, args, originator).await
    }

    async fn create_signature(
        &self,
        args: CreateSignatureArgs,
        originator: Option<&str>,
    ) -> Result<CreateSignatureResult, WalletError> {
        WalletInterface::create_signature(&*self.inner, args, originator).await
    }

    async fn verify_signature(
        &self,
        args: VerifySignatureArgs,
        originator: Option<&str>,
    ) -> Result<VerifySignatureResult, WalletError> {
        WalletInterface::verify_signature(&*self.inner, args, originator).await
    }

    async fn encrypt(
        &self,
        args: EncryptArgs,
        originator: Option<&str>,
    ) -> Result<EncryptResult, WalletError> {
        WalletInterface::encrypt(&*self.inner, args, originator).await
    }

    async fn decrypt(
        &self,
        args: DecryptArgs,
        originator: Option<&str>,
    ) -> Result<DecryptResult, WalletError> {
        WalletInterface::decrypt(&*self.inner, args, originator).await
    }

    async fn create_hmac(
        &self,
        args: CreateHmacArgs,
        originator: Option<&str>,
    ) -> Result<CreateHmacResult, WalletError> {
        WalletInterface::create_hmac(&*self.inner, args, originator).await
    }

    async fn verify_hmac(
        &self,
        args: VerifyHmacArgs,
        originator: Option<&str>,
    ) -> Result<VerifyHmacResult, WalletError> {
        WalletInterface::verify_hmac(&*self.inner, args, originator).await
    }

    async fn reveal_counterparty_key_linkage(
        &self,
        args: RevealCounterpartyKeyLinkageArgs,
        originator: Option<&str>,
    ) -> Result<RevealCounterpartyKeyLinkageResult, WalletError> {
        WalletInterface::reveal_counterparty_key_linkage(&*self.inner, args, originator).await
    }

    async fn reveal_specific_key_linkage(
        &self,
        args: RevealSpecificKeyLinkageArgs,
        originator: Option<&str>,
    ) -> Result<RevealSpecificKeyLinkageResult, WalletError> {
        WalletInterface::reveal_specific_key_linkage(&*self.inner, args, originator).await
    }

    // -----------------------------------------------------------------------
    // Overridden methods
    // -----------------------------------------------------------------------

    async fn internalize_action(
        &self,
        _args: InternalizeActionArgs,
        _originator: Option<&str>,
    ) -> Result<InternalizeActionResult, WalletError> {
        println!("[MockWallet] internalize_action called -- accepting");
        Ok(InternalizeActionResult { accepted: true })
    }

    async fn list_certificates(
        &self,
        args: ListCertificatesArgs,
        _originator: Option<&str>,
    ) -> Result<ListCertificatesResult, WalletError> {
        let certs = self.certificates.lock().await;
        let matching: Vec<CertificateResult> = certs
            .iter()
            .filter(|mc| {
                let type_match =
                    args.types.is_empty() || args.types.contains(&mc.certificate.cert_type);
                let certifier_match = args.certifiers.is_empty()
                    || args.certifiers.contains(&mc.certificate.certifier);
                type_match && certifier_match
            })
            .map(|mc| CertificateResult {
                certificate: mc.certificate.clone(),
                keyring: Some(mc.master_keyring.clone()),
                verifier: None,
            })
            .collect();

        println!(
            "[MockWallet] list_certificates: {} matching out of {} total",
            matching.len(),
            certs.len()
        );

        Ok(ListCertificatesResult {
            total_certificates: matching.len() as u32,
            certificates: matching,
        })
    }

    async fn prove_certificate(
        &self,
        args: ProveCertificateArgs,
        _originator: Option<&str>,
    ) -> Result<ProveCertificateResult, WalletError> {
        let certs = self.certificates.lock().await;
        let matching = certs.iter().find(|mc| {
            Some(mc.certificate.cert_type.clone()) == args.certificate.cert_type
                && Some(mc.certificate.subject.clone()) == args.certificate.subject
                && Some(mc.certificate.serial_number.clone()) == args.certificate.serial_number
                && Some(mc.certificate.certifier.clone()) == args.certificate.certifier
        });

        match matching {
            Some(mc) => {
                println!(
                    "[MockWallet] prove_certificate: found matching cert, creating keyring for verifier"
                );
                let keyring = mc
                    .create_keyring_for_verifier(
                        &args.verifier,
                        &args.fields_to_reveal,
                        args.certificate.certifier.as_ref().unwrap(),
                        self,
                    )
                    .await
                    .map_err(|e| {
                        WalletError::Internal(format!(
                            "failed to create keyring for verifier: {}",
                            e
                        ))
                    })?;
                Ok(ProveCertificateResult {
                    keyring_for_verifier: keyring,
                    certificate: None,
                    verifier: None,
                })
            }
            None => Err(WalletError::Internal(
                "no matching certificate found for prove_certificate".to_string(),
            )),
        }
    }

    // -----------------------------------------------------------------------
    // Stub methods -- delegate to inner (which returns NotImplemented)
    // -----------------------------------------------------------------------

    async fn create_action(
        &self,
        args: CreateActionArgs,
        originator: Option<&str>,
    ) -> Result<CreateActionResult, WalletError> {
        WalletInterface::create_action(&*self.inner, args, originator).await
    }

    async fn sign_action(
        &self,
        args: SignActionArgs,
        originator: Option<&str>,
    ) -> Result<SignActionResult, WalletError> {
        WalletInterface::sign_action(&*self.inner, args, originator).await
    }

    async fn abort_action(
        &self,
        args: AbortActionArgs,
        originator: Option<&str>,
    ) -> Result<AbortActionResult, WalletError> {
        WalletInterface::abort_action(&*self.inner, args, originator).await
    }

    async fn list_actions(
        &self,
        args: ListActionsArgs,
        originator: Option<&str>,
    ) -> Result<ListActionsResult, WalletError> {
        WalletInterface::list_actions(&*self.inner, args, originator).await
    }

    async fn list_outputs(
        &self,
        args: ListOutputsArgs,
        originator: Option<&str>,
    ) -> Result<ListOutputsResult, WalletError> {
        WalletInterface::list_outputs(&*self.inner, args, originator).await
    }

    async fn relinquish_output(
        &self,
        args: RelinquishOutputArgs,
        originator: Option<&str>,
    ) -> Result<RelinquishOutputResult, WalletError> {
        WalletInterface::relinquish_output(&*self.inner, args, originator).await
    }

    async fn acquire_certificate(
        &self,
        args: AcquireCertificateArgs,
        originator: Option<&str>,
    ) -> Result<Certificate, WalletError> {
        WalletInterface::acquire_certificate(&*self.inner, args, originator).await
    }

    async fn relinquish_certificate(
        &self,
        args: RelinquishCertificateArgs,
        originator: Option<&str>,
    ) -> Result<RelinquishCertificateResult, WalletError> {
        WalletInterface::relinquish_certificate(&*self.inner, args, originator).await
    }

    async fn discover_by_identity_key(
        &self,
        args: DiscoverByIdentityKeyArgs,
        originator: Option<&str>,
    ) -> Result<DiscoverCertificatesResult, WalletError> {
        WalletInterface::discover_by_identity_key(&*self.inner, args, originator).await
    }

    async fn discover_by_attributes(
        &self,
        args: DiscoverByAttributesArgs,
        originator: Option<&str>,
    ) -> Result<DiscoverCertificatesResult, WalletError> {
        WalletInterface::discover_by_attributes(&*self.inner, args, originator).await
    }

    async fn is_authenticated(
        &self,
        originator: Option<&str>,
    ) -> Result<AuthenticatedResult, WalletError> {
        WalletInterface::is_authenticated(&*self.inner, originator).await
    }

    async fn wait_for_authentication(
        &self,
        originator: Option<&str>,
    ) -> Result<AuthenticatedResult, WalletError> {
        WalletInterface::wait_for_authentication(&*self.inner, originator).await
    }

    async fn get_height(&self, originator: Option<&str>) -> Result<GetHeightResult, WalletError> {
        WalletInterface::get_height(&*self.inner, originator).await
    }

    async fn get_header_for_height(
        &self,
        args: GetHeaderArgs,
        originator: Option<&str>,
    ) -> Result<GetHeaderResult, WalletError> {
        WalletInterface::get_header_for_height(&*self.inner, args, originator).await
    }

    async fn get_network(&self, originator: Option<&str>) -> Result<GetNetworkResult, WalletError> {
        WalletInterface::get_network(&*self.inner, originator).await
    }

    async fn get_version(&self, originator: Option<&str>) -> Result<GetVersionResult, WalletError> {
        WalletInterface::get_version(&*self.inner, originator).await
    }
}
