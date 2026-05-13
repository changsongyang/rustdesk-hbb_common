use crate::ResultType;
use rustls_pki_types::{ServerName, UnixTime};
use std::sync::Arc;
use tokio_rustls::rustls::{self, client::WebPkiServerVerifier, ClientConfig};
use tokio_rustls::rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    DigitallySignedStruct, Error as TLSError, SignatureScheme,
};

// https://github.com/seanmonstar/reqwest/blob/fd61bc93e6f936454ce0b978c6f282f06eee9287/src/tls.rs#L608
#[cfg(debug_assertions)]
#[derive(Debug)]
pub(crate) struct NoVerifier;

#[cfg(debug_assertions)]
impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer,
        _intermediates: &[rustls_pki_types::CertificateDer],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TLSError> {
        log::warn!("⚠️ WARNING: Skipping certificate verification in debug mode!");
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TLSError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TLSError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

/// A certificate verifier that tries a primary verifier first,
/// and falls back to a platform verifier if the primary fails.
#[cfg(any(target_os = "android", target_os = "ios"))]
#[derive(Debug)]
struct FallbackPlatformVerifier {
    primary: Arc<dyn ServerCertVerifier>,
    fallback: Arc<dyn ServerCertVerifier>,
}

#[cfg(any(target_os = "android", target_os = "ios"))]
impl FallbackPlatformVerifier {
    fn with_platform_fallback(
        primary: Arc<dyn ServerCertVerifier>,
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> Result<Self, TLSError> {
        #[cfg(target_os = "android")]
        if !crate::config::ANDROID_RUSTLS_PLATFORM_VERIFIER_INITIALIZED
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return Err(TLSError::General(
                "rustls-platform-verifier not initialized".to_string(),
            ));
        }
        let fallback = Arc::new(rustls_platform_verifier::Verifier::new(provider)?);
        Ok(Self { primary, fallback })
    }
}

#[cfg(any(target_os = "android", target_os = "ios"))]
impl ServerCertVerifier for FallbackPlatformVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls_pki_types::CertificateDer<'_>,
        intermediates: &[rustls_pki_types::CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TLSError> {
        match self.primary.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(verified) => Ok(verified),
            Err(primary_err) => {
                match self.fallback.verify_server_cert(
                    end_entity,
                    intermediates,
                    server_name,
                    ocsp_response,
                    now,
                ) {
                    Ok(verified) => Ok(verified),
                    Err(fallback_err) => {
                        log::error!(
                            "Both primary and fallback verifiers failed to verify server certificate, primary error: {:?}, fallback error: {:?}",
                            primary_err,
                            fallback_err
                        );
                        Err(primary_err)
                    }
                }
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TLSError> {
        self.primary.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TLSError> {
        self.primary.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.primary.supported_verify_schemes()
    }
}

fn webpki_server_verifier(
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> ResultType<Arc<WebPkiServerVerifier>> {
    let mut root_cert_store = rustls::RootCertStore::empty();
    root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let rustls_native_certs::CertificateResult { certs, errors, .. } =
        rustls_native_certs::load_native_certs();
    if !errors.is_empty() {
        log::warn!("native root CA certificate loading errors: {errors:?}");
    }
    root_cert_store.add_parsable_certificates(certs);

    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(root_cert_store),
        provider.clone(),
    )
    .allow_unknown_revocation_status()
    .build()
    .map_err(|e| anyhow::anyhow!(e))?;
    Ok(verifier)
}

pub fn client_config(danger_accept_invalid_cert: bool) -> ResultType<ClientConfig> {
    if danger_accept_invalid_cert {
        client_config_danger()
    } else {
        client_config_safe()
    }
}

pub fn client_config_safe() -> ResultType<ClientConfig> {
    let config_builder = rustls::ClientConfig::builder();
    let provider = config_builder.crypto_provider().clone();
    let webpki_verifier = webpki_server_verifier(provider.clone())?;
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        match FallbackPlatformVerifier::with_platform_fallback(webpki_verifier.clone(), provider) {
            Ok(fallback_verifier) => {
                let config = config_builder
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(fallback_verifier))
                    .with_no_client_auth();
                Ok(config)
            }
            Err(e) => {
                log::error!(
                    "Failed to create fallback verifier: {:?}, use webpki verifier instead",
                    e
                );
                let config = config_builder
                    .with_webpki_verifier(webpki_verifier)
                    .with_no_client_auth();
                Ok(config)
            }
        }
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let config = config_builder
            .with_webpki_verifier(webpki_verifier)
            .with_no_client_auth();
        Ok(config)
    }
}

pub fn client_config_danger() -> ResultType<ClientConfig> {
    #[cfg(not(debug_assertions))]
    {
        log::error!("⚠️ ERROR: client_config_danger() called in production! Certificate verification cannot be disabled.");
        bail!("Insecure certificate verification is not allowed in production builds");
    }
    
    #[cfg(debug_assertions)]
    {
        log::warn!("⚠️ WARNING: Using client_config_danger() - certificate verification is disabled!");
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        Ok(config)
    }
}
