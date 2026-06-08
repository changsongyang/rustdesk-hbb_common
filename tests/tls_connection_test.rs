//! Integration tests for TLS connection with rustls-platform-verifier 0.7.0
//!
//! These tests verify that the TLS connection functionality works correctly
//! after upgrading rustls-platform-verifier from 0.3.1 to 0.7.0.

#[cfg(test)]
mod tests {
    use hbb_common::Result;

    /// Test that rustls-platform-verifier can be instantiated
    #[test]
    fn test_verifier_creation() -> Result<()> {
        // This test verifies that the Verifier can be created with the new API
        let _verifier = rustls_platform_verifier::Verifier::new();
        Ok(())
    }

    /// Test that we can build a ClientConfig with the new API
    #[test]
    fn test_client_config_builder() -> Result<()> {
        use rustls::ClientConfig;
        use std::sync::Arc;

        // New API pattern from 0.7.0
        let config = ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(
                rustls_platform_verifier::Verifier::new(),
            ))
            .with_no_client_auth();

        assert!(config.client_cert_verifier.is_some());
        Ok(())
    }

    /// Test HTTPS connection to a known working endpoint
    #[tokio::test]
    async fn test_https_connection() -> Result<()> {
        // This is a basic integration test to verify TLS connections work
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(
                rustls::ClientConfig::builder()
                    .with_safe_defaults()
                    .with_custom_certificate_verifier(std::sync::Arc::new(
                        rustls_platform_verifier::Verifier::new(),
                    ))
                    .with_no_client_auth(),
            )
            .build()?;

        // Test with a reliable HTTPS endpoint
        let response = client
            .get("https://httpbin.org/get")
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await?;

        assert!(response.status().is_success());
        Ok(())
    }
}
