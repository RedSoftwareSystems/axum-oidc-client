//! HTTP client construction for axum-oidc-client.
//!
//! This module is the single source of truth for building [`reqwest::Client`]
//! instances used throughout the crate.  All outbound HTTP requests — OIDC
//! discovery, token exchange, and token refresh — go through
//! [`build_http_client`] so that custom CA certificate support is applied
//! uniformly without duplication.
//!
//! # Custom CA certificates
//!
//! When a path is supplied and a reqwest TLS feature is enabled, the PEM file
//! is read from disk, parsed as an X.509 certificate, and added to the client's
//! trust store via [`reqwest::ClientBuilder::add_root_certificate`].  When the
//! `reqwest-rustls-tls` feature is enabled, [`use_rustls_tls()`] is set to
//! guarantee a consistent TLS backend across all call sites.
//!
//! # Errors
//!
//! [`build_http_client`] returns [`Error::InvalidResponse`] (rather than
//! panicking) when:
//! - A custom CA certificate is configured without a reqwest TLS feature.
//! - The certificate file cannot be read from the given path.
//! - The file contents cannot be parsed as a PEM-encoded X.509 certificate.
//! - The [`reqwest::ClientBuilder`] fails to produce a client (this is
//!   exceedingly rare but possible if TLS initialisation fails).

use reqwest::Client;

use crate::errors::Error;

/// Build a [`reqwest::Client`] that optionally trusts a custom CA certificate.
///
/// This is the **only** place in the crate where `reqwest::Client` instances
/// are constructed.  Using it everywhere ensures:
///
/// - Custom CA certificates are honoured for every outbound request (OIDC
///   discovery, token exchange, token refresh).
/// - The TLS backend is consistent: `use_rustls_tls()` is set whenever a
///   custom certificate is provided.
/// - Errors are reported cleanly via [`Error`] instead of panicking.
///
/// # Arguments
///
/// * `custom_ca_cert` – Optional path to a PEM-encoded X.509 CA certificate
///   file.  Pass `None` to build a default client that trusts the system root
///   store.
///
/// # Errors
///
/// Returns [`Error::InvalidResponse`] if a custom CA certificate is configured
/// without a reqwest TLS feature, if the certificate file cannot be read or
/// parsed, or if the underlying [`reqwest::ClientBuilder::build`] call fails.
///
/// # Examples
///
/// This is an internal helper used by authentication and JWT discovery flows.
pub(crate) fn build_http_client(custom_ca_cert: Option<&str>) -> Result<Client, Error> {
    let builder = match custom_ca_cert {
        Some(path) => {
            #[cfg(not(any(
                feature = "reqwest-rustls-tls",
                feature = "reqwest-native-tls",
                feature = "reqwest-native-tls-vendored"
            )))]
            {
                return Err(Error::InvalidResponse(format!(
                    "Custom CA certificate '{path}' requires one reqwest TLS feature: \
                     `reqwest-rustls-tls`, `reqwest-native-tls`, or `reqwest-native-tls-vendored`"
                )));
            }

            #[cfg(any(
                feature = "reqwest-rustls-tls",
                feature = "reqwest-native-tls",
                feature = "reqwest-native-tls-vendored"
            ))]
            build_http_client_with_custom_ca(path)?
        }
        None => reqwest::ClientBuilder::new(),
    };

    builder
        .build()
        .map_err(|e| Error::InvalidResponse(format!("Failed to build HTTP client: {e}")))
}

#[cfg(any(
    feature = "reqwest-rustls-tls",
    feature = "reqwest-native-tls",
    feature = "reqwest-native-tls-vendored"
))]
fn build_http_client_with_custom_ca(path: &str) -> Result<reqwest::ClientBuilder, Error> {
    let pem = std::fs::read(path).map_err(|e| {
        Error::InvalidResponse(format!(
            "Failed to read custom CA certificate from '{path}': {e}"
        ))
    })?;

    // reqwest's rustls backend defers PEM validation to connection
    // time, so Certificate::from_pem always succeeds regardless of
    // content.  Validate eagerly here: a valid PEM certificate file
    // must contain at least one "-----BEGIN CERTIFICATE-----" block.
    let pem_text = std::str::from_utf8(&pem).unwrap_or("");
    if !pem_text.contains("-----BEGIN CERTIFICATE-----") {
        return Err(Error::InvalidResponse(format!(
            "Failed to parse custom CA certificate from '{path}': \
             no PEM certificate block found"
        )));
    }

    let cert = reqwest::Certificate::from_pem(&pem).map_err(|e| {
        Error::InvalidResponse(format!(
            "Failed to parse custom CA certificate from '{path}': {e}"
        ))
    })?;

    let builder = reqwest::ClientBuilder::new().add_root_certificate(cert);

    #[cfg(feature = "reqwest-rustls-tls")]
    let builder = builder.use_rustls_tls();

    Ok(builder)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_http_client_no_cert() {
        let result = build_http_client(None);
        assert!(result.is_ok(), "default client should build without error");
    }

    #[test]
    fn test_build_http_client_missing_cert_file() {
        let result = build_http_client(Some("/nonexistent/path/ca.pem"));
        assert!(
            matches!(result, Err(Error::InvalidResponse(_))),
            "missing cert file should return InvalidResponse"
        );
        if let Err(Error::InvalidResponse(msg)) = result {
            assert!(
                msg.contains("/nonexistent/path/ca.pem"),
                "error message should contain the cert path"
            );
        }
    }

    #[test]
    fn test_build_http_client_invalid_pem() {
        // Write a temp file with plain text content (no PEM headers).
        // The early validation in build_http_client detects the missing
        // "-----BEGIN CERTIFICATE-----" block and returns an error before
        // handing the bytes to reqwest (whose rustls backend would otherwise
        // defer validation to connection time and succeed here).
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        tmp.write_all(b"not a valid pem certificate")
            .expect("write");
        let path = tmp.path().to_str().expect("path");

        let result = build_http_client(Some(path));
        assert!(
            matches!(result, Err(Error::InvalidResponse(_))),
            "invalid PEM should return InvalidResponse"
        );
        if let Err(Error::InvalidResponse(msg)) = result {
            assert!(
                msg.contains(path),
                "error message should contain the cert path"
            );
        }
    }
}
