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
//! When a path is supplied the PEM file is read from disk, parsed as an X.509
//! certificate, and added to the client's trust store via
//! [`reqwest::ClientBuilder::add_root_certificate`].  [`use_rustls_tls()`] is
//! always set when a custom certificate is provided to guarantee a consistent
//! TLS backend across all call sites.
//!
//! # Errors
//!
//! [`build_http_client`] returns [`Error::InvalidResponse`] (rather than
//! panicking) when:
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
/// Returns [`Error::InvalidResponse`] if the certificate file cannot be read
/// or parsed, or if the underlying [`reqwest::ClientBuilder::build`] call
/// fails.
///
/// # Examples
///
/// ```rust,no_run
/// use axum_oidc_client::http_client::build_http_client;
///
/// # fn example() -> Result<(), axum_oidc_client::errors::Error> {
/// // Default client — trusts the system root store.
/// let client = build_http_client(None)?;
///
/// // Client that also trusts a private CA.
/// let client = build_http_client(Some("/etc/ssl/my-corp-ca.pem"))?;
/// # Ok(())
/// # }
/// ```
pub fn build_http_client(custom_ca_cert: Option<&str>) -> Result<Client, Error> {
    let builder = match custom_ca_cert {
        Some(path) => {
            let pem = std::fs::read(path).map_err(|e| {
                Error::InvalidResponse(format!(
                    "Failed to read custom CA certificate from '{path}': {e}"
                ))
            })?;
            let cert = reqwest::Certificate::from_pem(&pem).map_err(|e| {
                Error::InvalidResponse(format!(
                    "Failed to parse custom CA certificate from '{path}': {e}"
                ))
            })?;
            reqwest::ClientBuilder::new()
                .add_root_certificate(cert)
                .use_rustls_tls()
        }
        None => reqwest::ClientBuilder::new(),
    };

    builder
        .build()
        .map_err(|e| Error::InvalidResponse(format!("Failed to build HTTP client: {e}")))
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
        // Write a temp file with invalid PEM content and verify the parse
        // error is returned correctly.
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
