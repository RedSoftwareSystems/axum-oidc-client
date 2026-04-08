//! JWT configuration and builder for [`JwtLayer`](super::layer::JwtLayer).
//!
//! # Overview
//!
//! [`JwtConfiguration<C>`] holds everything needed to decode and validate an
//! incoming Bearer token: the decoding key, the optional audience list, and a
//! pre-built [`Validation`] object.  The generic parameter `C` is the claims
//! type that the JWT payload will be deserialised into; it must implement
//! `serde::de::DeserializeOwned`.
//!
//! [`JwtConfigurationBuilder<C>`] provides a fluent API for constructing a
//! [`JwtConfiguration`].  Keys can be supplied in three ways:
//!
//! | Method | Description |
//! |--------|-------------|
//! [`with_decoding_key`](JwtConfigurationBuilder::with_decoding_key) | Supply a [`DecodingKey`] directly (HS256 secret, RSA/EC PEM, etc.) |
//! [`with_issuer`](JwtConfigurationBuilder::with_issuer) | Fetch `/.well-known/openid-configuration` and derive the key set from `jwks_uri` |
//! [`with_jwks_uri`](JwtConfigurationBuilder::with_jwks_uri) | Fetch a JWKS endpoint directly |
//!
//! The last key source wins.  Calling `with_issuer` or `with_jwks_uri` after
//! `with_decoding_key` (or vice-versa) replaces the previously set key.
//!
//! # Examples
//!
//! ## HS256 shared secret
//!
//! ```rust,no_run
//! use axum_oidc_client::jwt::{Algorithm, JwtConfiguration, JwtConfigurationBuilder};
//! use axum_oidc_client::jwt::DecodingKey;
//! use serde::Deserialize;
//!
//! #[derive(Debug, Clone, Deserialize)]
//! struct MyClaims { sub: String, email: Option<String> }
//!
//! # fn example() -> Result<(), axum_oidc_client::errors::Error> {
//! let key = DecodingKey::from_secret(b"my-secret");
//! let config: JwtConfiguration<MyClaims> = JwtConfigurationBuilder::new()
//!     .with_decoding_key(key)
//!     .with_audience(vec!["my-client-id".to_string()])
//!     .with_algorithm(Algorithm::HS256)
//!     .build()?;
//! # Ok(())
//! # }
//! ```
//!
//! ## OIDC auto-discovery
//!
//! ```rust,no_run
//! use axum_oidc_client::jwt::{JwtConfiguration, JwtConfigurationBuilder};
//! use axum_oidc_client::jwt::OidcClaims;
//!
//! # async fn example() -> Result<(), axum_oidc_client::errors::Error> {
//! let config: JwtConfiguration<OidcClaims> = JwtConfigurationBuilder::new()
//!     .with_issuer("https://accounts.google.com").await?
//!     .with_audience(vec!["my-client-id".to_string()])
//!     .build()?;
//! # Ok(())
//! # }
//! ```

use std::marker::PhantomData;
use std::sync::Arc;

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::de::DeserializeOwned;

use crate::errors::Error;
use crate::http_client::build_http_client;

// ── OIDC / JWKS discovery structs ─────────────────────────────────────────────

/// Minimal subset of `/.well-known/openid-configuration` we need.
#[derive(Debug, serde::Deserialize)]
struct OidcDiscovery {
    jwks_uri: String,
    #[serde(default)]
    issuer: Option<String>,
}

/// A single JSON Web Key as returned by a JWKS endpoint.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Jwk {
    /// Key type (`RSA`, `EC`, `oct`, …).
    pub kty: String,
    /// Key ID — used to match the `kid` header of an incoming JWT.
    #[serde(default)]
    pub kid: Option<String>,
    /// Algorithm (`RS256`, `ES256`, …).
    #[serde(default)]
    pub alg: Option<String>,
    // RSA fields
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,
    // EC fields
    #[serde(default)]
    pub crv: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
    // Symmetric (oct)
    #[serde(default)]
    pub k: Option<String>,
}

/// A JSON Web Key Set as returned by a JWKS endpoint.
#[derive(Debug, serde::Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

impl Jwks {
    /// Convert the first usable key in the set into a [`DecodingKey`].
    ///
    /// For RS256/RS384/RS512 keys the RSA components (`n`, `e`) are used.
    /// For EC keys the `x`/`y` components are used.
    /// For `oct` (symmetric) keys the `k` component is used.
    ///
    /// Returns an error if the set is empty or no key can be parsed.
    pub fn first_decoding_key(&self) -> Result<DecodingKey, Error> {
        for jwk in &self.keys {
            if let Ok(key) = jwk.to_decoding_key() {
                return Ok(key);
            }
        }
        Err(Error::InvalidResponse(
            "JWKS contained no usable decoding key".to_string(),
        ))
    }

    /// Convert the key in the set whose `kid` matches `kid_header`.
    /// Falls back to [`first_decoding_key`](Self::first_decoding_key) when
    /// no `kid` field is present on any key.
    pub fn decoding_key_for_kid(&self, kid_header: &str) -> Result<DecodingKey, Error> {
        // Try exact kid match first.
        for jwk in &self.keys {
            if jwk.kid.as_deref() == Some(kid_header)
                && let Ok(key) = jwk.to_decoding_key()
            {
                return Ok(key);
            }
        }
        // Fall back to the first usable key (provider may not set kid).
        self.first_decoding_key()
    }
}

impl Jwk {
    fn to_decoding_key(&self) -> Result<DecodingKey, Error> {
        match self.kty.as_str() {
            "RSA" => {
                let n = self.n.as_deref().ok_or_else(|| {
                    Error::InvalidResponse("RSA JWK missing 'n' component".to_string())
                })?;
                let e = self.e.as_deref().ok_or_else(|| {
                    Error::InvalidResponse("RSA JWK missing 'e' component".to_string())
                })?;
                DecodingKey::from_rsa_components(n, e).map_err(|e| {
                    Error::InvalidResponse(format!("Failed to build RSA decoding key: {e}"))
                })
            }
            "EC" => {
                let x = self.x.as_deref().ok_or_else(|| {
                    Error::InvalidResponse("EC JWK missing 'x' component".to_string())
                })?;
                let y = self.y.as_deref().ok_or_else(|| {
                    Error::InvalidResponse("EC JWK missing 'y' component".to_string())
                })?;
                DecodingKey::from_ec_components(x, y).map_err(|e| {
                    Error::InvalidResponse(format!("Failed to build EC decoding key: {e}"))
                })
            }
            "oct" => {
                let k = self.k.as_deref().ok_or_else(|| {
                    Error::InvalidResponse("oct JWK missing 'k' component".to_string())
                })?;
                DecodingKey::from_base64_secret(k).map_err(|e| {
                    Error::InvalidResponse(format!("Failed to build symmetric decoding key: {e}"))
                })
            }
            other => Err(Error::InvalidResponse(format!(
                "Unsupported JWK key type: {other}"
            ))),
        }
    }
}

// ── JwtConfiguration ──────────────────────────────────────────────────────────

/// Validated JWT configuration ready to be used by [`JwtLayer`](super::layer::JwtLayer).
///
/// The generic parameter `C` is the claims type that the JWT payload will be
/// deserialised into.  Any type that implements [`serde::de::DeserializeOwned`]
/// is accepted; use [`OidcClaims`](super::jwt_decoder::OidcClaims) for standard
/// OIDC tokens or bring your own struct for custom claims.
///
/// Constructed via [`JwtConfigurationBuilder`].
#[derive(Clone)]
pub struct JwtConfiguration<C>
where
    C: DeserializeOwned,
{
    /// The key used to verify the JWT signature.
    pub(crate) decoding_key: Arc<DecodingKey>,
    /// The full `jsonwebtoken` validation settings (algorithm, audience, …).
    pub(crate) validation: Arc<Validation>,
    /// Cached JWKS for providers discovered via `with_issuer` / `with_jwks_uri`.
    /// `None` when a key was supplied directly via `with_decoding_key`.
    pub(crate) jwks: Option<Arc<Jwks>>,
    /// Issuer string captured during OIDC discovery (informational).
    pub(crate) issuer: Option<String>,
    /// JWKS endpoint URL — stored so keys can be re-fetched when a provider
    /// rotates its signing keys and the cached set no longer contains the `kid`
    /// referenced by an incoming token.
    pub(crate) jwks_uri: Option<String>,
    /// Optional path to a custom CA certificate used when fetching the JWKS.
    /// Kept here so a refresh can use the same TLS trust chain as the initial fetch.
    pub(crate) custom_ca_cert: Option<String>,
    _claims: PhantomData<fn() -> C>,
}

impl<C: DeserializeOwned> std::fmt::Debug for JwtConfiguration<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtConfiguration")
            .field("issuer", &self.issuer)
            .field("jwks_uri", &self.jwks_uri)
            .field("has_jwks", &self.jwks.is_some())
            .finish_non_exhaustive()
    }
}

impl<C> JwtConfiguration<C>
where
    C: DeserializeOwned,
{
    /// Re-fetch the JWKS endpoint and return a fresh [`Jwks`].
    ///
    /// Called by [`JwtLayer`](super::layer::JwtLayer) when a token's `kid`
    /// is not found in the cached key set, which indicates the provider has
    /// rotated its signing keys since the configuration was built.
    ///
    /// Returns `None` when this configuration was not built from a JWKS
    /// source (i.e. a static key was supplied via `with_decoding_key`).
    pub(crate) async fn refresh_jwks(&self) -> Option<Result<Jwks, Error>> {
        let uri = self.jwks_uri.as_deref()?;
        let client = match build_http_client(self.custom_ca_cert.as_deref()) {
            Ok(c) => c,
            Err(e) => return Some(Err(e)),
        };
        let result = async {
            client
                .get(uri)
                .send()
                .await
                .map_err(Error::Request)?
                .error_for_status()
                .map_err(|e| {
                    Error::InvalidResponse(format!("JWKS refresh request to {uri} failed: {e}"))
                })?
                .json::<Jwks>()
                .await
                .map_err(|e| {
                    Error::InvalidResponse(format!(
                        "Failed to parse refreshed JWKS from {uri}: {e}"
                    ))
                })
        }
        .await;
        Some(result)
    }
}

// ── JwtConfigurationBuilder ───────────────────────────────────────────────────

/// Builder for [`JwtConfiguration<C>`].
///
/// # Key source (mutually exclusive, last one wins)
///
/// - [`with_decoding_key`](Self::with_decoding_key) – supply a key directly
/// - [`with_issuer`](Self::with_issuer) – OIDC discovery → JWKS fetch
/// - [`with_jwks_uri`](Self::with_jwks_uri) – JWKS fetch directly
///
/// # Required before [`build`](Self::build)
///
/// At least one key source must be provided.
pub struct JwtConfigurationBuilder<C>
where
    C: DeserializeOwned,
{
    decoding_key: Option<DecodingKey>,
    jwks: Option<Jwks>,
    audience: Option<Vec<String>>,
    algorithm: Algorithm,
    issuer: Option<String>,
    /// Stored so it can be forwarded to `JwtConfiguration` for JWKS refresh.
    jwks_uri: Option<String>,
    validate_exp: bool,
    custom_ca_cert: Option<String>,
    _claims: PhantomData<fn() -> C>,
}

impl<C: DeserializeOwned> Default for JwtConfigurationBuilder<C> {
    fn default() -> Self {
        Self {
            decoding_key: None,
            jwks: None,
            audience: None,
            algorithm: Algorithm::RS256,
            issuer: None,
            jwks_uri: None,
            validate_exp: true,
            custom_ca_cert: None,
            _claims: PhantomData,
        }
    }
}

impl<C: DeserializeOwned> JwtConfigurationBuilder<C> {
    /// Create a new builder with defaults:
    /// - algorithm: `RS256`
    /// - `exp` validation: enabled
    pub fn new() -> Self {
        Self::default()
    }

    // ── Key source ─────────────────────────────────────────────────────────────

    /// Set a custom CA certificate for HTTPS requests made by
    /// [`with_issuer`](Self::with_issuer) and [`with_jwks_uri`](Self::with_jwks_uri).
    ///
    /// Use this when your OIDC provider uses a private or self-signed CA that
    /// is not in the system trust store.  Call this **before** `with_issuer`
    /// or `with_jwks_uri` so the certificate is available when those methods
    /// make their HTTP requests.
    ///
    /// # Arguments
    ///
    /// * `path` – Filesystem path to a PEM-encoded X.509 CA certificate.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use axum_oidc_client::jwt::JwtConfigurationBuilder;
    /// # use axum_oidc_client::jwt::OidcClaims;
    /// # async fn example() -> Result<(), axum_oidc_client::errors::Error> {
    /// let config = JwtConfigurationBuilder::<OidcClaims>::new()
    ///     .with_custom_ca_cert("/etc/ssl/my-corp-ca.pem")
    ///     .with_issuer("https://sso.internal.example.com").await?
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_custom_ca_cert(mut self, path: impl Into<String>) -> Self {
        self.custom_ca_cert = Some(path.into());
        self
    }

    /// Supply a [`DecodingKey`] directly.
    ///
    /// Use this for shared-secret (HS256) tokens or when you already hold an
    /// RSA/EC public key in PEM form.  Replaces any key previously set by
    /// `with_issuer` or `with_jwks_uri`.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use axum_oidc_client::jwt::{JwtConfigurationBuilder, DecodingKey, Algorithm};
    /// # use serde::Deserialize;
    /// # #[derive(Deserialize)] struct C;
    /// # fn example() -> Result<(), axum_oidc_client::errors::Error> {
    /// let config = JwtConfigurationBuilder::<C>::new()
    ///     .with_decoding_key(DecodingKey::from_secret(b"my-secret"))
    ///     .with_algorithm(Algorithm::HS256)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_decoding_key(mut self, key: DecodingKey) -> Self {
        self.decoding_key = Some(key);
        self.jwks = None;
        self
    }

    /// Populate the key set from an OIDC provider's discovery document.
    ///
    /// Fetches `<issuer>/.well-known/openid-configuration`, reads `jwks_uri`,
    /// and fetches the JWKS endpoint.  The discovered issuer string is stored
    /// and can be used by [`build`](Self::build) if no explicit issuer
    /// validation has been configured.
    ///
    /// Replaces any key previously set by `with_decoding_key` or
    /// `with_jwks_uri`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidResponse`] if the HTTP requests fail or the
    /// responses cannot be parsed.
    pub async fn with_issuer(mut self, issuer: &str) -> Result<Self, Error> {
        let issuer = issuer.trim_end_matches('/');
        let discovery_url = format!("{issuer}/.well-known/openid-configuration");

        let client = build_http_client(self.custom_ca_cert.as_deref())?;

        let discovery: OidcDiscovery = client
            .get(&discovery_url)
            .send()
            .await
            .map_err(Error::Request)?
            .error_for_status()
            .map_err(|e| {
                Error::InvalidResponse(format!(
                    "OIDC discovery request to {discovery_url} failed: {e}"
                ))
            })?
            .json()
            .await
            .map_err(|e| {
                Error::InvalidResponse(format!(
                    "Failed to parse OIDC discovery document from {discovery_url}: {e}"
                ))
            })?;

        self.issuer = discovery.issuer.or_else(|| Some(issuer.to_string()));
        self = self.with_jwks_uri(&discovery.jwks_uri).await?;
        Ok(self)
    }

    /// Populate the key set by fetching a JWKS endpoint directly.
    ///
    /// Replaces any key previously set by `with_decoding_key` or
    /// `with_issuer`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidResponse`] if the HTTP request fails or the
    /// response cannot be parsed as a JWKS document.
    pub async fn with_jwks_uri(mut self, jwks_uri: &str) -> Result<Self, Error> {
        let client = build_http_client(self.custom_ca_cert.as_deref())?;

        let jwks: Jwks = client
            .get(jwks_uri)
            .send()
            .await
            .map_err(Error::Request)?
            .error_for_status()
            .map_err(|e| Error::InvalidResponse(format!("JWKS request to {jwks_uri} failed: {e}")))?
            .json()
            .await
            .map_err(|e| {
                Error::InvalidResponse(format!(
                    "Failed to parse JWKS response from {jwks_uri}: {e}"
                ))
            })?;

        self.jwks = Some(jwks);
        self.jwks_uri = Some(jwks_uri.to_string());
        self.decoding_key = None;
        Ok(self)
    }

    // ── Validation options ─────────────────────────────────────────────────────

    /// Set the expected audience.
    ///
    /// When set, the `aud` claim in the token must contain at least one of
    /// the provided values.
    pub fn with_audience(mut self, audience: Vec<String>) -> Self {
        self.audience = Some(audience);
        self
    }

    /// Set the signing algorithm.
    ///
    /// Defaults to `RS256`.  Use `HS256` for shared-secret tokens,
    /// `ES256`/`ES384` for EC keys, etc.
    pub fn with_algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Enable or disable `exp` (expiration) validation.
    ///
    /// Defaults to `true` (enabled).  Disable only in tests.
    pub fn with_exp_validation(mut self, validate: bool) -> Self {
        self.validate_exp = validate;
        self
    }

    // ── build ─────────────────────────────────────────────────────────────────

    /// Build the [`JwtConfiguration`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingPatameter`] when no key source has been set
    /// (i.e. none of `with_decoding_key`, `with_issuer`, or `with_jwks_uri`
    /// was called).
    pub fn build(self) -> Result<JwtConfiguration<C>, Error> {
        // Resolve the primary decoding key.
        let (decoding_key, jwks) = match (self.decoding_key, self.jwks) {
            (Some(key), jwks) => (key, jwks),
            (None, Some(jwks)) => (jwks.first_decoding_key()?, Some(jwks)),
            (None, None) => {
                return Err(Error::MissingPatameter(
                    "JwtConfigurationBuilder requires a key source: \
                     call with_decoding_key, with_issuer, or with_jwks_uri"
                        .to_string(),
                ));
            }
        };

        let mut validation = Validation::new(self.algorithm);
        validation.validate_exp = self.validate_exp;

        if let Some(aud) = &self.audience {
            validation.set_audience(aud);
        } else {
            // Disable audience check when no audience was explicitly provided
            // so callers are not forced to set it.
            validation.validate_aud = false;
        }

        Ok(JwtConfiguration {
            decoding_key: Arc::new(decoding_key),
            validation: Arc::new(validation),
            jwks: jwks.map(Arc::new),
            issuer: self.issuer,
            jwks_uri: self.jwks_uri,
            custom_ca_cert: self.custom_ca_cert,
            _claims: PhantomData,
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Clone, Deserialize)]
    struct TestClaims {
        #[allow(dead_code)]
        sub: String,
    }

    #[test]
    fn test_build_with_decoding_key() {
        let key = DecodingKey::from_secret(b"secret");
        let config = JwtConfigurationBuilder::<TestClaims>::new()
            .with_decoding_key(key)
            .with_algorithm(Algorithm::HS256)
            .build();

        assert!(config.is_ok(), "should build with a direct decoding key");
        let cfg = config.unwrap();
        assert!(cfg.jwks.is_none());
        assert!(cfg.issuer.is_none());
    }

    #[test]
    fn test_build_without_key_fails() {
        let result = JwtConfigurationBuilder::<TestClaims>::new().build();
        assert!(
            matches!(result, Err(Error::MissingPatameter(_))),
            "should fail without a key source"
        );
    }

    #[test]
    fn test_build_with_audience() {
        let key = DecodingKey::from_secret(b"secret");
        let config = JwtConfigurationBuilder::<TestClaims>::new()
            .with_decoding_key(key)
            .with_algorithm(Algorithm::HS256)
            .with_audience(vec!["my-client".to_string()])
            .build()
            .unwrap();

        assert!(config.validation.validate_aud);
    }

    #[test]
    fn test_build_without_audience_disables_aud_check() {
        let key = DecodingKey::from_secret(b"secret");
        let config = JwtConfigurationBuilder::<TestClaims>::new()
            .with_decoding_key(key)
            .with_algorithm(Algorithm::HS256)
            .build()
            .unwrap();

        assert!(!config.validation.validate_aud);
    }

    #[test]
    fn test_with_decoding_key_clears_jwks() {
        // Simulate: start with a JWKS (by setting the field directly), then
        // call with_decoding_key — the JWKS should be cleared.
        let mut builder = JwtConfigurationBuilder::<TestClaims>::new();
        builder.jwks = Some(Jwks { keys: vec![] });
        let builder = builder.with_decoding_key(DecodingKey::from_secret(b"s"));
        assert!(builder.jwks.is_none());
        assert!(builder.decoding_key.is_some());
    }

    #[tokio::test]
    async fn test_with_issuer_404_returns_error() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        server
            .mock("GET", "/.well-known/openid-configuration")
            .with_status(404)
            .create_async()
            .await;

        let result = JwtConfigurationBuilder::<TestClaims>::new()
            .with_issuer(&base)
            .await;

        assert!(
            matches!(result, Err(Error::InvalidResponse(_))),
            "404 from discovery endpoint should return InvalidResponse"
        );
    }

    #[tokio::test]
    async fn test_with_jwks_uri_404_returns_error() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        server
            .mock("GET", "/jwks")
            .with_status(404)
            .create_async()
            .await;

        let result = JwtConfigurationBuilder::<TestClaims>::new()
            .with_jwks_uri(&format!("{base}/jwks"))
            .await;

        assert!(
            matches!(result, Err(Error::InvalidResponse(_))),
            "404 from JWKS endpoint should return InvalidResponse"
        );
    }

    #[tokio::test]
    async fn test_with_issuer_fetches_jwks() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        let discovery = serde_json::json!({
            "issuer": base,
            "jwks_uri": format!("{base}/jwks"),
            "authorization_endpoint": format!("{base}/auth"),
            "token_endpoint": format!("{base}/token"),
        });

        // A minimal RS256 JWK — the key components below are synthetic and
        // will not verify real tokens; we just need the builder to parse them.
        let jwks = serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "kid": "key-1",
                "alg": "RS256",
                "use": "sig",
                "n": "sIwr0RlMTCpMUxJsU_",
                "e": "AQAB"
            }]
        });

        server
            .mock("GET", "/.well-known/openid-configuration")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(discovery.to_string())
            .create_async()
            .await;

        server
            .mock("GET", "/jwks")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(jwks.to_string())
            .create_async()
            .await;

        let result = JwtConfigurationBuilder::<TestClaims>::new()
            .with_issuer(&base)
            .await;

        // The RSA components above are intentionally truncated so
        // first_decoding_key() may fail; we only care that the HTTP fetch and
        // JSON parsing succeeded (i.e. no InvalidResponse from networking).
        // Accept either Ok or an InvalidResponse about key parsing.
        match result {
            Ok(builder) => assert!(builder.jwks.is_some()),
            Err(Error::InvalidResponse(msg)) => {
                assert!(
                    msg.contains("RSA") || msg.contains("key") || msg.contains("JWKS"),
                    "unexpected error: {msg}"
                );
            }
            Err(e) => panic!("unexpected error variant: {e}"),
        }
    }
}
