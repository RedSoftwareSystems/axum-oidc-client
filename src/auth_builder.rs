//! OAuth2 configuration builder module.
//!
//! This module provides a builder pattern for constructing [`OAuthConfiguration`]
//! instances with validation and sensible defaults.
//!
//! Endpoints can be populated automatically from an OIDC provider's discovery
//! document by calling [`OAuthConfigurationBuilder::with_issuer`].  Any field
//! set explicitly with a `with_*` setter always takes precedence over values
//! fetched from the discovery document.
//!
//! # Examples
//!
//! ## Manual endpoint configuration
//!
//! ```rust,no_run
//! use axum_oidc_client::auth_builder::OAuthConfigurationBuilder;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = OAuthConfigurationBuilder::default()
//!     .with_authorization_endpoint("https://accounts.google.com/o/oauth2/auth")
//!     .with_token_endpoint("https://oauth2.googleapis.com/token")
//!     .with_client_id("your-client-id")
//!     .with_client_secret("your-client-secret")
//!     .with_redirect_uri("http://localhost:8080/auth/callback")
//!     .with_private_cookie_key("your-secret-key-at-least-32-bytes")
//!     .with_scopes(vec!["openid", "email", "profile"])
//!     .with_post_logout_redirect_uri("/")
//!     .with_session_max_age(30) // 30 minutes
//!     .with_token_max_age(5)    // 5 minutes
//!     .build()?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Auto-discovery via issuer URL
//!
//! ```rust,no_run
//! use axum_oidc_client::auth_builder::OAuthConfigurationBuilder;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = OAuthConfigurationBuilder::default()
//!     .with_issuer("https://accounts.google.com").await?
//!     .with_client_id("your-client-id")
//!     .with_client_secret("your-client-secret")
//!     .with_redirect_uri("http://localhost:8080/auth/callback")
//!     .with_private_cookie_key("your-secret-key-at-least-32-bytes")
//!     .with_post_logout_redirect_uri("/")
//!     .with_session_max_age(30)
//!     .build()?;
//! # Ok(())
//! # }
//! ```

use std::fmt::Display;

use axum_extra::extract::cookie::Key;
use serde::Deserialize;

use crate::auth::{CodeChallengeMethod, OAuthConfiguration};
use crate::errors::Error;
use crate::http_client::build_http_client;

// ─── OIDC Discovery document ──────────────────────────────────────────────────

/// Subset of the OIDC Provider Metadata returned by the
/// `/.well-known/openid-configuration` discovery endpoint.
///
/// Only the fields that map directly to [`OAuthConfigurationBuilder`] are
/// captured here.  Additional fields present in the document are silently
/// ignored via `#[serde(deny_unknown_fields)]` being absent.
///
/// Reference: [OpenID Connect Discovery 1.0 §3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)
#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    /// `authorization_endpoint` — URL of the authorization server's
    /// authorization endpoint.  Maps to
    /// [`OAuthConfigurationBuilder::authorization_endpoint`].
    authorization_endpoint: String,

    /// `token_endpoint` — URL of the authorization server's token endpoint.
    /// Maps to [`OAuthConfigurationBuilder::token_endpoint`].
    token_endpoint: String,

    /// `end_session_endpoint` — URL of the OP's logout endpoint (optional).
    /// Present only for providers that support RP-Initiated Logout.
    /// Maps to [`OAuthConfigurationBuilder::end_session_endpoint`].
    #[serde(default)]
    end_session_endpoint: Option<String>,

    /// `scopes_supported` — list of OAuth 2.0 scope values the server supports
    /// (optional).  When present and the builder has no explicit scopes set,
    /// the intersection of this list with `["openid", "email", "profile"]` is
    /// used so we only request scopes the provider actually supports.
    #[serde(default)]
    scopes_supported: Option<Vec<String>>,

    /// `code_challenge_methods_supported` — PKCE methods supported by the
    /// provider (optional).  When present and the builder has not had
    /// `with_code_challenge_method` called, `S256` is selected if supported,
    /// otherwise `plain`.
    #[serde(default)]
    code_challenge_methods_supported: Option<Vec<String>>,
}

/// OAuth2 scopes wrapper.
///
/// A collection of OAuth2 scopes that will be requested during authentication.
/// Scopes are joined with spaces when serialized.
///
/// # Default Scopes
///
/// - `openid` - Required for OIDC
/// - `email` - User's email address
/// - `profile` - User's profile information
#[derive(Debug, Clone)]
pub struct Scopes(Vec<String>);

impl Default for Scopes {
    fn default() -> Self {
        Self(vec![
            "openid".to_string(),
            "email".to_string(),
            "profile".to_string(),
        ])
    }
}

impl Display for Scopes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.join(" "))
    }
}

/// Builder for constructing [`OAuthConfiguration`].
///
/// Provides a fluent API for building OAuth2 configurations with validation
/// and sensible defaults.
///
/// Endpoints can be populated automatically from an OIDC discovery document
/// by calling [`with_issuer`](Self::with_issuer).  Any field subsequently set
/// with a `with_*` setter overrides the discovered value.
///
/// # Required Fields
///
/// The following fields must be set before calling [`build()`](Self::build),
/// either manually or via [`with_issuer`](Self::with_issuer):
/// - `client_id`
/// - `client_secret`
/// - `redirect_uri`
/// - `authorization_endpoint`
/// - `token_endpoint`
/// - `private_cookie_key`
///
/// # Optional Fields
///
/// - `scopes` - Defaults to `["openid", "email", "profile"]`
/// - `code_challenge_method` - Defaults to `S256`
/// - `end_session_endpoint` - For OIDC logout support (auto-discovered when present)
/// - `post_logout_redirect_uri` - Where to redirect after logout
/// - `custom_ca_cert` - Path to custom CA certificate
/// - `session_max_age` - Maximum session duration in minutes
/// - `token_max_age` - Maximum token age in minutes
///
/// # Examples
///
/// ```rust,no_run
/// use axum_oidc_client::auth_builder::OAuthConfigurationBuilder;
/// use axum_oidc_client::auth::CodeChallengeMethod;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = OAuthConfigurationBuilder::default()
///     .with_client_id("my-client-id")
///     .with_client_secret("my-client-secret")
///     .with_redirect_uri("http://localhost:8080/auth/callback")
///     .with_authorization_endpoint("https://provider.com/oauth/authorize")
///     .with_token_endpoint("https://provider.com/oauth/token")
///     .with_private_cookie_key("secret-key-min-32-bytes-long")
///     .with_post_logout_redirect_uri("/")
///     .with_session_max_age(30)
///     .with_code_challenge_method(CodeChallengeMethod::S256)
///     .build()?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Default, Clone)]
pub struct OAuthConfigurationBuilder {
    /// Secret key for encrypting session cookies
    pub private_cookie_key: Option<Key>,
    /// OAuth2 client identifier
    pub client_id: Option<String>,
    /// OAuth2 client secret
    pub client_secret: Option<String>,
    /// Redirect URI for OAuth2 callback
    pub redirect_uri: Option<String>,
    /// OAuth2 authorization endpoint URL
    pub authorization_endpoint: Option<String>,
    /// OAuth2 token endpoint URL
    pub token_endpoint: Option<String>,
    /// Optional OIDC end session endpoint URL
    pub end_session_endpoint: Option<String>,
    /// URI to redirect to after logout
    pub post_logout_redirect_uri: Option<String>,
    /// OAuth2 scopes to request
    pub scopes: Scopes,
    /// PKCE code challenge method
    pub code_challenge_method: CodeChallengeMethod,
    /// Optional path to custom CA certificate
    pub custom_ca_cert: Option<String>,
    /// Maximum session age in minutes
    pub session_max_age: Option<i64>,
    /// Maximum token age in minutes
    pub token_max_age: Option<i64>,
    /// Base path for authentication routes
    pub base_path: Option<String>,
    /// Tracks whether `with_code_challenge_method` was called explicitly so
    /// that `with_issuer` knows not to overwrite it with the discovered value.
    code_challenge_method_explicit: bool,
    /// Tracks whether `with_scopes` was called explicitly so that `with_issuer`
    /// knows not to overwrite the scopes with the discovered values.
    scopes_explicit: bool,
}

impl OAuthConfigurationBuilder {
    // ── OIDC discovery ────────────────────────────────────────────────────────

    /// Populate endpoints from the provider's OIDC discovery document.
    ///
    /// Fetches `<issuer>/.well-known/openid-configuration` and fills in:
    ///
    /// | Discovery field                       | Builder field               | Condition                        |
    /// |---------------------------------------|-----------------------------|----------------------------------|
    /// | `authorization_endpoint`              | `authorization_endpoint`    | not already set                  |
    /// | `token_endpoint`                      | `token_endpoint`            | not already set                  |
    /// | `end_session_endpoint`                | `end_session_endpoint`      | not already set, present in doc  |
    /// | `scopes_supported`                    | `scopes`                    | `with_scopes` not called         |
    /// | `code_challenge_methods_supported`    | `code_challenge_method`     | `with_code_challenge_method` not called |
    ///
    /// Fields already set via a `with_*` setter are **never overwritten**.
    ///
    /// # Scope selection
    ///
    /// When `scopes_supported` is present in the discovery document and
    /// `with_scopes` has not been called, this method requests only those
    /// scopes from the default set `["openid", "email", "profile"]` that the
    /// provider declares it supports.  If `scopes_supported` is absent the
    /// defaults are left unchanged.
    ///
    /// # PKCE method selection
    ///
    /// When `code_challenge_methods_supported` is present and
    /// `with_code_challenge_method` has not been called, `S256` is selected if
    /// it appears in the list; otherwise `plain` is used.  If the field is
    /// absent the default (`S256`) is left unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotValidUri`] if the issuer URL cannot be parsed, or
    /// [`Error::Request`] / [`Error::InvalidResponse`] if the HTTP request or
    /// JSON deserialization fails.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use axum_oidc_client::auth_builder::OAuthConfigurationBuilder;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Endpoints are filled in automatically; only credentials are needed.
    /// let config = OAuthConfigurationBuilder::default()
    ///     .with_issuer("https://accounts.google.com").await?
    ///     .with_client_id("your-client-id")
    ///     .with_client_secret("your-client-secret")
    ///     .with_redirect_uri("http://localhost:8080/auth/callback")
    ///     .with_private_cookie_key("your-secret-key-at-least-32-bytes")
    ///     .with_post_logout_redirect_uri("/")
    ///     .with_session_max_age(30)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn with_issuer(self, issuer: &str) -> Result<Self, Error> {
        // Normalise: strip any trailing slash so we can append the well-known
        // path unconditionally.
        let issuer = issuer.trim_end_matches('/');
        let discovery_url = format!("{}/.well-known/openid-configuration", issuer);

        let client = build_http_client(self.custom_ca_cert.as_deref())?;
        let response = client
            .get(&discovery_url)
            .send()
            .await
            .map_err(Error::Request)?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(Error::InvalidResponse(format!(
                "OIDC discovery request to {discovery_url} returned HTTP {status}: {body}"
            )));
        }

        let doc: OidcDiscovery = response.json().await.map_err(|e| {
            Error::InvalidResponse(format!(
                "Failed to parse OIDC discovery document from {discovery_url}: {e}"
            ))
        })?;

        // Only fill in fields that have not already been set explicitly.
        let authorization_endpoint = self
            .authorization_endpoint
            .or(Some(doc.authorization_endpoint));

        let token_endpoint = self.token_endpoint.or(Some(doc.token_endpoint));

        let end_session_endpoint = self.end_session_endpoint.or(doc.end_session_endpoint);

        // Resolve scopes: use the discovered intersection only when the caller
        // has not set explicit scopes.
        let scopes = if self.scopes_explicit {
            self.scopes
        } else if let Some(supported) = doc.scopes_supported {
            let defaults = ["openid", "email", "profile"];
            let filtered: Vec<String> = defaults
                .iter()
                .filter(|s| supported.iter().any(|sup| sup == *s))
                .map(|s| s.to_string())
                .collect();
            // Fall back to the full defaults if the intersection is empty
            // (e.g. the provider lists scopes under different names).
            if filtered.is_empty() {
                self.scopes
            } else {
                Scopes(filtered)
            }
        } else {
            self.scopes
        };

        // Resolve PKCE method: prefer S256 when supported, fall back to plain.
        let code_challenge_method = if self.code_challenge_method_explicit {
            self.code_challenge_method
        } else if let Some(methods) = doc.code_challenge_methods_supported {
            if methods.iter().any(|m| m.eq_ignore_ascii_case("S256")) {
                CodeChallengeMethod::S256
            } else {
                CodeChallengeMethod::Plain
            }
        } else {
            self.code_challenge_method
        };

        Ok(Self {
            authorization_endpoint,
            token_endpoint,
            end_session_endpoint,
            scopes,
            code_challenge_method,
            ..self
        })
    }
}

impl OAuthConfigurationBuilder {
    /// Set the private cookie key for session encryption.
    ///
    /// The key should be at least 32 bytes long. If shorter, it will be padded.
    /// If longer than 64 bytes, it will be truncated.
    ///
    /// # Arguments
    ///
    /// * `private_cookie_key` - Secret key for encrypting session cookies
    ///
    /// # Security
    ///
    /// Use a cryptographically strong random value. Never hardcode this in production.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use axum_oidc_client::auth_builder::OAuthConfigurationBuilder;
    ///
    /// let builder = OAuthConfigurationBuilder::default()
    ///     .with_private_cookie_key("my-secret-key-at-least-32-bytes-long");
    /// ```
    pub fn with_private_cookie_key(self, private_cookie_key: &str) -> Self {
        let mut key_bytes = [0u8; 64];
        let input_bytes = private_cookie_key.as_bytes();
        let copy_len = input_bytes.len().min(64);
        key_bytes[..copy_len].copy_from_slice(&input_bytes[..copy_len]);

        Self {
            private_cookie_key: Some(Key::from(&key_bytes)),
            ..self
        }
    }
    /// Set the OAuth2 client ID.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The client identifier issued by the OAuth2 provider
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use axum_oidc_client::auth_builder::OAuthConfigurationBuilder;
    ///
    /// let builder = OAuthConfigurationBuilder::default()
    ///     .with_client_id("my-client-id");
    /// ```
    pub fn with_client_id(self, client_id: &str) -> Self {
        Self {
            client_id: Some(client_id.to_string()),
            ..self
        }
    }

    /// Set the OAuth2 client secret.
    ///
    /// # Arguments
    ///
    /// * `client_secret` - The client secret issued by the OAuth2 provider
    ///
    /// # Security
    ///
    /// Never expose this value in client-side code or public repositories.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use axum_oidc_client::auth_builder::OAuthConfigurationBuilder;
    ///
    /// let builder = OAuthConfigurationBuilder::default()
    ///     .with_client_secret("my-client-secret");
    /// ```
    pub fn with_client_secret(self, client_secret: &str) -> Self {
        Self {
            client_secret: Some(client_secret.to_string()),
            ..self
        }
    }

    /// Set the OAuth2 redirect URI.
    ///
    /// This must exactly match one of the redirect URIs configured in your
    /// OAuth2 provider's application settings.
    ///
    /// # Arguments
    ///
    /// * `redirect_uri` - The URI where users are redirected after authentication
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use axum_oidc_client::auth_builder::OAuthConfigurationBuilder;
    ///
    /// let builder = OAuthConfigurationBuilder::default()
    ///     .with_redirect_uri("http://localhost:8080/auth/callback");
    /// ```
    pub fn with_redirect_uri(self, redirect_uri: &str) -> Self {
        Self {
            redirect_uri: Some(redirect_uri.to_string()),
            ..self
        }
    }

    /// Set the OAuth2 authorization endpoint URL.
    ///
    /// # Arguments
    ///
    /// * `authorization_endpoint` - The OAuth2 provider's authorization URL
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use axum_oidc_client::auth_builder::OAuthConfigurationBuilder;
    ///
    /// let builder = OAuthConfigurationBuilder::default()
    ///     .with_authorization_endpoint("https://accounts.google.com/o/oauth2/auth");
    /// ```
    pub fn with_authorization_endpoint(self, authorization_endpoint: &str) -> Self {
        Self {
            authorization_endpoint: Some(authorization_endpoint.to_string()),
            ..self
        }
    }

    /// Set the OAuth2 token endpoint URL.
    ///
    /// # Arguments
    ///
    /// * `token_endpoint` - The OAuth2 provider's token exchange URL
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use axum_oidc_client::auth_builder::OAuthConfigurationBuilder;
    ///
    /// let builder = OAuthConfigurationBuilder::default()
    ///     .with_token_endpoint("https://oauth2.googleapis.com/token");
    /// ```
    pub fn with_token_endpoint(self, token_endpoint: &str) -> Self {
        Self {
            token_endpoint: Some(token_endpoint.to_string()),
            ..self
        }
    }

    /// Set the OIDC end session endpoint URL (optional).
    ///
    /// Required if you want to use OIDC logout functionality.
    ///
    /// # Arguments
    ///
    /// * `end_session_endpoint` - The OIDC provider's logout endpoint URL
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use axum_oidc_client::auth_builder::OAuthConfigurationBuilder;
    ///
    /// let builder = OAuthConfigurationBuilder::default()
    ///     .with_end_session_endpoint("https://accounts.google.com/o/oauth2/revoke");
    /// ```
    pub fn with_end_session_endpoint(self, end_session_endpoint: &str) -> Self {
        Self {
            end_session_endpoint: Some(end_session_endpoint.to_string()),
            ..self
        }
    }

    /// Set the post-logout redirect URI (optional).
    ///
    /// Where to redirect users after they log out.
    ///
    /// # Arguments
    ///
    /// * `post_logout_redirect_uri` - The URI to redirect to after logout
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use axum_oidc_client::auth_builder::OAuthConfigurationBuilder;
    ///
    /// let builder = OAuthConfigurationBuilder::default()
    ///     .with_post_logout_redirect_uri("http://localhost:8080");
    /// ```
    pub fn with_post_logout_redirect_uri(self, post_logout_redirect_uri: &str) -> Self {
        Self {
            post_logout_redirect_uri: Some(post_logout_redirect_uri.to_string()),
            ..self
        }
    }

    /// Set the PKCE code challenge method.
    ///
    /// # Arguments
    ///
    /// * `code_challenge_method` - The method for PKCE challenge (S256 or Plain)
    ///
    /// # Default
    ///
    /// Defaults to `CodeChallengeMethod::S256`
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use axum_oidc_client::auth_builder::OAuthConfigurationBuilder;
    /// use axum_oidc_client::auth::CodeChallengeMethod;
    ///
    /// let builder = OAuthConfigurationBuilder::default()
    ///     .with_code_challenge_method(CodeChallengeMethod::S256);
    /// ```
    pub fn with_code_challenge_method(self, code_challenge_method: CodeChallengeMethod) -> Self {
        Self {
            code_challenge_method,
            code_challenge_method_explicit: true,
            ..self
        }
    }

    /// Set the OAuth2 scopes to request.
    ///
    /// # Arguments
    ///
    /// * `scopes` - List of scope identifiers
    ///
    /// # Default
    ///
    /// If not set, defaults to `["openid", "email", "profile"]`
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use axum_oidc_client::auth_builder::OAuthConfigurationBuilder;
    ///
    /// let builder = OAuthConfigurationBuilder::default()
    ///     .with_scopes(vec!["openid", "email", "profile", "read:user"]);
    /// ```
    pub fn with_scopes(self, scopes: Vec<&str>) -> Self {
        Self {
            scopes: Scopes(scopes.into_iter().map(String::from).collect()),
            scopes_explicit: true,
            ..self
        }
    }

    /// Set a custom CA certificate path (optional).
    ///
    /// Use this when your OAuth2 provider uses a custom certificate authority
    /// that is not in the system's trust store.
    ///
    /// # Arguments
    ///
    /// * `ca_cert` - Path to the CA certificate file
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use axum_oidc_client::auth_builder::OAuthConfigurationBuilder;
    ///
    /// let builder = OAuthConfigurationBuilder::default()
    ///     .with_custom_ca_cert("/path/to/ca-cert.pem");
    /// ```
    pub fn with_custom_ca_cert(self, ca_cert: &str) -> Self {
        Self {
            custom_ca_cert: Some(ca_cert.to_string()),
            ..self
        }
    }

    /// Set the maximum session age in minutes.
    ///
    /// Sessions older than this will be considered expired and require
    /// re-authentication.
    ///
    /// # Arguments
    ///
    /// * `minutes` - Maximum session duration in minutes
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use axum_oidc_client::auth_builder::OAuthConfigurationBuilder;
    ///
    /// let builder = OAuthConfigurationBuilder::default()
    ///     .with_session_max_age(30); // 30 minutes
    /// ```
    pub fn with_session_max_age(self, minutes: i64) -> Self {
        Self {
            session_max_age: Some(minutes),
            ..self
        }
    }

    /// Set the maximum token age in seconds.
    ///
    /// Tokens older than this will be considered expired even if the
    /// provider's expiration time is longer.
    ///
    /// # Arguments
    ///
    /// * `seconds` - Maximum token age in seconds
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use axum_oidc_client::auth_builder::OAuthConfigurationBuilder;
    ///
    /// let builder = OAuthConfigurationBuilder::default()
    ///     .with_token_max_age(300); // 5 minutes
    /// ```
    pub fn with_token_max_age(self, seconds: i64) -> Self {
        Self {
            token_max_age: Some(seconds),
            ..self
        }
    }

    /// Set a custom base path for authentication routes.
    ///
    /// By default, authentication routes are mounted at `/auth`:
    /// - `/auth` - Start OAuth flow
    /// - `/auth/callback` - OAuth callback
    /// - `/auth/logout` - Logout
    ///
    /// # Arguments
    ///
    /// * `base_path` - The base path (e.g., "/api/auth", "/oauth")
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use axum_oidc_client::auth_builder::OAuthConfigurationBuilder;
    ///
    /// let builder = OAuthConfigurationBuilder::default()
    ///     .with_base_path("/api/auth");
    /// ```
    ///
    /// **Important:** Update your redirect_uri to match:
    /// ```rust,no_run
    /// use axum_oidc_client::auth_builder::OAuthConfigurationBuilder;
    ///
    /// let config = OAuthConfigurationBuilder::default()
    ///     .with_base_path("/api/auth")
    ///     .with_redirect_uri("http://localhost:8080/api/auth/callback")
    ///     // ... other config
    ///     # .with_client_id("test")
    ///     # .with_client_secret("test")
    ///     # .with_authorization_endpoint("http://test")
    ///     # .with_token_endpoint("http://test")
    ///     # .with_private_cookie_key("test")
    ///     # .with_session_max_age(30)
    ///     .build();
    /// ```
    pub fn with_base_path(self, base_path: impl Into<String>) -> Self {
        let path = base_path.into();
        // Remove trailing slash if present
        let normalized = path.trim_end_matches('/').to_string();
        Self {
            base_path: Some(normalized),
            ..self
        }
    }

    /// Build the OAuth configuration.
    ///
    /// Validates that all required fields are set and constructs an
    /// [`OAuthConfiguration`] instance.
    ///
    /// # Required Fields
    ///
    /// The following fields must be set:
    /// - `private_cookie_key`
    /// - `client_id`
    /// - `client_secret`
    /// - `redirect_uri`
    /// - `authorization_endpoint`
    /// - `token_endpoint`
    /// - `session_max_age`
    /// - `post_logout_redirect_uri`
    ///
    /// # Returns
    ///
    /// * `Ok(OAuthConfiguration)` - A valid configuration
    /// * `Err(Error::MissingParameter)` - If any required field is missing
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use axum_oidc_client::auth_builder::OAuthConfigurationBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = OAuthConfigurationBuilder::default()
    ///     .with_client_id("client-id")
    ///     .with_client_secret("client-secret")
    ///     .with_redirect_uri("http://localhost:8080/auth/callback")
    ///     .with_authorization_endpoint("https://provider.com/oauth/authorize")
    ///     .with_token_endpoint("https://provider.com/oauth/token")
    ///     .with_private_cookie_key("secret-key-at-least-32-bytes")
    ///     .with_session_max_age(30)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn build(self) -> Result<OAuthConfiguration, Error> {
        let layer = OAuthConfiguration {
            private_cookie_key: self
                .private_cookie_key
                .ok_or(Error::MissingPatameter("private_cookie_key".to_string()))?,
            client_id: self
                .client_id
                .ok_or(Error::MissingPatameter("client_id".to_string()))?,
            client_secret: self
                .client_secret
                .ok_or(Error::MissingPatameter("client_secret".to_string()))?,
            redirect_uri: self
                .redirect_uri
                .ok_or(Error::MissingPatameter("redirect_uri".to_string()))?,
            session_max_age: self
                .session_max_age
                .ok_or(Error::MissingPatameter("session_max_age".to_string()))?,
            token_max_age: self.token_max_age,
            authorization_endpoint: self.authorization_endpoint.ok_or(Error::MissingPatameter(
                "authorization_endpoint".to_string(),
            ))?,
            token_endpoint: self
                .token_endpoint
                .ok_or(Error::MissingPatameter("token_endpoint".to_string()))?,
            end_session_endpoint: self.end_session_endpoint,
            post_logout_redirect_uri: self.post_logout_redirect_uri.ok_or(
                Error::MissingPatameter("post_logout_redirect_uri".to_string()),
            )?,
            scopes: self.scopes.0.join(" "),
            code_challenge_method: self.code_challenge_method,
            custom_ca_cert: self.custom_ca_cert,
            base_path: self.base_path.unwrap_or_else(|| "/auth".to_string()),
        };
        Ok(layer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal discovery JSON document for use in tests.
    fn discovery_json(
        auth: &str,
        token: &str,
        end_session: Option<&str>,
        scopes: Option<&[&str]>,
        pkce_methods: Option<&[&str]>,
    ) -> String {
        let end_session_field = match end_session {
            Some(url) => format!(r#","end_session_endpoint":"{}""#, url),
            None => String::new(),
        };
        let scopes_field = match scopes {
            Some(s) => {
                let list = s
                    .iter()
                    .map(|v| format!(r#""{}""#, v))
                    .collect::<Vec<_>>()
                    .join(",");
                format!(r#","scopes_supported":[{}]"#, list)
            }
            None => String::new(),
        };
        let pkce_field = match pkce_methods {
            Some(m) => {
                let list = m
                    .iter()
                    .map(|v| format!(r#""{}""#, v))
                    .collect::<Vec<_>>()
                    .join(",");
                format!(r#","code_challenge_methods_supported":[{}]"#, list)
            }
            None => String::new(),
        };
        format!(
            r#"{{"authorization_endpoint":"{auth}","token_endpoint":"{token}"{end_session_field}{scopes_field}{pkce_field}}}"#,
        )
    }

    #[tokio::test]
    async fn test_with_issuer_fills_endpoints() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        let body = discovery_json(
            &format!("{base}/oauth2/auth"),
            &format!("{base}/oauth2/token"),
            Some(&format!("{base}/oauth2/logout")),
            None,
            None,
        );
        server
            .mock("GET", "/.well-known/openid-configuration")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create_async()
            .await;

        let builder = OAuthConfigurationBuilder::default()
            .with_issuer(&base)
            .await
            .expect("with_issuer should succeed");

        assert_eq!(
            builder.authorization_endpoint.as_deref(),
            Some(format!("{base}/oauth2/auth").as_str())
        );
        assert_eq!(
            builder.token_endpoint.as_deref(),
            Some(format!("{base}/oauth2/token").as_str())
        );
        assert_eq!(
            builder.end_session_endpoint.as_deref(),
            Some(format!("{base}/oauth2/logout").as_str())
        );
    }

    #[tokio::test]
    async fn test_with_issuer_does_not_overwrite_explicit_endpoints() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        let body = discovery_json(
            &format!("{base}/discovered/auth"),
            &format!("{base}/discovered/token"),
            None,
            None,
            None,
        );
        server
            .mock("GET", "/.well-known/openid-configuration")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create_async()
            .await;

        let builder = OAuthConfigurationBuilder::default()
            .with_authorization_endpoint("https://manual.example.com/auth")
            .with_token_endpoint("https://manual.example.com/token")
            .with_issuer(&base)
            .await
            .expect("with_issuer should succeed");

        // Manual values must survive discovery.
        assert_eq!(
            builder.authorization_endpoint.as_deref(),
            Some("https://manual.example.com/auth")
        );
        assert_eq!(
            builder.token_endpoint.as_deref(),
            Some("https://manual.example.com/token")
        );
    }

    #[tokio::test]
    async fn test_with_issuer_scopes_intersection() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        // Provider supports openid and email but NOT profile.
        let body = discovery_json(
            &format!("{base}/auth"),
            &format!("{base}/token"),
            None,
            Some(&["openid", "email"]),
            None,
        );
        server
            .mock("GET", "/.well-known/openid-configuration")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create_async()
            .await;

        let builder = OAuthConfigurationBuilder::default()
            .with_issuer(&base)
            .await
            .expect("with_issuer should succeed");

        assert_eq!(builder.scopes.to_string(), "openid email");
    }

    #[tokio::test]
    async fn test_with_issuer_scopes_explicit_not_overwritten() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        let body = discovery_json(
            &format!("{base}/auth"),
            &format!("{base}/token"),
            None,
            Some(&["openid"]),
            None,
        );
        server
            .mock("GET", "/.well-known/openid-configuration")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create_async()
            .await;

        let builder = OAuthConfigurationBuilder::default()
            .with_scopes(vec!["openid", "email", "profile", "custom"])
            .with_issuer(&base)
            .await
            .expect("with_issuer should succeed");

        // Explicit scopes must be preserved unchanged.
        assert_eq!(builder.scopes.to_string(), "openid email profile custom");
    }

    #[tokio::test]
    async fn test_with_issuer_pkce_s256_preferred() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        let body = discovery_json(
            &format!("{base}/auth"),
            &format!("{base}/token"),
            None,
            None,
            Some(&["plain", "S256"]),
        );
        server
            .mock("GET", "/.well-known/openid-configuration")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create_async()
            .await;

        let builder = OAuthConfigurationBuilder::default()
            .with_issuer(&base)
            .await
            .expect("with_issuer should succeed");

        assert_eq!(builder.code_challenge_method, CodeChallengeMethod::S256);
    }

    #[tokio::test]
    async fn test_with_issuer_pkce_plain_fallback() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        let body = discovery_json(
            &format!("{base}/auth"),
            &format!("{base}/token"),
            None,
            None,
            Some(&["plain"]),
        );
        server
            .mock("GET", "/.well-known/openid-configuration")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create_async()
            .await;

        let builder = OAuthConfigurationBuilder::default()
            .with_issuer(&base)
            .await
            .expect("with_issuer should succeed");

        assert_eq!(builder.code_challenge_method, CodeChallengeMethod::Plain);
    }

    #[tokio::test]
    async fn test_with_issuer_pkce_explicit_not_overwritten() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        // Discovery says only plain is supported.
        let body = discovery_json(
            &format!("{base}/auth"),
            &format!("{base}/token"),
            None,
            None,
            Some(&["plain"]),
        );
        server
            .mock("GET", "/.well-known/openid-configuration")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create_async()
            .await;

        // But the caller explicitly requested S256.
        let builder = OAuthConfigurationBuilder::default()
            .with_code_challenge_method(CodeChallengeMethod::S256)
            .with_issuer(&base)
            .await
            .expect("with_issuer should succeed");

        assert_eq!(builder.code_challenge_method, CodeChallengeMethod::S256);
    }

    #[tokio::test]
    async fn test_with_issuer_trailing_slash_normalised() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        let body = discovery_json(
            &format!("{base}/auth"),
            &format!("{base}/token"),
            None,
            None,
            None,
        );
        // The mock is registered without trailing slash — if normalisation
        // works correctly the request will hit this exact path.
        server
            .mock("GET", "/.well-known/openid-configuration")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create_async()
            .await;

        // Pass issuer WITH a trailing slash.
        let result = OAuthConfigurationBuilder::default()
            .with_issuer(&format!("{base}/"))
            .await;

        assert!(result.is_ok(), "trailing slash should be normalised");
    }

    #[tokio::test]
    async fn test_with_issuer_http_error_propagated() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        server
            .mock("GET", "/.well-known/openid-configuration")
            .with_status(404)
            .with_body("not found")
            .create_async()
            .await;

        let result = OAuthConfigurationBuilder::default()
            .with_issuer(&base)
            .await;

        assert!(
            matches!(result, Err(Error::InvalidResponse(_))),
            "HTTP 404 should surface as InvalidResponse"
        );
    }

    #[test]
    fn test_with_private_cookie_key() {
        let auth_builder = OAuthConfigurationBuilder::default()
            .with_private_cookie_key("test_key_SLKASDFSDJKLHSDJKLFHSDL_FGSFDGSDFGSDFGSDFGSDF");

        // Create expected key the same way as the implementation (padded to 64 bytes)
        let mut expected_key_bytes = [0u8; 64];
        let input = "test_key_SLKASDFSDJKLHSDJKLFHSDL_FGSFDGSDFGSDFGSDFGSDF";
        let input_bytes = input.as_bytes();
        let copy_len = input_bytes.len().min(64);
        expected_key_bytes[..copy_len].copy_from_slice(&input_bytes[..copy_len]);

        assert_eq!(
            auth_builder.private_cookie_key,
            Some(Key::from(&expected_key_bytes))
        );
    }

    #[test]
    fn test_with_client_id() {
        let auth_builder = OAuthConfigurationBuilder::default().with_client_id("test_id");
        assert_eq!(auth_builder.client_id.as_deref(), Some("test_id"));
    }

    #[test]
    fn test_with_client_secret() {
        let auth_builder = OAuthConfigurationBuilder::default().with_client_secret("test_secret");
        assert_eq!(auth_builder.client_secret.as_deref(), Some("test_secret"));
    }

    #[test]
    fn test_with_redirect_uri() {
        let auth_builder = OAuthConfigurationBuilder::default().with_redirect_uri("test_redirect");
        assert_eq!(auth_builder.redirect_uri.as_deref(), Some("test_redirect"));
    }

    #[test]
    fn test_with_authorization_endpoint() {
        let auth_builder =
            OAuthConfigurationBuilder::default().with_authorization_endpoint("test_auth_endpoint");
        assert_eq!(
            auth_builder.authorization_endpoint.as_deref(),
            Some("test_auth_endpoint")
        );
    }

    #[test]
    fn test_with_token_endpoint() {
        let auth_builder =
            OAuthConfigurationBuilder::default().with_token_endpoint("test_token_endpoint");
        assert_eq!(
            auth_builder.token_endpoint.as_deref(),
            Some("test_token_endpoint")
        );
    }

    #[test]
    fn test_with_end_session_endpoint() {
        let auth_builder = OAuthConfigurationBuilder::default()
            .with_end_session_endpoint("test_end_session_endpoint");
        assert_eq!(
            auth_builder.end_session_endpoint.as_deref(),
            Some("test_end_session_endpoint")
        );
    }

    #[test]
    fn test_with_post_logout_redirect_uri() {
        let auth_builder =
            OAuthConfigurationBuilder::default().with_post_logout_redirect_uri("test_logout_uri");
        assert_eq!(
            auth_builder.post_logout_redirect_uri.as_deref(),
            Some("test_logout_uri")
        );
    }

    #[test]
    fn test_with_scopes() {
        let auth_builder = OAuthConfigurationBuilder::default().with_scopes(vec!["a", "b", "c"]);
        assert_eq!(format!("{scopes}", scopes = auth_builder.scopes), "a b c");
    }

    #[test]
    fn code_with_auth_challenge_method() {
        let auth_builder = OAuthConfigurationBuilder::default()
            .with_code_challenge_method(CodeChallengeMethod::Plain);
        assert_eq!(
            auth_builder.code_challenge_method,
            CodeChallengeMethod::Plain
        );
    }

    #[test]
    fn test_builder_chain() {
        let auth_builder = OAuthConfigurationBuilder::default()
            .with_private_cookie_key("test_key")
            .with_client_id("test_id")
            .with_client_secret("test_secret")
            .with_redirect_uri("test_redirect")
            .with_authorization_endpoint("test_auth_endpoint")
            .with_token_endpoint("test_token_endpoint")
            .with_scopes(vec!["openid", "email", "test"])
            .with_code_challenge_method(CodeChallengeMethod::S256);

        // Create expected key the same way as the implementation (padded to 64 bytes)
        let mut expected_key_bytes = [0u8; 64];
        let input = "test_key";
        let input_bytes = input.as_bytes();
        let copy_len = input_bytes.len().min(64);
        expected_key_bytes[..copy_len].copy_from_slice(&input_bytes[..copy_len]);

        assert_eq!(
            auth_builder.private_cookie_key,
            Some(Key::from(&expected_key_bytes))
        );
        assert_eq!(auth_builder.client_id.as_deref(), Some("test_id"));
        assert_eq!(auth_builder.client_secret.as_deref(), Some("test_secret"));
        assert_eq!(auth_builder.redirect_uri.as_deref(), Some("test_redirect"));
        assert_eq!(
            auth_builder.authorization_endpoint.as_deref(),
            Some("test_auth_endpoint")
        );
        assert_eq!(
            auth_builder.token_endpoint.as_deref(),
            Some("test_token_endpoint")
        );
        assert_eq!(
            format!("{scopes}", scopes = auth_builder.scopes),
            "openid email test"
        );
        assert_eq!(
            auth_builder.code_challenge_method,
            CodeChallengeMethod::S256
        );
    }

    #[test]
    fn test_with_base_path() {
        let auth_builder = OAuthConfigurationBuilder::default().with_base_path("/api/auth");
        assert_eq!(auth_builder.base_path.as_deref(), Some("/api/auth"));
    }

    #[test]
    fn test_base_path_removes_trailing_slash() {
        let auth_builder = OAuthConfigurationBuilder::default().with_base_path("/api/auth/");
        assert_eq!(auth_builder.base_path.as_deref(), Some("/api/auth"));
    }

    #[test]
    fn test_base_path_default() {
        let config = OAuthConfigurationBuilder::default()
            .with_client_id("test")
            .with_client_secret("test")
            .with_redirect_uri("http://localhost/callback")
            .with_authorization_endpoint("http://localhost/auth")
            .with_token_endpoint("http://localhost/token")
            .with_private_cookie_key("test_key_at_least_32_bytes_long")
            .with_session_max_age(30)
            .with_post_logout_redirect_uri("/")
            .build()
            .unwrap();

        assert_eq!(config.base_path, "/auth");
    }

    #[test]
    fn test_base_path_custom() {
        let config = OAuthConfigurationBuilder::default()
            .with_client_id("test")
            .with_client_secret("test")
            .with_redirect_uri("http://localhost/callback")
            .with_authorization_endpoint("http://localhost/auth")
            .with_token_endpoint("http://localhost/token")
            .with_private_cookie_key("test_key_at_least_32_bytes_long")
            .with_session_max_age(30)
            .with_post_logout_redirect_uri("/")
            .with_base_path("/api/auth")
            .build()
            .unwrap();

        assert_eq!(config.base_path, "/api/auth");
    }
}
