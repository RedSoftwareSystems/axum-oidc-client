//! OAuth2 configuration builder module.
//!
//! This module provides a builder pattern for constructing [`OAuthConfiguration`]
//! instances with validation and sensible defaults.
//!
//! # Examples
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
//!     .with_session_max_age(30) // 30 minutes
//!     .with_token_max_age(5)    // 5 minutes
//!     .build()?;
//! # Ok(())
//! # }
//! ```

use std::fmt::Display;

use axum_extra::extract::cookie::Key;

use crate::auth::{CodeChallengeMethod, OAuthConfiguration};
use crate::errors::Error;

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
/// # Required Fields
///
/// The following fields must be set before calling [`build()`](Self::build):
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
/// - `end_session_endpoint` - For OIDC logout support
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
