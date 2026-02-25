//! Core authentication module for OAuth2/OIDC with PKCE support.
//!
//! This module provides the main authentication layer and configuration types
//! for integrating OAuth2 authentication into Axum applications.
//!
//! # Main Types
//!
//! - [`AuthLayer`] - Tower layer for adding authentication to your Axum app
//! - [`OAuthConfiguration`] - Configuration for OAuth2 endpoints and credentials
//! - [`CodeChallengeMethod`] - PKCE code challenge method (S256 or Plain)
//! - [`LogoutHandler`] - Trait for implementing custom logout behavior
//!
//! # Examples
//!
//! ```rust,no_run
//! use axum::{Router, routing::get};
//! use axum_oidc_client::{
//!     auth::{AuthLayer, CodeChallengeMethod},
//!     auth_builder::OAuthConfigurationBuilder,
//!     auth_cache::AuthCache,
//!     logout::handle_default_logout::DefaultLogoutHandler,
//! };
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = OAuthConfigurationBuilder::default()
//!     .with_authorization_endpoint("https://provider.com/oauth/authorize")
//!     .with_token_endpoint("https://provider.com/oauth/token")
//!     .with_client_id("client-id")
//!     .with_client_secret("client-secret")
//!     .with_redirect_uri("http://localhost:8080/auth/callback")
//!     .with_private_cookie_key("secret-key")
//!     .with_scopes(vec!["openid", "email"])
//!     .build()?;
//!
//! # #[cfg(feature = "redis")]
//! let cache: Arc<dyn AuthCache + Send + Sync> = Arc::new(
//!     axum_oidc_client::redis::AuthCache::new("redis://127.0.0.1/", 3600)
//! );
//!
//! let logout_handler = Arc::new(DefaultLogoutHandler);
//!
//! let app = Router::new()
//!     .route("/", get(|| async { "Hello!" }))
//!     .layer(AuthLayer::new(Arc::new(config), cache, logout_handler));
//! # Ok(())
//! # }
//! ```

use axum::{
    extract::Request,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::{cookie::Key, PrivateCookieJar};
use chrono::{Duration, Local};
use futures_util::future::BoxFuture;
use http::request::Parts;
use pkce_std::Method;
use reqwest::Client;

use std::{
    fmt::Display,
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service};

use crate::{
    auth_cache::AuthCache,
    auth_router::{
        handle_auth::handle_auth,
        handle_callback::{handle_callback, AccessTokenResponse},
        handle_default::handle_default,
    },
    auth_session::AuthSession,
    errors::Error,
};

/// PKCE code challenge method.
///
/// Defines how the code verifier is transformed into a code challenge
/// during the OAuth2 PKCE flow.
///
/// # Variants
///
/// - `S256` - SHA-256 hash of the code verifier (recommended)
/// - `Plain` - Plain text code verifier (not recommended for production)
///
/// # Examples
///
/// ```
/// use axum_oidc_client::auth::CodeChallengeMethod;
///
/// let method = CodeChallengeMethod::S256;
/// assert_eq!(method.to_string(), "S256");
///
/// let plain = CodeChallengeMethod::Plain;
/// assert_eq!(plain.to_string(), "plain");
/// ```
#[derive(Debug, Clone, PartialEq, Default)]
pub enum CodeChallengeMethod {
    /// SHA-256 hashing method (recommended, default)
    #[default]
    S256,
    /// Plain text method (not recommended for production)
    Plain,
}

impl Display for CodeChallengeMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodeChallengeMethod::S256 => write!(f, "S256"),
            CodeChallengeMethod::Plain => write!(f, "plain"),
        }
    }
}

/// Calculate token expiration time based on expires_in and token_max_age.
///
/// This function determines when a token should be considered expired,
/// taking into account both the provider's expiration time and the
/// application's configured maximum token age.
///
/// # Arguments
///
/// * `expires_in` - Optional seconds until token expiration from the OAuth provider
/// * `token_max_age` - Optional maximum allowed token age in seconds from configuration
///
/// # Returns
///
/// `None` when both `expires_in` and `token_max_age` are absent — in this case
/// no expiry is tracked and the refresh logic is disabled.
///
/// Otherwise `Some(DateTime)` representing the current time plus the calculated
/// expiration duration, which is at least 1 second and determined as follows:
/// - Both present: `min(expires_in - 1, token_max_age)`
/// - Only `expires_in`: `expires_in - 1`
/// - Only `token_max_age`: `token_max_age`
///
/// # Examples
///
/// ```ignore
/// // Token expires in 3600 seconds, max age is 1800
/// let expiration = calculate_token_expiration(Some(3600), Some(1800));
/// // Uses min(3599, 1800) = 1800 seconds
///
/// // No expiry info at all — refresh is disabled
/// let expiration = calculate_token_expiration(None, None);
/// assert!(expiration.is_none());
/// ```
pub fn calculate_token_expiration(
    expires_in: Option<i64>,
    token_max_age: Option<i64>,
) -> Option<chrono::DateTime<Local>> {
    let seconds = match (expires_in, token_max_age) {
        (None, None) => return None,
        (Some(exp), None) => std::cmp::max(1, exp - 1),
        (None, Some(max_age)) => std::cmp::max(1, max_age),
        (Some(exp), Some(max_age)) => std::cmp::max(1, std::cmp::min(exp - 1, max_age)),
    };
    Some(Local::now() + Duration::seconds(seconds))
}

impl AuthSession {
    pub fn new(response: &AccessTokenResponse, conf: &OAuthConfiguration) -> Self {
        AuthSession {
            id_token: response.id_token.to_owned(),
            access_token: response.access_token.to_owned(),
            token_type: response.token_type.to_owned(),
            refresh_token: response.refresh_token.clone(),
            scope: response.scope.clone(),
            expires: calculate_token_expiration(response.expires_in, conf.token_max_age),
        }
    }
}

impl From<CodeChallengeMethod> for Method {
    fn from(method: CodeChallengeMethod) -> Self {
        match method {
            CodeChallengeMethod::S256 => Method::Sha256,
            CodeChallengeMethod::Plain => Method::Plain,
        }
    }
}

/// OAuth2/OIDC configuration.
///
/// Contains all necessary configuration for OAuth2 authentication including
/// endpoints, credentials, and session management settings.
///
/// # Fields
///
/// * `private_cookie_key` - Secret key for encrypting session cookies
/// * `client_id` - OAuth2 client identifier
/// * `client_secret` - OAuth2 client secret
/// * `redirect_uri` - URI where the provider redirects after authentication
/// * `authorization_endpoint` - OAuth2 authorization endpoint URL
/// * `token_endpoint` - OAuth2 token endpoint URL
/// * `end_session_endpoint` - Optional OIDC end session endpoint URL
/// * `post_logout_redirect_uri` - URI to redirect to after logout
/// * `scopes` - Space-separated list of OAuth2 scopes
/// * `code_challenge_method` - PKCE code challenge method
/// * `custom_ca_cert` - Optional path to custom CA certificate
/// * `session_max_age` - Maximum session age in seconds
/// * `token_max_age` - Optional maximum token age in seconds
///
/// # Examples
///
/// Use [`crate::auth_builder::OAuthConfigurationBuilder`] to construct:
///
/// ```rust,no_run
/// use axum_oidc_client::auth_builder::OAuthConfigurationBuilder;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = OAuthConfigurationBuilder::default()
///     .with_authorization_endpoint("https://provider.com/oauth/authorize")
///     .with_token_endpoint("https://provider.com/oauth/token")
///     .with_client_id("my-client-id")
///     .with_client_secret("my-client-secret")
///     .with_redirect_uri("http://localhost:8080/auth/callback")
///     .with_private_cookie_key("secret-key-at-least-32-bytes")
///     .with_scopes(vec!["openid", "email", "profile"])
///     .build()?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct OAuthConfiguration {
    /// Secret key for encrypting session cookies
    pub private_cookie_key: Key,
    /// OAuth2 client identifier
    pub client_id: String,
    /// OAuth2 client secret
    pub client_secret: String,
    /// Redirect URI for OAuth2 callback
    pub redirect_uri: String,
    /// OAuth2 authorization endpoint URL
    pub authorization_endpoint: String,
    /// OAuth2 token endpoint URL
    pub token_endpoint: String,
    /// Optional OIDC end session endpoint URL
    pub end_session_endpoint: Option<String>,
    /// URI to redirect to after logout
    pub post_logout_redirect_uri: String,
    /// Space-separated list of OAuth2 scopes
    pub scopes: String,
    /// PKCE code challenge method
    pub code_challenge_method: CodeChallengeMethod,
    /// Optional path to custom CA certificate file
    pub custom_ca_cert: Option<String>,
    /// Maximum session age in seconds
    pub session_max_age: i64,
    /// Optional maximum token age in seconds
    pub token_max_age: Option<i64>,
    /// Base path for authentication routes (default: "/auth")
    pub base_path: String,
}

/// Session cookie key name.
///
/// This constant defines the name of the cookie used to store the session identifier.
pub const SESSION_KEY: &str = "AUTH_SESSION";

/// Trait for handling logout behavior.
///
/// Implement this trait to customize the logout process for your application.
/// The library provides two built-in implementations:
/// - [`crate::logout::handle_default_logout::DefaultLogoutHandler`] - Simple logout with session cleanup
/// - [`crate::logout::handle_oidc_logout::OidcLogoutHandler`] - OIDC logout with provider notification
///
/// # Examples
///
/// ## Using the Default Handler
///
/// ```rust,no_run
/// use axum_oidc_client::logout::handle_default_logout::DefaultLogoutHandler;
/// use std::sync::Arc;
///
/// let logout_handler = Arc::new(DefaultLogoutHandler);
/// ```
///
/// ## Using the OIDC Handler
///
/// ```rust,no_run
/// use axum_oidc_client::logout::handle_oidc_logout::OidcLogoutHandler;
/// use std::sync::Arc;
///
/// let logout_handler = Arc::new(
///     OidcLogoutHandler::new("https://provider.com/oauth/logout")
/// );
/// ```
///
/// ## Custom Implementation
///
/// ```rust,no_run
/// use axum_oidc_client::auth::{LogoutHandler, OAuthConfiguration};
/// use axum_oidc_client::auth_cache::AuthCache;
/// use axum_oidc_client::errors::Error;
/// use axum::response::Response;
/// use http::request::Parts;
/// use std::sync::Arc;
/// use futures_util::future::BoxFuture;
///
/// struct CustomLogoutHandler;
///
/// impl LogoutHandler for CustomLogoutHandler {
///     fn handle_logout<'a>(
///         &'a self,
///         parts: &'a mut Parts,
///         configuration: Arc<OAuthConfiguration>,
///         cache: Arc<dyn AuthCache + Send + Sync>,
///     ) -> BoxFuture<'a, Result<Response, Error>> {
///         Box::pin(async move {
///             // Custom logout logic here
///             # unimplemented!()
///         })
///     }
/// }
/// ```
pub trait LogoutHandler: Send + Sync {
    /// Handle the logout request.
    ///
    /// This method is called when a user requests to log out. Implementations should:
    /// 1. Remove the session cookie
    /// 2. Invalidate the session in the cache
    /// 3. Optionally notify the OAuth provider
    /// 4. Redirect the user appropriately
    ///
    /// # Arguments
    ///
    /// * `parts` - The request parts containing headers, extensions, and query parameters
    /// * `configuration` - The OAuth configuration
    /// * `cache` - The authentication cache for session storage
    ///
    /// # Returns
    ///
    /// A future that resolves to either:
    /// * `Ok(Response)` - A successful logout response (typically a redirect)
    /// * `Err(Error)` - An error if logout fails
    ///
    /// # Returns
    /// A response that handles the logout (typically a redirect or HTML page)
    fn handle_logout<'a>(
        &'a self,
        parts: &'a mut Parts,
        configuration: Arc<OAuthConfiguration>,
        cache: Arc<dyn AuthCache + Send + Sync>,
    ) -> BoxFuture<'a, Result<Response, Error>>;
}

#[derive(Clone)]
pub struct AuthLayer {
    oauth_client: Arc<Client>,
    configuration: Arc<OAuthConfiguration>,
    cache: Arc<dyn AuthCache + Send + Sync>,
    logout_handler: Arc<dyn LogoutHandler>,
}

impl AuthLayer {
    pub fn new(
        configuration: Arc<OAuthConfiguration>,
        cache: Arc<dyn AuthCache + Send + Sync>,
        logout_handler: Arc<dyn LogoutHandler>,
    ) -> Self {
        let oauth_client = Arc::new(
            match configuration.custom_ca_cert.clone() {
                Some(custom_ca_cert) => {
                    let cert = std::fs::read(custom_ca_cert).unwrap();
                    let cert = reqwest::Certificate::from_pem(&cert).unwrap();
                    reqwest::ClientBuilder::new()
                        .add_root_certificate(cert)
                        .use_rustls_tls()
                }
                None => reqwest::ClientBuilder::new(),
            }
            .build()
            .unwrap(),
        );
        Self {
            configuration,
            cache,
            oauth_client,
            logout_handler,
        }
    }

    /// Create a new AuthLayer with a custom logout handler
    ///
    /// This is an alias for `new()` and is provided for backwards compatibility.
    pub fn with_logout_handler(
        configuration: Arc<OAuthConfiguration>,
        cache: Arc<dyn AuthCache + Send + Sync>,
        logout_handler: Arc<dyn LogoutHandler>,
    ) -> Self {
        Self::new(configuration, cache, logout_handler)
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthMiddleware {
            inner,
            configuration: self.configuration.clone(),
            cache: self.cache.clone(),
            oauth_client: self.oauth_client.clone(),
            logout_handler: self.logout_handler.clone(),
        }
    }
}

#[derive(Clone)]
pub struct AuthMiddleware<S> {
    inner: S,
    configuration: Arc<OAuthConfiguration>,
    cache: Arc<dyn AuthCache + Send + Sync>,
    oauth_client: Arc<Client>,
    logout_handler: Arc<dyn LogoutHandler>,
}

impl<S> Service<Request> for AuthMiddleware<S>
where
    S: Service<Request, Response = Response> + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request) -> Self::Future {
        let OAuthConfiguration {
            private_cookie_key, ..
        } = self.configuration.as_ref();
        let headers = request.headers().clone();
        let uri = request.uri().clone();
        let path = uri.path().to_string();
        let jar = PrivateCookieJar::from_headers(&headers, private_cookie_key.to_owned());

        let cache = self.cache.clone();
        let configuration = self.configuration.clone();
        let client = self.oauth_client.clone();

        // Add extensions to request for extractors
        request.extensions_mut().insert(cache.clone());
        request.extensions_mut().insert(configuration.clone());
        request.extensions_mut().insert(client.clone());

        let session_id = jar
            .get(SESSION_KEY)
            .map(|cookie| cookie.value().to_string());

        // Build the auth routes dynamically based on base_path from configuration
        let base_path = &configuration.base_path;
        let auth_route = base_path.clone();
        let callback_route = format!("{}/callback", base_path);
        let logout_route = format!("{}/logout", base_path);

        match path.as_str() {
            p if p == auth_route => Box::pin(async move {
                match handle_auth(configuration, cache).await {
                    Ok(response) => Ok(response),
                    Err(err) => Ok(err.into_response()),
                }
            }),
            p if p == callback_route => {
                let (mut parts, _) = request.into_parts();
                Box::pin(async move {
                    match handle_callback(&mut parts, uri).await {
                        Ok(response) => Ok(response),
                        Err(err) => match err {
                            Error::MissingCodeVerifier => {
                                Ok((jar, Redirect::temporary("/MissingCodeVerifier"))
                                    .into_response())
                            }
                            _ => Ok(err.into_response()),
                        },
                    }
                })
            }
            p if p == logout_route => {
                let (mut parts, _) = request.into_parts();
                let logout_handler = self.logout_handler.clone();
                Box::pin(async move {
                    match logout_handler
                        .handle_logout(&mut parts, configuration, cache)
                        .await
                    {
                        Ok(response) => Ok(response),
                        Err(err) => Ok(err.into_response()),
                    }
                })
            }
            _ => {
                let future = self.inner.call(request);
                Box::pin(async move {
                    handle_default(configuration, cache, jar, session_id, future).await
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_session::AuthSession;

    // Mock cache for testing
    #[allow(dead_code)]
    struct MockCache;

    impl AuthCache for MockCache {
        fn get_code_verifier(
            &self,
            _challenge_state: &str,
        ) -> BoxFuture<'_, Result<Option<String>, Error>> {
            Box::pin(async { Ok(None) })
        }

        fn set_code_verifier(
            &self,
            _challenge_state: &str,
            _code_verifier: &str,
        ) -> BoxFuture<'_, Result<(), Error>> {
            Box::pin(async { Ok(()) })
        }

        fn invalidate_code_verifier(
            &self,
            _challenge_state: &str,
        ) -> BoxFuture<'_, Result<(), Error>> {
            Box::pin(async { Ok(()) })
        }

        fn get_auth_session(&self, _id: &str) -> BoxFuture<'_, Result<Option<AuthSession>, Error>> {
            Box::pin(async { Ok(None) })
        }

        fn set_auth_session(
            &self,
            _id: &str,
            _session: AuthSession,
        ) -> BoxFuture<'_, Result<(), Error>> {
            Box::pin(async { Ok(()) })
        }

        fn invalidate_auth_session(&self, _id: &str) -> BoxFuture<'_, Result<(), Error>> {
            Box::pin(async { Ok(()) })
        }

        fn extend_auth_session(&self, _id: &str, _ttl: i64) -> BoxFuture<'_, Result<(), Error>> {
            Box::pin(async { Ok(()) })
        }
    }

    fn create_test_config() -> OAuthConfiguration {
        use axum_extra::extract::cookie::Key;
        OAuthConfiguration {
            private_cookie_key: Key::from(&[0u8; 64]),
            client_id: "test-client".to_string(),
            client_secret: "test-secret".to_string(),
            redirect_uri: "http://localhost:8080/auth/callback".to_string(),
            authorization_endpoint: "http://localhost/auth".to_string(),
            token_endpoint: "http://localhost/token".to_string(),
            end_session_endpoint: None,
            post_logout_redirect_uri: "/".to_string(),
            scopes: "openid email".to_string(),
            code_challenge_method: CodeChallengeMethod::S256,
            session_max_age: 30,
            token_max_age: Some(60),
            custom_ca_cert: None,
            base_path: "/auth".to_string(),
        }
    }

    #[test]
    fn test_default_base_path() {
        let config = create_test_config();

        assert_eq!(config.base_path, "/auth");
    }

    #[test]
    fn test_custom_base_path() {
        let mut config = create_test_config();
        config.base_path = "/api/auth".to_string();

        assert_eq!(config.base_path, "/api/auth");
    }

    #[test]
    fn test_base_path_can_be_customized() {
        let mut config = create_test_config();
        config.base_path = "/oauth".to_string();

        assert_eq!(config.base_path, "/oauth");
    }

    #[test]
    fn test_base_path_with_different_values() {
        let mut config1 = create_test_config();
        config1.base_path = "/oauth".to_string();
        assert_eq!(config1.base_path, "/oauth");

        let mut config2 = create_test_config();
        config2.base_path = "/api/v1/auth".to_string();
        assert_eq!(config2.base_path, "/api/v1/auth");

        let mut config3 = create_test_config();
        config3.base_path = "/auth/custom".to_string();
        assert_eq!(config3.base_path, "/auth/custom");
    }
}
