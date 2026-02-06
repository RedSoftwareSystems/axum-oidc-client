//! # axum-oidc-client
//!
//! A comprehensive OAuth2/OIDC authentication library for Axum web applications with PKCE support.
//!
//! ## Features
//!
//! - **OAuth2/OIDC Authentication**: Full support for OAuth2 and OpenID Connect protocols
//! - **PKCE Support**: Implements Proof Key for Code Exchange (RFC 7636) for enhanced security
//! - **Automatic Token Refresh**: Seamlessly refreshes expired ID tokens and access tokens using OAuth2 refresh token flow
//! - **Flexible Caching**: Pluggable cache backends with built-in Redis support
//! - **Session Management**: Secure session handling with encrypted cookies
//! - **Logout Handlers**: Support for both standard and OIDC logout flows
//! - **Type-safe Extractors**: Convenient extractors for authenticated users and sessions
//! - **Custom CA Certificates**: Support for custom certificate authorities
//!
//! ## Quick Start
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
//! // Build OAuth configuration
//! let config = OAuthConfigurationBuilder::default()
//!     .with_authorization_endpoint("https://accounts.google.com/o/oauth2/auth")
//!     .with_token_endpoint("https://oauth2.googleapis.com/token")
//!     .with_client_id("your-client-id")
//!     .with_client_secret("your-client-secret")
//!     .with_redirect_uri("http://localhost:8080/auth/callback")
//!     .with_private_cookie_key("your-secret-key")
//!     .with_scopes(vec!["openid", "email", "profile"])
//!     .with_code_challenge_method(CodeChallengeMethod::S256)
//!     .build()?;
//!
//! // Create a cache implementation (using Redis in this example)
//! # #[cfg(feature = "redis")]
//! let cache: Arc<dyn AuthCache + Send + Sync> = Arc::new(
//!     axum_oidc_client::redis::AuthCache::new("redis://127.0.0.1/", 3600)
//! );
//!
//! // Create logout handler
//! let logout_handler = Arc::new(DefaultLogoutHandler);
//!
//! // Build your application
//! let app = Router::new()
//!     .route("/", get(|| async { "Hello, World!" }))
//!     .layer(AuthLayer::new(Arc::new(config), cache, logout_handler));
//!
//! # Ok(())
//! # }
//! ```
//!
//! ## Module Overview
//!
//! - [`auth`]: Core authentication types and the `AuthLayer` for Axum
//! - [`auth_builder`]: Builder pattern for constructing OAuth configurations
//! - [`auth_cache`]: Cache trait and implementations for storing auth state
//! - [`auth_session`]: Session management and token handling
//! - [`extractors`]: Type-safe extractors for accessing authenticated user data with automatic ID token and access token refresh
//! - [`logout`]: Logout handler implementations (default and OIDC)
//! - [`errors`]: Error types used throughout the library
//! - [`redis`]: Redis-based cache implementation (requires `redis` feature)
//!
//! ## Automatic ID Token and Access Token Refresh
//!
//! The library automatically refreshes expired ID tokens and access tokens using the OAuth2 refresh token flow.
//! When using the provided extractors (`AccessToken`, `IdToken`, `AuthSession`), token expiration
//! is checked on each request. If tokens are expired, the library:
//!
//! 1. Uses the refresh token to request new ID token and access token from the provider
//! 2. Updates the session with the new tokens and expiration time
//! 3. Saves the updated session to the cache
//! 4. Returns the fresh token to your handler
//!
//! This happens transparently - your application code doesn't need to handle token refresh manually.
//!
//! ## Configuration
//!
//! The library uses a builder pattern for configuration. See [`auth_builder::OAuthConfigurationBuilder`]
//! for all available options.
//!
//! ### Code Challenge Methods
//!
//! The library supports two PKCE code challenge methods:
//! - `S256`: SHA-256 hashing (recommended, default)
//! - `Plain`: Plain text (not recommended for production)
//!
//! ## Cache Backends
//!
//! Implement the [`auth_cache::AuthCache`] trait to create custom cache backends.
//! Built-in implementations:
//!
//! - **Redis**: Available with the `redis` feature flag
//!
//! ## Security Considerations
//!
//! - Always use `S256` code challenge method in production
//! - Use strong, randomly generated values for `private_cookie_key`
//! - Ensure secure transport (HTTPS) for all OAuth endpoints
//! - Configure appropriate session and token expiration times
//! - Validate redirect URIs match your OAuth provider configuration
//!
//! ## Feature Flags
//!
//! - `redis`: Enable Redis cache backend (default TLS)
//! - `redis-rustls`: Enable Redis with rustls for TLS
//! - `redis-native-tls`: Enable Redis with native-tls
//!
//! ## Examples
//!
//! See the `examples/sample-server` directory for a complete working example.

pub mod auth;
pub mod auth_builder;
pub mod auth_cache;
mod auth_router;
pub mod auth_session;
pub mod errors;
pub mod extractors;
pub mod logout;

#[cfg(any(
    feature = "redis",
    feature = "redis-rustls",
    feature = "redis-native-tls"
))]
pub mod redis;
