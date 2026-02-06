//! Type-safe extractors for accessing authenticated user data with automatic ID token and access token refresh.
//!
//! This module provides Axum extractors that make it easy to access OAuth2 tokens and
//! session data in your route handlers. All extractors automatically handle token expiration
//! by using the OAuth2 refresh token flow to obtain fresh ID tokens and access tokens when needed.
//!
//! # Automatic ID Token and Access Token Refresh
//!
//! When you use any of these extractors in a route handler, the library automatically:
//!
//! 1. Checks if the session's ID token and access token have expired
//! 2. If expired, uses the refresh token to request new ID token and access token from the provider
//! 3. Updates the session with the new tokens and expiration time
//! 4. Saves the refreshed session back to the cache
//! 5. Provides the fresh tokens to your handler
//!
//! This all happens transparently - your handler code never needs to check expiration
//! or manually refresh tokens.
//!
//! # Available Extractors
//!
//! ## Required Authentication
//!
//! These extractors require the user to be authenticated. If the user is not authenticated
//! or token refresh fails, they will be redirected to the OAuth2 provider.
//!
//! - [`crate::auth_session::AuthSession`] - Full session with all token information
//! - [`AccessToken`] - Just the access token string
//! - [`IdToken`] - Just the ID token string
//!
//! ## Optional Authentication
//!
//! These extractors work for both authenticated and unauthenticated users, making them
//! suitable for public routes that can optionally show personalized content.
//!
//! - [`OptionalAuthSession`] - Optional full session
//! - [`OptionalAccessToken`] - Optional access token
//! - [`OptionalIdToken`] - Optional ID token
//!
//! # Examples
//!
//! ## Protected Route with Full Session
//!
//! ```rust,no_run
//! use axum_oidc_client::auth_session::AuthSession;
//!
//! async fn dashboard(session: AuthSession) -> String {
//!     // ID token and access token are automatically refreshed if expired
//!     format!(
//!         "Welcome! Your token expires at: {}\nScopes: {}",
//!         session.expires,
//!         session.scope
//!     )
//! }
//! ```
//!
//! ## Protected Route with Access Token Only
//!
//! ```rust,no_run
//! use axum_oidc_client::extractors::AccessToken;
//!
//! async fn api_call(token: AccessToken) -> String {
//!     // Access token is automatically refreshed if expired
//!     // Access the token string with *token
//!     format!("Making API call with token: {}", &*token[..20])
//! }
//! ```
//!
//! ## Protected Route with ID Token
//!
//! ```rust,no_run
//! use axum_oidc_client::extractors::IdToken;
//!
//! async fn user_profile(token: IdToken) -> String {
//!     // ID token is automatically refreshed if expired
//!     format!("User ID token: {}", *token)
//! }
//! ```
//!
//! ## Public Route with Optional Authentication
//!
//! ```rust,no_run
//! use axum_oidc_client::extractors::OptionalIdToken;
//!
//! async fn home(OptionalIdToken(token): OptionalIdToken) -> String {
//!     match token {
//!         Some(id_token) => format!("Welcome back, authenticated user!"),
//!         None => format!("Welcome! Please log in."),
//!     }
//! }
//! ```
//!
//! ## Making External API Calls
//!
//! ```rust,no_run
//! use axum_oidc_client::extractors::AccessToken;
//! use reqwest::Client;
//!
//! async fn fetch_user_data(token: AccessToken) -> Result<String, String> {
//!     let client = Client::new();
//!
//!     // Access token is guaranteed to be fresh and valid (auto-refreshed if expired)
//!     let response = client
//!         .get("https://api.example.com/user/data")
//!         .bearer_auth(&*token)
//!         .send()
//!         .await
//!         .map_err(|e| e.to_string())?;
//!
//!     response.text().await.map_err(|e| e.to_string())
//! }
//! ```
//!
//! ## Mixed Public/Private Content
//!
//! ```rust,no_run
//! use axum_oidc_client::extractors::OptionalAccessToken;
//!
//! async fn content(OptionalAccessToken(token): OptionalAccessToken) -> String {
//!     if let Some(access_token) = token {
//!         // User is authenticated - show personalized content
//!         format!("Your personalized dashboard")
//!     } else {
//!         // User not authenticated - show public content
//!         format!("Public landing page")
//!     }
//! }
//! ```
//!
//! # ID Token and Access Token Refresh Flow
//!
//! When ID token and access token are expired, the refresh flow works as follows:
//!
//! 1. **Expiration Check**: Compare `session.expires` with current time
//! 2. **Refresh Request**: Send POST to token endpoint with refresh token:
//!    ```text
//!    POST /token
//!    grant_type=refresh_token
//!    refresh_token={session.refresh_token}
//!    client_id={config.client_id}
//!    ```
//! 3. **Update Session**: Parse response and update:
//!    - `access_token` - New access token (always updated)
//!    - `id_token` - New ID token (updated if provider returns it)
//!    - `refresh_token` - New refresh token (updated if provider returns it)
//!    - `expires` - New expiration time
//! 4. **Persist**: Save updated session to cache
//! 5. **Continue**: Handler receives fresh tokens
//!
//! # Error Handling
//!
//! If ID token and access token refresh fails (e.g., refresh token expired or revoked),
//! the user is automatically redirected to the OAuth2 provider to re-authenticate.
//! Your handler code is never called with invalid tokens.
//!
//! # Requirements for Token Refresh
//!
//! For automatic token refresh to work, ensure:
//!
//! 1. **Refresh Token Scope**: Request the appropriate scope for refresh tokens:
//!    - Most providers: Include `"offline_access"` in scopes
//!    - Google: Include `"openid"` and use `access_type=offline` parameter
//!
//! 2. **Provider Support**: Verify your OAuth2 provider supports refresh tokens
//!
//! 3. **Cache Configuration**: Ensure cache is properly configured and accessible
//!
//! # Performance Considerations
//!
//! - ID token and access token refresh only happens when tokens are expired, not on every request
//! - Refreshed ID tokens and access tokens are immediately persisted to cache for subsequent requests
//! - Multiple concurrent requests with expired tokens will result in only one refresh
//!   (handled by the cache layer)

mod auth_session_extractor;
mod shared;
mod token_extractors;

pub use auth_session_extractor::OptionalAuthSession;
pub use token_extractors::{AccessToken, IdToken, OptionalAccessToken, OptionalIdToken};
