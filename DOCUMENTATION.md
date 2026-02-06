# axum-oidc-client API Documentation

Complete API documentation and usage guide for the axum-oidc-client library.

## Table of Contents

1. [Overview](#overview)
2. [Core Concepts](#core-concepts)
3. [API Reference](#api-reference)
4. [Usage Patterns](#usage-patterns)
5. [Security Guidelines](#security-guidelines)
6. [Examples](#examples)

## Overview

`axum-oidc-client` is a comprehensive OAuth2/OIDC authentication library for Axum web applications. It provides:

- Full OAuth2 and OpenID Connect protocol support
- PKCE (Proof Key for Code Exchange) for enhanced security
- Automatic ID token and access token refresh using OAuth2 refresh token flow
- Pluggable cache backends
- Encrypted session management
- Type-safe extractors with automatic ID token and access token refresh
- Flexible logout handlers

## Core Concepts

### Authentication Flow

1. **User Request** → User accesses a protected route
2. **Auth Check** → Middleware checks for valid session
3. **Redirect to Provider** → If not authenticated, redirect to OAuth provider
4. **User Authenticates** → User logs in at provider
5. **Callback** → Provider redirects to `/auth/callback` with code
6. **Token Exchange** → Application exchanges code for tokens (with PKCE)
7. **Session Creation** → Session stored in cache, cookie set
8. **Access Granted** → User redirected to original route

### Token Refresh Flow

When a token expires, the library automatically handles refresh:

1. **Expiration Detection** → Extractor checks if token is expired
2. **Refresh Request** → Uses refresh token to request new access token
3. **Token Update** → Receives new access token and expiration time
4. **Session Update** → Updates session with new token information
5. **Cache Sync** → Saves updated session to cache
6. **Transparent Access** → Handler receives fresh token automatically

### PKCE (Proof Key for Code Exchange)

PKCE enhances OAuth2 security by:

- Generating a cryptographic random string (code verifier)
- Creating a challenge from the verifier (using S256 or Plain method)
- Sending the challenge during authorization
- Sending the verifier during token exchange
- Provider validates verifier matches challenge

## API Reference

### Module: `auth`

Core authentication types and middleware.

#### `AuthLayer`

Tower layer that adds OAuth2 authentication to your Axum application.

```rust
pub struct AuthLayer {
    configuration: Arc<OAuthConfiguration>,
    cache: Arc<dyn AuthCache + Send + Sync>,
    logout_handler: Arc<dyn LogoutHandler>,
}

impl AuthLayer {
    pub fn new(
        configuration: Arc<OAuthConfiguration>,
        cache: Arc<dyn AuthCache + Send + Sync>,
        logout_handler: Arc<dyn LogoutHandler>,
    ) -> Self
}
```

**Usage:**

```rust
let layer = AuthLayer::new(config, cache, logout_handler);
app.layer(layer)
```

**Methods:**

- `new()` - Create a new AuthLayer
- `with_logout_handler()` - Alias for `new()` (backwards compatibility)

#### `OAuthConfiguration`

OAuth2/OIDC configuration container.

**Fields:**

- `private_cookie_key: Key` - Session encryption key
- `client_id: String` - OAuth2 client identifier
- `base_path: String` - Base path for authentication routes (default: "/auth")
- `client_secret: String` - OAuth2 client secret
- `redirect_uri: String` - Callback URI
- `authorization_endpoint: String` - Provider's auth endpoint
- `token_endpoint: String` - Provider's token endpoint
- `end_session_endpoint: Option<String>` - OIDC logout endpoint
- `post_logout_redirect_uri: String` - Post-logout redirect
- `scopes: String` - Requested scopes (space-separated)
- `code_challenge_method: CodeChallengeMethod` - PKCE method
- `custom_ca_cert: Option<String>` - Custom CA certificate path
- `session_max_age: i64` - Session duration (minutes)
- `token_max_age: Option<i64>` - Token duration (seconds)

#### `CodeChallengeMethod`

PKCE code challenge methods.

```rust
pub enum CodeChallengeMethod {
    S256,   // SHA-256 (recommended)
    Plain,  // Plain text (not recommended)
}
```

#### `LogoutHandler` Trait

Customize logout behavior.

```rust
pub trait LogoutHandler: Send + Sync {
    fn handle_logout<'a>(
        &'a self,
        parts: &'a mut Parts,
        configuration: Arc<OAuthConfiguration>,
        cache: Arc<dyn AuthCache + Send + Sync>,
    ) -> BoxFuture<'a, Result<Response, Error>>;
}
```

**Implementations:**

- `DefaultLogoutHandler` - Simple logout with redirect
- `OidcLogoutHandler` - OIDC logout with provider notification

### Module: `auth_builder`

Builder pattern for OAuth configuration.

#### `OAuthConfigurationBuilder`

Fluent API for building configurations.

**Methods:**

| Method                               | Required | Description                                        |
| ------------------------------------ | -------- | -------------------------------------------------- |
| `with_client_id(id)`                 | Yes      | Set OAuth2 client ID                               |
| `with_client_secret(secret)`         | Yes      | Set OAuth2 client secret                           |
| `with_redirect_uri(uri)`             | Yes      | Set callback URI                                   |
| `with_authorization_endpoint(url)`   | Yes      | Set auth endpoint                                  |
| `with_token_endpoint(url)`           | Yes      | Set token endpoint                                 |
| `with_private_cookie_key(key)`       | Yes      | Set session encryption key                         |
| `with_session_max_age(minutes)`      | Yes      | Set session duration                               |
| `with_scopes(scopes)`                | No       | Set OAuth scopes (default: openid, email, profile) |
| `with_code_challenge_method(method)` | No       | Set PKCE method (default: S256)                    |
| `with_end_session_endpoint(url)`     | No       | Set OIDC logout endpoint                           |
| `with_post_logout_redirect_uri(uri)` | No       | Set post-logout redirect                           |
| `with_custom_ca_cert(path)`          | No       | Set custom CA certificate                          |
| `with_token_max_age(seconds)`        | No       | Set token max age                                  |
| `build()`                            | -        | Build the configuration                            |

**Example:**

```rust
let config = OAuthConfigurationBuilder::default()
    .with_client_id("client-id")
    .with_client_secret("client-secret")
    .with_redirect_uri("http://localhost:8080/auth/callback")
    .with_authorization_endpoint("https://provider.com/oauth/authorize")
    .with_token_endpoint("https://provider.com/oauth/token")
    .with_private_cookie_key("secret-key")
    .with_session_max_age(30)
    .with_base_path("/auth")  // Optional, default is "/auth"
    .build()?;
```

**Custom Base Path Example:**

```rust
let config = OAuthConfigurationBuilder::default()
    .with_base_path("/api/auth")  // Custom base path
    .with_redirect_uri("http://localhost:8080/api/auth/callback")  // Match base_path
    // ... other config
    .build()?;
```

### Module: `auth_cache`

Cache trait and implementations.

#### `AuthCache` Trait

```rust
#[async_trait]
pub trait AuthCache {
    async fn get(&self, key: &str) -> Option<String>;
    async fn set(&self, key: &str, value: &str);
    async fn delete(&self, key: &str);
}
```

**Built-in Implementations:**

**Redis Cache** (requires `redis` feature):

```rust
use axum_oidc_client::redis::AuthCache;

let cache = AuthCache::new("redis://127.0.0.1/", 3600);
```

**Custom Implementation:**

```rust
struct MyCache { /* ... */ }

#[async_trait]
impl AuthCache for MyCache {
    async fn get(&self, key: &str) -> Option<String> {
        // Implementation
    }

    async fn set(&self, key: &str, value: &str) {
        // Implementation
    }

    async fn delete(&self, key: &str) {
        // Implementation
    }
}
```

### Module: `auth_session`

Session management and token storage.

#### `AuthSession`

Contains authenticated user's session data.

**Fields:**

```rust
pub struct AuthSession {
    pub id_token: String,
    pub access_token: String,
    pub token_type: String,
    pub refresh_token: String,
    pub scope: String,
    pub expires: DateTime<Local>,
}
```

**Auto-Refresh:**
The `AuthSession` extractor automatically refreshes expired tokens when used in route handlers. If the session's access token has expired, the extractor:

1. Uses the refresh token to obtain a new access token
2. Updates all token fields (access_token, id_token if provided, expires)
3. Saves the updated session to cache
4. Returns the refreshed session to your handler

This means you never need to manually check expiration or refresh tokens.

**Usage as Extractor:**

```rust
async fn protected(session: AuthSession) -> String {
    format!("Token expires: {}", session.expires)
}
```

### Module: `extractors`

Type-safe extractors for route handlers with automatic ID token and access token refresh support.

All extractors automatically check token expiration and refresh ID tokens and access tokens when needed, providing seamless token management without manual intervention.

#### `AuthSession`

Requires authentication. Redirects to OAuth if not authenticated. Automatically refreshes expired ID token and access token.

```rust
async fn protected_route(session: AuthSession) -> String {
    // ID token and access token are automatically refreshed if expired
    format!("Hello! Your token: {}", session.access_token)
}
```

#### `AccessToken`

Extracts only the access token with automatic refresh if expired.

```rust
use axum_oidc_client::extractors::AccessToken;

async fn api_call(token: AccessToken) -> String {
    // Access token is automatically refreshed if expired
    format!("API call with: {}", *token)
}
```

#### `IdToken`

Extracts only the ID token with automatic refresh if expired.

```rust
use axum_oidc_client::extractors::IdToken;

async fn user_info(token: IdToken) -> String {
    // ID token is automatically refreshed if expired
    format!("User ID: {}", *token)
}
```

#### `OptionalAccessToken`

Optional access token for public routes with automatic refresh if expired.

```rust
use axum_oidc_client::extractors::OptionalAccessToken;

async fn maybe_protected(OptionalAccessToken(token): OptionalAccessToken) -> String {
    match token {
        Some(access_token) => format!("Authenticated with: {}", access_token),
        None => format!("Public access"),
    }
}
```

#### `OptionalIdToken`

Optional ID token for public routes with automatic refresh if expired.

```rust
use axum_oidc_client::extractors::OptionalIdToken;

async fn public_route(OptionalIdToken(token): OptionalIdToken) -> String {
    match token {
        Some(id_token) => format!("Welcome back!"),
        None => format!("Please log in"),
    }
}
```

### Module: `logout`

Logout handler implementations.

#### `DefaultLogoutHandler`

Simple local logout with session cleanup and redirect.

**When to use:**

- The OAuth provider doesn't support OIDC logout (e.g., Google, GitHub)
- You only need to clear the local session without notifying the provider
- You're implementing custom logout logic

```rust
use axum_oidc_client::logout::handle_default_logout::DefaultLogoutHandler;

let handler = Arc::new(DefaultLogoutHandler);
```

**Behavior:**

1. Removes session cookie
2. Deletes session from cache
3. Redirects to `post_logout_redirect_uri` (default: "/")

#### `OidcLogoutHandler`

OIDC-compliant logout with provider notification (RP-Initiated Logout).

**When to use:**

- The OAuth provider supports OIDC RP-Initiated Logout (e.g., Keycloak, Azure AD, Okta, Auth0)
- You need to end the session at the provider
- You want single logout across multiple applications

```rust
use axum_oidc_client::logout::handle_oidc_logout::OidcLogoutHandler;

let handler = Arc::new(OidcLogoutHandler::new(
    "https://provider.com/oidc/logout"
));
```

**Behavior:**

1. Removes session cookie
2. Deletes session from cache
3. Redirects to provider's `end_session_endpoint` with `id_token_hint`
4. Provider logs out user and redirects to `post_logout_redirect_uri`

#### Custom `LogoutHandler`

You can implement the `LogoutHandler` trait to create custom logout behavior:

```rust
use axum_oidc_client::auth::{LogoutHandler, OAuthConfiguration, SESSION_KEY};
use axum_oidc_client::auth_cache::AuthCache;
use axum_oidc_client::errors::Error;
use axum::response::{Redirect, IntoResponse, Response};
use axum_extra::extract::{cookie::Cookie, PrivateCookieJar};
use futures_util::future::BoxFuture;
use http::request::Parts;
use std::sync::Arc;

struct CustomLogoutHandler {
    custom_redirect: String,
}

impl LogoutHandler for CustomLogoutHandler {
    fn handle_logout<'a>(
        &'a self,
        parts: &'a mut Parts,
        configuration: Arc<OAuthConfiguration>,
        cache: Arc<dyn AuthCache + Send + Sync>,
    ) -> BoxFuture<'a, Result<Response, Error>> {
        Box::pin(async move {
            // Custom logout logic: audit logging, custom redirects, etc.

            // Clean up session (similar to DefaultLogoutHandler)
            let jar = PrivateCookieJar::from_headers(
                &parts.headers,
                configuration.private_cookie_key.clone(),
            );

            if let Some(session_cookie) = jar.get(SESSION_KEY) {
                cache.invalidate_auth_session(session_cookie.value()).await?;
            }

            let jar = jar.remove(Cookie::build(SESSION_KEY).path("/"));

            Ok((jar, Redirect::to(&self.custom_redirect)).into_response())
        })
    }
}
```

### Module: `errors`

Error types used throughout the library.

```rust
pub enum Error {
    MissingParameter(String),
    InvalidToken,
    CacheError,
    NetworkError,
    // ... more variants
}
```

## Usage Patterns

### Automatic ID Token and Access Token Refresh

The library provides automatic ID token and access token refresh without any manual intervention required.

#### How Token Refresh Works

```rust
use axum_oidc_client::{auth_session::AuthSession, extractors::AccessToken};

// Example 1: Full session with automatic token refresh
async fn dashboard(session: AuthSession) -> String {
    // If ID token and access token expired, they're automatically refreshed before this handler runs
    // You always get valid, fresh tokens
    format!("Token expires at: {}", session.expires)
}

// Example 2: Access token only with automatic refresh
async fn api_endpoint(token: AccessToken) -> String {
    // Access token is automatically refreshed if expired
    // You can safely use it for API calls
    call_external_api(&token).await
}
```

#### Refresh Process

When an extractor detects expired ID token and access token:

1. **Check Expiration**: Compares `session.expires` with current time
2. **Refresh Request**: POSTs to token endpoint with refresh token:
   ```
   grant_type=refresh_token
   refresh_token={session.refresh_token}
   client_id={config.client_id}
   ```
3. **Update Session**: Updates session with new tokens:
   - `access_token` - Always updated with new access token
   - `id_token` - Updated with new ID token if provider returns it
   - `refresh_token` - Updated if provider returns new refresh token
   - `expires` - Calculated from new `expires_in`
4. **Save to Cache**: Persists updated session
5. **Return Fresh Tokens**: Handler receives valid ID token and access token

#### Error Handling

If ID token and access token refresh fails (e.g., refresh token expired or revoked):

```rust
// The extractor will return an error response
// User will be redirected to re-authenticate
async fn protected(session: AuthSession) -> String {
    // If refresh fails, user never reaches here
    // They're automatically redirected to OAuth provider
    format!("Valid session with fresh tokens: {} / {}", session.access_token, session.id_token)
}
```

### Basic Application

```rust
use axum::{Router, routing::get};
use axum_oidc_client::{
    auth::AuthLayer,
    auth_builder::OAuthConfigurationBuilder,
    logout::handle_default_logout::DefaultLogoutHandler,
};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build configuration
    let config = OAuthConfigurationBuilder::default()
        .with_client_id(std::env::var("OAUTH_CLIENT_ID")?)
        .with_client_secret(std::env::var("OAUTH_CLIENT_SECRET")?)
        .with_redirect_uri("http://localhost:8080/auth/callback")
        .with_authorization_endpoint("https://provider.com/authorize")
        .with_token_endpoint("https://provider.com/token")
        .with_private_cookie_key(&std::env::var("COOKIE_KEY")?)
        .with_session_max_age(30)
        .build()?;

    // Create cache
    let cache = Arc::new(
        axum_oidc_client::redis::AuthCache::new("redis://127.0.0.1/", 3600)
    );

    // Create logout handler
    let logout_handler = Arc::new(DefaultLogoutHandler);

    // Build app
    let app = Router::new()
        .route("/", get(home))
        .route("/protected", get(protected))
        .layer(AuthLayer::new(Arc::new(config), cache, logout_handler));

    // Start server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn home() -> &'static str {
    "Home Page"
}

async fn protected(session: axum_oidc_client::auth_session::AuthSession) -> String {
    format!("Protected! Expires: {}", session.expires)
}
```

### Public and Protected Routes

```rust
use axum_oidc_client::{
    auth_session::AuthSession,
    extractors::{AccessToken, OptionalIdToken}
};

// Public route with optional auth
async fn home(OptionalIdToken(token): OptionalIdToken) -> Html<String> {
    let content = match token {
        Some(_) => r#"
            <a href="/protected">Go to Protected Area</a>
            <a href="/auth/logout">Logout</a>
        "#,
        None => r#"
            <a href="/auth">Login</a>
        "#,
    };
    Html(format!("<html><body>{}</body></html>", content))
}

// Protected route - requires auth with full session
async fn protected(session: AuthSession) -> String {
    // ID token and access token automatically refreshed if expired
    format!("Welcome! Token type: {}", session.token_type)
}

// Protected route - requires auth with just access token
async fn api_data(token: AccessToken) -> String {
    // Access token automatically refreshed if expired
    format!("Fetching data with token: {}", *token)
}
```

### Using Different Extractors

```rust
use axum_oidc_client::{
    auth_session::AuthSession,
    extractors::{AccessToken, IdToken, OptionalAccessToken}
};

// Use AuthSession when you need full session info
async fn dashboard(session: AuthSession) -> String {
    format!(
        "Session info:\n\
         Token Type: {}\n\
         Expires: {}\n\
         Scopes: {}",
        session.token_type,
        session.expires,
        session.scope
    )
}

// Use AccessToken for API calls
async fn external_api(token: AccessToken) -> Result<String, Error> {
    let client = reqwest::Client::new();
    let response = client
        .get("https://api.example.com/data")
        .bearer_auth(&*token)  // Access token is automatically fresh
        .send()
        .await?;
    Ok(response.text().await?)
}

// Use IdToken to get user identity
async fn user_profile(token: IdToken) -> String {
    // Decode ID token to get user info
    format!("User ID token: {}", *token)
}

// Use OptionalAccessToken for mixed public/private content
async fn personalized_content(OptionalAccessToken(token): OptionalAccessToken) -> String {
    if let Some(access_token) = token {
        // User is authenticated, show personalized content
        format!("Personalized content for user")
    } else {
        // User not authenticated, show public content
        format!("Public content")
    }
}
```

### Custom Logout Handler

```rust
use axum_oidc_client::auth::LogoutHandler;
use futures_util::future::BoxFuture;

struct CustomLogoutHandler {
    custom_redirect: String,
}

impl LogoutHandler for CustomLogoutHandler {
    fn handle_logout<'a>(
        &'a self,
        parts: &'a mut Parts,
        configuration: Arc<OAuthConfiguration>,
        cache: Arc<dyn AuthCache + Send + Sync>,
    ) -> BoxFuture<'a, Result<Response, Error>> {
        Box::pin(async move {
            // Custom logout logic
            // 1. Log the logout event
            println!("User logging out...");

            // 2. Clean up session (similar to default handler)
            // ... session cleanup code ...

            // 3. Redirect to custom location
            Ok(Redirect::to(&self.custom_redirect).into_response())
        })
    }
}
```

### Environment-based Configuration

```rust
use dotenv::dotenv;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();

    let config = OAuthConfigurationBuilder::default()
        .with_client_id(&env::var("OAUTH_CLIENT_ID")?)
        .with_client_secret(&env::var("OAUTH_CLIENT_SECRET")?)
        .with_redirect_uri(&env::var("OAUTH_REDIRECT_URI")?)
        .with_authorization_endpoint(&env::var("OAUTH_AUTH_ENDPOINT")?)
        .with_token_endpoint(&env::var("OAUTH_TOKEN_ENDPOINT")?)
        .with_private_cookie_key(&env::var("PRIVATE_COOKIE_KEY")?)
        .with_session_max_age(
            env::var("SESSION_MAX_AGE")?.parse().unwrap_or(30)
        )
        .build()?;

    // ... rest of app
    Ok(())
}
```

## Security Guidelines

### 1. PKCE Code Challenge Method

**Always use S256 in production:**

```rust
// ✅ Recommended
.with_code_challenge_method(CodeChallengeMethod::S256)

// ❌ Not recommended for production
.with_code_challenge_method(CodeChallengeMethod::Plain)
```

### 2. Private Cookie Key

**Generate strong random keys:**

```bash
# Generate a secure key
openssl rand -base64 64
```

```rust
// ✅ Good - Use environment variable with generated key
.with_private_cookie_key(&env::var("PRIVATE_COOKIE_KEY")?)

// ❌ Bad - Hardcoded weak key
.with_private_cookie_key("my-secret-key")
```

### 3. HTTPS in Production

**Use HTTPS for all OAuth endpoints:**

```rust
// ✅ Production
.with_redirect_uri("https://myapp.com/auth/callback")
.with_authorization_endpoint("https://provider.com/authorize")

// ⚠️ Development only
.with_redirect_uri("http://localhost:8080/auth/callback")
```

### 4. Session Expiration

**Configure appropriate timeouts:**

```rust
// Balance security and user experience
.with_session_max_age(30)    // 30 minutes session
.with_token_max_age(300)     // 5 minutes token max age
```

### 5. Scope Minimization

**Request only necessary scopes:**

```rust
// ✅ Good - Only request what you need
.with_scopes(vec!["openid", "email"])

// ❌ Bad - Requesting unnecessary permissions
.with_scopes(vec!["openid", "email", "profile", "admin", "write:all"])
```

### 6. Redirect URI Validation

**Ensure redirect URI matches provider configuration:**

```rust
// Must exactly match what's configured in OAuth provider
.with_redirect_uri("https://myapp.com/auth/callback")
```

### 7. Error Handling

**Don't leak sensitive information in errors:**

```rust
match result {
    Ok(session) => { /* ... */ },
    Err(e) => {
        // ❌ Bad - Exposes details
        eprintln!("Auth error: {:?}", e);

        // ✅ Good - Log internally, show generic message to user
        log::error!("Authentication failed: {:?}", e);
        return "Authentication failed. Please try again.";
    }
}
```

## Examples

### Google OAuth

Google supports OAuth2 but **does not implement OIDC logout**. Use `DefaultLogoutHandler`.

```rust
use axum_oidc_client::logout::handle_default_logout::DefaultLogoutHandler;

let config = OAuthConfigurationBuilder::default()
    .with_authorization_endpoint("https://accounts.google.com/o/oauth2/auth")
    .with_token_endpoint("https://oauth2.googleapis.com/token")
    .with_client_id("your-client-id.apps.googleusercontent.com")
    .with_client_secret("your-client-secret")
    .with_redirect_uri("http://localhost:8080/auth/callback")
    .with_private_cookie_key(&env::var("COOKIE_KEY")?)
    .with_scopes(vec!["openid", "email", "profile"])
    .with_session_max_age(30)
    // Note: DO NOT set end_session_endpoint for Google
    .build()?;

let logout_handler = Arc::new(DefaultLogoutHandler);
```

### GitHub OAuth

GitHub uses OAuth2 (not OIDC). Use `DefaultLogoutHandler`.

```rust
use axum_oidc_client::logout::handle_default_logout::DefaultLogoutHandler;

let config = OAuthConfigurationBuilder::default()
    .with_authorization_endpoint("https://github.com/login/oauth/authorize")
    .with_token_endpoint("https://github.com/login/oauth/access_token")
    .with_client_id("your-github-client-id")
    .with_client_secret("your-github-client-secret")
    .with_redirect_uri("http://localhost:8080/auth/callback")
    .with_private_cookie_key(&env::var("COOKIE_KEY")?)
    .with_scopes(vec!["read:user", "user:email"])
    .with_session_max_age(30)
    // Note: GitHub doesn't support OIDC logout
    .build()?;

let logout_handler = Arc::new(DefaultLogoutHandler);
```

### Keycloak

Keycloak fully supports OIDC including RP-Initiated Logout. Use `OidcLogoutHandler`.

```rust
use axum_oidc_client::logout::handle_oidc_logout::OidcLogoutHandler;

let realm = "your-realm";
let keycloak_url = "https://keycloak.example.com";

let config = OAuthConfigurationBuilder::default()
    .with_authorization_endpoint(&format!("{}/realms/{}/protocol/openid-connect/auth", keycloak_url, realm))
    .with_token_endpoint(&format!("{}/realms/{}/protocol/openid-connect/token", keycloak_url, realm))
    .with_end_session_endpoint(&format!("{}/realms/{}/protocol/openid-connect/logout", keycloak_url, realm))
    .with_client_id("your-client-id")
    .with_client_secret("your-client-secret")
    .with_redirect_uri("http://localhost:8080/auth/callback")
    .with_post_logout_redirect_uri("http://localhost:8080")
    .with_private_cookie_key(&env::var("COOKIE_KEY")?)
    .with_scopes(vec!["openid", "email", "profile"])
    .with_session_max_age(30)
    .build()?;

// Use OidcLogoutHandler with the end_session_endpoint
let logout_handler = Arc::new(OidcLogoutHandler::new(
    &format!("{}/realms/{}/protocol/openid-connect/logout", keycloak_url, realm)
));
```

### Microsoft Azure AD

Azure AD supports OIDC logout. Use `OidcLogoutHandler`.

```rust
use axum_oidc_client::logout::handle_oidc_logout::OidcLogoutHandler;

let tenant_id = "common"; // or specific tenant ID

let config = OAuthConfigurationBuilder::default()
    .with_authorization_endpoint(&format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize",
        tenant_id
    ))
    .with_token_endpoint(&format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        tenant_id
    ))
    .with_end_session_endpoint(&format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/logout",
        tenant_id
    ))
    .with_client_id("your-azure-client-id")
    .with_client_secret("your-azure-client-secret")
    .with_redirect_uri("http://localhost:8080/auth/callback")
    .with_post_logout_redirect_uri("http://localhost:8080")
    .with_private_cookie_key(&env::var("COOKIE_KEY")?)
    .with_scopes(vec!["openid", "email", "profile"])
    .with_session_max_age(30)
    .build()?;

// Use OidcLogoutHandler for Azure AD
let logout_handler = Arc::new(OidcLogoutHandler::new(
    &format!("https://login.microsoftonline.com/{}/oauth2/v2.0/logout", tenant_id)
));
```

### Provider Compatibility Summary

| Provider | OIDC Support   | Logout Support         | Recommended Handler    |
| -------- | -------------- | ---------------------- | ---------------------- |
| Google   | Partial        | ❌ No OIDC logout      | `DefaultLogoutHandler` |
| GitHub   | ❌ OAuth2 only | ❌ No OIDC logout      | `DefaultLogoutHandler` |
| Keycloak | ✅ Full        | ✅ RP-Initiated Logout | `OidcLogoutHandler`    |
| Azure AD | ✅ Full        | ✅ RP-Initiated Logout | `OidcLogoutHandler`    |
| Okta     | ✅ Full        | ✅ RP-Initiated Logout | `OidcLogoutHandler`    |
| Auth0    | ✅ Full        | ✅ RP-Initiated Logout | `OidcLogoutHandler`    |

```

## Automatic Routes

The `AuthLayer` adds these routes automatically:

| Route                         | Method | Description                                       |
| ----------------------------- | ------ | ------------------------------------------------- |
| `/auth`                       | GET    | Initiates OAuth flow, redirects to provider       |
| `/auth/callback`              | GET    | Handles OAuth callback, exchanges code for tokens |
| `/auth/logout`                | GET    | Logs out user, clears session                     |
| `/auth/logout?redirect=/path` | GET    | Logs out and redirects to custom path             |

## Troubleshooting

### Common Issues

**Issue: "Missing parameter" error**

```

Solution: Ensure all required configuration is set before calling build()

```

**Issue: Session not persisting**

```

Solution: Check Redis connection and ensure cookies are enabled

```

**Issue: Redirect loop**

```

Solution: Verify redirect_uri matches exactly in provider settings

```

**Issue: Token expired too quickly**

```

Solution: Adjust session_max_age and token_max_age settings

```

**Issue: ID token and access token refresh failing**

```

Solution:

1. Ensure your OAuth provider supports refresh tokens for obtaining new ID tokens and access tokens
2. Check that the 'offline_access' or equivalent scope is requested
3. Verify refresh_token is being stored in session
4. Check provider logs for refresh token errors

```

**Issue: Frequent re-authentication required**

```

Solution:

1. Verify refresh token is being returned by provider
2. Check token_max_age isn't set too low (tokens will refresh frequently)
3. Ensure cache is properly storing updated sessions with refreshed tokens
4. Verify provider's refresh token expiration policy

```

## Additional Resources

- [RFC 6749 - OAuth 2.0](https://tools.ietf.org/html/rfc6749)
- [RFC 7636 - PKCE](https://tools.ietf.org/html/rfc7636)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
- [Axum Documentation](https://docs.rs/axum)

---

**Last Updated:** 2024
**Version:** 0.1.0
```
