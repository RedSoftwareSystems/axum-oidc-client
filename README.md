# axum-oidc-client

A comprehensive OAuth2/OIDC authentication library for Axum web applications with PKCE (Proof Key for Code Exchange) support and token auto refresh capabilities.

[![Crates.io](https://img.shields.io/crates/v/axum-oidc-client.svg)](https://crates.io/crates/axum-oidc-client)
[![Documentation](https://docs.rs/axum-oidc-client/badge.svg)](https://docs.rs/axum-oidc-client)
[![License](https://img.shields.io/crates/l/axum-oidc-client.svg)](LICENSE)

## Features

- ✅ **OAuth2/OIDC Authentication** - Full support for OAuth2 and OpenID Connect protocols
- 🔐 **PKCE Support** - Implements RFC 7636 for enhanced security
- 🔄 **Automatic Token Refresh** - Seamlessly refreshes expired ID tokens and access tokens using OAuth2 refresh token flow
- 💾 **Flexible Caching** - Pluggable cache backends with built-in Redis support
- 🍪 **Secure Sessions** - Encrypted cookie-based session management
- 🚪 **Logout Handlers** - Support for both standard and OIDC logout flows
- 🎯 **Type-safe Extractors** - Convenient extractors for authenticated users and sessions
- 🔧 **Customizable** - Extensible with custom CA certificates and logout handlers
- ⚡ **Production Ready** - Battle-tested with comprehensive error handling

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
axum-oidc-client = "0.1.0"
axum = "0.7"
tokio = { version = "1", features = ["full"] }
```

### Feature Flags

- `redis` - Enable Redis cache backend with default TLS (enabled by default)
- `redis-rustls` - Enable Redis with rustls for TLS
- `redis-native-tls` - Enable Redis with native-tls

```toml
[dependencies]
axum-oidc-client = { version = "0.1.0", features = ["redis"] }
```

## Quick Start

```rust
use axum::{Router, routing::get};
use axum_oidc_client::{
    auth::{AuthLayer, CodeChallengeMethod},
    auth_builder::OAuthConfigurationBuilder,
    auth_cache::AuthCache,
    logout::handle_default_logout::DefaultLogoutHandler,
};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build OAuth configuration
    let config = OAuthConfigurationBuilder::default()
        .with_authorization_endpoint("https://accounts.google.com/o/oauth2/auth")
        .with_token_endpoint("https://oauth2.googleapis.com/token")
        .with_client_id("your-client-id")
        .with_client_secret("your-client-secret")
        .with_redirect_uri("http://localhost:8080/auth/callback")
        .with_private_cookie_key("your-secret-key-at-least-32-bytes")
        .with_scopes(vec!["openid", "email", "profile"])
        .with_code_challenge_method(CodeChallengeMethod::S256)
        .with_session_max_age(30) // 30 minutes
        .with_base_path("/auth") // Optional: customize auth routes (default: "/auth")
        .build()?;

    // Create cache (Redis example)
    let cache: Arc<dyn AuthCache + Send + Sync> = Arc::new(
        axum_oidc_client::redis::AuthCache::new("redis://127.0.0.1/", 3600)
    );

    // Create logout handler
    let logout_handler = Arc::new(DefaultLogoutHandler);

    // Build your application
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
    "Hello, World!"
}

// This route requires authentication
async fn protected(session: axum_oidc_client::auth_session::AuthSession) -> String {
    format!("Hello, authenticated user! Token expires in: {} seconds", session.expires)
}
```

## Automatic ID Token and Access Token Refresh

The library automatically refreshes expired ID tokens and access tokens when they expire. This happens transparently when you use the provided extractors.

### How It Works

1. **Token Expiration Check** - On each request, the library checks if the ID token and access token have expired
2. **Automatic Refresh** - If expired, uses the refresh token to obtain new ID token and access token
3. **Session Update** - Updates the session with the new ID token, access token, and expiration time
4. **Cache Sync** - Saves the refreshed session back to the cache
5. **Seamless Access** - Your handler receives the fresh token automatically

### Using Auto-Refresh Extractors

```rust
use axum_oidc_client::extractors::{AccessToken, IdToken};
use axum_oidc_client::auth_session::AuthSession;

// Access token extractor with automatic refresh
async fn api_call(token: AccessToken) -> String {
    // Access token is automatically refreshed if expired
    format!("Using token: {}", *token)
}

// ID token extractor with automatic refresh
async fn user_info(token: IdToken) -> String {
    // ID token is automatically refreshed if expired
    format!("User ID token: {}", *token)
}

// Full session extractor with automatic token refresh
async fn dashboard(session: AuthSession) -> String {
    // ID token and access token are automatically refreshed if expired
    format!("Session expires: {}", session.expires)
}
```

### Extractors with Automatic Token Refresh

- `AccessToken` - Extracts the access token (automatically refreshed if expired)
- `IdToken` - Extracts the ID token (automatically refreshed if expired)
- `AuthSession` - Extracts full session (ID token and access token automatically refreshed if expired)
- `OptionalAccessToken` - Optional access token (automatically refreshed if expired)
- `OptionalIdToken` - Optional ID token (automatically refreshed if expired)

### Refresh Token Storage

Refresh tokens are automatically:

- Stored in the session during initial authentication
- Used to obtain new ID tokens and access tokens when they expire
- Updated if the provider issues a new refresh token during refresh
- Persisted in the cache with the session

## API Documentation

### Core Modules

#### `auth`

The core authentication module providing the main layer and configuration types.

**Key Types:**

- `AuthLayer` - Tower layer for adding authentication to your Axum app
- `OAuthConfiguration` - Configuration for OAuth2 endpoints and credentials
- `CodeChallengeMethod` - PKCE code challenge method (S256 or Plain)
- `LogoutHandler` - Trait for implementing custom logout behavior

#### `auth_builder`

Builder pattern for constructing OAuth configurations.

**Example:**

```rust
use axum_oidc_client::auth_builder::OAuthConfigurationBuilder;

let config = OAuthConfigurationBuilder::default()
    .with_client_id("my-client-id")
    .with_client_secret("my-client-secret")
    .with_redirect_uri("http://localhost:8080/auth/callback")
    .with_authorization_endpoint("https://provider.com/oauth/authorize")
    .with_token_endpoint("https://provider.com/oauth/token")
    .with_private_cookie_key("secret-key-min-32-bytes-long")
    .with_scopes(vec!["openid", "email", "profile"])
    .build()?;
```

#### `auth_cache`

Cache trait and implementations for storing authentication state.

**Trait:**

```rust
pub trait AuthCache {
    async fn get(&self, key: &str) -> Option<String>;
    async fn set(&self, key: &str, value: &str);
    async fn delete(&self, key: &str);
}
```

**Built-in Implementations:**

- `redis::AuthCache` - Redis-backed cache (requires `redis` feature)

**Custom Implementation:**

```rust
use axum_oidc_client::auth_cache::AuthCache;
use async_trait::async_trait;

struct MyCache;

#[async_trait]
impl AuthCache for MyCache {
    async fn get(&self, key: &str) -> Option<String> {
        // Your implementation
    }

    async fn set(&self, key: &str, value: &str) {
        // Your implementation
    }

    async fn delete(&self, key: &str) {
        // Your implementation
    }
}
```

#### `auth_session`

Session management and token handling.

**Key Type:**

- `AuthSession` - Contains authenticated user's session data

**Fields:**

```rust
pub struct AuthSession {
    pub id_token: String,
    pub access_token: String,
    pub token_type: String,
    pub refresh_token: Option<String>,
    pub scope: String,
    pub expires: DateTime<Local>,
}
```

#### `extractors`

Type-safe extractors for accessing authenticated user data with automatic ID token and access token refresh.

**Available Extractors:**

- `AuthSession` - Full session (automatically refreshes ID token and access token if expired), redirects to OAuth if not authenticated
- `AccessToken` - Access token extractor (automatically refreshes if expired)
- `IdToken` - ID token extractor (automatically refreshes if expired)
- `OptionalAccessToken` - Optional access token (automatically refreshes if expired)
- `OptionalIdToken` - Optional ID token (automatically refreshes if expired)

**Example:**

```rust
use axum_oidc_client::auth_session::AuthSession;
use axum_oidc_client::extractors::{AccessToken, IdToken, OptionalIdToken};

// Protected route with full session
async fn protected(session: AuthSession) -> String {
    // ID token and access token are automatically refreshed if expired
    format!("Authenticated! Token: {}", session.access_token)
}

// Protected route with just access token
async fn api_endpoint(token: AccessToken) -> String {
    // Access token is automatically refreshed if expired
    format!("API call with token: {}", *token)
}

// Protected route with ID token
async fn user_profile(token: IdToken) -> String {
    // ID token is automatically refreshed if expired
    format!("User profile with ID: {}", *token)
}

// Public route with optional authentication
async fn home(OptionalIdToken(token): OptionalIdToken) -> String {
    match token {
        Some(id_token) => format!("Welcome back!"),
        None => format!("Please log in"),
    }
}
```

#### `logout`

Logout handler implementations.

**Built-in Handlers:**

1. **DefaultLogoutHandler** - Simple local logout with session cleanup

   Use this handler when:
   - The OAuth provider doesn't support OIDC logout (e.g., Google, GitHub)
   - You only need to clear the local session without notifying the provider
   - You're implementing custom logout logic

   ```rust
   use axum_oidc_client::logout::handle_default_logout::DefaultLogoutHandler;
   let handler = Arc::new(DefaultLogoutHandler);
   ```

   **Behavior:**
   - Removes session cookie
   - Deletes session from cache
   - Redirects to `post_logout_redirect_uri` (default: "/")

2. **OidcLogoutHandler** - OIDC-compliant logout with provider notification

   Use this handler when:
   - The OAuth provider supports OIDC RP-Initiated Logout (e.g., Keycloak, Azure AD)
   - You need to end the session at the provider
   - You want single logout across multiple applications

   ```rust
   use axum_oidc_client::logout::handle_oidc_logout::OidcLogoutHandler;
   let handler = Arc::new(OidcLogoutHandler::new("https://provider.com/oidc/logout"));
   ```

   **Behavior:**
   - Removes session cookie
   - Deletes session from cache
   - Redirects to provider's `end_session_endpoint` with `id_token_hint`
   - Provider logs out user and redirects to `post_logout_redirect_uri`

**Custom Handler:**

You can implement the `LogoutHandler` trait to create custom logout behavior:

```rust
use axum_oidc_client::auth::LogoutHandler;
use futures_util::future::BoxFuture;
use axum::response::{Redirect, IntoResponse};

struct CustomLogoutHandler {
    custom_redirect: String,
}

impl LogoutHandler for CustomLogoutHandler {
    fn handle_logout<'a>(
        &'a self,
        parts: &'a mut http::request::Parts,
        configuration: Arc<OAuthConfiguration>,
        cache: Arc<dyn AuthCache + Send + Sync>,
    ) -> BoxFuture<'a, Result<Response, Error>> {
        Box::pin(async move {
            // Your custom logout logic
            // For example: audit logging, custom redirects, etc.

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

### Automatic Routes

The `AuthLayer` automatically adds the following routes (default base path is `/auth`):

- `GET /auth` - Initiates OAuth2 authorization flow
- `GET /auth/callback` - OAuth2 callback endpoint (handles authorization code exchange)
- `GET /auth/logout` - Logout endpoint (redirects to home by default)
- `GET /auth/logout?redirect=/path` - Logout with custom redirect

### Configurable Base Path

You can customize the base path for authentication routes via configuration:

```rust
let config = OAuthConfigurationBuilder::default()
    // ... other config
    .with_base_path("/api/auth")  // Custom base path (default: "/auth")
    .with_redirect_uri("http://localhost:8080/api/auth/callback")  // Match your base_path
    .build()?;

// Routes will be available at:
// - GET /api/auth
// - GET /api/auth/callback
// - GET /api/auth/logout
```

## Configuration

### Required Configuration

```rust
OAuthConfigurationBuilder::default()
    .with_client_id("...")              // OAuth2 client ID
    .with_client_secret("...")          // OAuth2 client secret
    .with_redirect_uri("...")           // Callback URL
    .with_authorization_endpoint("...")  // Authorization URL
    .with_token_endpoint("...")         // Token exchange URL
    .with_private_cookie_key("...")     // Session encryption key (min 32 bytes)
    .with_session_max_age(30)           // Session duration in minutes
    .build()?;
```

### Optional Configuration

```rust
builder
    .with_scopes(vec!["openid", "email"])  // OAuth scopes (default: openid, email, profile)
    .with_code_challenge_method(CodeChallengeMethod::S256)  // PKCE method (default: S256)
    .with_end_session_endpoint("...")      // OIDC logout endpoint (only for OIDC-compliant providers)
    .with_post_logout_redirect_uri("...")  // Post-logout redirect (default: "/")
    .with_custom_ca_cert("/path/to/ca.pem") // Custom CA certificate
    .with_token_max_age(300)               // Token max age in seconds
    .with_base_path("/api/auth")           // Custom base path for auth routes (default: "/auth")
```

**Note on `end_session_endpoint`:**

- Only set this if your OAuth provider supports OIDC RP-Initiated Logout
- Use with `OidcLogoutHandler` to properly logout from the provider
- Not all providers support this (e.g., Google, GitHub don't implement OIDC logout)

## OAuth Providers

### Google

Google supports OAuth2 but **does not implement OIDC logout**. Use `DefaultLogoutHandler` for logout.

```rust
use axum_oidc_client::logout::handle_default_logout::DefaultLogoutHandler;

let config = OAuthConfigurationBuilder::default()
    .with_authorization_endpoint("https://accounts.google.com/o/oauth2/auth")
    .with_token_endpoint("https://oauth2.googleapis.com/token")
    .with_client_id("your-client-id.apps.googleusercontent.com")
    .with_client_secret("your-client-secret")
    .with_redirect_uri("http://localhost:8080/auth/callback")
    .with_private_cookie_key("your-secret-key-at-least-32-bytes")
    .with_scopes(vec!["openid", "email", "profile"])
    .with_session_max_age(30)
    // Note: DO NOT set end_session_endpoint for Google
    .build()?;

let logout_handler = Arc::new(DefaultLogoutHandler);
```

### GitHub

GitHub uses OAuth2 (not OIDC). Use `DefaultLogoutHandler` for logout.

```rust
use axum_oidc_client::logout::handle_default_logout::DefaultLogoutHandler;

let config = OAuthConfigurationBuilder::default()
    .with_authorization_endpoint("https://github.com/login/oauth/authorize")
    .with_token_endpoint("https://github.com/login/oauth/access_token")
    .with_client_id("your-client-id")
    .with_client_secret("your-client-secret")
    .with_redirect_uri("http://localhost:8080/auth/callback")
    .with_private_cookie_key("your-secret-key-at-least-32-bytes")
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
    .with_private_cookie_key("your-secret-key-at-least-32-bytes")
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

let tenant = "common"; // or your tenant ID
let config = OAuthConfigurationBuilder::default()
    .with_authorization_endpoint(&format!("https://login.microsoftonline.com/{}/oauth2/v2.0/authorize", tenant))
    .with_token_endpoint(&format!("https://login.microsoftonline.com/{}/oauth2/v2.0/token", tenant))
    .with_end_session_endpoint(&format!("https://login.microsoftonline.com/{}/oauth2/v2.0/logout", tenant))
    .with_client_id("your-client-id")
    .with_client_secret("your-client-secret")
    .with_redirect_uri("http://localhost:8080/auth/callback")
    .with_post_logout_redirect_uri("http://localhost:8080")
    .with_private_cookie_key("your-secret-key-at-least-32-bytes")
    .with_scopes(vec!["openid", "email", "profile"])
    .with_session_max_age(30)
    .build()?;

// Use OidcLogoutHandler for Azure AD
let logout_handler = Arc::new(OidcLogoutHandler::new(
    &format!("https://login.microsoftonline.com/{}/oauth2/v2.0/logout", tenant)
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

## Security Considerations

### PKCE Code Challenge Method

Always use `CodeChallengeMethod::S256` in production. The `Plain` method is only for testing or legacy systems that don't support S256.

```rust
.with_code_challenge_method(CodeChallengeMethod::S256)  // ✅ Recommended
.with_code_challenge_method(CodeChallengeMethod::Plain) // ⚠️ Not recommended
```

### Private Cookie Key

Use a cryptographically strong random value for the private cookie key:

```rust
// ✅ Good: Generate with a tool like openssl
// openssl rand -base64 64
.with_private_cookie_key("generated-random-key-at-least-32-bytes-long")

// ❌ Bad: Hardcoded or weak key
.with_private_cookie_key("my-secret-key")
```

### HTTPS in Production

Always use HTTPS for all endpoints in production:

```rust
// ✅ Production
.with_redirect_uri("https://myapp.com/auth/callback")

// ⚠️ Development only
.with_redirect_uri("http://localhost:8080/auth/callback")
```

### Session and Token Expiration

Configure appropriate expiration times based on your security requirements:

```rust
.with_session_max_age(30)    // 30 minutes - balance between UX and security
.with_token_max_age(300)     // 5 minutes - force token refresh
```

## Advanced Usage

### Custom Auth Routes Base Path

You can mount authentication routes at a custom base path instead of the default `/auth`:

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
    let config = OAuthConfigurationBuilder::default()
        .with_client_id("your-client-id")
        .with_client_secret("your-client-secret")
        .with_base_path("/api/auth")  // Custom base path
        // IMPORTANT: redirect_uri must match your custom base path
        .with_redirect_uri("http://localhost:8080/api/auth/callback")
        .with_authorization_endpoint("https://provider.com/oauth/authorize")
        .with_token_endpoint("https://provider.com/oauth/token")
        .with_private_cookie_key("your-secret-key-at-least-32-bytes")
        .with_session_max_age(30)
        .build()?;

    let cache = Arc::new(/* your cache implementation */);
    let logout_handler = Arc::new(DefaultLogoutHandler);

    let app = Router::new()
        .route("/", get(home))
        .route("/api/protected", get(protected))
        .layer(AuthLayer::new(Arc::new(config), cache, logout_handler));

    // Routes are now available at:
    // - GET /api/auth          (start OAuth flow)
    // - GET /api/auth/callback (OAuth callback)
    // - GET /api/auth/logout   (logout)

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn home() -> &'static str { "Home" }
async fn protected(session: axum_oidc_client::auth_session::AuthSession) -> String {
    format!("Protected content! Token expires: {}", session.expires)
}
```

**Key Points:**

- Use `.with_base_path("/api/auth")` in the configuration builder to set a custom base path
- Update your `redirect_uri` in the configuration to match: `http://localhost:8080/api/auth/callback`
- Update your OAuth provider settings with the new redirect URI
- The base path can be any valid path (e.g., `/oauth`, `/api/v1/auth`, etc.)
- Trailing slashes are automatically removed
- Default is `/auth` if not specified

## Examples

See the `examples/sample-server` directory for a complete working example with:

- Environment variable configuration
- CLI argument parsing
- Multiple route types (public and protected)
- Redis cache integration
- Custom logout handling

Run the example:

```bash
cd examples/sample-server
cargo run -- --client-id YOUR_ID --client-secret YOUR_SECRET
```

## Error Handling

The library uses a custom `Error` type for all operations:

```rust
use axum_oidc_client::errors::Error;

match config.build() {
    Ok(config) => { /* use config */ },
    Err(Error::MissingParameter(param)) => {
        eprintln!("Missing required parameter: {}", param);
    },
    Err(e) => {
        eprintln!("Configuration error: {:?}", e);
    }
}
```

## Testing

```bash
# Run all tests
cargo test

# Run with specific features
cargo test --features redis

# Run example
cargo run --example sample-server
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built on top of [Axum](https://github.com/tokio-rs/axum)
- Uses [pkce](https://crates.io/crates/pkce) for PKCE implementation
- Session management with [tower-cookies](https://crates.io/crates/tower-cookies)

## Support

- 📚 [Documentation](https://docs.rs/axum-oidc-client)
- 🐛 [Issue Tracker](https://github.com/yourusername/axum-oidc-client/issues)
- 💬 [Discussions](https://github.com/yourusername/axum-oidc-client/discussions)
