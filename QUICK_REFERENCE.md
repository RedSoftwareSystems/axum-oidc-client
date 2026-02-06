# axum-oidc-client Quick Reference

A quick reference guide for common tasks and API usage.

## Installation

```toml
[dependencies]
axum-oidc-client = "0.1.0"
axum = "0.7"
tokio = { version = "1", features = ["full"] }
```

## Basic Setup (5 Steps)

```rust
use axum::{Router, routing::get};
use axum_oidc_client::{
    auth::AuthLayer,
    auth_builder::OAuthConfigurationBuilder,
    logout::handle_default_logout::DefaultLogoutHandler,
    auth_session::AuthSession,
};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Build configuration
    let config = OAuthConfigurationBuilder::default()
        .with_client_id("your-client-id")
        .with_client_secret("your-client-secret")
        .with_redirect_uri("http://localhost:8080/auth/callback")
        .with_authorization_endpoint("https://provider.com/oauth/authorize")
        .with_token_endpoint("https://provider.com/oauth/token")
        .with_private_cookie_key("secret-key-at-least-32-bytes-long")
        .with_session_max_age(30)
        .with_base_path("/auth")  // Optional: default is "/auth"
        .build()?;

    // 2. Create cache
    let cache = Arc::new(
        axum_oidc_client::redis::AuthCache::new("redis://127.0.0.1/", 3600)
    );

    // 3. Create logout handler
    let logout_handler = Arc::new(DefaultLogoutHandler);

    // 4. Build app with auth layer
    let app = Router::new()
        .route("/", get(home))
        .route("/protected", get(protected))
        .layer(AuthLayer::new(Arc::new(config), cache, logout_handler));

    // 5. Start server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn home() -> &'static str { "Home" }
async fn protected(session: AuthSession) -> String {
    // Token is automatically refreshed if expired
    format!("Protected! Expires: {}", session.expires)
}
```

## Common Imports

```rust
// Core
use axum_oidc_client::auth::{AuthLayer, CodeChallengeMethod, OAuthConfiguration};
use axum_oidc_client::auth_builder::OAuthConfigurationBuilder;
use axum_oidc_client::auth_cache::AuthCache;

// Session & Extractors (all support auto-refresh)
use axum_oidc_client::auth_session::AuthSession;
use axum_oidc_client::extractors::{
    AccessToken, IdToken, OptionalAccessToken, OptionalIdToken
};

// Logout
use axum_oidc_client::logout::handle_default_logout::DefaultLogoutHandler;
use axum_oidc_client::logout::handle_oidc_logout::OidcLogoutHandler;

// Cache
use axum_oidc_client::redis::AuthCache as RedisCache;

// Errors
use axum_oidc_client::errors::Error;
```

## Configuration Cheat Sheet

### Minimal Required Config

```rust
OAuthConfigurationBuilder::default()
    .with_client_id("...")
    .with_client_secret("...")
    .with_redirect_uri("...")
    .with_authorization_endpoint("...")
    .with_token_endpoint("...")
    .with_private_cookie_key("...")
    .with_session_max_age(30)
    .with_base_path("/auth")  // Optional, default is "/auth"
    .build()?
```

### Full Config

```rust
OAuthConfigurationBuilder::default()
    // Required
    .with_client_id("client-id")
    .with_client_secret("client-secret")
    .with_redirect_uri("http://localhost:8080/auth/callback")
    .with_authorization_endpoint("https://provider.com/authorize")
    .with_token_endpoint("https://provider.com/token")
    .with_private_cookie_key("secret-key-min-32-bytes")
    .with_session_max_age(30)
    // Optional
    .with_scopes(vec!["openid", "email", "profile"])
    .with_code_challenge_method(CodeChallengeMethod::S256)
    .with_end_session_endpoint("https://provider.com/logout")
    .with_post_logout_redirect_uri("http://localhost:8080")
    .with_custom_ca_cert("/path/to/ca.pem")
    .with_token_max_age(300)
    .build()?
```

## Route Handlers

All extractors automatically refresh expired ID tokens and access tokens before your handler runs.

### Protected Route (Full Session)

```rust
use axum_oidc_client::auth_session::AuthSession;

async fn protected(session: AuthSession) -> String {
    // ID token and access token are automatically refreshed if expired
    format!("Hello! Token expires: {}", session.expires)
}
```

### Protected Route (Access Token Only)

```rust
use axum_oidc_client::extractors::AccessToken;

async fn api_call(token: AccessToken) -> String {
    // Access token is automatically refreshed if expired
    format!("Using token: {}", *token)
}
```

### Protected Route (ID Token Only)

```rust
use axum_oidc_client::extractors::IdToken;

async fn user_info(token: IdToken) -> String {
    // ID token is automatically refreshed if expired
    format!("User ID: {}", *token)
}
```

### Public Route (Optional Auth)

```rust
use axum_oidc_client::extractors::OptionalIdToken;

async fn home(OptionalIdToken(token): OptionalIdToken) -> String {
    match token {
        Some(_) => "Welcome back!".to_string(),
        None => "Please log in".to_string(),
    }
}
```

### Access Session Data

```rust
async fn show_token(session: AuthSession) -> String {
    // ID token and access token are automatically refreshed if expired
    format!(
        "Access Token: {}\nID Token: {}\nToken Type: {}\nScopes: {}\nExpires: {}",
        session.access_token,
        session.id_token,
        session.token_type,
        session.scope,
        session.expires
    )
}
```

## Automatic ID Token and Access Token Refresh

The library automatically refreshes expired ID tokens and access tokens transparently using the OAuth2 refresh token flow.

### How It Works

```rust
use axum_oidc_client::extractors::AccessToken;

async fn my_handler(token: AccessToken) -> String {
    // Before this handler runs:
    // 1. Extractor checks if access token expired
    // 2. If expired, uses refresh token to get new ID token and access token
    // 3. Updates session with new tokens and expiration
    // 4. Saves updated session to cache
    // 5. Your handler receives fresh access token
    format!("Access token is always fresh: {}", *token)
}
```

### Extractors with Automatic Token Refresh

All these extractors support automatic ID token and access token refresh:

- `AuthSession` - Full session (ID token and access token automatically refreshed if expired)
- `AccessToken` - Just the access token (automatically refreshed if expired)
- `IdToken` - Just the ID token (automatically refreshed if expired)
- `OptionalAccessToken` - Optional access token (automatically refreshed if expired)
- `OptionalIdToken` - Optional ID token (automatically refreshed if expired)

### ID Token and Access Token Refresh Flow

When ID token and access token expire:

```
1. Request arrives → Extractor checks session.expires
2. Tokens expired? → POST to token_endpoint with refresh_token
3. Get response → Receive new id_token, access_token, expires_in
4. Update session → session.id_token = new_id_token, session.access_token = new_access_token
5. Save to cache → cache.set_auth_session(session_id, session)
6. Continue → Handler receives fresh tokens
```

### Required Scopes

To enable ID token and access token refresh, include the appropriate scope:

```rust
// For OAuth2 providers that use 'offline_access'
.with_scopes(vec!["openid", "email", "offline_access"])

// For Google (uses 'access_type=offline' via authorization params)
.with_scopes(vec!["openid", "email", "profile"])
```

### Error Handling

If ID token and access token refresh fails (e.g., refresh token expired):

```rust
async fn protected(session: AuthSession) -> String {
    // If refresh fails, user is redirected to re-authenticate
    // Your handler is never called with invalid/expired tokens
    format!("Tokens are valid: {} / {}", session.access_token, session.id_token)
}
```

## OAuth Providers

### Google

```rust
.with_authorization_endpoint("https://accounts.google.com/o/oauth2/auth")
.with_token_endpoint("https://oauth2.googleapis.com/token")
.with_end_session_endpoint("https://accounts.google.com/o/oauth2/revoke")
.with_scopes(vec!["openid", "email", "profile"])
```

### GitHub

```rust
.with_authorization_endpoint("https://github.com/login/oauth/authorize")
.with_token_endpoint("https://github.com/login/oauth/access_token")
.with_scopes(vec!["read:user", "user:email"])
```

### Microsoft Azure AD

```rust
let tenant = "common";
.with_authorization_endpoint(&format!(
    "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize", tenant
))
.with_token_endpoint(&format!(
    "https://login.microsoftonline.com/{}/oauth2/v2.0/token", tenant
))
.with_scopes(vec!["openid", "email", "profile"])
```

## Cache Implementations

### Redis Cache

```rust
use axum_oidc_client::redis::AuthCache;

let cache: Arc<dyn axum_oidc_client::auth_cache::AuthCache + Send + Sync> =
    Arc::new(AuthCache::new("redis://127.0.0.1/", 3600));
```

### Custom Cache

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

## Logout Handlers

### Default Logout

Use when provider doesn't support OIDC logout (Google, GitHub).

```rust
use axum_oidc_client::logout::handle_default_logout::DefaultLogoutHandler;

let handler = Arc::new(DefaultLogoutHandler);
```

**Behavior:** Clears local session, redirects to `post_logout_redirect_uri`

### OIDC Logout

Use when provider supports RP-Initiated Logout (Keycloak, Azure AD, Okta, Auth0).

```rust
use axum_oidc_client::logout::handle_oidc_logout::OidcLogoutHandler;

let handler = Arc::new(OidcLogoutHandler::new(
    "https://provider.com/oidc/logout"
));
```

**Behavior:** Clears local session, redirects to provider's logout endpoint with `id_token_hint`

### Custom Logout

Implement `LogoutHandler` trait for custom behavior (audit logging, special redirects, etc.).

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
            // Custom logic (e.g., audit logging)
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

### Provider Compatibility

| Provider | OIDC Logout | Handler                |
| -------- | ----------- | ---------------------- |
| Google   | ❌          | `DefaultLogoutHandler` |
| GitHub   | ❌          | `DefaultLogoutHandler` |
| Keycloak | ✅          | `OidcLogoutHandler`    |
| Azure AD | ✅          | `OidcLogoutHandler`    |
| Okta     | ✅          | `OidcLogoutHandler`    |
| Auth0    | ✅          | `OidcLogoutHandler`    |

## Provider Examples

### Google

❌ No OIDC logout - use `DefaultLogoutHandler`

```rust
use axum_oidc_client::logout::handle_default_logout::DefaultLogoutHandler;

let config = OAuthConfigurationBuilder::default()
    .with_authorization_endpoint("https://accounts.google.com/o/oauth2/auth")
    .with_token_endpoint("https://oauth2.googleapis.com/token")
    .with_client_id("your-id.apps.googleusercontent.com")
    .with_client_secret("your-secret")
    .with_redirect_uri("http://localhost:8080/auth/callback")
    .with_private_cookie_key("your-key-min-32-bytes")
    .with_scopes(vec!["openid", "email", "profile"])
    .with_session_max_age(30)
    .build()?;

let logout_handler = Arc::new(DefaultLogoutHandler);
```

### GitHub

❌ No OIDC logout - use `DefaultLogoutHandler`

```rust
use axum_oidc_client::logout::handle_default_logout::DefaultLogoutHandler;

let config = OAuthConfigurationBuilder::default()
    .with_authorization_endpoint("https://github.com/login/oauth/authorize")
    .with_token_endpoint("https://github.com/login/oauth/access_token")
    .with_client_id("your-client-id")
    .with_client_secret("your-client-secret")
    .with_redirect_uri("http://localhost:8080/auth/callback")
    .with_private_cookie_key("your-key-min-32-bytes")
    .with_scopes(vec!["read:user", "user:email"])
    .with_session_max_age(30)
    .build()?;

let logout_handler = Arc::new(DefaultLogoutHandler);
```

### Keycloak

✅ Full OIDC support - use `OidcLogoutHandler`

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
    .with_private_cookie_key("your-key-min-32-bytes")
    .with_scopes(vec!["openid", "email", "profile"])
    .with_session_max_age(30)
    .build()?;

let logout_handler = Arc::new(OidcLogoutHandler::new(
    &format!("{}/realms/{}/protocol/openid-connect/logout", keycloak_url, realm)
));
```

### Azure AD

✅ Full OIDC support - use `OidcLogoutHandler`

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
    .with_private_cookie_key("your-key-min-32-bytes")
    .with_scopes(vec!["openid", "email", "profile"])
    .with_session_max_age(30)
    .build()?;

let logout_handler = Arc::new(OidcLogoutHandler::new(
    &format!("https://login.microsoftonline.com/{}/oauth2/v2.0/logout", tenant)
));
```

````

## Automatic Routes

Default base path is `/auth`. Customize via configuration:

| Route                             | Description                 |
| --------------------------------- | --------------------------- |
| `GET /auth`                       | Start OAuth flow            |
| `GET /auth/callback`              | OAuth callback (automatic)  |
| `GET /auth/logout`                | Logout (default redirect)   |
| `GET /auth/logout?redirect=/path` | Logout with custom redirect |

```rust
// Customize auth routes base path via configuration
let config = OAuthConfigurationBuilder::default()
    .with_base_path("/api/auth")  // Custom base path
    .with_redirect_uri("http://localhost:8080/api/auth/callback")  // Match base_path
    // ... other config
    .build()?;

// Routes become: /api/auth, /api/auth/callback, /api/auth/logout
```

## Environment Variables Pattern

```bash
# .env file
OAUTH_CLIENT_ID=your-client-id
OAUTH_CLIENT_SECRET=your-client-secret
OAUTH_REDIRECT_URI=http://localhost:8080/auth/callback
OAUTH_AUTHORIZATION_ENDPOINT=https://provider.com/authorize
OAUTH_TOKEN_ENDPOINT=https://provider.com/token
PRIVATE_COOKIE_KEY=your-secret-key-at-least-32-bytes
SESSION_MAX_AGE=30
````

```rust
use dotenv::dotenv;
use std::env;

dotenv().ok();

let config = OAuthConfigurationBuilder::default()
    .with_client_id(&env::var("OAUTH_CLIENT_ID")?)
    .with_client_secret(&env::var("OAUTH_CLIENT_SECRET")?)
    .with_redirect_uri(&env::var("OAUTH_REDIRECT_URI")?)
    .with_authorization_endpoint(&env::var("OAUTH_AUTHORIZATION_ENDPOINT")?)
    .with_token_endpoint(&env::var("OAUTH_TOKEN_ENDPOINT")?)
    .with_private_cookie_key(&env::var("PRIVATE_COOKIE_KEY")?)
    .with_session_max_age(env::var("SESSION_MAX_AGE")?.parse()?)
    .build()?;
```

## Security Checklist

- [ ] Use `CodeChallengeMethod::S256` (not Plain)
- [ ] Generate strong random `private_cookie_key` (min 32 bytes)
- [ ] Use HTTPS in production for all endpoints
- [ ] Set appropriate `session_max_age` (e.g., 30 minutes)
- [ ] Request only necessary scopes
- [ ] Store secrets in environment variables
- [ ] Verify `redirect_uri` matches provider configuration
- [ ] Enable HTTPS-only cookies in production

## Common Patterns

### Public + Protected Routes

```rust
Router::new()
    .route("/", get(public_home))           // Anyone
    .route("/about", get(public_about))     // Anyone
    .route("/dashboard", get(dashboard))    // Auth required
    .route("/profile", get(profile))        // Auth required
    .layer(auth_layer)
```

### Optional Auth Display

```rust
async fn home(OptionalIdToken(token): OptionalIdToken) -> Html<String> {
    let links = if token.is_some() {
        r#"<a href="/dashboard">Dashboard</a> | <a href="/auth/logout">Logout</a>"#
    } else {
        r#"<a href="/auth">Login</a>"#
    };
    Html(format!("<html><body>{}</body></html>", links))
}
```

### Error Handling

```rust
match config.build() {
    Ok(cfg) => cfg,
    Err(Error::MissingParameter(param)) => {
        panic!("Missing config: {}", param);
    }
    Err(e) => {
        panic!("Config error: {:?}", e);
    }
}
```

## Debugging Tips

### Enable Logging

```toml
[dependencies]
tracing = "0.1"
tracing-subscriber = "0.3"
```

```rust
tracing_subscriber::fmt::init();
```

### Check Session, ID Token, Access Token, and Refresh Token

```rust
async fn debug(session: AuthSession) -> String {
    let now = chrono::Local::now();
    let is_expired = session.expires <= now;

    format!(
        "Session Debug:\n\
         Token Type: {}\n\
         Expires: {}\n\
         Current Time: {}\n\
         Is Expired: {}\n\
         Scopes: {}\n\
         Has Refresh Token: {}\n\
         Access Token (first 20): {}\n\
         ID Token (first 20): {}",
        session.token_type,
        session.expires,
        now,
        is_expired,
        session.scope,
        !session.refresh_token.is_empty(),
        &session.access_token[..20.min(session.access_token.len())],
        &session.id_token[..20.min(session.id_token.len())]
    )
}
```

### Test OAuth Flow

1. Start server
2. Visit `http://localhost:8080/auth`
3. Should redirect to provider
4. After login, should redirect back to `/auth/callback`
5. Then redirect to original destination or home

### Test ID Token and Access Token Refresh

```rust
async fn test_refresh(session: AuthSession) -> String {
    // Wait for tokens to expire, then access again
    // The extractor will automatically refresh ID token and access token
    format!(
        "Tokens expire: {}\n\
         Access token (first 20 chars): {}\n\
         ID token (first 20 chars): {}",
        session.expires,
        &session.access_token[..20.min(session.access_token.len())],
        &session.id_token[..20.min(session.id_token.len())]
    )
}
```

## Common Issues

| Issue                               | Solution                                                 |
| ----------------------------------- | -------------------------------------------------------- |
| "Missing parameter" error           | Check all required config is set                         |
| Session not persisting              | Verify Redis connection                                  |
| Redirect loop                       | Check redirect_uri matches provider                      |
| Token expired immediately           | Adjust session_max_age and token_max_age                 |
| CORS errors                         | Ensure redirect_uri is whitelisted in provider           |
| ID/access token refresh not working | Ensure 'offline_access' or equivalent scope is requested |
| Refresh token empty                 | Check provider returns refresh_token in response         |
| Frequent re-authentication          | Verify refresh tokens are being stored and used          |

## Testing

```bash
# Run tests
cargo test

# Run with features
cargo test --features redis

# Run example
cargo run --example sample-server -- \
  --client-id YOUR_ID \
  --client-secret YOUR_SECRET
```

## Generate Secrets

```bash
# Cookie key (64 bytes base64)
openssl rand -base64 64

# Cookie key (32 bytes hex)
openssl rand -hex 32
```

## Reference Links

- [Full Documentation](https://docs.rs/axum-oidc-client)
- [Examples](./examples/)
- [OAuth 2.0 RFC](https://tools.ietf.org/html/rfc6749)
- [PKCE RFC](https://tools.ietf.org/html/rfc7636)
- [OpenID Connect](https://openid.net/connect/)

---

**Version:** 0.1.0  
**Last Updated:** 2024
