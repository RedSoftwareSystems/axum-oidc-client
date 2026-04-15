# axum-oidc-client

A comprehensive OAuth2/OIDC authentication library for Axum web applications with PKCE (Proof Key for Code Exchange) support and token auto refresh capabilities.

[![Crates.io](https://img.shields.io/crates/v/axum-oidc-client.svg)](https://crates.io/crates/axum-oidc-client)
[![Documentation](https://docs.rs/axum-oidc-client/badge.svg)](https://docs.rs/axum-oidc-client)
[![License](https://img.shields.io/crates/l/axum-oidc-client.svg)](LICENSE)

## Features

- ✅ **OAuth2/OIDC Authentication** - Full support for OAuth2 and OpenID Connect protocols
- 🔐 **PKCE Support** - Implements RFC 7636 for enhanced security
- 🔄 **Automatic Token Refresh** - Seamlessly refreshes expired ID tokens and access tokens using OAuth2 refresh token flow
- 💾 **Flexible Caching** - Pluggable cache backends with built-in two-tier in-memory (Moka L1) and Redis support
- 🍪 **Secure Sessions** - Encrypted cookie-based session management
- 🚪 **Logout Handlers** - Support for both standard and OIDC logout flows
- 🎯 **Type-safe Extractors** - Convenient extractors for authenticated users and sessions
- 🔧 **Customizable** - Extensible with custom CA certificates and logout handlers
- ⚡ **Production Ready** - Battle-tested with comprehensive error handling

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
axum-oidc-client = "0.5"
axum = "0.8"
tokio = { version = "1", features = ["full"] }
```

### Feature Flags

#### Top-level (default)

- `authentication` *(default)* – The full OAuth2/OIDC stack: `AuthenticationLayer`, session management, `AuthCache`, `OAuthConfigurationBuilder`, route handlers, extractors, and logout handlers.  Implied by every cache/backend feature.
- `jwt` *(default)* – JWT validation utilities: `JwtLayer`, `OidcClaims`, `JwtConfiguration`, `JwtConfigurationBuilder`, `JwtClaims`, `OptionalJwtClaims`.

#### Cache backends (each implies `authentication`)

- `moka-cache` *(default)* – Two-tier in-memory Moka L1 cache
- `redis` – Redis cache backend (rustls TLS)
- `redis-rustls` – Redis with explicit rustls TLS
- `redis-native-tls` – Redis with native-tls
- `sql-cache-postgres` – PostgreSQL backend via sqlx
- `sql-cache-mysql` – MySQL/MariaDB backend via sqlx
- `sql-cache-sqlite` – SQLite backend via sqlx
- `sql-cache-all` – All three SQL backends at once (useful for testing)

```toml
[dependencies]
# Default: includes authentication, jwt, and moka-cache features
axum-oidc-client = "0.5"

# With JWT validation + Redis cache backend
axum-oidc-client = { version = "0.5", features = ["jwt", "redis"] }

# With Redis + two-tier cache (L1 Moka + L2 Redis)
axum-oidc-client = { version = "0.5", features = ["moka-cache", "redis"] }

# With PostgreSQL cache backend
axum-oidc-client = { version = "0.5", features = ["sql-cache-postgres"] }

# With SQLite cache backend (great for development)
axum-oidc-client = { version = "0.5", features = ["sql-cache-sqlite"] }

# With Moka L1 + PostgreSQL L2 two-tier cache
axum-oidc-client = { version = "0.5", features = ["moka-cache", "sql-cache-postgres"] }
```

## Quick Start

```rust
use axum::{Router, routing::get};
use axum_oidc_client::{
    auth::{AuthenticationLayer, CodeChallengeMethod},
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

    // Create cache — L1-only in-memory cache using Moka (requires `moka-cache` feature, enabled by default).
    // For Redis (L2), enable the `redis` feature and see the Cache section below.
    let cache: Arc<dyn AuthCache + Send + Sync> = Arc::new(
        axum_oidc_client::cache::TwoTierAuthCache::new(
            None, // no L2 backend; pass Some(redis_cache) to enable Redis
            axum_oidc_client::cache::config::TwoTierCacheConfig::default(),
        )?
    );

    // Create logout handler
    let logout_handler = Arc::new(DefaultLogoutHandler);

    // Build your application
    let app = Router::new()
        .route("/", get(home))
        .route("/protected", get(protected))
        .layer(AuthenticationLayer::new(Arc::new(config), cache, logout_handler));

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
    let expires = session.expires
        .map(|e| e.to_string())
        .unwrap_or_else(|| "(no expiry)".to_string());
    format!("Hello, authenticated user! Token expires: {}", expires)
}
```

## JWT Validation

The `jwt` feature (enabled by default) provides standalone JWT Bearer token validation via `JwtLayer`. This is useful when you want to protect routes using JWT tokens issued by an external identity provider, without requiring the full OAuth2 session flow.

```rust
use axum::{Router, routing::get};
use axum_oidc_client::{
    jwt::{JwtLayer, JwtConfigurationBuilder, Algorithm, DecodingKey, OidcClaims},
    extractors::JwtClaims,
};
use std::sync::Arc;

async fn protected(JwtClaims(claims): JwtClaims<OidcClaims>) -> String {
    format!("Hello, {}!", claims.sub)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Option A: shared secret (HS256)
    let config = JwtConfigurationBuilder::<OidcClaims>::new()
        .with_decoding_key(DecodingKey::from_secret(b"my-secret"))
        .with_algorithm(Algorithm::HS256)
        .with_audience(vec!["my-client-id".to_string()])
        .build()?;

    // Option B: OIDC auto-discovery (RS256, fetches JWKS automatically)
    // let config = JwtConfigurationBuilder::<OidcClaims>::new()
    //     .with_issuer("https://accounts.google.com").await?
    //     .with_audience(vec!["my-client-id".to_string()])
    //     .build()?;

    let app = Router::new()
        .route("/protected", get(protected))
        .layer(JwtLayer::new(Arc::new(config)));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
    axum::serve(listener, app).await?;
    Ok(())
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
    let expires = session.expires
        .map(|e| e.to_string())
        .unwrap_or_else(|| "(no expiry)".to_string());
    format!("Session expires: {}", expires)
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

### Module Overview

The library is organised under two top-level namespaces, each gated by a matching feature flag.

#### `authentication` module (and backward-compat aliases)

Requires the `authentication` feature (default). All sub-modules are also accessible via their short aliases for backward compatibility.

| Canonical path | Alias | Key types |
|---|---|---|
| `authentication` | `auth` | `AuthenticationLayer` (Tower layer), `AuthLayer` *(backward-compat alias — see note below)*, `OAuthConfiguration`, `CodeChallengeMethod`, `LogoutHandler` |
| `authentication::builder` | `auth_builder` | `OAuthConfigurationBuilder` — supports `.with_issuer(url).await?` for OIDC auto-discovery |
| `authentication::cache` | `auth_cache` | `AuthCache` trait |
| `authentication::session` | `auth_session` | `AuthSession` |
| `authentication::moka` | `cache` | `TwoTierAuthCache`, `TwoTierCacheConfig` *(requires `moka-cache`)* |
| `authentication::redis` | `redis` | Redis `AuthCache` *(requires `redis`)* |
| `authentication::sql_cache` | `sql_cache` | `SqlAuthCache`, `SqlCacheConfig` *(requires `sql-cache-*`)* |
| `authentication::logout` | `logout` | `DefaultLogoutHandler`, `OidcLogoutHandler` |
| `extractors` | — | `AuthSession`, `AccessToken`, `IdToken`, `OptionalAuthSession`, `OptionalAccessToken`, `OptionalIdToken`, `JwtClaims<C>`, `OptionalJwtClaims<C>` |

> **`AuthLayer` rename note:** `AuthLayer` is a backward-compatible type alias for `AuthenticationLayer`. All existing code that references `AuthLayer` compiles unchanged.

#### `jwt` module

Requires the `jwt` feature (default).

| Path | Key types |
|---|---|
| `jwt` | `JwtLayer<C>`, `JwtConfiguration<C>`, `JwtConfigurationBuilder<C>`, `OidcClaims`, `decode_jwt`, `decode_jwt_unverified`, `Algorithm`, `DecodingKey`, `Validation` |
| `jwt::oidc` | `OidcClaims` (also re-exported as `jwt::OidcClaims`) |

### Core Modules

#### `sql_cache`

SQL database cache backend implementing `AuthCache` via [`sqlx`](https://crates.io/crates/sqlx). An alternative L2 backend to Redis — useful when you already run a SQL database and want to avoid an extra Redis dependency.

Also accessible as `authentication::sql_cache`.

**Supported databases:**

| Feature               | Database         | Notes                                      |
|-----------------------|------------------|--------------------------------------------|
| `sql-cache-postgres`  | PostgreSQL       | Best for high-concurrency production use   |
| `sql-cache-mysql`     | MySQL / MariaDB  | Good general-purpose option                |
| `sql-cache-sqlite`    | SQLite           | Ideal for development / single-instance    |

**Quick start (SQLite):**

```rust
use axum_oidc_client::sql_cache::{SqlAuthCache, SqlCacheConfig};
use std::sync::Arc;

let config = SqlCacheConfig {
    connection_string: "sqlite://cache.db".to_string(),
    ..Default::default()
};

let cache = Arc::new(SqlAuthCache::new(config).await?);
cache.init_schema().await?; // creates table + index (idempotent)
```

**PostgreSQL with two-tier (Moka L1 + Postgres L2):**

```rust
use axum_oidc_client::sql_cache::{SqlAuthCache, SqlCacheConfig};
use axum_oidc_client::cache::{TwoTierAuthCache, config::TwoTierCacheConfig};
use axum_oidc_client::auth_cache::AuthCache;
use std::sync::Arc;

let sql = Arc::new(SqlAuthCache::new(SqlCacheConfig {
    connection_string: "postgresql://user:pass@localhost/mydb".to_string(),
    ..Default::default()
}).await?);
sql.init_schema().await?;

let cache: Arc<dyn AuthCache + Send + Sync> = Arc::new(
    TwoTierAuthCache::new(Some(sql), TwoTierCacheConfig::default())?
);
```

**Schema** (created by `init_schema()`, table name is configurable):

```sql
-- PostgreSQL
CREATE UNLOGGED TABLE IF NOT EXISTS oidc_cache (
    cache_key   VARCHAR(255) PRIMARY KEY,
    cache_value TEXT         NOT NULL,
    expires_at  BIGINT       NOT NULL  -- Unix timestamp (seconds)
);
CREATE INDEX IF NOT EXISTS idx_oidc_cache_expires ON oidc_cache (expires_at);

-- MySQL / MariaDB and SQLite use a regular (logged) table.
```

> **PostgreSQL note:** The table is declared `UNLOGGED` because it holds ephemeral cache data
> (PKCE code verifiers and auth sessions) that does not need to survive a crash or server restart.
> `UNLOGGED` tables bypass WAL writes, giving significantly higher write throughput and lower I/O.
> The trade-off — the table is truncated automatically on crash recovery — is acceptable for a
> cache: on restart the application simply re-authenticates any affected sessions.

**Key design points:**
- **PostgreSQL** uses an `UNLOGGED TABLE` — no WAL writes, higher write throughput, lower I/O
- Expired rows are never returned (reads include `AND expires_at > now` — lazy deletion)
- A background Tokio task purges expired rows in batches of 1 000 rows at a configurable interval (default: every 5 minutes); stop it with `cache.shutdown().await`
- Fully composable with `TwoTierAuthCache` as the L2 backend

**PostgreSQL: VACUUM after bulk deletes (recommended):**

PostgreSQL uses MVCC (Multi-Version Concurrency Control): a `DELETE` statement does not immediately
free disk pages — it marks rows as "dead" tuples that are reclaimed only when a `VACUUM` pass runs
over the table. On a high-churn cache table this can cause table bloat if dead tuples accumulate
faster than `autovacuum` reclaims them.

`autovacuum` (enabled by default in all modern PostgreSQL installations) will eventually reclaim
dead tuples automatically, but for a dedicated cache table with high write/delete throughput it is
good practice to tune it aggressively and/or schedule a manual `VACUUM`.

*1. Tune `autovacuum` per-table (run once after `init_schema`, idempotent):*

```sql
ALTER TABLE oidc_cache SET (
    autovacuum_vacuum_scale_factor  = 0.01,  -- vacuum after 1 % of rows change (default: 20 %)
    autovacuum_analyze_scale_factor = 0.01,  -- analyze after 1 % of rows change (default: 10 %)
    autovacuum_vacuum_cost_delay    = 2       -- ms; lower = faster vacuum at the cost of more I/O
);
```

*2. Manual `VACUUM` forms — choose the right one for your situation:*

```sql
-- Standard: reclaim dead tuples without locking the table. Safe for production.
VACUUM oidc_cache;

-- Recommended for scheduled maintenance: also refreshes planner statistics.
VACUUM ANALYZE oidc_cache;

-- Full rewrite: maximum space reclamation, but takes an ACCESS EXCLUSIVE lock.
-- Only use during a maintenance window when no live traffic hits the cache.
VACUUM FULL oidc_cache;
```

*3. Schedule via system cron (outside the database):*

```text
# Run VACUUM ANALYZE on the cache table every night at 03:00.
0 3 * * *  psql -U myuser -d mydb -c "VACUUM ANALYZE oidc_cache;"
```

*4. Schedule via `pg_cron` (entirely inside PostgreSQL — no external cron needed):*

```sql
-- Install the extension once per database cluster (superuser required).
CREATE EXTENSION IF NOT EXISTS pg_cron;

-- Schedule VACUUM ANALYZE every night at 03:00 server time.
SELECT cron.schedule(
    'vacuum-oidc-cache',         -- unique job name
    '0 3 * * *',                 -- standard cron expression
    'VACUUM ANALYZE oidc_cache'  -- SQL statement to execute
);

-- Inspect scheduled jobs.
SELECT * FROM cron.job;

-- Remove the job when it is no longer needed.
SELECT cron.unschedule('vacuum-oidc-cache');
```

> **Note:** Because the cache table is declared `UNLOGGED`, PostgreSQL already skips WAL writes
> for all DML. `VACUUM` itself is not WAL-logged either, so the combination of `UNLOGGED` +
> regular `VACUUM` gives the best trade-off between write performance, storage efficiency, and
> query-planner accuracy.

#### `cache`

Two-tier authentication cache combining a fast in-process [Moka](https://crates.io/crates/moka) L1 cache with any `AuthCache` implementation as the L2 backend (requires `moka-cache` feature, **enabled by default**).

Also accessible as `authentication::moka`.

**Cache-aside pattern:**

| Operation  | L1 (Moka)                      | L2 (backend)                   |
|------------|--------------------------------|--------------------------------|
| Read       | Check first; on miss go to L2  | Read on L1 miss; populate L1   |
| Write      | Write                          | Write                          |
| Invalidate | Remove                         | Remove                         |

**L1-only (in-memory, no external dependency):**

```rust
use axum_oidc_client::cache::{TwoTierAuthCache, config::TwoTierCacheConfig};

let cache: Arc<dyn AuthCache + Send + Sync> = Arc::new(
    TwoTierAuthCache::new(None, TwoTierCacheConfig::default())?
);
```

The same type is also importable as `axum_oidc_client::authentication::moka::TwoTierAuthCache`; both paths refer to the same type.

**Two-tier (Moka L1 + Redis L2):**

```rust
use axum_oidc_client::cache::{TwoTierAuthCache, config::TwoTierCacheConfig};

let redis = Arc::new(axum_oidc_client::redis::AuthCache::new("redis://127.0.0.1/", 3600));
let cache: Arc<dyn AuthCache + Send + Sync> = Arc::new(
    TwoTierAuthCache::new(Some(redis), TwoTierCacheConfig {
        l1_max_capacity: 10_000,
        l1_ttl_sec: 3600,
        l1_time_to_idle_sec: Some(1800),
        enable_l1: true,
    })?
);
```


#### `auth`

The core authentication module providing the main layer and configuration types.

Also accessible as `authentication`.

**Key Types:**

- `AuthenticationLayer` - Tower layer for adding authentication to your Axum app
- `AuthLayer` - Backward-compatible type alias for `AuthenticationLayer`; existing code using `AuthLayer` compiles unchanged
- `OAuthConfiguration` - Configuration for OAuth2 endpoints and credentials
- `CodeChallengeMethod` - PKCE code challenge method (S256 or Plain)
- `LogoutHandler` - Trait for implementing custom logout behavior

#### `auth_builder`

Builder pattern for constructing OAuth configurations.

Also accessible as `authentication::builder`.

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

**OIDC auto-discovery** (fetches endpoints from the provider's `/.well-known/openid-configuration`):

```rust
let config = OAuthConfigurationBuilder::default()
    .with_issuer("https://accounts.google.com").await?
    .with_client_id("my-client-id")
    .with_client_secret("my-client-secret")
    .with_redirect_uri("http://localhost:8080/auth/callback")
    .with_private_cookie_key("secret-key-min-32-bytes-long")
    .with_scopes(vec!["openid", "email", "profile"])
    // Optional: set false if your provider rejects redirect_uri in the token request
    // .with_token_request_redirect_uri(false)
    .build()?;
```

> **Provider compatibility note:** By default `redirect_uri` is included in the token exchange
> request (RFC 6749 §4.1.3).  Call `.with_token_request_redirect_uri(false)` if your provider
> rejects redundant `redirect_uri` parameters during token exchange (e.g. Okta when only one
> redirect URI is registered).

#### `auth_cache`

Cache trait and implementations for storing authentication state.

Also accessible as `authentication::cache`.

**Trait:**

```rust
pub trait AuthCache {
    async fn get(&self, key: &str) -> Option<String>;
    async fn set(&self, key: &str, value: &str);
    async fn delete(&self, key: &str);
}
```

**Built-in Implementations:**

- `cache::TwoTierAuthCache` (alias: `authentication::moka::TwoTierAuthCache`) - Two-tier cache: fast in-process Moka L1 + any `AuthCache` as L2 backend (requires `moka-cache` feature, **enabled by default**)
- `redis::AuthCache` (alias: `authentication::redis::AuthCache`) - Redis-backed cache (requires `redis` feature)
- `sql_cache::SqlAuthCache` (alias: `authentication::sql_cache::SqlAuthCache`) - SQL-backed cache supporting PostgreSQL, MySQL, and SQLite (requires `sql-cache-*` feature)

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

Also accessible as `authentication::session`.

**Key Type:**

- `AuthSession` - Contains authenticated user's session data

**Fields:**

```rust
pub struct AuthSession {
    pub id_token: String,
    pub access_token: String,
    pub token_type: String,
    pub refresh_token: Option<String>, // None if provider did not issue a refresh token
    pub scope: Option<String>,         // None if provider did not return scope
    pub expires: Option<DateTime<Local>>, // None if no expiry info was available
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
- `JwtClaims<C>` - Extracts decoded JWT claims from a Bearer token; returns 401 if no valid Bearer token is present. Requires `JwtLayer` to be installed and the `jwt` feature (default).
- `OptionalJwtClaims<C>` - Same as `JwtClaims<C>` but returns `None` for unauthenticated requests instead of 401. Requires `JwtLayer` and the `jwt` feature (default).

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
        Some(_id_token) => "Welcome back!".to_string(),
        None => "Please log in".to_string(),
    }
}
```

#### `logout`

Logout handler implementations.

Also accessible as `authentication::logout`.

**Built-in Handlers:**

1. **DefaultLogoutHandler** - Simple local logout with session cleanup

   Use this handler when:
   - The OAuth provider doesn't support OIDC logout (e.g., Google, GitHub)
   - You only need to clear the local session without notifying the provider
   - You're implementing custom logout logic

   ```rust
   use axum_oidc_client::logout::handle_default_logout::DefaultLogoutHandler;
   // Also available as:
   // use axum_oidc_client::authentication::logout::handle_default_logout::DefaultLogoutHandler;
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

The `AuthenticationLayer` automatically adds the following routes (default base path is `/auth`):

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
    auth::AuthenticationLayer,
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

    let cache: Arc<dyn axum_oidc_client::auth_cache::AuthCache + Send + Sync> = Arc::new(
        axum_oidc_client::cache::TwoTierAuthCache::new(
            None,
            axum_oidc_client::cache::config::TwoTierCacheConfig::default(),
        )?
    );
    let logout_handler = Arc::new(DefaultLogoutHandler);

    let app = Router::new()
        .route("/", get(home))
        .route("/api/protected", get(protected))
        .layer(AuthenticationLayer::new(Arc::new(config), cache, logout_handler));

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
    let expires = session.expires
        .map(|e| e.to_string())
        .unwrap_or_else(|| "(no expiry)".to_string());
    format!("Protected content! Token expires: {}", expires)
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

See the `examples/www-server` directory for a complete working example with:

- Environment variable configuration
- CLI argument parsing
- Multiple route types (public and protected)
- Redis cache integration
- Custom logout handling

Run the example:

```bash
cd examples/www-server
cargo run -- --client-id YOUR_ID --client-secret YOUR_SECRET
```

## Error Handling

The library uses a custom `Error` type for all operations. As of v0.2.1, `Error` implements both `std::fmt::Display` and `std::error::Error`, making it fully composable with standard Rust error-handling idioms (`?`, `Box<dyn std::error::Error>`, `anyhow`, etc.).

```rust
use axum_oidc_client::errors::Error;

match result {
    Ok(session) => { /* use session */ },
    Err(Error::MissingPatameter(param)) => {
        eprintln!("Missing required parameter: {}", param);
    },
    Err(Error::SessionExpired) => {
        eprintln!("Session expired, redirect to login");
    },
    Err(Error::TokenRefreshFailedAuth(msg)) => {
        eprintln!("Token refresh failed: {}", msg);
    },
    Err(e) => {
        // Display impl gives a human-readable message
        eprintln!("Auth error: {}", e);
        // source() exposes the underlying cause where available
        if let Some(cause) = std::error::Error::source(&e) {
            eprintln!("Caused by: {}", cause);
        }
    }
}
```

## Testing

```bash
# Run all tests
cargo test

# Run with specific features
cargo test --features redis
cargo test --features moka-cache
cargo test --features sql-cache-sqlite
cargo test --all-features

# Run example
cargo run --example www-server
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built on top of [Axum](https://github.com/tokio-rs/axum)
- Uses [pkce-std](https://crates.io/crates/pkce-std) for PKCE implementation
- Session management with [axum-extra](https://crates.io/crates/axum-extra) private cookies
- Two-tier in-memory caching via [Moka](https://crates.io/crates/moka)
- Optional Redis support via [redis-rs](https://crates.io/crates/redis)

## Support

- 📚 [Documentation](https://docs.rs/axum-oidc-client)
- 🐛 [Issue Tracker](https://github.com/RedSoftwareSystems/axum-oidc-client/issues)
- 💬 [Discussions](https://github.com/RedSoftwareSystems/axum-oidc-client/discussions)
