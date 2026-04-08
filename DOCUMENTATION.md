# axum-oidc-client API Documentation (v0.4.0)

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
- Pluggable cache backends with two-tier in-memory (Moka L1) and Redis support
- Encrypted session management
- Type-safe extractors with automatic ID token and access token refresh
- Flexible logout handlers
- Standalone JWT validation via `JwtLayer`, independent of the full OAuth2 session stack

## Feature Flags

### Top-level (default)

| Flag | Default | Description |
|---|---|---|
| `authentication` | ✅ | Full OAuth2/OIDC stack (session management, cache, extractors, logout). Implied by every cache feature. |
| `jwt` | ✅ | JWT validation via `JwtLayer`, `OidcClaims`, `JwtConfiguration`, `JwtConfigurationBuilder`. |

### Cache backends (each implies `authentication`)

| Flag | Default | Description |
|---|---|---|
| `moka-cache` | ✅ | Two-tier in-process Moka L1 cache (`TwoTierAuthCache`). |
| `redis` | ❌ | Redis L2 backend (plain TCP). |
| `redis-rustls` | ❌ | Redis L2 backend with rustls TLS. |
| `redis-native-tls` | ❌ | Redis L2 backend with native-tls TLS. |
| `sql-cache-postgres` | ❌ | PostgreSQL SQL cache backend. |
| `sql-cache-mysql` | ❌ | MySQL/MariaDB SQL cache backend. |
| `sql-cache-sqlite` | ❌ | SQLite SQL cache backend. |
| `sql-cache-all` | ❌ | All three SQL cache backends. |

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

> **Module restructuring note (v0.4.0):** All authentication-related modules are now organised
> under `authentication/` with backward-compatible re-exports at their original paths. No existing
> code needs to change.
>
> | Old path | New canonical path | Still works? |
> |---|---|---|
> | `auth::AuthenticationLayer` | `authentication::AuthenticationLayer` | ✅ via alias |
> | `auth_builder::OAuthConfigurationBuilder` | `authentication::builder::OAuthConfigurationBuilder` | ✅ via alias |
> | `auth_cache::AuthCache` | `authentication::cache::AuthCache` | ✅ via alias |
> | `auth_session::AuthSession` | `authentication::session::AuthSession` | ✅ via alias |
> | `cache::TwoTierAuthCache` | `authentication::moka::TwoTierAuthCache` | ✅ via alias |
> | `sql_cache::SqlAuthCache` | `authentication::sql_cache::SqlAuthCache` | ✅ via alias |
> | `logout::*` | `authentication::logout::*` | ✅ via alias |

### Module: `sql_cache`

SQL database cache backend implementing [`AuthCache`](crate::auth_cache::AuthCache) via [`sqlx`](https://crates.io/crates/sqlx). Provides PostgreSQL, MySQL/MariaDB, and SQLite backends as an alternative L2 cache to Redis (requires one of the `sql-cache-*` feature flags).

#### `SqlCacheConfig`

```rust
pub struct SqlCacheConfig {
    /// Database connection URL. Examples:
    ///   PostgreSQL: "postgresql://user:pass@host/dbname"
    ///   MySQL:      "mysql://user:pass@host/dbname"
    ///   SQLite:     "sqlite://path/to/file.db" or "sqlite://:memory:"
    pub connection_string: String,        // required — no default
    pub max_connections: u32,             // default: 20
    pub min_connections: u32,             // default: 2
    pub cleanup_interval_sec: u64,        // default: 300 (5 min)
    pub table_name: String,               // default: "oidc_cache"
    pub acquire_timeout_sec: u64,         // default: 30
    pub code_verifier_ttl_sec: i64,       // default: 60
}
```

#### `SqlAuthCache`

```rust
use axum_oidc_client::sql_cache::{SqlAuthCache, SqlCacheConfig};
use std::sync::Arc;

// SQLite — ideal for development and single-instance deployments
let config = SqlCacheConfig {
    connection_string: "sqlite://cache.db".to_string(),
    ..Default::default()
};
let cache = Arc::new(SqlAuthCache::new(config).await?);
cache.init_schema().await?;  // creates table + index (idempotent, safe to call on every startup)

// PostgreSQL
let config = SqlCacheConfig {
    connection_string: "postgresql://user:pass@localhost/mydb".to_string(),
    max_connections: 20,
    ..Default::default()
};
let cache = Arc::new(SqlAuthCache::new(config).await?);
cache.init_schema().await?;
```

**Methods:**

| Method                          | Description                                                          |
|---------------------------------|----------------------------------------------------------------------|
| `SqlAuthCache::new(config)`     | Async constructor; starts background cleanup task                    |
| `cache.init_schema()`           | Creates table + index (idempotent; call once on startup)             |
| `cache.shutdown()`              | Gracefully stops the background cleanup task                         |
| `cache.config()`                | Returns a reference to the `SqlCacheConfig` used at construction     |

**Schema** (created by `init_schema()`, table name from `SqlCacheConfig::table_name`):

```sql
-- PostgreSQL
CREATE UNLOGGED TABLE IF NOT EXISTS oidc_cache (
    cache_key   VARCHAR(255) PRIMARY KEY,
    cache_value TEXT         NOT NULL,
    expires_at  BIGINT       NOT NULL   -- Unix timestamp (seconds)
);
CREATE INDEX IF NOT EXISTS idx_oidc_cache_expires ON oidc_cache (expires_at);

-- MySQL / MariaDB and SQLite use a regular (logged) table.
```

> **PostgreSQL note:** The table is declared `UNLOGGED` because it holds ephemeral cache data
> (PKCE code verifiers and auth sessions) that does not need to survive a crash or server restart.
> `UNLOGGED` tables bypass WAL writes, giving significantly higher write throughput and lower I/O.
> The trade-off — the table is truncated automatically on crash recovery — is acceptable for a
> cache: on restart the application simply re-authenticates any affected sessions.

**Key prefixes used internally:**

| Prefix      | Entry type              |
|-------------|-------------------------|
| `cv:`       | PKCE code verifiers     |
| `session:`  | Auth sessions (JSON)    |

**TTL management:**
- All reads include `AND expires_at > <now>` so expired rows are never returned (lazy deletion).
- A background Tokio task purges expired rows in batches of 1 000 rows at `cleanup_interval_sec` intervals. Stop it with `cache.shutdown().await`.

**PostgreSQL: VACUUM after bulk deletes (recommended):**

PostgreSQL uses MVCC (Multi-Version Concurrency Control): a `DELETE` statement does not immediately
free disk pages — it marks rows as "dead" tuples that are reclaimed only when a `VACUUM` pass runs
over the table. On a high-churn cache table this can cause table bloat if dead tuples accumulate
faster than `autovacuum` reclaims them.

`autovacuum` (enabled by default in all modern PostgreSQL installations) will eventually reclaim
dead tuples automatically, but for a dedicated cache table with high write/delete throughput it is
good practice to tune it aggressively and/or schedule a manual `VACUUM`:

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

**Composing with `TwoTierAuthCache` (Moka L1 + SQL L2):**

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
    TwoTierAuthCache::new(
        Some(sql as Arc<dyn AuthCache + Send + Sync>),
        TwoTierCacheConfig::default(),
    )?
);
```

**Database-specific notes:**

| Database      | Feature flag          | UPSERT syntax                                | Notes                                                         |
|---------------|-----------------------|----------------------------------------------|---------------------------------------------------------------|
| PostgreSQL    | `sql-cache-postgres`  | `INSERT … ON CONFLICT … DO UPDATE`           | Uses `UNLOGGED TABLE` — no WAL writes, higher write throughput|
| MySQL/MariaDB | `sql-cache-mysql`     | `INSERT … ON DUPLICATE KEY UPDATE`           | Use InnoDB engine; utf8mb4 charset                            |
| SQLite        | `sql-cache-sqlite`    | `INSERT OR REPLACE INTO …`                   | Enable WAL mode for better concurrency in prod                |

### Module: `cache`

Two-tier authentication cache combining a fast in-process [Moka](https://crates.io/crates/moka) L1 cache with any `AuthCache` implementation as the L2 backend (requires the `moka-cache` feature, **enabled by default**).

#### `TwoTierAuthCache`

```rust
use axum_oidc_client::cache::{TwoTierAuthCache, config::TwoTierCacheConfig};
use axum_oidc_client::auth_cache::AuthCache;
use std::sync::Arc;

// L1-only (pure in-memory, no external dependency)
let cache: Arc<dyn AuthCache + Send + Sync> = Arc::new(
    TwoTierAuthCache::new(None, TwoTierCacheConfig::default())?
);

// Two-tier: Moka L1 + Redis L2 (requires both `moka-cache` and `redis` features)
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

**Cache-aside behaviour:**

| Operation  | L1 (Moka)                         | L2 (backend)                   |
|------------|-----------------------------------|--------------------------------|
| Read       | Check first; on miss, read L2     | Read on L1 miss; populate L1   |
| Write      | Write                             | Write                          |
| Invalidate | Remove                            | Remove                         |

#### `TwoTierCacheConfig`

Configuration struct to tune L1 behaviour:

```rust
pub struct TwoTierCacheConfig {
    /// Maximum number of entries in the Moka L1 cache. Default: 10_000
    pub l1_max_capacity: u64,
    /// Time-to-live per entry in seconds. Default: 3600
    pub l1_ttl_sec: u64,
    /// Optional idle-eviction timeout in seconds. Default: None
    pub l1_time_to_idle_sec: Option<u64>,
    /// Set to false to bypass Moka entirely (useful for testing). Default: true
    pub enable_l1: bool,
}
```

### Module: `auth`

Core authentication types and middleware.

#### `AuthenticationLayer`

Tower layer that adds OAuth2 authentication to your Axum application.

```rust
pub struct AuthenticationLayer {
    configuration: Arc<OAuthConfiguration>,
    cache: Arc<dyn AuthCache + Send + Sync>,
    logout_handler: Arc<dyn LogoutHandler>,
}

/// Backward-compatible type alias — existing code using `AuthLayer` continues to compile.
/// `AuthLayer` and `AuthenticationLayer` are identical; use whichever you prefer.
pub type AuthLayer = AuthenticationLayer;

impl AuthenticationLayer {
    pub fn new(
        configuration: Arc<OAuthConfiguration>,
        cache: Arc<dyn AuthCache + Send + Sync>,
        logout_handler: Arc<dyn LogoutHandler>,
    ) -> Self
}
```

**Usage:**

```rust
let layer = AuthenticationLayer::new(config, cache, logout_handler);
// AuthLayer is a backward-compatible alias: AuthLayer::new(…) also works.
app.layer(layer)
```

**Methods:**

- `new()` - Create a new `AuthenticationLayer`
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
| `with_issuer(url).await?`            | No*      | OIDC auto-discovery: populates `authorization_endpoint`, `token_endpoint`, and `end_session_endpoint` from the provider's discovery document |
| `with_client_id(id)`                 | Yes      | Set OAuth2 client ID                               |
| `with_client_secret(secret)`         | Yes      | Set OAuth2 client secret                           |
| `with_redirect_uri(uri)`             | Yes      | Set callback URI                                   |
| `with_authorization_endpoint(url)`   | Yes*     | Set auth endpoint (not required when using `with_issuer`) |
| `with_token_endpoint(url)`           | Yes*     | Set token endpoint (not required when using `with_issuer`) |
| `with_private_cookie_key(key)`       | Yes      | Set session encryption key                         |
| `with_session_max_age(minutes)`      | Yes      | Set session duration                               |
| `with_scopes(scopes)`                | No       | Set OAuth scopes (default: openid, email, profile) |
| `with_code_challenge_method(method)` | No       | Set PKCE method (default: S256)                    |
| `with_end_session_endpoint(url)`     | No       | Set OIDC logout endpoint                           |
| `with_post_logout_redirect_uri(uri)` | No       | Set post-logout redirect                           |
| `with_custom_ca_cert(path)`          | No       | Set custom CA certificate                          |
| `with_token_max_age(seconds)`        | No       | Set token max age                                  |
| `with_token_request_redirect_uri(bool)` | No    | Include `redirect_uri` in the token request (default: `true`; set `false` for providers that reject it) |
| `build()`                            | -        | Build the configuration                            |

> *When `with_issuer` is used, `with_authorization_endpoint` and `with_token_endpoint` are not
> required because the endpoints are populated automatically from the provider's OIDC discovery
> document. You may still call them explicitly to override individual values if needed.

**OIDC Auto-Discovery Example:**

Use `with_issuer` to automatically populate `authorization_endpoint`, `token_endpoint`, and
`end_session_endpoint` from the provider's `/.well-known/openid-configuration` document:

```rust
// Auto-populate authorization_endpoint, token_endpoint, end_session_endpoint
let config = OAuthConfigurationBuilder::default()
    .with_issuer("https://accounts.google.com").await?
    .with_client_id("your-client-id")
    .with_client_secret("your-client-secret")
    .with_redirect_uri("http://localhost:8080/auth/callback")
    .with_private_cookie_key(&env::var("COOKIE_KEY")?)
    .with_session_max_age(30)
    .build()?;
```

**Manual Endpoint Example:**

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

**Two-Tier Cache** (requires `moka-cache` feature, **enabled by default**):

```rust
use axum_oidc_client::cache::{TwoTierAuthCache, config::TwoTierCacheConfig};

// L1-only
let cache = TwoTierAuthCache::new(None, TwoTierCacheConfig::default())?;
```

**SQL Cache** (requires a `sql-cache-*` feature):

```rust
use axum_oidc_client::sql_cache::{SqlAuthCache, SqlCacheConfig};

let cache = SqlAuthCache::new(SqlCacheConfig {
    connection_string: "sqlite://:memory:".to_string(),
    ..Default::default()
}).await?;
cache.init_schema().await?;
```

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
    /// None if the provider did not issue a refresh token
    pub refresh_token: Option<String>,
    /// None if the provider did not return a scope
    pub scope: Option<String>,
    /// None if neither `expires_in` nor `token_max_age` were available at session creation.
    /// When None, the token refresh logic is disabled entirely.
    pub expires: Option<DateTime<Local>>,
}
```

**Auto-Refresh:**
The `AuthSession` extractor automatically refreshes expired tokens when used in route handlers. If the session's access token has expired and a `refresh_token` is present, the extractor:

1. Uses the refresh token to obtain a new access token
2. Updates all token fields (`access_token`, `id_token` if provided, `expires` if new expiry info is returned)
3. Saves the updated session to cache
4. Returns the refreshed session to your handler

When `expires` is `None`, the refresh logic is skipped (no expiry info was available at session creation).
When `refresh_token` is `None`, expired sessions require re-authentication.

This means you never need to manually check expiration or refresh tokens.

**Usage as Extractor:**

```rust
async fn protected(session: AuthSession) -> String {
    let expires = session.expires
        .map(|e| e.to_string())
        .unwrap_or_else(|| "(no expiry)".to_string());
    let scope = session.scope.as_deref().unwrap_or("(none)");
    format!("Token expires: {} | Scopes: {}", expires, scope)
}
```

### Module: `extractors`

Type-safe extractors for route handlers with automatic ID token and access token refresh support.

All OAuth2/OIDC session extractors automatically check token expiration and refresh ID tokens and
access tokens when needed, providing seamless token management without manual intervention.

For stateless JWT validation (without a full OAuth2 session), see the
[`JwtClaims<C>`](#jwtclaimsc) and [`OptionalJwtClaims<C>`](#optionaljwtclaimsc) extractors below,
which are populated by [`JwtLayer`](#jwtlayerc).

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

#### `JwtClaims<C>`

Extracts decoded JWT claims that were injected into the request extensions by [`JwtLayer<C>`](#jwtlayerc). Returns `401 Unauthorized` when the extension is absent (i.e. no valid Bearer token was presented, or `JwtLayer` was not applied to the route).

Requires the `jwt` feature flag (**enabled by default**).

```rust
use axum_oidc_client::extractors::JwtClaims;
use axum_oidc_client::jwt::OidcClaims;

async fn handler(JwtClaims(claims): JwtClaims<OidcClaims>) -> String {
    format!("sub: {}", claims.sub)
}
```

#### `OptionalJwtClaims<C>`

Same as `JwtClaims<C>` but returns `None` instead of rejecting the request when no valid token is
present. Suitable for public routes that show enriched content to authenticated callers.

Requires the `jwt` feature flag (**enabled by default**).

```rust
use axum_oidc_client::extractors::OptionalJwtClaims;
use axum_oidc_client::jwt::OidcClaims;

async fn handler(OptionalJwtClaims(claims): OptionalJwtClaims<OidcClaims>) -> String {
    match claims {
        Some(c) => format!("Hello, {}!", c.sub),
        None    => "Hello, anonymous!".to_string(),
    }
}
```

### Module: `jwt`

Standalone JWT validation layer, independent of the full OAuth2/OIDC session stack. Requires the
`jwt` feature flag (**enabled by default**).

All types in `jwt::oidc` are re-exported directly from `jwt` for convenience (e.g.
`axum_oidc_client::jwt::OidcClaims`).

#### `JwtConfiguration<C>`

```rust
pub struct JwtConfiguration<C: DeserializeOwned> { /* opaque */ }
```

Holds the decoding key, validation settings (algorithm, audience, expiry), and an optional JWKS
fetched from a remote endpoint. Built exclusively via [`JwtConfigurationBuilder<C>`](#jwtconfigurationbuilderc).

#### `JwtConfigurationBuilder<C>`

Fluent builder for `JwtConfiguration<C>`. The default builder targets RS256 with `exp` validation
enabled.

**Methods:**

| Method | Description |
|---|---|
| `new()` | Default builder (RS256, `exp` validation enabled). |
| `with_custom_ca_cert(path)` | Trust a custom CA certificate for HTTPS requests (e.g. self-signed IdP). |
| `with_decoding_key(key)` | Provide the decoding key directly (`DecodingKey` from `jsonwebtoken`). Use for HS256 shared secrets or an explicit RSA/EC PEM. |
| `with_issuer(url).await?` | Perform OIDC discovery against `url/.well-known/openid-configuration`, then fetch the advertised JWKS. Populates the key set automatically. |
| `with_jwks_uri(url).await?` | Fetch a JWKS directly from `url` without OIDC discovery. |
| `with_audience(vec![...])` | Set one or more expected audience values (`aud` claim). |
| `with_algorithm(alg)` | Override the signature algorithm (default: `Algorithm::RS256`). |
| `with_exp_validation(bool)` | Enable or disable `exp` claim validation (default: `true`). |
| `build()` | Consume the builder and return `Result<JwtConfiguration<C>, Error>`. |

**Examples:**

```rust
use axum_oidc_client::jwt::{JwtConfigurationBuilder, OidcClaims};

// OIDC auto-discovery (most common for production)
let config = JwtConfigurationBuilder::<OidcClaims>::new()
    .with_issuer("https://accounts.google.com").await?
    .with_audience(vec!["my-client-id".to_string()])
    .build()?;

// Direct JWKS URI
let config = JwtConfigurationBuilder::<OidcClaims>::new()
    .with_jwks_uri("https://provider.example.com/.well-known/jwks.json").await?
    .with_audience(vec!["my-client-id".to_string()])
    .build()?;

// Shared secret (HS256)
use jsonwebtoken::{DecodingKey, Algorithm};

let config = JwtConfigurationBuilder::<OidcClaims>::new()
    .with_decoding_key(DecodingKey::from_secret(b"secret"))
    .with_algorithm(Algorithm::HS256)
    .build()?;
```

#### `JwtLayer<C>`

Tower middleware layer that validates incoming JWTs and makes their decoded claims available to
downstream handlers via request extensions.

**Behaviour:**

1. Extracts the `Authorization: Bearer <token>` header from the incoming request.
2. Decodes and validates the token against the `JwtConfiguration<C>` provided at construction.
3. On success, inserts the decoded claims as a request extension (type `C`).
4. On failure (missing header, invalid token, expired token, bad signature, etc.) the layer
   silently continues without inserting the extension — it does **not** short-circuit the request.

Handlers access the claims via the [`JwtClaims<C>`](#jwtclaimsc) extractor (returns 401 if absent)
or [`OptionalJwtClaims<C>`](#optionaljwtclaimsc) (returns `None` if absent).

```rust
use axum::{Router, routing::get};
use axum_oidc_client::jwt::{JwtLayer, JwtConfigurationBuilder, OidcClaims};
use std::sync::Arc;

let config = JwtConfigurationBuilder::<OidcClaims>::new()
    .with_issuer("https://accounts.google.com").await?
    .with_audience(vec!["my-client-id".to_string()])
    .build()?;

let app = Router::new()
    .route("/protected", get(handler))
    .layer(JwtLayer::new(Arc::new(config)));
```

#### `OidcClaims`

Standard OIDC/JWT claims struct. Re-exported as `axum_oidc_client::jwt::OidcClaims`; the
canonical definition lives in `jwt::oidc`.

**Fields:**

| Field | Type | Description |
|---|---|---|
| `sub` | `String` | Subject identifier |
| `iss` | `Option<String>` | Issuer |
| `aud` | `Option<Value>` | Audience (string or array) |
| `exp` | `Option<i64>` | Expiration time (Unix timestamp) |
| `iat` | `Option<i64>` | Issued-at time (Unix timestamp) |
| `nbf` | `Option<i64>` | Not-before time (Unix timestamp) |
| `jti` | `Option<String>` | JWT ID |
| `nonce` | `Option<String>` | Nonce (used in OIDC implicit/hybrid flows) |
| `email` | `Option<String>` | User's email address |
| `email_verified` | `Option<bool>` | Whether the email has been verified |
| `name` | `Option<String>` | Full display name |
| `given_name` | `Option<String>` | Given (first) name |
| `family_name` | `Option<String>` | Family (last) name |
| `picture` | `Option<String>` | Profile picture URL |
| `locale` | `Option<String>` | BCP 47 locale tag |
| `zoneinfo` | `Option<String>` | IANA time zone |
| `extra` | `HashMap<String, Value>` | Any additional provider-specific claims |

#### `Jwk` / `Jwks`

Public types representing JSON Web Keys fetched from a JWKS endpoint.

- `Jwks` is the top-level container returned by a JWKS endpoint (`{ "keys": [...] }`).
- `Jwk` represents a single key entry.
- `Jwks::decoding_key_for_kid(kid)` returns the `DecodingKey` for the entry whose `kid` field
  matches the supplied key ID. Use this when rotating keys: decode the token header with
  `decode_jwt_unverified` to read `kid`, then select the correct key before full verification.

#### Free functions

```rust
use axum_oidc_client::jwt::{decode_jwt, decode_jwt_unverified, OidcClaims};
use jsonwebtoken::{DecodingKey, Validation};
```

**`decode_jwt`**

```rust
pub fn decode_jwt(
    token: &str,
    key: &DecodingKey,
    validation: &Validation,
) -> Result<TokenData<OidcClaims>, Error>
```

Fully decode and cryptographically verify a JWT. Returns the parsed `Header` and `OidcClaims`
wrapped in `TokenData`, or an `Error` if validation fails.

**`decode_jwt_unverified`**

```rust
pub fn decode_jwt_unverified(
    token: &str,
) -> Result<(Header, OidcClaims), Error>
```

Decode the JWT header and payload **without verifying the signature**. Use this solely to read
metadata (e.g. `kid`, `alg`) before selecting the correct key for full verification. Never use
the returned claims for authorisation decisions.

**Typical key-rotation pattern:**

```rust
use axum_oidc_client::jwt::{decode_jwt_unverified, OidcClaims};

let (header, _unverified) = decode_jwt_unverified(token)?;
if let Some(kid) = &header.kid {
    let key = jwks.decoding_key_for_kid(kid)?;
    let verified = decode_jwt(token, &key, &validation)?;
    // use verified.claims safely
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

Error types used throughout the library. As of v0.2.1, `Error` implements both `std::fmt::Display` and `std::error::Error`, making it fully composable with standard Rust error-handling idioms (`?`, `Box<dyn std::error::Error>`, etc.).

```rust
pub enum Error {
    // Core errors
    MissingCodeVerifier,
    MissingPatameter(String),
    NotValidUri(String),
    Request(reqwest::Error),
    InvalidCodeResponse(serde_html_form::de::Error),
    InvalidTokenResponse(serde_json::Error),
    InvalidResponse(String),
    CacheError(String),
    TokenRefreshFailed(String),
    // HTTP status code errors
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    NotFound(String),
    TooManyRequests(String),
    InternalServerError(String),
    BadGateway(String),
    ServiceUnavailable(String),
    UnknownStatusCode(u16, String),
    // Configuration errors
    AuthCacheNotConfigured,
    OAuthConfigNotConfigured,
    HttpClientNotConfigured,
    // Session and authentication errors
    SessionNotFound,
    SessionExpired,
    CacheAccessError(String),
    SessionUpdateFailed(String),
    TokenRefreshFailedAuth(String),
}
```

`Error` implements `std::fmt::Display` (human-readable messages) and `std::error::Error` with `source()` chaining for `Request`, `InvalidCodeResponse`, and `InvalidTokenResponse`.

**Usage example:**

```rust
use axum_oidc_client::errors::Error;

match result {
    Ok(session) => { /* use session */ },
    Err(Error::SessionExpired) => {
        eprintln!("Session expired, redirect to login");
    },
    Err(Error::TokenRefreshFailedAuth(msg)) => {
        eprintln!("Refresh failed: {}", msg);
    },
    Err(e) => {
        // Display impl gives a human-readable message
        eprintln!("Auth error: {}", e);
        // source() provides the underlying cause where available
        if let Some(cause) = std::error::Error::source(&e) {
            eprintln!("Caused by: {}", cause);
        }
    }
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
    let expires = session.expires
        .map(|e| e.to_string())
        .unwrap_or_else(|| "(no expiry)".to_string());
    format!("Token expires at: {}", expires)
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

1. **Check Expiration**: Inspects `session.expires` — if `None`, refresh is skipped entirely; if `Some(t)` and `t <= now`, proceed to refresh
2. **Check Refresh Token**: Inspects `session.refresh_token` — if `None`, user is redirected to re-authenticate; if `Some(token)`, proceed
3. **Refresh Request**: POSTs to token endpoint with refresh token:
   ```
   grant_type=refresh_token
   refresh_token={session.refresh_token}
   client_id={config.client_id}
   ```
4. **Update Session**: Updates session with new tokens:
   - `access_token` - Always updated with new access token
   - `id_token` - Updated with new ID token if provider returns it
   - `refresh_token` - Updated if provider returns new refresh token (token rotation)
   - `expires` - Updated only if the provider returns new expiry info (`expires_in`)
5. **Save to Cache**: Persists updated session
6. **Return Fresh Tokens**: Handler receives valid ID token and access token

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
    auth::AuthenticationLayer,
    auth_builder::OAuthConfigurationBuilder,
    auth_cache::AuthCache,
    cache::{TwoTierAuthCache, config::TwoTierCacheConfig},
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

    // Create cache — L1-only in-memory (requires `moka-cache` feature, enabled by default).
    // Replace None with Some(redis_cache) to add Redis as L2 backend.
    let cache: Arc<dyn AuthCache + Send + Sync> = Arc::new(
        TwoTierAuthCache::new(None, TwoTierCacheConfig::default())?
    );

    // Create logout handler
    let logout_handler = Arc::new(DefaultLogoutHandler);

    // Build app
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
    "Home Page"
}

async fn protected(session: axum_oidc_client::auth_session::AuthSession) -> String {
    let expires = session.expires
        .map(|e| e.to_string())
        .unwrap_or_else(|| "(no expiry)".to_string());
    format!("Protected! Expires: {}", expires)
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
    let expires = session.expires
        .map(|e| e.to_string())
        .unwrap_or_else(|| "(no expiry)".to_string());
    let scope = session.scope.as_deref().unwrap_or("(none)");
    format!(
        "Session info:\n\
         Token Type: {}\n\
         Expires: {}\n\
         Scopes: {}",
        session.token_type,
        expires,
        scope
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
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    let cache: Arc<dyn axum_oidc_client::auth_cache::AuthCache + Send + Sync> = Arc::new(
        axum_oidc_client::cache::TwoTierAuthCache::new(
            None,
            axum_oidc_client::cache::config::TwoTierCacheConfig::default(),
        )?
    );

    // ... rest of app setup
    let _ = cache;
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


## Automatic Routes

The `AuthenticationLayer` (also accessible via the `AuthLayer` alias) adds these routes automatically:

| Route                         | Method | Description                                       |
| ----------------------------- | ------ | ------------------------------------------------- |
| `/auth`                       | GET    | Initiates OAuth flow, redirects to provider       |
| `/auth/callback`              | GET    | Handles OAuth callback, exchanges code for tokens |
| `/auth/logout`                | GET    | Logs out user, clears session                     |
| `/auth/logout?redirect=/path` | GET    | Logs out and redirects to custom path             |

> **Note:** The base path `/auth` is the default. Use `.with_base_path("/api/auth")` in the
> `OAuthConfigurationBuilder` to mount routes at a custom path.

## Troubleshooting

### Common Issues

**Issue: "Missing parameter" error**

> **Solution:** Ensure all required configuration is set before calling `.build()`.

**Issue: Session not persisting**

> **Solution:** Check Redis/cache connection and ensure cookies are enabled in the browser.

**Issue: Redirect loop**

> **Solution:** Verify `redirect_uri` matches exactly what is configured in your OAuth provider settings.

**Issue: Token expired too quickly**

> **Solution:** Adjust `session_max_age` and `token_max_age` settings to appropriate values.

**Issue: ID token and access token refresh failing**

> **Solution:**
> 1. Ensure your OAuth provider supports refresh tokens for obtaining new ID tokens and access tokens
> 2. Check that the `offline_access` (or equivalent) scope is requested
> 3. Verify `refresh_token` is being stored in the session (it is now `Option<String>` — check it is `Some`)
> 4. Check provider logs for refresh token errors

**Issue: Frequent re-authentication required**

> **Solution:**
> 1. Verify the refresh token is being returned by the provider (`session.refresh_token` is `Some`)
> 2. Check `token_max_age` isn't set too low (tokens will refresh frequently)
> 3. Ensure the cache is properly storing updated sessions with refreshed tokens
> 4. Verify the provider's refresh token expiration policy

**Issue: `session.expires` or `session.scope` is `None`**

> **Solution:** These fields are now `Option` types as of v0.2.0. Some providers do not return
> `expires_in` or `scope` in the token response. Always handle the `None` case:
> ```rust
> let expires = session.expires.map(|e| e.to_string()).unwrap_or_else(|| "(no expiry)".to_string());
> let scope = session.scope.as_deref().unwrap_or("(none)");
> ```

**Issue: Token exchange fails with `invalid_request` or `redirect_uri mismatch` from the provider**

> **Solution:**
> Some providers (e.g. Okta, certain Azure AD configurations) reject the token-exchange
> request when `redirect_uri` is included redundantly — typically when only one redirect URI
> is registered on the application.  Set `with_token_request_redirect_uri(false)` on the
> builder to omit the parameter:
>
> ```rust
> let config = OAuthConfigurationBuilder::default()
>     .with_issuer("https://your-provider.example.com").await?
>     .with_client_id("your-client-id")
>     .with_client_secret("your-client-secret")
>     .with_redirect_uri("http://localhost:8080/auth/callback")
>     .with_private_cookie_key(&env::var("COOKIE_KEY")?)
>     .with_session_max_age(30)
>     .with_token_request_redirect_uri(false)
>     .build()?;
> ```
>
> Per [RFC 6749 §4.1.3](https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3), `redirect_uri`
> is required in the token request only when it was included in the authorization request, and
> must be identical if present.  The default (`true`) includes it for maximum compatibility.

**Issue: `JwtClaims` extractor returns 401 even though a token is sent**

> **Solution:**
> 1. Confirm `JwtLayer` is applied to the router or route in question — the layer must sit between
>    the client and the handler for the extension to be populated.
> 2. Check that the token is not expired, the audience matches `with_audience(...)`, and the
>    signing algorithm matches `with_algorithm(...)`.
> 3. Use `decode_jwt_unverified` to inspect the token header/claims without performing signature
>    verification, which helps identify mismatches before involving the full validation stack.

## Additional Resources

- [RFC 6749 - OAuth 2.0](https://tools.ietf.org/html/rfc6749)
- [RFC 7636 - PKCE](https://tools.ietf.org/html/rfc7636)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
- [Axum Documentation](https://docs.rs/axum)

---

**Last Updated:** 2026-03-25
**Version:** 0.4.0
