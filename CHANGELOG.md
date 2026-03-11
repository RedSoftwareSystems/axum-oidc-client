# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **PostgreSQL cache table is now `UNLOGGED`** (`sql_cache` module): `SqlAuthCache::init_schema()` now creates the cache table as `CREATE UNLOGGED TABLE IF NOT EXISTS …` on PostgreSQL. `UNLOGGED` tables bypass WAL (Write-Ahead Log) writes, giving significantly higher write throughput and lower I/O, at the cost of the table being truncated automatically after a crash or unclean shutdown. This is the correct trade-off for a cache: the data held (PKCE code verifiers and auth sessions) is ephemeral and does not need to survive a crash — on restart the application simply re-authenticates any affected sessions. MySQL/MariaDB and SQLite backends are unaffected and continue to use regular tables.

### Documentation

- **PostgreSQL `VACUUM` guidance added** (`sql_cache` module): documented the MVCC dead-tuple problem that arises on high-churn cache tables and the recommended mitigations:
  - Tune `autovacuum` aggressively per-table via `ALTER TABLE oidc_cache SET (autovacuum_vacuum_scale_factor = 0.01, …)` so it fires more frequently than the global default (20 % row-change threshold).
  - Use `VACUUM oidc_cache` or `VACUUM ANALYZE oidc_cache` for routine scheduled maintenance; reserve `VACUUM FULL` for maintenance windows only (it takes an `ACCESS EXCLUSIVE` lock).
  - Provided a system-cron example (`0 3 * * *  psql … -c "VACUUM ANALYZE oidc_cache;"`) for scheduling outside the database.
  - Provided a `pg_cron` example (`SELECT cron.schedule(…)`) for scheduling entirely inside PostgreSQL without an external cron daemon.
  - Added a note clarifying that `UNLOGGED` + regular `VACUUM` is the optimal combination: `UNLOGGED` skips WAL writes for all DML, and `VACUUM` itself is not WAL-logged either, giving the best trade-off between write performance, storage efficiency, and query-planner accuracy.
  - Updated: `src/sql_cache/cleanup.rs` (new `## PostgreSQL: VACUUM after bulk deletes` section), `src/sql_cache/mod.rs` (new `# PostgreSQL: VACUUM after bulk deletes` section), `DOCUMENTATION.md`, and `README.md`.

## [0.3.0] - 2026-03-04

### Added

- **SQL cache backend** (`sql_cache` module) — implements the `AuthCache` trait for SQL databases via [`sqlx`](https://crates.io/crates/sqlx), providing an alternative L2 backend to Redis:
  - `SqlAuthCache` — the main cache struct; constructed with `SqlAuthCache::new(config).await?` and initialised with `cache.init_schema().await?`
  - `SqlCacheConfig` — configuration struct with fields: `connection_string`, `max_connections`, `min_connections`, `cleanup_interval_sec`, `table_name`, `acquire_timeout_sec`, `code_verifier_ttl_sec`
  - Three database backends, each selected via a Cargo feature flag:
    - `sql-cache-postgres` — PostgreSQL via `sqlx`; uses `INSERT … ON CONFLICT … DO UPDATE` for upserts
    - `sql-cache-mysql` — MySQL / MariaDB via `sqlx`; uses `INSERT … ON DUPLICATE KEY UPDATE` for upserts
    - `sql-cache-sqlite` — SQLite via `sqlx`; uses `INSERT OR REPLACE` for upserts; ideal for development and single-instance deployments
    - `sql-cache-all` — convenience feature enabling all three backends at once (useful for testing)
  - Single unified cache table (`oidc_cache` by default, configurable via `SqlCacheConfig::table_name`):
    ```sql
    CREATE TABLE IF NOT EXISTS oidc_cache (
        cache_key   VARCHAR(255) PRIMARY KEY,
        cache_value TEXT         NOT NULL,
        expires_at  BIGINT       NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_oidc_cache_expires ON oidc_cache (expires_at);
    ```
  - Key prefixes: `cv:{state}` for PKCE code verifiers, `session:{id}` for auth sessions (JSON-serialised)
  - **Lazy expiry**: all reads include `AND expires_at > <now>` so expired rows are never returned even before cleanup runs
  - **Background cleanup task**: a Tokio task spawned automatically in `SqlAuthCache::new` purges expired rows in bounded batches of 1 000 rows; interval is configurable; the task can be stopped gracefully via `SqlAuthCache::shutdown()`
  - Fully composable with `TwoTierAuthCache`: pass a `SqlAuthCache` as the L2 backend to get Moka L1 + SQL L2 two-tier caching
  - New submodules (all `pub`): `sql_cache::schema` (DDL strings), `sql_cache::queries` (ANSI SQL + per-db UPSERT helpers), `sql_cache::cleanup` (background task)
  - New dependency: `sqlx = { version = "0.8", features = ["runtime-tokio", "chrono"] }` (optional, pulled in only when a `sql-cache-*` feature is enabled)
  - New dependency: `tokio-util = { version = "0.7", features = ["rt"] }` (for `CancellationToken` used by the cleanup task)
  - New dependency: `tracing = { version = "0.1" }` (for structured logging in the cleanup task)
  - 24 integration tests in `tests/sql_cache_sqlite.rs` covering: schema idempotency, code-verifier and session CRUD, upsert, key-prefix isolation, custom table name, concurrent reads/writes, TTL extension, error paths, two-tier integration (Moka L1 + SQLite L2), and graceful shutdown

## [0.2.1] - 2026-03-04

### Added

- **`Error` trait implementations**: `Error` now implements `std::fmt::Display` and `std::error::Error`
  - `Display` provides human-readable messages for all error variants
  - `std::error::Error::source()` exposes the underlying cause for `Request`, `InvalidCodeResponse`, and `InvalidTokenResponse` variants
  - Makes `Error` composable with standard Rust error-handling idioms (`?`, `Box<dyn std::error::Error>`, `thiserror`, etc.)

### Changed

- **Documentation examples** (`src/extractors/mod.rs`): fixed access-token string truncation to use `.chars().take(20)` instead of a raw byte-index slice, avoiding potential panics on multi-byte characters
- **Documentation examples** (`src/auth.rs`, `src/auth_builder.rs`, `src/lib.rs`): added missing `.with_post_logout_redirect_uri("/")` and `.with_session_max_age(…)` calls to builder snippets so they compile cleanly as doc-tests

## [0.2.0] - 2026-03-04

### Added

- **Feature**: Two-tier authentication cache (`cache` module, requires `moka-cache` feature)
  - Introduced `TwoTierAuthCache`: combines a fast in-process [Moka](https://crates.io/crates/moka) L1 cache with any `AuthCache` implementation as the L2 backend (e.g. Redis)
  - Implements a cache-aside pattern: reads check L1 first; on miss, L2 is queried and the result is promoted to L1; writes and invalidations are applied to both tiers
  - `TwoTierCacheConfig` struct to tune L1 behaviour:
    - `l1_max_capacity`: maximum number of entries (default `10_000`)
    - `l1_ttl_sec`: time-to-live per entry in seconds (default `3600`)
    - `l1_time_to_idle_sec`: optional idle-eviction timeout (default `None`)
    - `enable_l1`: bypass Moka entirely when set to `false` (useful for testing)
  - L2 backend is optional: the cache can operate in L1-only mode (no L2) or L2-only mode (L1 disabled)
  - Comprehensive unit-test suite covering all combinations of L1-only, L2-only and two-tier modes
  - Public API exposed via `axum_oidc_client::cache::{TwoTierAuthCache, config::TwoTierCacheConfig}`

### Changed

- **Cargo features**: renamed the `moka` feature to `moka-cache` to better reflect its purpose and avoid a name collision with the `moka` dependency; `moka-cache` is now a **default feature**
- **Dependency**: enabled the `future` feature of the `moka` crate to support async cache operations
- **Documentation** (`src/lib.rs`): documented the new `cache` module and `moka-cache` feature in the crate-level rustdoc

## [0.1.2] - 2026-02-26

### Changed

- **Breaking**: Made `expires_in`, `refresh_token`, and `scope` optional in token response and session structs to comply with OAuth2/OIDC specifications
  - `AccessTokenResponse`: `expires_in` is now `Option<i64>`, `refresh_token` is now `Option<String>`, `scope` is now `Option<String>`
  - `RefreshTokenResponse`: `expires_in` is now `Option<i64>`
  - `AuthSession`: `expires` is now `Option<DateTime<Local>>`, `refresh_token` is now `Option<String>`, `scope` is now `Option<String>`
  - `calculate_token_expiration` now accepts `Option<i64>` for `expires_in` and returns `Option<DateTime<Local>>`; returns `None` when both `expires_in` and `token_max_age` are absent
  - Token refresh logic is automatically disabled when `AuthSession.expires` is `None` (i.e. neither `expires_in` nor `token_max_age` were available at session creation)
  - Token refresh logic is automatically skipped when `AuthSession.refresh_token` is `None`
  - After a successful token refresh, `session.expires` is only updated if the refresh response provides new expiry information
  - Updated sample protected route to gracefully display `"(no expiry)"` and `"(none)"` when optional fields are absent

## [0.1.1] - 2026

### Added

- **Feature**: Configurable authentication routes base path
  - Added `base_path` field to `OAuthConfiguration` with default value `/auth`
  - Added `with_base_path()` method to `OAuthConfigurationBuilder` to customize auth routes location
  - Default base path remains `/auth` for backwards compatibility
  - Allows mounting auth routes at custom paths like `/api/auth`, `/oauth`, etc.
  - Base path is configured via the builder, not the layer
  - Example: `OAuthConfigurationBuilder::default().with_base_path("/api/auth").build()?`
  - Automatically removes trailing slashes from base path

### Fixed

- **Documentation**: Corrected OAuth provider configuration examples
  - Removed incorrect `end_session_endpoint` for Google (Google does not support OIDC logout)
  - Removed incorrect `end_session_endpoint` for GitHub (GitHub does not support OIDC logout)
  - Clarified that `OAUTH_END_SESSION_ENDPOINT` should only be set for OIDC-compliant providers

### Added

- **Documentation**: Added comprehensive provider configuration examples
  - Added Keycloak configuration example with full OIDC logout support
  - Added detailed provider compatibility table showing OIDC and logout support
  - Created new `PROVIDER_EXAMPLES.md` with complete examples for:
    - Google (with `DefaultLogoutHandler`)
    - GitHub (with `DefaultLogoutHandler`)
    - Keycloak (with `OidcLogoutHandler`)
    - Microsoft Azure AD (with `OidcLogoutHandler`)
    - Okta (with `OidcLogoutHandler`)
    - Auth0 (with `OidcLogoutHandler`)
  - Added setup instructions for each provider
  - Added environment variable examples for each provider

### Changed

- **Documentation**: Improved logout handler documentation
  - Clarified when to use `DefaultLogoutHandler` vs `OidcLogoutHandler`
  - Added detailed explanation of OIDC RP-Initiated Logout
  - Enhanced custom `LogoutHandler` trait implementation examples
  - Updated all documentation files (README.md, DOCUMENTATION.md, QUICK_REFERENCE.md)
  - Added behavior descriptions for each logout handler
  - Improved code examples with complete, runnable configurations

### Documentation

- Enhanced `README.md` with:
  - Clear provider compatibility summary table
  - Proper logout handler selection guidance
  - Complete configuration examples for each provider
  - Custom `LogoutHandler` implementation example

- Enhanced `DOCUMENTATION.md` with:
  - Detailed logout handler documentation
  - Provider-specific examples with proper handlers
  - Custom logout handler implementation guide

- Enhanced `QUICK_REFERENCE.md` with:
  - Quick provider comparison table
  - Complete provider configuration snippets
  - Logout handler selection guidance

- Updated example configuration files:
  - `examples/sample-server/src/config.rs`: Added clarifying comments for `end_session_endpoint`
  - `examples/sample-server/src/env.rs`: Updated environment variable documentation

## [0.1.0] - 2026

### Added

- Initial release
- OAuth2/OIDC authentication support
- PKCE (Proof Key for Code Exchange) implementation
- Automatic token refresh for ID tokens and access tokens
- Pluggable cache backends with Redis support
- Secure session management with encrypted cookies
- Type-safe extractors (AuthSession, AccessToken, IdToken, OptionalAccessToken, OptionalIdToken)
- Logout handlers (DefaultLogoutHandler, OidcLogoutHandler)
- Customizable logout handler trait
- Comprehensive documentation and examples
