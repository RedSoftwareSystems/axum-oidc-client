# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
