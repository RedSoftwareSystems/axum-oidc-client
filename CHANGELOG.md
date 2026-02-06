# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

## [0.1.0] - 2024

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
