# OAuth Provider Configuration Examples

This document provides complete configuration examples for popular OAuth2/OIDC providers with `axum-oidc-client`.

## Table of Contents

- [Google](#google)
- [GitHub](#github)
- [Keycloak](#keycloak)
- [Microsoft Azure AD](#microsoft-azure-ad)
- [Okta](#okta)
- [Auth0](#auth0)
- [Understanding OIDC Logout](#understanding-oidc-logout)
- [Choosing the Right Logout Handler](#choosing-the-right-logout-handler)

## Google

**OIDC Support:** Partial (OAuth2 with OpenID Connect for authentication)  
**Logout Support:** ❌ Does not support OIDC RP-Initiated Logout  
**Recommended Handler:** `DefaultLogoutHandler`

### Configuration

```rust
use axum_oidc_client::{
    auth::AuthLayer,
    auth_builder::OAuthConfigurationBuilder,
    logout::handle_default_logout::DefaultLogoutHandler,
};
use std::sync::Arc;

let config = OAuthConfigurationBuilder::default()
    .with_authorization_endpoint("https://accounts.google.com/o/oauth2/auth")
    .with_token_endpoint("https://oauth2.googleapis.com/token")
    .with_client_id("your-client-id.apps.googleusercontent.com")
    .with_client_secret("your-client-secret")
    .with_redirect_uri("http://localhost:8080/auth/callback")
    .with_private_cookie_key("your-secret-key-at-least-32-bytes")
    .with_scopes(vec!["openid", "email", "profile"])
    .with_session_max_age(30)
    // Note: Do NOT set end_session_endpoint for Google
    .build()?;

// Use DefaultLogoutHandler since Google doesn't support OIDC logout
let logout_handler = Arc::new(DefaultLogoutHandler);

let auth_layer = AuthLayer::new(Arc::new(config), cache, logout_handler);
```

### Environment Variables

```bash
# .env
OAUTH_AUTHORIZATION_ENDPOINT=https://accounts.google.com/o/oauth2/auth
OAUTH_TOKEN_ENDPOINT=https://oauth2.googleapis.com/token
OAUTH_CLIENT_ID=your-client-id.apps.googleusercontent.com
OAUTH_CLIENT_SECRET=your-client-secret
OAUTH_REDIRECT_URI=http://localhost:8080/auth/callback
OAUTH_SCOPES=openid,email,profile
PRIVATE_COOKIE_KEY=your-secret-key-at-least-32-bytes-long
SESSION_MAX_AGE=30
# Do NOT set OAUTH_END_SESSION_ENDPOINT for Google
```

### Setting Up Google OAuth

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable Google+ API
4. Go to "Credentials" → "Create Credentials" → "OAuth 2.0 Client ID"
5. Set application type to "Web application"
6. Add authorized redirect URI: `http://localhost:8080/auth/callback`
7. Copy Client ID and Client Secret

---

## GitHub

**OIDC Support:** ❌ OAuth2 only  
**Logout Support:** ❌ Does not support OIDC logout  
**Recommended Handler:** `DefaultLogoutHandler`

### Configuration

```rust
use axum_oidc_client::{
    auth::AuthLayer,
    auth_builder::OAuthConfigurationBuilder,
    logout::handle_default_logout::DefaultLogoutHandler,
};
use std::sync::Arc;

let config = OAuthConfigurationBuilder::default()
    .with_authorization_endpoint("https://github.com/login/oauth/authorize")
    .with_token_endpoint("https://github.com/login/oauth/access_token")
    .with_client_id("your-github-client-id")
    .with_client_secret("your-github-client-secret")
    .with_redirect_uri("http://localhost:8080/auth/callback")
    .with_private_cookie_key("your-secret-key-at-least-32-bytes")
    .with_scopes(vec!["read:user", "user:email"])
    .with_session_max_age(30)
    // Note: GitHub doesn't support OIDC logout
    .build()?;

// Use DefaultLogoutHandler since GitHub doesn't support OIDC logout
let logout_handler = Arc::new(DefaultLogoutHandler);

let auth_layer = AuthLayer::new(Arc::new(config), cache, logout_handler);
```

### Environment Variables

```bash
# .env
OAUTH_AUTHORIZATION_ENDPOINT=https://github.com/login/oauth/authorize
OAUTH_TOKEN_ENDPOINT=https://github.com/login/oauth/access_token
OAUTH_CLIENT_ID=your-github-client-id
OAUTH_CLIENT_SECRET=your-github-client-secret
OAUTH_REDIRECT_URI=http://localhost:8080/auth/callback
OAUTH_SCOPES=read:user,user:email
PRIVATE_COOKIE_KEY=your-secret-key-at-least-32-bytes-long
SESSION_MAX_AGE=30
# Do NOT set OAUTH_END_SESSION_ENDPOINT for GitHub
```

### Setting Up GitHub OAuth

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click "New OAuth App"
3. Fill in application details
4. Set Authorization callback URL: `http://localhost:8080/auth/callback`
5. Click "Register application"
6. Copy Client ID and generate Client Secret

---

## Keycloak

**OIDC Support:** ✅ Full OpenID Connect support  
**Logout Support:** ✅ Supports OIDC RP-Initiated Logout  
**Recommended Handler:** `OidcLogoutHandler`

### Configuration

```rust
use axum_oidc_client::{
    auth::AuthLayer,
    auth_builder::OAuthConfigurationBuilder,
    logout::handle_oidc_logout::OidcLogoutHandler,
};
use std::sync::Arc;

let realm = "your-realm";
let keycloak_url = "https://keycloak.example.com";

let config = OAuthConfigurationBuilder::default()
    .with_authorization_endpoint(&format!(
        "{}/realms/{}/protocol/openid-connect/auth",
        keycloak_url, realm
    ))
    .with_token_endpoint(&format!(
        "{}/realms/{}/protocol/openid-connect/token",
        keycloak_url, realm
    ))
    .with_end_session_endpoint(&format!(
        "{}/realms/{}/protocol/openid-connect/logout",
        keycloak_url, realm
    ))
    .with_client_id("your-client-id")
    .with_client_secret("your-client-secret")
    .with_redirect_uri("http://localhost:8080/auth/callback")
    .with_post_logout_redirect_uri("http://localhost:8080")
    .with_private_cookie_key("your-secret-key-at-least-32-bytes")
    .with_scopes(vec!["openid", "email", "profile"])
    .with_session_max_age(30)
    .build()?;

// Use OidcLogoutHandler for proper logout with Keycloak
let logout_handler = Arc::new(OidcLogoutHandler::new(&format!(
    "{}/realms/{}/protocol/openid-connect/logout",
    keycloak_url, realm
)));

let auth_layer = AuthLayer::new(Arc::new(config), cache, logout_handler);
```

### Environment Variables

```bash
# .env
KEYCLOAK_URL=https://keycloak.example.com
KEYCLOAK_REALM=your-realm

OAUTH_AUTHORIZATION_ENDPOINT=${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/auth
OAUTH_TOKEN_ENDPOINT=${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token
OAUTH_END_SESSION_ENDPOINT=${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/logout
OAUTH_CLIENT_ID=your-client-id
OAUTH_CLIENT_SECRET=your-client-secret
OAUTH_REDIRECT_URI=http://localhost:8080/auth/callback
POST_LOGOUT_REDIRECT_URI=http://localhost:8080
OAUTH_SCOPES=openid,email,profile
PRIVATE_COOKIE_KEY=your-secret-key-at-least-32-bytes-long
SESSION_MAX_AGE=30
```

### Setting Up Keycloak

1. Access Keycloak Admin Console
2. Select or create a realm
3. Go to "Clients" → "Create"
4. Set Client ID
5. Set Client Protocol to "openid-connect"
6. Set Access Type to "confidential"
7. Add Valid Redirect URIs: `http://localhost:8080/auth/callback`
8. Add Valid Post Logout Redirect URIs: `http://localhost:8080`
9. Save and copy the Client Secret from "Credentials" tab

---

## Microsoft Azure AD

**OIDC Support:** ✅ Full OpenID Connect support  
**Logout Support:** ✅ Supports OIDC logout  
**Recommended Handler:** `OidcLogoutHandler`

### Configuration

```rust
use axum_oidc_client::{
    auth::AuthLayer,
    auth_builder::OAuthConfigurationBuilder,
    logout::handle_oidc_logout::OidcLogoutHandler,
};
use std::sync::Arc;

let tenant = "common"; // Use "common", "organizations", "consumers", or your tenant ID

let config = OAuthConfigurationBuilder::default()
    .with_authorization_endpoint(&format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize",
        tenant
    ))
    .with_token_endpoint(&format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        tenant
    ))
    .with_end_session_endpoint(&format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/logout",
        tenant
    ))
    .with_client_id("your-application-client-id")
    .with_client_secret("your-client-secret")
    .with_redirect_uri("http://localhost:8080/auth/callback")
    .with_post_logout_redirect_uri("http://localhost:8080")
    .with_private_cookie_key("your-secret-key-at-least-32-bytes")
    .with_scopes(vec!["openid", "email", "profile"])
    .with_session_max_age(30)
    .build()?;

// Use OidcLogoutHandler for proper logout with Azure AD
let logout_handler = Arc::new(OidcLogoutHandler::new(&format!(
    "https://login.microsoftonline.com/{}/oauth2/v2.0/logout",
    tenant
)));

let auth_layer = AuthLayer::new(Arc::new(config), cache, logout_handler);
```

### Environment Variables

```bash
# .env
AZURE_TENANT=common  # or your tenant ID

OAUTH_AUTHORIZATION_ENDPOINT=https://login.microsoftonline.com/${AZURE_TENANT}/oauth2/v2.0/authorize
OAUTH_TOKEN_ENDPOINT=https://login.microsoftonline.com/${AZURE_TENANT}/oauth2/v2.0/token
OAUTH_END_SESSION_ENDPOINT=https://login.microsoftonline.com/${AZURE_TENANT}/oauth2/v2.0/logout
OAUTH_CLIENT_ID=your-application-client-id
OAUTH_CLIENT_SECRET=your-client-secret
OAUTH_REDIRECT_URI=http://localhost:8080/auth/callback
POST_LOGOUT_REDIRECT_URI=http://localhost:8080
OAUTH_SCOPES=openid,email,profile
PRIVATE_COOKIE_KEY=your-secret-key-at-least-32-bytes-long
SESSION_MAX_AGE=30
```

### Setting Up Azure AD

1. Go to [Azure Portal](https://portal.azure.com/)
2. Navigate to "Azure Active Directory" → "App registrations"
3. Click "New registration"
4. Set name and supported account types
5. Add Redirect URI: `http://localhost:8080/auth/callback`
6. Click "Register"
7. Go to "Certificates & secrets" → "New client secret"
8. Copy the Client Secret value
9. Go to "Authentication" → "Logout URL" → Add `http://localhost:8080`

---

## Okta

**OIDC Support:** ✅ Full OpenID Connect support  
**Logout Support:** ✅ Supports OIDC RP-Initiated Logout  
**Recommended Handler:** `OidcLogoutHandler`

### Configuration

```rust
use axum_oidc_client::{
    auth::AuthLayer,
    auth_builder::OAuthConfigurationBuilder,
    logout::handle_oidc_logout::OidcLogoutHandler,
};
use std::sync::Arc;

let okta_domain = "your-domain.okta.com"; // or your custom domain

let config = OAuthConfigurationBuilder::default()
    .with_authorization_endpoint(&format!(
        "https://{}/oauth2/default/v1/authorize",
        okta_domain
    ))
    .with_token_endpoint(&format!(
        "https://{}/oauth2/default/v1/token",
        okta_domain
    ))
    .with_end_session_endpoint(&format!(
        "https://{}/oauth2/default/v1/logout",
        okta_domain
    ))
    .with_client_id("your-okta-client-id")
    .with_client_secret("your-okta-client-secret")
    .with_redirect_uri("http://localhost:8080/auth/callback")
    .with_post_logout_redirect_uri("http://localhost:8080")
    .with_private_cookie_key("your-secret-key-at-least-32-bytes")
    .with_scopes(vec!["openid", "email", "profile"])
    .with_session_max_age(30)
    .build()?;

// Use OidcLogoutHandler for proper logout with Okta
let logout_handler = Arc::new(OidcLogoutHandler::new(&format!(
    "https://{}/oauth2/default/v1/logout",
    okta_domain
)));

let auth_layer = AuthLayer::new(Arc::new(config), cache, logout_handler);
```

### Environment Variables

```bash
# .env
OKTA_DOMAIN=your-domain.okta.com

OAUTH_AUTHORIZATION_ENDPOINT=https://${OKTA_DOMAIN}/oauth2/default/v1/authorize
OAUTH_TOKEN_ENDPOINT=https://${OKTA_DOMAIN}/oauth2/default/v1/token
OAUTH_END_SESSION_ENDPOINT=https://${OKTA_DOMAIN}/oauth2/default/v1/logout
OAUTH_CLIENT_ID=your-okta-client-id
OAUTH_CLIENT_SECRET=your-okta-client-secret
OAUTH_REDIRECT_URI=http://localhost:8080/auth/callback
POST_LOGOUT_REDIRECT_URI=http://localhost:8080
OAUTH_SCOPES=openid,email,profile
PRIVATE_COOKIE_KEY=your-secret-key-at-least-32-bytes-long
SESSION_MAX_AGE=30
```

### Setting Up Okta

1. Go to [Okta Developer Console](https://developer.okta.com/)
2. Navigate to "Applications" → "Create App Integration"
3. Choose "OIDC - OpenID Connect"
4. Choose "Web Application"
5. Set Sign-in redirect URIs: `http://localhost:8080/auth/callback`
6. Set Sign-out redirect URIs: `http://localhost:8080`
7. Save and copy Client ID and Client Secret

---

## Auth0

**OIDC Support:** ✅ Full OpenID Connect support  
**Logout Support:** ✅ Supports OIDC logout  
**Recommended Handler:** `OidcLogoutHandler`

### Configuration

```rust
use axum_oidc_client::{
    auth::AuthLayer,
    auth_builder::OAuthConfigurationBuilder,
    logout::handle_oidc_logout::OidcLogoutHandler,
};
use std::sync::Arc;

let auth0_domain = "your-tenant.auth0.com"; // or your custom domain

let config = OAuthConfigurationBuilder::default()
    .with_authorization_endpoint(&format!(
        "https://{}/authorize",
        auth0_domain
    ))
    .with_token_endpoint(&format!(
        "https://{}/oauth/token",
        auth0_domain
    ))
    .with_end_session_endpoint(&format!(
        "https://{}/v2/logout",
        auth0_domain
    ))
    .with_client_id("your-auth0-client-id")
    .with_client_secret("your-auth0-client-secret")
    .with_redirect_uri("http://localhost:8080/auth/callback")
    .with_post_logout_redirect_uri("http://localhost:8080")
    .with_private_cookie_key("your-secret-key-at-least-32-bytes")
    .with_scopes(vec!["openid", "email", "profile"])
    .with_session_max_age(30)
    .build()?;

// Use OidcLogoutHandler for proper logout with Auth0
let logout_handler = Arc::new(OidcLogoutHandler::new(&format!(
    "https://{}/v2/logout",
    auth0_domain
)));

let auth_layer = AuthLayer::new(Arc::new(config), cache, logout_handler);
```

### Environment Variables

```bash
# .env
AUTH0_DOMAIN=your-tenant.auth0.com

OAUTH_AUTHORIZATION_ENDPOINT=https://${AUTH0_DOMAIN}/authorize
OAUTH_TOKEN_ENDPOINT=https://${AUTH0_DOMAIN}/oauth/token
OAUTH_END_SESSION_ENDPOINT=https://${AUTH0_DOMAIN}/v2/logout
OAUTH_CLIENT_ID=your-auth0-client-id
OAUTH_CLIENT_SECRET=your-auth0-client-secret
OAUTH_REDIRECT_URI=http://localhost:8080/auth/callback
POST_LOGOUT_REDIRECT_URI=http://localhost:8080
OAUTH_SCOPES=openid,email,profile
PRIVATE_COOKIE_KEY=your-secret-key-at-least-32-bytes-long
SESSION_MAX_AGE=30
```

### Setting Up Auth0

1. Go to [Auth0 Dashboard](https://manage.auth0.com/)
2. Navigate to "Applications" → "Create Application"
3. Choose "Regular Web Applications"
4. Go to "Settings" tab
5. Add Allowed Callback URLs: `http://localhost:8080/auth/callback`
6. Add Allowed Logout URLs: `http://localhost:8080`
7. Copy Domain, Client ID, and Client Secret

---

## Understanding OIDC Logout

### What is OIDC RP-Initiated Logout?

OIDC RP-Initiated Logout (also called "logout endpoint") is an OpenID Connect specification that allows your application (the Relying Party) to:

1. End the user's session at the identity provider
2. Ensure single logout across multiple applications
3. Redirect users back to your application after logout

### How It Works

1. User clicks logout in your app
2. Your app clears local session
3. Your app redirects to provider's `end_session_endpoint` with:
   - `id_token_hint` - The user's ID token
   - `post_logout_redirect_uri` - Where to redirect after logout
4. Provider ends the user's session
5. Provider redirects back to your `post_logout_redirect_uri`

### Providers Without OIDC Logout

Some providers (Google, GitHub) don't implement OIDC logout because:

- **Google**: Uses OAuth2 for authentication but doesn't support logout endpoint
- **GitHub**: Only implements OAuth2, not full OpenID Connect

For these providers, use `DefaultLogoutHandler` which:
- Clears the local session
- Invalidates the cache
- Redirects to your specified URI
- Does NOT notify the provider (provider session remains active)

---

## Choosing the Right Logout Handler

### Use `DefaultLogoutHandler` when:

- ✅ Provider doesn't support OIDC logout (Google, GitHub)
- ✅ You only need to clear local session
- ✅ You're implementing custom logout logic
- ✅ Provider is OAuth2 only (not OIDC)

```rust
use axum_oidc_client::logout::handle_default_logout::DefaultLogoutHandler;

let logout_handler = Arc::new(DefaultLogoutHandler);
```

**Behavior:**
1. Removes session cookie
2. Deletes session from cache
3. Redirects to `post_logout_redirect_uri`
4. Provider session remains active (user may still be logged in at provider)

### Use `OidcLogoutHandler` when:

- ✅ Provider supports OIDC RP-Initiated Logout (Keycloak, Azure AD, Okta, Auth0)
- ✅ You need to end the session at the provider
- ✅ You want single logout across multiple applications
- ✅ You need complete logout from the identity provider

```rust
use axum_oidc_client::logout::handle_oidc_logout::OidcLogoutHandler;

let logout_handler = Arc::new(OidcLogoutHandler::new(
    "https://provider.com/oidc/logout"
));
```

**Behavior:**
1. Removes session cookie
2. Deletes session from cache
3. Redirects to provider's `end_session_endpoint` with `id_token_hint`
4. Provider ends user session
5. Provider redirects back to `post_logout_redirect_uri`

### Implement Custom `LogoutHandler` when:

- ✅ You need custom audit logging
- ✅ You want special redirect logic
- ✅ You need to call additional APIs during logout
- ✅ You want to notify multiple systems

See [README.md](README.md#custom-handler) for implementation details.

---

## Provider Comparison Table

| Provider   | OAuth2 | OIDC | ID Token | Logout Endpoint | Recommended Handler    | Notes                              |
| ---------- | ------ | ---- | -------- | --------------- | ---------------------- | ---------------------------------- |
| Google     | ✅     | ⚠️   | ✅       | ❌              | `DefaultLogoutHandler` | Partial OIDC, no logout endpoint   |
| GitHub     | ✅     | ❌   | ❌       | ❌              | `DefaultLogoutHandler` | OAuth2 only                        |
| Keycloak   | ✅     | ✅   | ✅       | ✅              | `OidcLogoutHandler`    | Full OIDC support                  |
| Azure AD   | ✅     | ✅   | ✅       | ✅              | `OidcLogoutHandler`    | Full OIDC support                  |
| Okta       | ✅     | ✅   | ✅       | ✅              | `OidcLogoutHandler`    | Full OIDC support                  |
| Auth0      | ✅     | ✅   | ✅       | ✅              | `OidcLogoutHandler`    | Full OIDC support                  |
| AWS Cognito| ✅     | ✅   | ✅       | ✅              | `OidcLogoutHandler`    | Full OIDC support                  |
| GitLab     | ✅     | ✅   | ✅       | ✅              | `OidcLogoutHandler`    | Full OIDC support (self-hosted)    |

---

## Additional Resources

- [OpenID Connect Specification](https://openid.net/specs/openid-connect-core-1_0.html)
- [OIDC RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [PKCE RFC 7636](https://tools.ietf.org/html/rfc7636)

---

**Version:** 0.1.0  
**Last Updated:** 2024
