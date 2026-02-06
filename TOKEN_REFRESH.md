# Automatic ID Token and Access Token Refresh Feature

Complete guide to automatic ID token and access token refresh in `axum-oidc-client`.

## Overview

The `axum-oidc-client` library provides **automatic ID token and access token refresh** functionality that transparently handles expired tokens without requiring any manual intervention in your application code. When you use the library's extractors, ID tokens and access tokens are automatically refreshed using the OAuth2 refresh token flow whenever they expire.

## How It Works

### The Refresh Process

When a request arrives at a protected route:

1. **Extraction** - The extractor retrieves the session from cache using the session cookie
2. **Expiration Check** - Compares `session.expires` with the current time
3. **Conditional Refresh** - If expired:
   - Sends POST request to the OAuth2 token endpoint
   - Includes the refresh token and client credentials
   - Receives new ID token, access token, and expiration time from the provider
   - Updates the session with fresh ID token and access token data
   - Saves the updated session back to cache
4. **Handler Execution** - Your route handler receives the fresh, valid tokens

### Request Flow Diagram

```
┌─────────────┐
│   Request   │
└──────┬──────┘
       │
       ▼
┌─────────────────────┐
│ Extract Session ID  │
│  from Cookie Jar    │
└──────┬──────────────┘
       │
       ▼
┌─────────────────────┐
│ Retrieve Session    │
│   from Cache        │
└──────┬──────────────┘
       │
       ▼
┌─────────────────────┐
│  Check Expiration   │
│ (expires <= now?)   │
└──────┬──────────────┘
       │
       ├─ No ──────────────────────┐
       │                           │
       │ Yes                       ▼
       ▼                    ┌──────────────┐
┌─────────────────────┐    │ Return Fresh │
│ POST /token         │    │   Session    │
│ grant_type=refresh  │    └──────┬───────┘
│ refresh_token=...   │           │
└──────┬──────────────┘           │
       │                           │
       ▼                           │
┌─────────────────────┐           │
│ Update Session      │           │
│ - access_token      │           │
│ - id_token          │           │
│ - expires           │           │
└──────┬──────────────┘           │
       │                           │
       ▼                           │
┌─────────────────────┐           │
│ Save to Cache       │           │
└──────┬──────────────┘           │
       │                           │
       └───────────────────────────┘
                │
                ▼
         ┌──────────────┐
         │   Handler    │
         │  (receives   │
         │ fresh token) │
         └──────────────┘
```

## Supported Extractors

All of the following extractors support automatic ID token and access token refresh:

### Required Authentication Extractors

These extractors require authentication and will redirect to OAuth if the user is not logged in:

- **`AuthSession`** - Full session with all token information (ID token and access token automatically refreshed if expired)
- **`AccessToken`** - Just the access token (automatically refreshed if expired)
- **`IdToken`** - Just the ID token (automatically refreshed if expired)

### Optional Authentication Extractors

These extractors work for both authenticated and unauthenticated users:

- **`OptionalAuthSession`** - Optional full session (ID token and access token automatically refreshed if expired when present)
- **`OptionalAccessToken`** - Optional access token (automatically refreshed if expired when present)
- **`OptionalIdToken`** - Optional ID token (automatically refreshed if expired when present)

## Usage Examples

### Example 1: Full Session with Auto-Refresh

```rust
use axum_oidc_client::auth_session::AuthSession;

async fn dashboard(session: AuthSession) -> String {
    // If ID token and access token were expired, they have already been refreshed
    // You always receive valid, fresh tokens
    format!(
        "Dashboard\n\
         Token Type: {}\n\
         Expires: {}\n\
         Scopes: {}",
        session.token_type,
        session.expires,
        session.scope
    )
}
```

### Example 2: Access Token Only

```rust
use axum_oidc_client::extractors::AccessToken;

async fn api_call(token: AccessToken) -> String {
    // Access token is automatically refreshed if it was expired
    // Safe to use for external API calls
    format!("Making API call with token: {}", &*token[..20])
}
```

### Example 3: Making External API Calls

```rust
use axum_oidc_client::extractors::AccessToken;
use reqwest::Client;

async fn fetch_user_data(token: AccessToken) -> Result<String, String> {
    let client = Client::new();

    // Access token is guaranteed to be fresh and valid (auto-refreshed if expired)
    let response = client
        .get("https://api.example.com/user/profile")
        .bearer_auth(&*token)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    response.text().await.map_err(|e| e.to_string())
}
```

### Example 4: Optional Authentication

```rust
use axum_oidc_client::extractors::OptionalAccessToken;

async fn personalized_content(
    OptionalAccessToken(token): OptionalAccessToken
) -> String {
    match token {
        Some(access_token) => {
            // Access token is automatically refreshed if it was expired
            format!("Personalized content for authenticated user")
        }
        None => {
            format!("Public content")
        }
    }
}
```

## Configuration Requirements

### 1. Request Refresh Token Scope

To enable ID token and access token refresh, you must request the appropriate scope from your OAuth2 provider:

```rust
use axum_oidc_client::auth_builder::OAuthConfigurationBuilder;

let config = OAuthConfigurationBuilder::default()
    // ... other config ...
    .with_scopes(vec![
        "openid",
        "email",
        "profile",
        "offline_access"  // Required for refresh tokens on most providers
    ])
    .build()?;
```

#### Provider-Specific Scopes

**Most OAuth2 Providers (Keycloak, Auth0, Azure AD, etc.):**

```rust
.with_scopes(vec!["openid", "email", "offline_access"])
```

**Google:**

```rust
// Google uses "openid" and returns refresh tokens automatically
// when access_type=offline is set (handled by the library)
.with_scopes(vec!["openid", "email", "profile"])
```

**GitHub:**

```rust
// GitHub doesn't expire tokens by default, but supports refresh
.with_scopes(vec!["read:user", "user:email"])
```

### 2. Verify Provider Support

Ensure your OAuth2 provider supports refresh tokens. Check the provider's documentation:

- Does it support the `refresh_token` grant type?
- Does it return a `refresh_token` in the token response?
- What is the refresh token lifetime?

### 3. Configure Token Expiration

Set appropriate expiration times in your configuration:

```rust
let config = OAuthConfigurationBuilder::default()
    // ... other config ...
    .with_session_max_age(30)     // Session valid for 30 minutes
    .with_token_max_age(300)      // Force token refresh after 5 minutes
    .build()?;
```

## Refresh Token Response

When ID token and access token are refreshed, the provider returns a response like:

```json
{
  "access_token": "new_access_token_here",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "new_refresh_token_here",
  "id_token": "new_id_token_here",
  "scope": "openid email profile"
}
```

The library automatically updates the session with:

- **`access_token`** - Always updated with the new access token
- **`id_token`** - Updated with new ID token if provider returns it (optional)
- **`refresh_token`** - Updated if provider returns a new refresh token (optional)
- **`expires`** - Calculated from `expires_in` and `token_max_age`
- **`scope`** - Updated if provider returns it (optional)

## Error Handling

### When Refresh Fails

If ID token and access token refresh fails (e.g., refresh token expired or revoked), the extractor:

1. **Returns Error** - The extractor fails with an authentication error
2. **Redirects User** - User is automatically redirected to the OAuth2 provider
3. **Prevents Handler Execution** - Your route handler is never called with invalid/expired tokens

```rust
async fn protected(session: AuthSession) -> String {
    // If refresh failed, this handler is never executed
    // User is redirected to re-authenticate instead
    format!("Tokens are valid: {} / {}", session.access_token, session.id_token)
}
```

### Common Refresh Failures

| Error Condition  | Cause                      | Solution                      |
| ---------------- | -------------------------- | ----------------------------- |
| `invalid_grant`  | Refresh token expired      | User must re-authenticate     |
| `invalid_grant`  | Refresh token revoked      | User must re-authenticate     |
| `invalid_client` | Client credentials wrong   | Check configuration           |
| Network timeout  | Provider unreachable       | Check network/provider status |
| Cache error      | Can't save updated session | Check cache connection        |

## Best Practices

### 1. Use Appropriate Extractors

Choose the right extractor for your use case:

```rust
// Need full session info? Use AuthSession
async fn dashboard(session: AuthSession) -> String { /* ... */ }

// Only need access token for API calls? Use AccessToken (more efficient)
async fn api_call(token: AccessToken) -> String { /* ... */ }

// Optional authentication? Use Optional variants
async fn home(OptionalIdToken(token): OptionalIdToken) -> String { /* ... */ }
```

### 2. Set Reasonable Token Lifetimes

Balance security and user experience:

```rust
.with_session_max_age(30)    // 30 minutes - good balance
.with_token_max_age(300)     // 5 minutes - force frequent refresh
```

**Short lifetimes (< 5 min):**

- ✅ Better security
- ❌ More refresh requests
- ❌ Higher load on provider

**Long lifetimes (> 60 min):**

- ✅ Fewer refresh requests
- ✅ Better performance
- ❌ Longer exposure if token leaked

### 3. Monitor Refresh Failures

Log refresh failures to detect issues:

```rust
// In production, log failed refreshes
// This helps identify when users need to re-authenticate
```

### 4. Handle Provider Outages

If the token endpoint is unavailable:

- Users with valid tokens continue working
- Users with expired tokens must wait for provider recovery
- Consider implementing retry logic for transient failures

### 5. Cache Configuration

Ensure your cache can handle concurrent updates:

```rust
// Redis automatically handles concurrent refresh requests
// Only one refresh happens even with multiple concurrent requests
let cache = Arc::new(
    axum_oidc_client::redis::AuthCache::new("redis://127.0.0.1/", 3600)
);
```

## Debugging Token Refresh

### Enable Logging

```rust
use tracing_subscriber;

tracing_subscriber::fmt::init();
```

This will log refresh attempts and failures.

### Check Refresh Token in Session

```rust
async fn debug_session(session: AuthSession) -> String {
    let now = chrono::Local::now();
    format!(
        "Session Debug:\n\
         Current Time: {}\n\
         Expires: {}\n\
         Is Expired: {}\n\
         Has Refresh Token: {}\n\
         Refresh Token (first 20): {}",
        now,
        session.expires,
        session.expires <= now,
        !session.refresh_token.is_empty(),
        &session.refresh_token[..20.min(session.refresh_token.len())]
    )
}
```

### Test Refresh Flow

```rust
// 1. Authenticate and get initial tokens
// 2. Wait for tokens to expire (or manually set short lifetime)
// 3. Make another request
// 4. Verify new ID token and access token were issued

async fn test_refresh(session: AuthSession) -> String {
    // Check expiration and tokens
    // If you see a newer expiration time than initial auth,
    // ID token and access token refresh is working
    format!("Expires: {} | Token: {}",
        session.expires,
        &session.access_token[..20]
    )
}
```

## Performance Considerations

### Caching Strategy

- ✅ Refreshed ID tokens and access tokens in sessions are immediately saved to cache
- ✅ Subsequent requests use the cached refreshed tokens
- ✅ No redundant refresh requests for the same session

### Network Overhead

Each ID token and access token refresh requires:

1. POST request to token endpoint with refresh token (~100-500ms)
2. Cache update operation to save new tokens (~1-10ms)

### Optimization Tips

1. **Use token_max_age wisely** - Don't force ID token and access token refresh too frequently
2. **Use specific extractors** - `AccessToken` or `IdToken` are lighter than full `AuthSession`
3. **Monitor refresh frequency** - High frequency may indicate misconfiguration

## Security Considerations

### Refresh Token Storage

- ✅ Refresh tokens stored in server-side cache only (used to obtain new ID tokens and access tokens)
- ✅ Never exposed to client (browser)
- ✅ Session ID encrypted in cookie, not the tokens themselves
- ✅ Refresh tokens deleted when user logs out

### Token Rotation

Some providers issue new refresh tokens on each ID token and access token refresh:

- ✅ Library automatically updates to new refresh token when provided
- ✅ Old refresh token is discarded
- ✅ Provides additional security through refresh token rotation

### Scope Changes

If provider reduces granted scopes during refresh:

- ✅ Session is updated with new scope list
- ⚠️ Your application should verify required scopes are present

## Troubleshooting

### Problem: ID tokens and access tokens not refreshing

**Check:**

1. Is `offline_access` (or equivalent) scope requested?
2. Does provider support refresh tokens for obtaining new ID tokens and access tokens?
3. Is refresh token present in session?
4. Are there errors in logs?

**Solution:**

```bash
# Check provider returns refresh token
curl -X POST https://provider.com/token \
  -d grant_type=authorization_code \
  -d code=AUTH_CODE \
  -d client_id=CLIENT_ID \
  -d client_secret=CLIENT_SECRET
# Look for "refresh_token" in response
```

### Problem: Refresh always fails with `invalid_grant`

**Possible Causes:**

1. Refresh token expired (check provider's refresh token lifetime)
2. Refresh token revoked by user or admin
3. Client credentials changed since token was issued

**Solution:**

- User must re-authenticate
- Check provider's refresh token settings

### Problem: High frequency of refresh requests

**Possible Causes:**

1. `token_max_age` set too low, forcing frequent ID token and access token refresh
2. Provider's access token lifetime too short
3. Multiple concurrent requests causing repeated refresh attempts

**Solution:**

```rust
// Increase token_max_age
.with_token_max_age(600)  // 10 minutes instead of 5
```

### Problem: Session lost after refresh

**Possible Causes:**

1. Cache connection lost during save of refreshed ID token and access token
2. Serialization error when saving updated session
3. Cache key mismatch

**Solution:**

- Check cache connectivity
- Verify cache configuration
- Check logs for specific errors

## Advanced Topics

### Custom Refresh Logic

If you need custom refresh behavior, implement your own cache:

```rust
use axum_oidc_client::auth_cache::AuthCache;
use async_trait::async_trait;

struct CustomCache;

#[async_trait]
impl AuthCache for CustomCache {
    async fn get(&self, key: &str) -> Option<String> {
        // Custom get logic with refresh handling
    }

    async fn set(&self, key: &str, value: &str) {
        // Custom set logic
    }

    async fn delete(&self, key: &str) {
        // Custom delete logic
    }
}
```

### Monitoring Refresh Metrics

Track ID token and access token refresh operations:

```rust
// Implement custom metrics in your cache implementation
// Track:
// - Number of ID token and access token refreshes per hour
// - Refresh success/failure rate
// - Average refresh latency
```

## Summary

The automatic ID token and access token refresh feature in `axum-oidc-client`:

- ✅ Works transparently without code changes
- ✅ Handles expired ID tokens and access tokens automatically
- ✅ Updates sessions with refreshed tokens atomically in cache
- ✅ Supports all OAuth2 providers that support refresh tokens
- ✅ Provides robust error handling
- ✅ Optimized for performance and security

Your application code never needs to manually check expiration or refresh ID tokens and access tokens - the library handles it all automatically when you use the provided extractors.
