# Sample Server Example

A complete example application demonstrating OAuth2/OIDC authentication with `axum-oidc-client`.

## Quick Start

### 1. Install Dependencies

```bash
cargo build
```

### 2. Configure OAuth Provider

Choose your provider and copy the corresponding example file:

```bash
# For Google OAuth2
cp .env.google.example .env

# For GitHub OAuth2
cp .env.github.example .env

# For Keycloak
cp .env.keycloak.example .env

# For Azure AD / Microsoft
cp .env.azure.example .env
```

Edit `.env` with your actual credentials.

### 3. Run the Server

```bash
cargo run
```

Or use environment variables directly:

```bash
OAUTH_CLIENT_ID=your-id OAUTH_CLIENT_SECRET=your-secret cargo run
```

### 4. Test the Flow

1. Visit http://localhost:8080
2. Click "Login" to start OAuth flow
3. Authenticate with your provider
4. Access protected routes
5. Click "Logout" to end session

## Provider Configuration

Provider-specific example files are available:

- `.env.google.example` - Google OAuth2 configuration
- `.env.github.example` - GitHub OAuth2 configuration
- `.env.keycloak.example` - Keycloak OIDC configuration
- `.env.azure.example` - Azure AD / Microsoft Identity Platform

### Google

**Note:** Google does NOT support OIDC logout. Use default configuration without `end_session_endpoint`.

```bash
# .env
OAUTH_AUTHORIZATION_ENDPOINT=https://accounts.google.com/o/oauth2/auth
OAUTH_TOKEN_ENDPOINT=https://oauth2.googleapis.com/token
OAUTH_CLIENT_ID=your-id.apps.googleusercontent.com
OAUTH_CLIENT_SECRET=your-secret
OAUTH_REDIRECT_URI=http://localhost:8080/auth/callback
OAUTH_SCOPES=openid,email,profile
PRIVATE_COOKIE_KEY=generate-with-openssl-rand-base64-64
# Do NOT set OAUTH_END_SESSION_ENDPOINT for Google
```

**Setup:**

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create project → Enable Google+ API
3. Create OAuth 2.0 Client ID (Web application)
4. Add redirect URI: `http://localhost:8080/auth/callback`

### GitHub

**Note:** GitHub does NOT support OIDC logout. Use default configuration.

```bash
# .env
OAUTH_AUTHORIZATION_ENDPOINT=https://github.com/login/oauth/authorize
OAUTH_TOKEN_ENDPOINT=https://github.com/login/oauth/access_token
OAUTH_CLIENT_ID=your-github-client-id
OAUTH_CLIENT_SECRET=your-github-secret
OAUTH_REDIRECT_URI=http://localhost:8080/auth/callback
OAUTH_SCOPES=read:user,user:email
PRIVATE_COOKIE_KEY=generate-with-openssl-rand-base64-64
# Do NOT set OAUTH_END_SESSION_ENDPOINT for GitHub
```

**Setup:**

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. New OAuth App
3. Set callback URL: `http://localhost:8080/auth/callback`

### Keycloak

**Note:** Keycloak supports full OIDC including logout. Set `end_session_endpoint`.

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
PRIVATE_COOKIE_KEY=generate-with-openssl-rand-base64-64
```

**Setup:**

1. Keycloak Admin Console → Select Realm
2. Clients → Create
3. Set Client Protocol: `openid-connect`
4. Set Access Type: `confidential`
5. Add Valid Redirect URIs: `http://localhost:8080/auth/callback`
6. Add Valid Post Logout Redirect URIs: `http://localhost:8080`

### Azure AD

**Note:** Azure AD supports full OIDC including logout.

```bash
# .env
AZURE_TENANT=common  # or your tenant ID

OAUTH_AUTHORIZATION_ENDPOINT=https://login.microsoftonline.com/${AZURE_TENANT}/oauth2/v2.0/authorize
OAUTH_TOKEN_ENDPOINT=https://login.microsoftonline.com/${AZURE_TENANT}/oauth2/v2.0/token
OAUTH_END_SESSION_ENDPOINT=https://login.microsoftonline.com/${AZURE_TENANT}/oauth2/v2.0/logout
OAUTH_CLIENT_ID=your-application-id
OAUTH_CLIENT_SECRET=your-client-secret
OAUTH_REDIRECT_URI=http://localhost:8080/auth/callback
POST_LOGOUT_REDIRECT_URI=http://localhost:8080
OAUTH_SCOPES=openid,email,profile
PRIVATE_COOKIE_KEY=generate-with-openssl-rand-base64-64
```

**Setup:**

1. [Azure Portal](https://portal.azure.com/) → Azure AD → App registrations
2. New registration
3. Add Redirect URI: `http://localhost:8080/auth/callback`
4. Certificates & secrets → New client secret
5. Authentication → Add logout URL: `http://localhost:8080`

### Okta

**Note:** Okta supports full OIDC including logout.

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
PRIVATE_COOKIE_KEY=generate-with-openssl-rand-base64-64
```

**Setup:**

1. [Okta Developer Console](https://developer.okta.com/)
2. Applications → Create App Integration
3. Choose OIDC → Web Application
4. Set redirect URIs and logout URIs

### Auth0

**Note:** Auth0 supports full OIDC including logout.

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
PRIVATE_COOKIE_KEY=generate-with-openssl-rand-base64-64
```

**Setup:**

1. [Auth0 Dashboard](https://manage.auth0.com/)
2. Applications → Create Application → Regular Web Application
3. Add Allowed Callback URLs: `http://localhost:8080/auth/callback`
4. Add Allowed Logout URLs: `http://localhost:8080`

## Command Line Usage

### Basic Usage

```bash
# With command-line arguments
cargo run -- \
  --client-id YOUR_ID \
  --client-secret YOUR_SECRET \
  --authorization-endpoint https://provider.com/authorize \
  --token-endpoint https://provider.com/token
```

### With OIDC Logout (Keycloak, Azure AD, Okta, Auth0)

```bash
cargo run -- \
  --client-id YOUR_ID \
  --client-secret YOUR_SECRET \
  --authorization-endpoint https://provider.com/authorize \
  --token-endpoint https://provider.com/token \
  --end-session-endpoint https://provider.com/logout \
  --post-logout-redirect-uri http://localhost:8080
```

### View All Options

```bash
cargo run -- --help
```

## Environment Variables

All CLI arguments can be set via environment variables:

| CLI Argument                 | Environment Variable           | Required | Default                                      |
| ---------------------------- | ------------------------------ | -------- | -------------------------------------------- |
| `--client-id`                | `OAUTH_CLIENT_ID`              | Yes      | -                                            |
| `--client-secret`            | `OAUTH_CLIENT_SECRET`          | Yes      | -                                            |
| `--authorization-endpoint`   | `OAUTH_AUTHORIZATION_ENDPOINT` | No       | `https://accounts.google.com/o/oauth2/auth`  |
| `--token-endpoint`           | `OAUTH_TOKEN_ENDPOINT`         | No       | `https://oauth2.googleapis.com/token`        |
| `--end-session-endpoint`     | `OAUTH_END_SESSION_ENDPOINT`   | No       | None (only set for OIDC providers)           |
| `--post-logout-redirect-uri` | `POST_LOGOUT_REDIRECT_URI`     | No       | `/`                                          |
| `--redirect-uri`             | `OAUTH_REDIRECT_URI`           | No       | `http://localhost:8080/auth/callback`        |
| `--base-path`                | `OAUTH_BASE_PATH`              | No       | `/auth`                                      |
| `--private-cookie-key`       | `PRIVATE_COOKIE_KEY`           | No       | `private_cookie_key` (change in production!) |
| `--scopes`                   | `OAUTH_SCOPES`                 | No       | `openid,email,profile`                       |
| `--host`                     | `SERVER_HOST`                  | No       | `127.0.0.1`                                  |
| `--port`                     | `SERVER_PORT`                  | No       | `8080`                                       |

## Dotenv File Priority

The application loads environment variables from dotenv files in this order:

1. File specified in `DOTENV_FILE` environment variable
2. `.env.local` (for local development overrides)
3. `.env` (for shared defaults)

Only the first existing file is loaded.

## Generating Secure Keys

Generate a secure private cookie key:

```bash
# Generate a secure random key
openssl rand -base64 64

# Use in .env file
echo "PRIVATE_COOKIE_KEY=$(openssl rand -base64 64)" >> .env
```

## Available Routes

| Route                             | Description                       | Auth Required |
| --------------------------------- | --------------------------------- | ------------- |
| `GET /`                           | Home page with login/logout links | No            |
| `GET /public`                     | Public page                       | No            |
| `GET /protected`                  | Protected page                    | Yes           |
| `GET /debug`                      | Session debug info                | Yes           |
| `GET /auth`                       | Start OAuth flow (auto-redirect)  | No            |
| `GET /auth/callback`              | OAuth callback (auto-handled)     | No            |
| `GET /auth/logout`                | Logout and redirect to home       | No            |
| `GET /auth/logout?redirect=/path` | Logout with custom redirect       | No            |

## Testing

### Manual Testing

1. **Start server:** `cargo run`
2. **Visit home:** http://localhost:8080
3. **Click login:** Redirects to OAuth provider
4. **Authenticate:** Login at provider
5. **Redirected back:** Should see protected content
6. **Visit protected route:** http://localhost:8080/protected
7. **Click logout:** Session cleared, redirected home

### Debug Session

Visit http://localhost:8080/debug to see:

- Token type
- Expiration time
- Current time
- Whether token is expired
- Scopes granted
- Whether refresh token exists

## Troubleshooting

### "Missing parameter" Error

Ensure `OAUTH_CLIENT_ID` and `OAUTH_CLIENT_SECRET` are set.

### Redirect Loop

Verify `OAUTH_REDIRECT_URI` matches exactly what's configured in your OAuth provider.

### "Invalid client" Error

- Check client ID and secret are correct
- Ensure redirect URI matches provider configuration exactly
- Verify scopes are supported by the provider

### Session Not Persisting

- Check Redis is running if using Redis cache
- Verify cookies are enabled in browser
- Check `PRIVATE_COOKIE_KEY` is set and consistent

### Logout Doesn't Work

- **For Google/GitHub:** Use `DefaultLogoutHandler` (no `end_session_endpoint`)
- **For Keycloak/Azure AD/Okta/Auth0:** Use `OidcLogoutHandler` with `end_session_endpoint`

## Production Deployment

### Security Checklist

- [ ] Use HTTPS for all endpoints
- [ ] Generate strong random `PRIVATE_COOKIE_KEY`
- [ ] Store secrets in environment variables or secret manager
- [ ] Use `CodeChallengeMethod::S256` (default)
- [ ] Set appropriate `session_max_age` (e.g., 30 minutes)
- [ ] Request only necessary OAuth scopes
- [ ] Verify redirect URIs in provider settings
- [ ] Enable secure cookies (automatic with HTTPS)

### Environment Configuration

```bash
# Production .env
OAUTH_REDIRECT_URI=https://yourapp.com/auth/callback
POST_LOGOUT_REDIRECT_URI=https://yourapp.com
PRIVATE_COOKIE_KEY=<generated-with-openssl-rand-base64-64>
SESSION_MAX_AGE=30
SERVER_HOST=0.0.0.0
SERVER_PORT=8080
```

## Additional Resources

- [Main README](../../README.md) - Library documentation
- [API Documentation](../../DOCUMENTATION.md) - Complete API reference
- [Quick Reference](../../QUICK_REFERENCE.md) - Common patterns
- [Provider Examples](../../PROVIDER_EXAMPLES.md) - Detailed provider configs

## License

This example is part of the `axum-oidc-client` project and is licensed under the MIT License.
