# Environment Configuration Files Guide

This directory contains example environment configuration files for different OAuth2/OIDC providers.

## Available Example Files

| File                    | Provider             | OIDC Support   | Logout Support         |
| ----------------------- | -------------------- | -------------- | ---------------------- |
| `.env.google.example`   | Google OAuth2        | Partial        | ❌ No OIDC logout      |
| `.env.github.example`   | GitHub OAuth2        | ❌ OAuth2 only | ❌ No OIDC logout      |
| `.env.keycloak.example` | Keycloak             | ✅ Full OIDC   | ✅ RP-Initiated Logout |
| `.env.azure.example`    | Azure AD / Microsoft | ✅ Full OIDC   | ✅ RP-Initiated Logout |

## Quick Setup

### 1. Choose Your Provider

Copy the appropriate example file to `.env`:

```bash
# For Google
cp .env.google.example .env

# For GitHub
cp .env.github.example .env

# For Keycloak
cp .env.keycloak.example .env

# For Azure AD
cp .env.azure.example .env
```

### 2. Update Credentials

Edit `.env` and replace the placeholder values:

- `OAUTH_CLIENT_ID` - Your OAuth2 client ID
- `OAUTH_CLIENT_SECRET` - Your OAuth2 client secret
- `PRIVATE_COOKIE_KEY` - Generate with: `openssl rand -base64 64`

### 3. Run the Application

```bash
cargo run
```

## Configuration Options

### Required Variables

All providers require these variables:

```bash
OAUTH_CLIENT_ID=your-client-id
OAUTH_CLIENT_SECRET=your-client-secret
OAUTH_REDIRECT_URI=http://localhost:8080/auth/callback
PRIVATE_COOKIE_KEY=your-secure-random-key
```

### Provider Endpoints

Each provider has specific endpoints:

**Google:**

```bash
OAUTH_AUTHORIZATION_ENDPOINT=https://accounts.google.com/o/oauth2/auth
OAUTH_TOKEN_ENDPOINT=https://oauth2.googleapis.com/token
```

**GitHub:**

```bash
OAUTH_AUTHORIZATION_ENDPOINT=https://github.com/login/oauth/authorize
OAUTH_TOKEN_ENDPOINT=https://github.com/login/oauth/access_token
```

**Keycloak:**

```bash
OAUTH_AUTHORIZATION_ENDPOINT=https://your-keycloak.com/realms/your-realm/protocol/openid-connect/auth
OAUTH_TOKEN_ENDPOINT=https://your-keycloak.com/realms/your-realm/protocol/openid-connect/token
OAUTH_END_SESSION_ENDPOINT=https://your-keycloak.com/realms/your-realm/protocol/openid-connect/logout
```

**Azure AD:**

```bash
OAUTH_AUTHORIZATION_ENDPOINT=https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize
OAUTH_TOKEN_ENDPOINT=https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
OAUTH_END_SESSION_ENDPOINT=https://login.microsoftonline.com/{tenant}/oauth2/v2.0/logout
```

### Optional Variables

```bash
# Custom base path for auth routes (default: /auth)
OAUTH_BASE_PATH=/api/auth

# Post-logout redirect (default: /)
POST_LOGOUT_REDIRECT_URI=http://localhost:8080/home

# PKCE method (default: S256)
CODE_CHALLENGE_METHOD=S256

# Server configuration
SERVER_HOST=127.0.0.1
SERVER_PORT=8080

# Custom CA certificate
CUSTOM_CA_CERT=/path/to/ca.pem
```

## Provider-Specific Notes

### Google

- ❌ Does NOT support OIDC logout
- Use `DefaultLogoutHandler` in code
- Do NOT set `OAUTH_END_SESSION_ENDPOINT`
- Scopes: `openid,email,profile`
- Client ID format: `*.apps.googleusercontent.com`

### GitHub

- ❌ OAuth2 only, not full OIDC
- Use `DefaultLogoutHandler` in code
- Do NOT set `OAUTH_END_SESSION_ENDPOINT`
- Different scope format: `read:user,user:email`
- No id_token, only access_token

### Keycloak

- ✅ Full OIDC support
- ✅ Supports RP-Initiated Logout
- Use `OidcLogoutHandler` in code
- Set `OAUTH_END_SESSION_ENDPOINT`
- Realm-specific endpoints

### Azure AD

- ✅ Full OIDC support
- ✅ Supports logout
- Use `OidcLogoutHandler` in code
- Set `OAUTH_END_SESSION_ENDPOINT`
- Tenant-specific endpoints
- Client ID is a UUID

## Security Best Practices

### Development

1. **Never commit** `.env` files with real credentials
2. Use `.env.local` for local overrides (already in `.gitignore`)
3. Generate secure keys: `openssl rand -base64 64`
4. Use `http://localhost` for redirect URIs

### Production

1. **Use HTTPS** for all redirect URIs
2. **Store secrets securely** in:
   - AWS: Secrets Manager or Parameter Store
   - Azure: Key Vault
   - GCP: Secret Manager
   - Kubernetes: Secrets
   - HashiCorp Vault
3. **Rotate credentials** regularly
4. **Use environment variables** instead of files
5. **Set proper CORS** and security headers
6. **Enable MFA** on OAuth provider accounts

## Troubleshooting

### "Invalid client" error

- Verify `OAUTH_CLIENT_ID` and `OAUTH_CLIENT_SECRET` are correct
- Check if credentials are properly URL-encoded
- Ensure client is enabled in provider console

### "Redirect URI mismatch" error

- Verify `OAUTH_REDIRECT_URI` exactly matches provider configuration
- Include protocol (`http://` or `https://`)
- Include port if not default (80/443)
- Check for trailing slashes

### "Invalid scope" error

- Verify scopes are supported by the provider
- Check scope format (comma-separated, no spaces)
- Google/Azure: `openid,email,profile`
- GitHub: `read:user,user:email`

### Session not persisting

- Ensure `PRIVATE_COOKIE_KEY` is set and consistent
- Check browser cookies are enabled
- Verify cookie secure flag matches protocol (HTTP/HTTPS)

## File Priority

The application loads environment files in this order:

1. File specified in `DOTENV_FILE` environment variable
2. `.env.local` (local overrides, in `.gitignore`)
3. `.env` (committed configuration)

Only the first existing file is loaded.

## Additional Resources

- [Main Documentation](../../README.md)
- [Provider Examples](../../PROVIDER_EXAMPLES.md)
- [Security Guidelines](../../README.md#security-considerations)
- Sample code in `src/main.rs`

## Support

For issues or questions:

- Check the [troubleshooting section](#troubleshooting)
- Review provider-specific documentation
- Check the main library documentation
