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

### 3. Choose a Cache Backend

The cache backend is selected at **compile time** via a Cargo feature flag.
Three modes are available:

| Feature       | Cache type                    | External dependency |
| ------------- | ----------------------------- | ------------------- |
| `cache-l2`    | Redis only                    | Redis server        |
| `cache-l1`    | Moka in-process only *(default)* | None             |
| `cache-l1-l2` | Moka L1 + Redis L2 (two-tier) | Redis server        |

See [Cache Backends](#cache-backends) for full details.

### 4. Run the Server

```bash
# Default: Moka in-process cache (no Redis needed)
cargo run

# Explicit Moka in-process cache
cargo run --no-default-features --features cache-l1

# Redis only
cargo run --no-default-features --features cache-l2

# Two-tier: Moka L1 + Redis L2
cargo run --no-default-features --features cache-l1-l2
```

Or use environment variables directly:

```bash
OAUTH_CLIENT_ID=your-id OAUTH_CLIENT_SECRET=your-secret cargo run
```

### 5. Test the Flow

1. Visit http://localhost:8080
2. Click "Login" to start OAuth flow
3. Authenticate with your provider
4. Access protected routes
5. Click "Logout" to end session

---

## Cache Backends

The cache backend is chosen at **compile time** by passing a `--features` flag to
Cargo.  Only one combination should be active at a time; enabling both `cache-l1`
and `cache-l2` individually is identical to enabling `cache-l1-l2`.

> **Compile-time guard:** Building with `--no-default-features` and no cache
> feature produces a clear compile error listing the available options.

### `cache-l2` — Redis only

Stores all session data in Redis.

```bash
cargo run --no-default-features --features cache-l2
```

**Additional CLI args / env vars:**

| CLI argument  | Environment variable | Default                | Description                        |
| ------------- | -------------------- | ---------------------- | ---------------------------------- |
| `--redis-url` | `REDIS_URL`          | `redis://127.0.0.1/`   | Redis connection URL               |
| `--cache-ttl` | `CACHE_TTL`          | `3600`                 | Session TTL in seconds             |

**`.env` snippet:**

```env
REDIS_URL=redis://127.0.0.1/
CACHE_TTL=3600
```

### `cache-l1` — Moka in-process only (default)

Stores all session data in a fast, bounded in-process cache using
[Moka](https://crates.io/crates/moka).  No external backend required — ideal
for local development or single-instance deployments where Redis is not
available.  This is the **default** when no feature flag is specified.

> **Note:** `extend_auth_session` resets the entry's wall-clock TTL to
> `L1_TTL_SEC` (re-insertion) rather than extending by an arbitrary delta,
> because Moka does not support per-entry TTL updates.

```bash
cargo run                                          # uses default = ["cache-l1"]
cargo run --no-default-features --features cache-l1
```

**Additional CLI args / env vars:**

| CLI argument           | Environment variable   | Default  | Description                                              |
| ---------------------- | ---------------------- | -------- | -------------------------------------------------------- |
| `--l1-max-capacity`    | `L1_MAX_CAPACITY`      | `10000`  | Maximum number of entries held by Moka                   |
| `--l1-ttl-sec`         | `L1_TTL_SEC`           | `3600`   | Time-to-live for L1 entries (seconds)                    |
| `--l1-time-to-idle-sec`| `L1_TIME_TO_IDLE_SEC`  | *(unset)*| Idle-eviction timeout in seconds; omit to disable        |

**`.env` snippet:**

```env
L1_MAX_CAPACITY=10000
L1_TTL_SEC=3600
# L1_TIME_TO_IDLE_SEC=1800   # optional: evict idle entries after 30 min
```

### `cache-l1-l2` — Two-tier: Moka L1 + Redis L2

Combines both tiers using a **cache-aside** pattern:

| Operation      | L1 (Moka)                              | L2 (Redis)                     |
| -------------- | -------------------------------------- | ------------------------------ |
| **Read**       | Check first; on miss go to L2          | Read on L1 miss; populate L1   |
| **Write**      | Write                                  | Write first (source of truth)  |
| **Invalidate** | Remove                                 | Remove                         |
| **Extend TTL** | Evict (re-fetched on next read)        | Extend                         |

```bash
cargo run --no-default-features --features cache-l1-l2
```

**Additional CLI args / env vars:** all of `cache-l1` and `cache-l2` combined.

**`.env` snippet:**

```env
# Redis (L2)
REDIS_URL=redis://127.0.0.1/
CACHE_TTL=3600

# Moka (L1) – TTL should match or slightly exceed CACHE_TTL
L1_MAX_CAPACITY=10000
L1_TTL_SEC=3600
# L1_TIME_TO_IDLE_SEC=1800
```

---

## Provider Configuration

Provider-specific example files are available:

- `.env.google.example` — Google OAuth2 configuration
- `.env.github.example` — GitHub OAuth2 configuration
- `.env.keycloak.example` — Keycloak OIDC configuration
- `.env.azure.example` — Azure AD / Microsoft Identity Platform

### Google

> **Note:** Google does NOT support OIDC logout. Do **not** set
> `OAUTH_END_SESSION_ENDPOINT`.

```env
OAUTH_AUTHORIZATION_ENDPOINT=https://accounts.google.com/o/oauth2/auth
OAUTH_TOKEN_ENDPOINT=https://oauth2.googleapis.com/token
OAUTH_CLIENT_ID=your-id.apps.googleusercontent.com
OAUTH_CLIENT_SECRET=your-secret
OAUTH_REDIRECT_URI=http://localhost:8080/auth/callback
OAUTH_SCOPES=openid,email,profile
PRIVATE_COOKIE_KEY=generate-with-openssl-rand-base64-64
```

**Setup:**

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create project → Enable Google+ API
3. Create OAuth 2.0 Client ID (Web application)
4. Add redirect URI: `http://localhost:8080/auth/callback`

### GitHub

> **Note:** GitHub does NOT support OIDC logout. Use default configuration.

```env
OAUTH_AUTHORIZATION_ENDPOINT=https://github.com/login/oauth/authorize
OAUTH_TOKEN_ENDPOINT=https://github.com/login/oauth/access_token
OAUTH_CLIENT_ID=your-github-client-id
OAUTH_CLIENT_SECRET=your-github-secret
OAUTH_REDIRECT_URI=http://localhost:8080/auth/callback
OAUTH_SCOPES=read:user,user:email
PRIVATE_COOKIE_KEY=generate-with-openssl-rand-base64-64
```

**Setup:**

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. New OAuth App
3. Set callback URL: `http://localhost:8080/auth/callback`

### Keycloak

> **Note:** Keycloak supports full OIDC including logout. Set `OAUTH_END_SESSION_ENDPOINT`.

```env
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

> **Note:** Azure AD supports full OIDC including logout.

```env
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

> **Note:** Okta supports full OIDC including logout.

```env
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

> **Note:** Auth0 supports full OIDC including logout.

```env
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

---

## Command Line Usage

### Basic Usage

```bash
# With command-line arguments (default: Moka in-process cache)
cargo run -- \
  --client-id YOUR_ID \
  --client-secret YOUR_SECRET \
  --authorization-endpoint https://provider.com/authorize \
  --token-endpoint https://provider.com/token
```

### Selecting a Cache Backend

```bash
# Moka in-process only (default — no Redis needed)
cargo run -- --client-id YOUR_ID --client-secret YOUR_SECRET

# Explicit Moka in-process only
cargo run --no-default-features --features cache-l1 -- \
  --client-id YOUR_ID --client-secret YOUR_SECRET \
  --l1-max-capacity 5000 \
  --l1-ttl-sec 1800

# Redis only
cargo run --no-default-features --features cache-l2 -- \
  --client-id YOUR_ID --client-secret YOUR_SECRET \
  --redis-url redis://127.0.0.1/ \
  --cache-ttl 3600

# Two-tier (Moka L1 + Redis L2)
cargo run --no-default-features --features cache-l1-l2 -- \
  --client-id YOUR_ID --client-secret YOUR_SECRET \
  --redis-url redis://127.0.0.1/ \
  --cache-ttl 3600 \
  --l1-max-capacity 10000 \
  --l1-ttl-sec 3600 \
  --l1-time-to-idle-sec 1800
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
# Options vary depending on the active cache feature
cargo run -- --help
cargo run --no-default-features --features cache-l1 -- --help
cargo run --no-default-features --features cache-l1-l2 -- --help
```

---

## Make Targets

The `Makefile` wraps common Cargo commands and supports a `FEATURES` variable
(default: `cache-l1`) that is forwarded to every `cargo` invocation.

### Generic targets (honour `FEATURES`)

```bash
make run                    # run with FEATURES=cache-l1 (default)
make run FEATURES=cache-l1  # override at call site
make dev FEATURES=cache-l1-l2
make build FEATURES=cache-l1
```

### Cache-specific shortcuts

```bash
# Run
make run-l2        # Redis only
make run-l1        # Moka in-process only
make run-l1-l2     # Two-tier

# Watch-run (requires cargo-watch)
make dev-l2
make dev-l1
make dev-l1-l2

# Build only
make build-l2
make build-l1
make build-l1-l2
```

### Other useful targets

```bash
make install       # install cargo-watch
make setup         # create .env.local from sample
make test          # run tests
make check         # cargo check
make fmt           # cargo fmt
make clippy        # cargo clippy
make clean         # clean build artifacts
make env           # print current .env.local contents
make help          # show all targets with descriptions
```

### Environment overrides

```bash
make run PORT=3000 HOST=0.0.0.0 FEATURES=cache-l1
DOTENV_FILE=.env.prod make run-l1-l2
```

---

## Environment Variables

### OAuth2 / OIDC

All CLI arguments can be set via environment variables:

| CLI argument                 | Environment variable           | Required | Default                                      |
| ---------------------------- | ------------------------------ | -------- | -------------------------------------------- |
| `--client-id`                | `OAUTH_CLIENT_ID`              | Yes      | —                                            |
| `--client-secret`            | `OAUTH_CLIENT_SECRET`          | Yes      | —                                            |
| `--authorization-endpoint`   | `OAUTH_AUTHORIZATION_ENDPOINT` | No       | `https://accounts.google.com/o/oauth2/auth`  |
| `--token-endpoint`           | `OAUTH_TOKEN_ENDPOINT`         | No       | `https://oauth2.googleapis.com/token`        |
| `--end-session-endpoint`     | `OAUTH_END_SESSION_ENDPOINT`   | No       | None (only for OIDC-compliant providers)     |
| `--post-logout-redirect-uri` | `POST_LOGOUT_REDIRECT_URI`     | No       | `/`                                          |
| `--redirect-uri`             | `OAUTH_REDIRECT_URI`           | No       | `http://localhost:8080/auth/callback`        |
| `--base-path`                | `OAUTH_BASE_PATH`              | No       | `/auth`                                      |
| `--private-cookie-key`       | `PRIVATE_COOKIE_KEY`           | No       | `private_cookie_key` *(change in prod!)*     |
| `--scopes`                   | `OAUTH_SCOPES`                 | No       | `openid,email,profile`                       |
| `--host`                     | `SERVER_HOST`                  | No       | `127.0.0.1`                                  |
| `--port`                     | `SERVER_PORT`                  | No       | `8080`                                       |

### Cache — L2 / Redis (`cache-l2`, `cache-l1-l2`)

| CLI argument  | Environment variable | Default              | Description            |
| ------------- | -------------------- | -------------------- | ---------------------- |
| `--redis-url` | `REDIS_URL`          | `redis://127.0.0.1/` | Redis connection URL   |
| `--cache-ttl` | `CACHE_TTL`          | `3600`               | Entry TTL in seconds   |

### Cache — L1 / Moka (`cache-l1`, `cache-l1-l2`)

| CLI argument            | Environment variable  | Default   | Description                              |
| ----------------------- | --------------------- | --------- | ---------------------------------------- |
| `--l1-max-capacity`     | `L1_MAX_CAPACITY`     | `10000`   | Maximum entries held by Moka             |
| `--l1-ttl-sec`          | `L1_TTL_SEC`          | `3600`    | Entry TTL in seconds                     |
| `--l1-time-to-idle-sec` | `L1_TIME_TO_IDLE_SEC` | *(unset)* | Idle-eviction timeout; omit to disable   |

---

## Dotenv File Priority

The application loads environment variables from dotenv files in this order:

1. File specified in `DOTENV_FILE` environment variable
2. `.env.local` (for local development overrides)
3. `.env` (for shared defaults)

Only the first existing file is loaded.

---

## Generating Secure Keys

```bash
# Generate a secure random private cookie key
openssl rand -base64 64

# Append it to your .env file
echo "PRIVATE_COOKIE_KEY=$(openssl rand -base64 64)" >> .env
```

---

## Available Routes

| Route                             | Description                       | Auth required |
| --------------------------------- | --------------------------------- | ------------- |
| `GET /`                           | Home page (public)                | No            |
| `GET /home`                       | Home page alias (public)          | No            |
| `GET /protected`                  | Protected page                    | Yes           |
| `GET /auth`                       | Start OAuth flow (auto-redirect)  | No            |
| `GET /auth/callback`              | OAuth callback (auto-handled)     | No            |
| `GET /auth/logout`                | Logout → home                     | No            |
| `GET /auth/logout?redirect=/path` | Logout → custom path              | No            |

---

## Testing

### Manual Testing

1. **Start server:** `cargo run` (or choose a cache feature)
2. **Visit home:** http://localhost:8080
3. **Click login:** Redirected to OAuth provider
4. **Authenticate:** Log in at the provider
5. **Redirected back:** See protected content
6. **Visit protected route:** http://localhost:8080/protected
7. **Click logout:** Session cleared, redirected home

### Cache-specific Smoke Tests

```bash
# Verify L1-only mode starts without Redis
cargo run --no-default-features --features cache-l1 -- \
  --client-id test --client-secret test

# Verify two-tier mode connects to Redis
cargo run --no-default-features --features cache-l1-l2 -- \
  --client-id test --client-secret test \
  --redis-url redis://127.0.0.1/
```

---

## Troubleshooting

### "Missing parameter" Error

Ensure `OAUTH_CLIENT_ID` and `OAUTH_CLIENT_SECRET` are set.

### Redirect Loop

Verify `OAUTH_REDIRECT_URI` matches exactly what is configured in your OAuth
provider.

### "Invalid client" Error

- Check client ID and secret are correct
- Ensure redirect URI matches provider configuration exactly
- Verify scopes are supported by the provider

### Session Not Persisting

- If using `cache-l2` or `cache-l1-l2`: confirm Redis is running and
  `REDIS_URL` is correct
- If using `cache-l1`: sessions are in-process only and lost on restart
- Verify cookies are enabled in the browser
- Check `PRIVATE_COOKIE_KEY` is set and consistent across restarts

### "At least one cache feature must be enabled" compile error

You ran `cargo build --no-default-features` without passing a `--features`
flag.  Add one of:

```bash
--features cache-l2      # Redis only
--features cache-l1      # Moka in-process only
--features cache-l1-l2   # Two-tier
```

### Logout Doesn't Work

- **For Google / GitHub:** Use `DefaultLogoutHandler` (no `OAUTH_END_SESSION_ENDPOINT`)
- **For Keycloak / Azure AD / Okta / Auth0:** Use `OidcLogoutHandler` with
  `OAUTH_END_SESSION_ENDPOINT`

---

## Production Deployment

### Security Checklist

- [ ] Use HTTPS for all endpoints
- [ ] Generate a strong random `PRIVATE_COOKIE_KEY` (`openssl rand -base64 64`)
- [ ] Store secrets in environment variables or a secret manager
- [ ] Use `CODE_CHALLENGE_METHOD=S256` (default)
- [ ] Set appropriate `session_max_age` (e.g. 30 minutes)
- [ ] Request only necessary OAuth scopes
- [ ] Verify redirect URIs in provider settings
- [ ] Enable secure cookies (automatic with HTTPS)

### Cache Recommendations for Production

| Scenario                          | Recommended feature |
| --------------------------------- | ------------------- |
| Single instance, no Redis         | `cache-l1`          |
| Single instance, Redis available  | `cache-l1-l2`       |
| Multi-instance, shared state      | `cache-l2` or `cache-l1-l2` |
| Development / testing             | `cache-l1` (no infrastructure needed) |

### Example Production `.env`

```env
# OAuth2
OAUTH_REDIRECT_URI=https://yourapp.com/auth/callback
POST_LOGOUT_REDIRECT_URI=https://yourapp.com
PRIVATE_COOKIE_KEY=<generated-with-openssl-rand-base64-64>
OAUTH_CLIENT_ID=your-client-id
OAUTH_CLIENT_SECRET=your-client-secret

# Server
SERVER_HOST=0.0.0.0
SERVER_PORT=8080

# Cache (two-tier example)
REDIS_URL=redis://redis-host:6379/
CACHE_TTL=1800
L1_MAX_CAPACITY=10000
L1_TTL_SEC=1800
L1_TIME_TO_IDLE_SEC=600
```

Run with:

```bash
cargo run --release --no-default-features --features cache-l1-l2
```

---

## Additional Resources

- [Main README](../../README.md) — Library documentation
- [API Documentation](../../DOCUMENTATION.md) — Complete API reference
- [Quick Reference](../../QUICK_REFERENCE.md) — Common patterns
- [Provider Examples](../../PROVIDER_EXAMPLES.md) — Detailed provider configs

## License

This example is part of the `axum-oidc-client` project and is licensed under the MIT License.
