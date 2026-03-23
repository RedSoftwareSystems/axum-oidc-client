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

| Feature       | Cache type                         | External dependency  |
| ------------- | ---------------------------------- | -------------------- |
| `cache-l2`    | Redis only                         | Redis server         |
| `cache-l1`    | Moka in-process only *(default)*   | None                 |
| `cache-l1-l2` | Moka L1 + Redis L2 (two-tier)      | Redis server         |
| `cache-pg`    | PostgreSQL only                    | PostgreSQL ≥ 12      |
| `cache-l1-pg` | Moka L1 + PostgreSQL L2 (two-tier) | PostgreSQL ≥ 12      |
| `cache-sqlite`    | SQLite only                        | None (file-based)    |
| `cache-l1-sqlite` | Moka L1 + SQLite L2 (two-tier)     | None (file-based)    |

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

# PostgreSQL only (start the Docker stack first — see below)
cargo run --no-default-features --features cache-pg

# Two-tier: Moka L1 + PostgreSQL L2 (recommended for production)
cargo run --no-default-features --features cache-l1-pg

# SQLite only (no external server required — file created automatically)
cargo run --no-default-features --features cache-sqlite

# Two-tier: Moka L1 + SQLite L2
cargo run --no-default-features --features cache-l1-sqlite
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

## Redis Quick Start (Docker)

The fastest way to get a Redis 7 instance running locally is with the included
Docker Compose stack.

```bash
# 1. Copy the Redis example env file
cp .env.redis.example .env.local

# 2. Edit .env.local — fill in real OAuth2 credentials, keep the Redis defaults
#    (REDIS_URL / CACHE_TTL)

# 3. Start Redis 7
make redis-up
# or: docker compose -f docker/docker-compose.redis.yml up -d

# 4. Run the server with the two-tier cache (Moka L1 + Redis L2)
make run-l1-redis
# or: cargo run --no-default-features --features cache-l1-l2
```

The stack starts a single service:

| Service  | Purpose                                                                        |
| -------- | ------------------------------------------------------------------------------ |
| `redis`  | Redis 7-alpine with LRU eviction and persistence disabled (ephemeral cache)    |

See [Docker Compose reference](#docker-compose-reference) for all make targets.

---

## PostgreSQL Quick Start (Docker)

The fastest way to get a PostgreSQL 18 instance running locally is with the
included Docker Compose stack.

```bash
# 1. Copy the postgres example env file
cp .env.postgres.example .env.local

# 2. Edit .env.local — fill in real OAuth2 credentials, keep the PG defaults
#    (POSTGRES_USER / POSTGRES_PASSWORD / POSTGRES_DB / PG_URL)

# 3. Start PostgreSQL 18 + the nightly pg-vacuum-cron service
make pg-up
# or: docker compose -f docker/docker-compose.postgres.yml up -d

# 4. Run the server with the two-tier cache (Moka L1 + PG L2)
make run-l1-pg
# or: cargo run --no-default-features --features cache-l1-pg
```

The stack starts two services:

| Service        | Purpose                                                           |
| -------------- | ----------------------------------------------------------------- |
| `postgres`     | PostgreSQL 18-alpine with autovacuum tuned for high-churn cache  |
| `pg-vacuum-cron`  | Alpine container that runs `VACUUM ANALYZE oidc_cache` at midnight |

See [Docker Compose reference](#docker-compose-reference) for all make targets.

---

## SQLite Quick Start

SQLite requires **no external server** — the cache database is a plain file on disk,
created automatically by sqlx on first connection.

```bash
# 1. Copy the SQLite example env file
cp .env.sqlite.example .env.local

# 2. Edit .env.local — fill in real OAuth2 credentials.
#    The SQLite defaults (SQLITE_URL=sqlite:///tmp/oidc_cache.db) work as-is.

# 3. Run the server with the SQLite-only cache
make run-sqlite
# or: cargo run --no-default-features --features cache-sqlite

# 4. (Optional) Run with the two-tier Moka L1 + SQLite L2 cache
make run-l1-sqlite
# or: cargo run --no-default-features --features cache-l1-sqlite
```

> **Tip:** For local development use `sqlite:///tmp/oidc_cache.db`.  To persist
> the file across Docker container restarts, create the named volume first with
> `make sqlite-up` and then set `SQLITE_URL=sqlite:////data/oidc_cache.db`.

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

### `cache-pg` — PostgreSQL only

Stores all session data in a PostgreSQL database via `sqlx`.  Uses the
[`SqlAuthCache`](../../src/sql_cache/mod.rs) backend with a background cleanup
task that periodically deletes expired rows.  No Moka in-process layer.

```bash
cargo run --no-default-features --features cache-pg
```

**Additional CLI args / env vars:**

| CLI argument                 | Environment variable     | Default                                              | Description                                |
| ---------------------------- | ------------------------ | ---------------------------------------------------- | ------------------------------------------ |
| `--pg-url`                   | `PG_URL`                 | `postgresql://oidc_user:oidc_pass@localhost:5432/oidc_cache` | PostgreSQL connection URL      |
| `--pg-max-connections`       | `PG_MAX_CONNECTIONS`     | `20`                                                 | Connection pool max size                   |
| `--pg-cleanup-interval-sec`  | `PG_CLEANUP_INTERVAL_SEC`| `300`                                                | Expired-row sweep interval (seconds)       |

**`.env` snippet:**

```env
PG_URL=postgresql://oidc_user:oidc_pass@localhost:5432/oidc_cache
PG_MAX_CONNECTIONS=20
PG_CLEANUP_INTERVAL_SEC=300
```

**Schema initialisation** is performed automatically on startup via
`SqlAuthCache::init_schema()` (`CREATE UNLOGGED TABLE IF NOT EXISTS oidc_cache …`).
The table is idempotent — safe to call on every restart.

### `cache-l1-pg` — Two-tier: Moka L1 + PostgreSQL L2 *(recommended for production)*

Combines the low-latency Moka in-process cache with PostgreSQL as the durable
L2 backend.  This is the best choice when you want:

- Sub-millisecond session reads served from L1
- Durable, crash-safe session persistence in PostgreSQL
- Shared state across multiple application instances (via the shared PG database)

| Operation      | L1 (Moka)                              | L2 (PostgreSQL)                  |
| -------------- | -------------------------------------- | -------------------------------- |
| **Read**       | Check first; on miss go to L2          | Read on L1 miss; populate L1     |
| **Write**      | Write                                  | Write first (source of truth)    |
| **Invalidate** | Remove                                 | Remove                           |
| **Extend TTL** | Evict (re-fetched on next read)        | Update `expires_at`              |

```bash
cargo run --no-default-features --features cache-l1-pg
```

**Additional CLI args / env vars:** all of `cache-l1` plus all of `cache-pg`,
and one additional L1 TTL override specific to the PG two-tier configuration:

| CLI argument        | Environment variable | Default | Description                                               |
| ------------------- | -------------------- | ------- | --------------------------------------------------------- |
| `--pg-l1-ttl-sec`   | `PG_L1_TTL_SEC`      | `1800`  | Moka L1 TTL when used in front of PostgreSQL (seconds)    |

**`.env` snippet:**

```env
# PostgreSQL (L2)
PG_URL=postgresql://oidc_user:oidc_pass@localhost:5432/oidc_cache
PG_MAX_CONNECTIONS=20
PG_CLEANUP_INTERVAL_SEC=300

# Moka (L1) — TTL should be <= session max-age
L1_MAX_CAPACITY=10000
PG_L1_TTL_SEC=1800
# L1_TIME_TO_IDLE_SEC=900   # optional
```

### `cache-sqlite` — SQLite only

Stores all session data in a local SQLite database file via `sqlx`.  Uses the
[`SqlAuthCache`](../../src/sql_cache/mod.rs) backend with a background cleanup
task that periodically deletes expired rows.  **No external server required.**

```bash
cargo run --no-default-features --features cache-sqlite
```

**Additional CLI args / env vars:**

| CLI argument                    | Environment variable        | Default                        | Description                                 |
| ------------------------------- | --------------------------- | ------------------------------ | ------------------------------------------- |
| `--sqlite-url`                  | `SQLITE_URL`                | `sqlite:///tmp/oidc_cache.db`  | SQLite connection URL (file path or `:memory:`) |
| `--sqlite-max-connections`      | `SQLITE_MAX_CONNECTIONS`    | `5`                            | Connection pool max size (keep ≤ 5)         |
| `--sqlite-cleanup-interval-sec` | `SQLITE_CLEANUP_INTERVAL_SEC` | `300`                        | Expired-row sweep interval (seconds)        |

**`.env` snippet:**

```env
SQLITE_URL=sqlite:///tmp/oidc_cache.db
SQLITE_MAX_CONNECTIONS=5
SQLITE_CLEANUP_INTERVAL_SEC=300
```

**SQLite URL formats:**

| URL                                  | Description                                         |
| ------------------------------------ | --------------------------------------------------- |
| `sqlite:///tmp/oidc_cache.db`        | File at `/tmp/oidc_cache.db`                        |
| `sqlite:////data/oidc_cache.db`      | Absolute path (four slashes) — use with Docker volume |
| `sqlite://:memory:`                  | In-memory only (lost on restart — for testing)      |

**Schema initialisation** is performed automatically on startup via
`SqlAuthCache::init_schema()` (`CREATE TABLE IF NOT EXISTS oidc_cache …`).
The table is idempotent — safe to call on every restart.

### `cache-l1-sqlite` — Two-tier: Moka L1 + SQLite L2

Combines the low-latency Moka in-process cache with SQLite as the durable L2
backend.  This is the recommended choice when you want:

- Sub-millisecond session reads served from L1
- Durable session persistence in a lightweight file database
- Zero infrastructure dependencies (no Redis, PostgreSQL, or MySQL required)

| Operation      | L1 (Moka)                              | L2 (SQLite)                      |
| -------------- | -------------------------------------- | -------------------------------- |
| **Read**       | Check first; on miss go to L2          | Read on L1 miss; populate L1     |
| **Write**      | Write                                  | Write first (source of truth)    |
| **Invalidate** | Remove                                 | Remove                           |
| **Extend TTL** | Evict (re-fetched on next read)        | Update `expires_at`              |

> **Why L1 matters with SQLite:** SQLite serialises concurrent writes (only one
> writer at a time).  The Moka L1 layer absorbs the vast majority of repeated
> session reads, so SQLite only sees cold-miss lookups and write traffic.  This
> eliminates writer contention even under high concurrency.

```bash
cargo run --no-default-features --features cache-l1-sqlite
```

**Additional CLI args / env vars:** all of `cache-l1` plus all of `cache-sqlite`, and one additional L1 TTL override:

| CLI argument          | Environment variable | Default | Description                                               |
| --------------------- | -------------------- | ------- | --------------------------------------------------------- |
| `--sqlite-l1-ttl-sec` | `SQLITE_L1_TTL_SEC`  | `1800`  | Moka L1 TTL when used in front of SQLite (seconds)        |

**`.env` snippet:**

```env
# SQLite (L2)
SQLITE_URL=sqlite:///tmp/oidc_cache.db
SQLITE_MAX_CONNECTIONS=5
SQLITE_CLEANUP_INTERVAL_SEC=300

# Moka (L1) — TTL should be <= session max-age
L1_MAX_CAPACITY=10000
SQLITE_L1_TTL_SEC=1800
# L1_TIME_TO_IDLE_SEC=900   # optional
```

---

## Docker Compose Reference

### Redis Docker reference

The `docker/docker-compose.redis.yml` stack runs a single Redis 7-alpine
container tuned for a short-TTL session cache.

#### Why no maintenance sidecar?

Redis manages its own memory automatically via the `maxmemory` +
`maxmemory-policy allkeys-lru` configuration: when the memory ceiling is
reached, the least-recently-used key is evicted.  All cache entries already
carry an explicit TTL set by the application, so Redis expires them
passively without any external cron job.

#### Compose environment variables

| Variable           | Default       | Description                                              |
| ------------------ | ------------- | -------------------------------------------------------- |
| `REDIS_PORT`       | `6379`        | Host-side port mapping                                   |
| `REDIS_PASSWORD`   | *(empty)*     | Optional AUTH password — leave unset for no auth         |
| `REDIS_MAXMEMORY`  | `256mb`       | Memory ceiling; LRU eviction triggers when reached       |

When `REDIS_PASSWORD` is set, update `REDIS_URL` in `.env.local` to
`redis://:<password>@127.0.0.1:6379/`.

#### Make targets (Redis Docker)

```bash
make redis-up      # Start Redis 7
make redis-down    # Stop containers; preserve redis_data volume
make redis-destroy # Stop containers AND delete redis_data volume (destructive!)
make redis-logs    # Follow logs from all services
make redis-ps      # Show service status
make redis-shell   # Open an interactive redis-cli shell inside the container
```

---

### PostgreSQL Docker reference

The `docker/docker-compose.postgres.yml` stack provides a fully configured PostgreSQL 18
environment for local development and CI.

### Services

#### `postgres` (PostgreSQL 18-alpine)

- Exposes port `${POSTGRES_PORT:-5432}` on the host.
- Data is persisted in the `pg_data` named Docker volume.
- Init scripts in `docker/postgres/init/` run once on first startup:
  - `01_oidc_cache.sql` — creates the `oidc_cache` UNLOGGED table, its index,
    and applies aggressive per-table autovacuum storage parameters.
- Runtime PostgreSQL parameters set via the `command:` key:

  | Parameter                          | Value   | Reason                                           |
  | ---------------------------------- | ------- | ------------------------------------------------ |
  | `autovacuum`                       | `on`    | Global autovacuum left enabled for all tables    |
  | `autovacuum_naptime`               | `30s`   | Daemon wakes every 30 s (default: 1 min)         |
  | `autovacuum_vacuum_scale_factor`   | `0.01`  | Vacuum after 1 % change (default: 20 %)          |
  | `autovacuum_analyze_scale_factor`  | `0.01`  | Analyze after 1 % change (default: 20 %)         |
  | `autovacuum_vacuum_cost_delay`     | `2`     | Near full-speed vacuum I/O (ms)                  |
  | `log_autovacuum_min_duration`      | `0`     | Log every autovacuum run (useful for tuning)     |
  | `synchronous_commit`               | `off`   | Higher write throughput (safe for a cache)       |
  | `wal_level`                        | `minimal` | Minimal WAL since replication is not used      |

  Additionally, the `01_oidc_cache.sql` init script overrides storage
  parameters on the `oidc_cache` table itself:

  ```sql
  ALTER TABLE oidc_cache SET (
      autovacuum_vacuum_scale_factor  = 0.01,
      autovacuum_analyze_scale_factor = 0.01,
      autovacuum_vacuum_threshold     = 50,
      autovacuum_analyze_threshold    = 50,
      autovacuum_vacuum_cost_delay    = 2
  );
  ```

  These per-table settings override the global GUC values **only** for
  `oidc_cache`, leaving all other tables in the database unaffected.

#### `pg-vacuum-cron` (Alpine + BusyBox crond)

A lightweight sidecar (~12 MB image) that runs a scheduled
`VACUUM ANALYZE oidc_cache` job via BusyBox `crond`.

- Schedule is controlled by `VACUUM_SCHEDULE` (default: `0 0 * * *` — every
  day at **midnight UTC**).
- Connects to PostgreSQL using credentials from the shared `pg-env` block; the
  password is stored in `~/.pgpass` (mode 600) so it never appears in process
  arguments or logs.
- Before the job runs, the script logs the dead-tuple count.  After the job it
  logs table size and statistics — all visible in `docker compose logs`.

**Why supplement autovacuum with a scheduled job?**

Autovacuum handles *routine* dead-tuple reclaim, but after large expiry waves
(e.g. thousands of sessions expiring at once at midnight) the autovacuum daemon
can fall behind.  A scheduled `VACUUM ANALYZE` ensures the table stays compact
and planner statistics stay accurate regardless of autovacuum's backlog.

### Compose environment variables

All variables have sensible defaults; override in your `.env.local` file or as
shell environment variables before running `docker compose`.

| Variable            | Default        | Description                                           |
| ------------------- | -------------- | ----------------------------------------------------- |
| `POSTGRES_USER`     | `oidc_user`    | PostgreSQL superuser name                             |
| `POSTGRES_PASSWORD` | `oidc_pass`    | PostgreSQL superuser password                         |
| `POSTGRES_DB`       | `oidc_cache`   | Database name                                         |
| `POSTGRES_PORT`     | `5432`         | Host-side port mapping                                |
| `VACUUM_SCHEDULE`   | `0 0 * * *`    | 5-field cron expression for the nightly VACUUM job    |

### Make targets (Docker)

```bash
make pg-up        # Start the stack (builds pg-vacuum-cron image if needed)
make pg-down      # Stop containers; preserve pg_data volume
make pg-destroy   # Stop containers AND delete pg_data volume (destructive!)
make pg-logs      # Follow logs from all services
make pg-ps        # Show service status
make pg-vacuum    # Run VACUUM ANALYZE manually (one-shot, useful for testing)
make pg-psql      # Open an interactive psql shell inside the postgres container
```

**To test the vacuum job without waiting until midnight:**

```bash
# Override the schedule to run every 5 minutes, then restart the stack
VACUUM_SCHEDULE="*/5 * * * *" make pg-up
make pg-logs   # watch the vacuum output
```

---

### SQLite Docker reference

The `docker/docker-compose.sqlite.yml` stack manages the `sqlite_data` named
Docker volume and a `sqlite-vacuum-cron` maintenance sidecar.  No database
server process is started — SQLite is purely file-based.

#### Services

| Service               | Purpose                                                                        |
| --------------------- | ------------------------------------------------------------------------------ |
| `sqlite-vacuum-cron`  | Alpine container that runs `VACUUM` + `PRAGMA optimize` on a cron schedule     |

#### `sqlite-vacuum-cron` (Alpine + BusyBox crond)

A lightweight sidecar (~8 MB image) that runs scheduled SQLite maintenance via
BusyBox `crond`.

- Schedule is controlled by `VACUUM_SCHEDULE` (default: `0 0 * * *` — every
  day at **midnight UTC**).
- Mounts the same `sqlite_data` volume as the sample-server so it operates on
  the live database file.
- The database file is created by the sample-server on first connection.  If
  the file does not exist yet when the cron job fires, the job skips
  gracefully and retries on the next scheduled run.

**What each step does:**

| Step               | Purpose                                                                              |
| ------------------ | ------------------------------------------------------------------------------------ |
| `VACUUM`           | Rewrites the database into a compacted file, returning free pages to the OS.  SQLite does not have a background purge thread — free pages from `DELETE` operations accumulate until `VACUUM` runs. |
| `PRAGMA optimize`  | SQLite's lightweight equivalent of `ANALYZE`.  Refreshes query-planner statistics for stale tables without rewriting the database file. |

**Why not WAL checkpoint instead?**
A `PRAGMA wal_checkpoint(TRUNCATE)` only merges the WAL file back into the main
database; it does not compact free pages left by deletes.  `VACUUM` is still
required to reclaim that space.

#### Compose environment variables

| Variable           | Default                  | Description                                        |
| ------------------ | ------------------------ | -------------------------------------------------- |
| `SQLITE_DB_PATH`   | `/data/oidc_cache.db`    | Absolute path to the database file in the container |
| `VACUUM_SCHEDULE`  | `0 0 * * *`              | 5-field cron expression for the nightly vacuum job  |

#### Make targets (SQLite Docker)

```bash
make sqlite-up       # Start the sqlite_data volume + sqlite-vacuum-cron sidecar
make sqlite-down     # Stop the stack; volume is preserved
make sqlite-destroy  # Remove the stack AND the sqlite_data volume (destructive!)
make sqlite-logs     # Follow logs from all services
make sqlite-ps       # Show service status
make sqlite-vacuum   # Run VACUUM + PRAGMA optimize manually (one-shot, useful for testing)
make sqlite-shell    # Open an interactive sqlite3 shell on oidc_cache.db
```

**To test the vacuum job without waiting until midnight:**

```bash
# Override the schedule to run every 5 minutes, then restart the stack
VACUUM_SCHEDULE="*/5 * * * *" make sqlite-up
make sqlite-logs   # watch the vacuum output
```

After running `make sqlite-up`, set the following in `.env.local`:

```env
SQLITE_URL=sqlite:////data/oidc_cache.db
```

Then start the server:

```bash
make run-sqlite      # SQLite-only cache
make run-l1-sqlite   # Moka L1 + SQLite L2 (recommended)
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

# PostgreSQL only
cargo run --no-default-features --features cache-pg -- \
  --client-id YOUR_ID --client-secret YOUR_SECRET \
  --pg-url postgresql://oidc_user:oidc_pass@localhost:5432/oidc_cache \
  --pg-max-connections 20

# Two-tier (Moka L1 + PostgreSQL L2) — recommended for production
cargo run --no-default-features --features cache-l1-pg -- \
  --client-id YOUR_ID --client-secret YOUR_SECRET \
  --pg-url postgresql://oidc_user:oidc_pass@localhost:5432/oidc_cache \
  --pg-max-connections 20 \
  --l1-max-capacity 10000 \
  --pg-l1-ttl-sec 1800
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
cargo run --no-default-features --features cache-pg -- --help
cargo run --no-default-features --features cache-l1-pg -- --help
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
make run-redis     # Redis only
make run-l1        # Moka in-process only
make run-l1-redis  # Two-tier (Moka + Redis)
make run-pg        # PostgreSQL only
make run-l1-pg     # Two-tier (Moka + PostgreSQL)  ← recommended

# Watch-run (requires cargo-watch)
make dev-redis
make dev-l1
make dev-l1-redis
make dev-pg
make dev-l1-pg

# Build only
make build-redis
make build-l1
make build-l1-redis
make build-pg
make build-l1-pg
```

```bash
# SQLite
make run-sqlite      # SQLite only
make run-l1-sqlite   # Two-tier (Moka + SQLite)  ← recommended for zero-infra prod

make dev-sqlite
make dev-l1-sqlite

make build-sqlite
make build-l1-sqlite
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
DOTENV_FILE=.env.prod make run-l1-redis
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

### Cache — PostgreSQL (`cache-pg`, `cache-l1-pg`)

| CLI argument                | Environment variable      | Default                                                      | Description                           |
| --------------------------- | ------------------------- | ------------------------------------------------------------ | ------------------------------------- |
| `--pg-url`                  | `PG_URL`                  | `postgresql://oidc_user:oidc_pass@localhost:5432/oidc_cache` | PostgreSQL connection URL             |
| `--pg-max-connections`      | `PG_MAX_CONNECTIONS`      | `20`                                                         | Connection pool max size              |
| `--pg-cleanup-interval-sec` | `PG_CLEANUP_INTERVAL_SEC` | `300`                                                        | Expired-row sweep interval (seconds)  |
| `--pg-l1-ttl-sec`           | `PG_L1_TTL_SEC`           | `1800`                                                       | Moka L1 TTL when backed by PG (`cache-l1-pg` only) |

### Cache — MySQL (`cache-mysql`, `cache-l1-mysql`)

| CLI argument                  | Environment variable         | Default                                              | Description                                |
| ----------------------------- | ---------------------------- | ---------------------------------------------------- | ------------------------------------------ |
| `--mysql-url`                 | `MYSQL_URL`                  | `mysql://oidc_user:oidc_pass@localhost:3306/oidc_cache` | MySQL connection URL                    |
| `--mysql-max-connections`     | `MYSQL_MAX_CONNECTIONS`      | `20`                                                 | Connection pool max size                   |
| `--mysql-cleanup-interval-sec`| `MYSQL_CLEANUP_INTERVAL_SEC` | `300`                                                | Expired-row sweep interval (seconds)       |
| `--mysql-l1-ttl-sec`          | `MYSQL_L1_TTL_SEC`           | `1800`                                               | Moka L1 TTL when backed by MySQL (`cache-l1-mysql` only) |

### Cache — SQLite (`cache-sqlite`, `cache-l1-sqlite`)

| CLI argument                    | Environment variable         | Default                        | Description                                              |
| ------------------------------- | ---------------------------- | ------------------------------ | -------------------------------------------------------- |
| `--sqlite-url`                  | `SQLITE_URL`                 | `sqlite:///tmp/oidc_cache.db`  | SQLite connection URL                                    |
| `--sqlite-max-connections`      | `SQLITE_MAX_CONNECTIONS`     | `5`                            | Connection pool max size (keep ≤ 5)                      |
| `--sqlite-cleanup-interval-sec` | `SQLITE_CLEANUP_INTERVAL_SEC`| `300`                          | Expired-row sweep interval (seconds)                     |
| `--sqlite-l1-ttl-sec`           | `SQLITE_L1_TTL_SEC`          | `1800`                         | Moka L1 TTL when backed by SQLite (`cache-l1-sqlite` only) |

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

# Start the Docker PostgreSQL stack and verify PG cache
make pg-up
cargo run --no-default-features --features cache-pg -- \
  --client-id test --client-secret test

# Two-tier PG smoke test
cargo run --no-default-features --features cache-l1-pg -- \
  --client-id test --client-secret test

# Manually trigger the vacuum job to verify it works
make pg-vacuum

# SQLite smoke test — no Docker stack needed, just a temp file
cargo run --no-default-features --features cache-sqlite -- \
  --client-id test --client-secret test \
  --sqlite-url sqlite:///tmp/oidc_cache_test.db

# Two-tier SQLite smoke test
cargo run --no-default-features --features cache-l1-sqlite -- \
  --client-id test --client-secret test \
  --sqlite-url sqlite:///tmp/oidc_cache_test.db
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
- If using `cache-pg` or `cache-l1-pg`: confirm PostgreSQL is running and
  `PG_URL` is correct; check `make pg-ps` to verify the Docker stack is healthy
- Verify cookies are enabled in the browser
- Check `PRIVATE_COOKIE_KEY` is set and consistent across restarts

### "At least one cache feature must be enabled" compile error

You ran `cargo build --no-default-features` without passing a `--features`
flag.  Add one of:

```bash
--features cache-l2          # Redis only
--features cache-l1          # Moka in-process only
--features cache-l1-l2       # Two-tier (Moka + Redis)
--features cache-pg          # PostgreSQL only
--features cache-l1-pg       # Two-tier (Moka + PostgreSQL)
--features cache-sqlite      # SQLite only
--features cache-l1-sqlite   # Two-tier (Moka + SQLite)
```

### PostgreSQL connection refused

- Ensure the Docker Compose stack is running: `make pg-ps`
- Start it if needed: `make pg-up`
- Check that `PG_URL` matches the compose credentials (`POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, `POSTGRES_PORT`)
- Connect manually to verify: `make pg-psql`

### SQLite file not found / permission denied

- Ensure the **parent directory** of `SQLITE_URL` exists and is writable.
  SQLite creates the file but not its parent directories.
- If using the Docker volume path (`sqlite:////data/oidc_cache.db`), run
  `make sqlite-up` first to create the `sqlite_data` volume.
- For in-memory testing use `SQLITE_URL=sqlite://:memory:` — no filesystem
  access required.
- SQLite does not require credentials — no username or password to configure.

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

| Scenario                                  | Recommended feature   |
| ----------------------------------------- | --------------------- |
| Single instance, no external backend      | `cache-l1`            |
| Single instance, Redis available          | `cache-l1-l2`         |
| Single instance, PostgreSQL available     | `cache-l1-pg`  ← **recommended** |
| Single instance, no infrastructure        | `cache-l1-sqlite`             |
| Multi-instance, shared state (Redis)      | `cache-l2` or `cache-l1-l2` |
| Multi-instance, shared state (PostgreSQL) | `cache-pg` or `cache-l1-pg` |
| Development / zero-infra testing          | `cache-sqlite` or `cache-l1-sqlite` |

**Why `cache-l1-pg` for single-instance production?**

PostgreSQL gives you durable session persistence (sessions survive restarts),
easy administration (`psql`, `pg_dump`), and a well-understood operational
model.  The Moka L1 layer absorbs most reads so PostgreSQL sees minimal load.
The included Docker Compose stack bundles a nightly `VACUUM ANALYZE` job to
keep the `oidc_cache` table lean at zero operational overhead.

### Example Production `.env` — PostgreSQL two-tier

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

# PostgreSQL cache (L2)
PG_URL=postgresql://oidc_user:strongpassword@pg-host:5432/oidc_cache
PG_MAX_CONNECTIONS=20
PG_CLEANUP_INTERVAL_SEC=300

# Moka L1 in front of PostgreSQL
L1_MAX_CAPACITY=10000
PG_L1_TTL_SEC=1800

# Docker Compose (if using the bundled stack)
POSTGRES_USER=oidc_user
POSTGRES_PASSWORD=strongpassword
POSTGRES_DB=oidc_cache
POSTGRES_PORT=5432
VACUUM_SCHEDULE=0 0 * * *
```

Run with:

```bash
cargo run --release --no-default-features --features cache-l1-pg
```

### Example Production `.env` — Redis two-tier

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

# Cache (two-tier Redis example)
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
- [`.env.postgres.example`](.env.postgres.example) — Full PostgreSQL + Docker configuration reference
- [`.env.redis.example`](.env.redis.example) — Redis + Docker configuration reference
- [`docker/docker-compose.redis.yml`](docker/docker-compose.redis.yml) — Redis 7 stack
- [`docker/docker-compose.postgres.yml`](docker/docker-compose.postgres.yml) — PostgreSQL 18 + pg-vacuum-cron stack
- [`.env.sqlite.example`](.env.sqlite.example) — SQLite configuration reference
- [`docker/docker-compose.sqlite.yml`](docker/docker-compose.sqlite.yml) — SQLite volume helper
- [`docker/postgres/init/01_oidc_cache.sql`](docker/postgres/init/01_oidc_cache.sql) — Schema and autovacuum settings

## License

This example is part of the `axum-oidc-client` project and is licensed under the MIT License.
