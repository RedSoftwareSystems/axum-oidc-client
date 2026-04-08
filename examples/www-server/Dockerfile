# ──────────────────────────────────────────────────────────────────────────────
# www-server Dockerfile
#
# Multi-stage build:
#   1. builder  – compiles the binary using the full Rust toolchain
#   2. runtime  – copies only the binary into a minimal Debian image
#
# Build context must be the repository root (axum-oidc-client/) so that the
# workspace crate referenced via `path = "../.."` is available.
#
# Build:
#   docker build -f examples/www-server/Dockerfile \
#       [--build-arg FEATURES=cache-l1] \
#       -t axum-www-server .
#
# Run:
#   docker run --rm \
#       -e OAUTH_ISSUER=https://accounts.google.com \
#       -e OAUTH_CLIENT_ID=your-client-id \
#       -e OAUTH_CLIENT_SECRET=your-client-secret \
#       -e OAUTH_REDIRECT_URI=http://localhost:8080/auth/callback \
#       -e PRIVATE_COOKIE_KEY=change-me-to-64-random-bytes \
#       -p 8080:8080 \
#       axum-www-server
#
# Cache backend selection (--build-arg FEATURES=<value>):
#   cache-l1          Moka in-process only (default, no external backend)
#   cache-l2          Redis only
#   cache-l1-l2       Moka L1 + Redis L2
#   cache-pg          PostgreSQL only
#   cache-l1-pg       Moka L1 + PostgreSQL L2
#   cache-mysql       MySQL / MariaDB only
#   cache-l1-mysql    Moka L1 + MySQL L2
#   cache-sqlite      SQLite only
#   cache-l1-sqlite   Moka L1 + SQLite L2
# ──────────────────────────────────────────────────────────────────────────────

# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM rust:1.93-slim-bookworm AS builder

# System packages needed to compile C/C++ dependencies (ring, sqlx, etc.).
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# ── Cache Cargo registry and crate dependencies before copying source ─────────
#
# Copy only the manifests and lock files first.  Docker will cache this layer
# as long as neither file changes, avoiding a full `cargo fetch` on every build.
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY examples/www-server/Cargo.toml examples/www-server/Cargo.toml

# Create a minimal stub for the library so `cargo fetch` (and the dep-only
# compilation below) succeeds without the full source tree.
RUN mkdir -p examples/www-server/src && \
    echo 'fn main() {}' > examples/www-server/src/main.rs

# Fetch all dependencies (populates the Cargo registry cache layer).
RUN cargo fetch --manifest-path examples/www-server/Cargo.toml

# ── Copy full source and build ─────────────────────────────────────────────────
COPY . .

# FEATURES selects the cache backend compiled into the binary.
# Defaults to `cache-l1` (Moka in-process — no external backend required).
ARG FEATURES=cache-l1

RUN cargo build \
        --release \
        --manifest-path examples/www-server/Cargo.toml \
        --no-default-features \
        --features "${FEATURES}"

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# Install CA certificates so the server can reach OIDC discovery endpoints
# over HTTPS, and curl for Docker health-check probes.
# No Rust toolchain, no build tools.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Run as a non-root user.
RUN useradd --no-create-home --shell /bin/false appuser
USER appuser

COPY --from=builder /build/examples/www-server/target/release/axum-www-server /usr/local/bin/www-server

EXPOSE 8080

# Sensible defaults — override at runtime via -e / --env-file.
ENV SERVER_HOST=0.0.0.0
ENV SERVER_PORT=8080

ENTRYPOINT ["www-server"]
