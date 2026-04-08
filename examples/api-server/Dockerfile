# ──────────────────────────────────────────────────────────────────────────────
# api-server Dockerfile
#
# Multi-stage build:
#   1. builder  – compiles the binary using the full Rust toolchain
#   2. runtime  – copies only the binary into a minimal Debian image
#
# Build context must be the repository root (axum-oidc-client/) so that the
# workspace crate referenced via `path = "../.."` is available.
#
# Build:
#   docker build -f examples/api-server/Dockerfile \
#       -t axum-api-server .
#
# Run:
#   docker run --rm \
#       -e JWT_ISSUER=https://accounts.google.com \
#       -p 8181:8181 \
#       axum-api-server
# ──────────────────────────────────────────────────────────────────────────────

# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM rust:1.93-slim-bookworm AS builder

# System packages needed to compile C/C++ dependencies (ring, etc.).
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
COPY examples/api-server/Cargo.toml examples/api-server/Cargo.toml

# Create a minimal stub so `cargo fetch` succeeds without the full source tree.
RUN mkdir -p examples/api-server/src && \
    echo 'fn main() {}' > examples/api-server/src/main.rs

# Fetch all dependencies (populates the Cargo registry cache layer).
RUN cargo fetch --manifest-path examples/api-server/Cargo.toml

# ── Copy full source and build ─────────────────────────────────────────────────
COPY . .

# The `jwt` feature is declared directly in examples/api-server/Cargo.toml
# as a dependency feature on axum-oidc-client, so no --features flag is needed.
RUN cargo build \
        --release \
        --manifest-path examples/api-server/Cargo.toml

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

COPY --from=builder /build/examples/api-server/target/release/axum-api-server /usr/local/bin/api-server

EXPOSE 8181

# Sensible defaults — override at runtime via -e / --env-file.
ENV SERVER_HOST=0.0.0.0
ENV SERVER_PORT=8181

ENTRYPOINT ["api-server"]
