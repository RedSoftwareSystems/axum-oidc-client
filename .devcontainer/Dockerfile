# ── Oxigate devcontainer ─────────────────────────────────────────────────────
# Base: Microsoft's official Rust devcontainer image on Debian 12 Bookworm.
# Provides: rustup, cargo, rust-analyzer, git, common dev utilities.
#
# Node.js and Docker CLI are installed via devcontainer features (see
# devcontainer.json) rather than here, so this Dockerfile only handles
# Rust-specific tooling and system packages.
ARG RUST_VERSION=1
FROM mcr.microsoft.com/devcontainers/rust:${RUST_VERSION}-bookworm

# ── System packages ───────────────────────────────────────────────────────────
# Install in a single layer to minimise image size.
RUN apt-get update && apt-get install -y --no-install-recommends \
    # ── OpenSSL (required by native-tls / reqwest) ──────────────────────────
    pkg-config \
    libssl-dev \
    openssl \
    # ── TLS / certificate utilities ─────────────────────────────────────────
    ca-certificates \
    # ── Build essentials ────────────────────────────────────────────────────
    build-essential \
    cmake \
    # ── Network & debugging ─────────────────────────────────────────────────
    curl \
    wget \
    # ── Shell utilities ──────────────────────────────────────────────────────
    bash-completion \
    make \
    jq \
    # ── Git extras ───────────────────────────────────────────────────────────
    git \
    git-lfs \
    # ── Process / system utilities ───────────────────────────────────────────
    procps \
    lsof \
    htop \
    # ── Security tools ───────────────────────────────────────────────────────
    gnupg2 \
    && rm -rf /var/lib/apt/lists/*

# ── Rust toolchain extras (run as the devcontainer user) ─────────────────────
USER vscode

# Update rustup and install the stable toolchain components.
RUN rustup update stable \
    && rustup component add \
        rustfmt \
        clippy \
        rust-src \
        rust-analyzer

# Cargo tools for development productivity and security auditing.
RUN cargo install --locked \
        cargo-watch      \
        cargo-nextest    \
        cargo-audit      \
        cargo-deny       \
        cargo-expand     \
        cargo-outdated   \
        cargo-edit

# ── Shell environment ─────────────────────────────────────────────────────────
ENV PATH="/home/vscode/.cargo/bin:${PATH}"

# ── Verify key tools are present ─────────────────────────────────────────────
RUN rustc --version \
    && cargo --version \
    && openssl version

# Return to root so the devcontainer entrypoint can run setup scripts.
USER root
