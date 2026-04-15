#!/usr/bin/env bash
# post-create.sh — Run once after the devcontainer is first created.
#
# Sets up the Oxigate workspace:
#   1. Ensures rustup and the stable toolchain are up to date
#   2. Installs Node.js dependencies for the example services
#   3. Generates TLS certificates for the example environment
#   4. Runs a cargo check to warm up the build cache
#   5. Runs cargo audit to surface any known vulnerabilities
#   6. Prints a summary of the environment

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
BOLD=$(tput bold    2>/dev/null || true)
GREEN=$(tput setaf 2 2>/dev/null || true)
CYAN=$(tput setaf  6 2>/dev/null || true)
YELLOW=$(tput setaf 3 2>/dev/null || true)
RESET=$(tput sgr0   2>/dev/null || true)

step()  { echo "${CYAN}${BOLD}» ${1}${RESET}"; }
ok()    { echo "${GREEN}${BOLD}✓ ${1}${RESET}"; }
warn()  { echo "${YELLOW}${BOLD}⚠ ${1}${RESET}"; }

# Workspace root is the directory that contains this script's parent (.devcontainer).
WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${WORKSPACE_ROOT}"

echo ""
echo "${BOLD}━━━  Oxigate devcontainer setup  ━━━${RESET}"
echo ""

# ── 1. Rust toolchain ─────────────────────────────────────────────────────────
step "Updating rustup and the stable toolchain…"
rustup self update 2>/dev/null || true   # may be read-only in some envs
rustup update stable --no-self-update
rustup component add rustfmt clippy rust-src rust-analyzer 2>/dev/null || true
ok "Rust $(rustc --version)"

# ── 2. Node.js dependencies for example services ──────────────────────────────
step "Installing Node.js dependencies for example/backend…"
if [ -f "example/backend/package.json" ]; then
    (cd example/backend && npm install --prefer-offline 2>/dev/null || npm install)
    ok "example/backend node_modules installed"
else
    warn "example/backend/package.json not found — skipping"
fi

step "Installing Node.js dependencies for example/cdn-service…"
if [ -f "example/cdn-service/package.json" ]; then
    (cd example/cdn-service && npm install --prefer-offline 2>/dev/null || npm install)
    ok "example/cdn-service node_modules installed"
else
    warn "example/cdn-service/package.json not found — skipping"
fi

# ── 3. TLS certificates for the example environment ───────────────────────────
step "Generating TLS certificates for the example environment…"
if [ -f "example/gen-certs.sh" ]; then
    if [ ! -f "example/certs/server.crt" ]; then
        chmod +x example/gen-certs.sh
        (cd example && ./gen-certs.sh)
        ok "TLS certificates generated in example/certs/"
    else
        ok "TLS certificates already exist — skipping generation"
    fi
else
    warn "example/gen-certs.sh not found — skipping certificate generation"
fi

# ── 4. Create example .env if it doesn't exist ────────────────────────────────
step "Setting up example/.env…"
if [ -f "example/.env.example" ] && [ ! -f "example/.env" ]; then
    cp example/.env.example example/.env
    # Generate a strong random cookie encryption key.
    COOKIE_KEY=$(openssl rand -base64 48 2>/dev/null || head -c 48 /dev/urandom | base64)
    # Replace the placeholder with the generated key (portable sed).
    sed -i "s|COOKIE_ENCRYPTION_KEY=change-me-to-a-random-string-at-least-32-chars!!|COOKIE_ENCRYPTION_KEY=${COOKIE_KEY}|" example/.env
    ok "example/.env created from .env.example (COOKIE_ENCRYPTION_KEY auto-generated)"
    warn "Edit example/.env and set OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, GATEWAY_HOSTNAME"
elif [ -f "example/.env" ]; then
    ok "example/.env already exists — skipping"
else
    warn "example/.env.example not found — skipping .env creation"
fi

# ── 5. Warm up the Cargo build cache ──────────────────────────────────────────
step "Running cargo check to warm up the build cache (this may take a while on first run)…"
cargo check --workspace --message-format=short 2>&1 | tail -5 || true
ok "Build cache warmed"

# ── 6. Security audit ─────────────────────────────────────────────────────────
step "Running cargo audit for known vulnerabilities…"
if command -v cargo-audit &>/dev/null; then
    cargo audit --color always 2>&1 || warn "cargo audit reported issues — review the output above"
else
    warn "cargo-audit not installed — skipping vulnerability scan"
fi

# ── 7. Deny check ─────────────────────────────────────────────────────────────
step "Checking license and dependency policy (cargo deny)…"
if command -v cargo-deny &>/dev/null; then
    if [ -f "deny.toml" ]; then
        cargo deny check 2>&1 || warn "cargo deny reported issues — review the output above"
    else
        warn "deny.toml not found — skipping cargo deny check"
    fi
else
    warn "cargo-deny not installed — skipping policy check"
fi

# ── 8. Environment summary ────────────────────────────────────────────────────
echo ""
echo "${BOLD}━━━  Environment summary  ━━━${RESET}"
echo ""
printf "  %-24s %s\n" "Rust:"       "$(rustc --version 2>/dev/null)"
printf "  %-24s %s\n" "Cargo:"      "$(cargo --version 2>/dev/null)"
printf "  %-24s %s\n" "Node.js:"    "$(node --version 2>/dev/null)"
printf "  %-24s %s\n" "npm:"        "$(npm --version 2>/dev/null)"
printf "  %-24s %s\n" "OpenSSL:"    "$(openssl version 2>/dev/null)"
printf "  %-24s %s\n" "Docker CLI:" "$(docker --version 2>/dev/null || echo 'not available')"
printf "  %-24s %s\n" "Make:"       "$(make --version 2>/dev/null | head -1)"
printf "  %-24s %s\n" "Git:"        "$(git --version 2>/dev/null)"
echo ""
echo "${GREEN}${BOLD}Devcontainer ready.${RESET}  To start the example stack:"
echo ""
echo "  cd example"
echo "  make up-build"
echo ""
