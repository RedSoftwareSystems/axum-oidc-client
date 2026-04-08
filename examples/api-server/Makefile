# api-server Makefile
#
# Provides convenient commands for developing and running the api-server.
#
# Usage (from either examples/ or examples/api-server/):
#   make               → help
#   make run           → run the server (reads shared ENV_FILE for defaults)
#   make dev           → watch-run with auto-reload on source changes
#   make setup         → ensure the shared .env.local exists (create if absent)
#   make env           → print the active .env.local contents
#
# Env file — shared with www-server, lives in examples/ (one level up):
#   ../.env.local           default (created by 'make setup' or www-server setup)
#
# Key variables read from the shared file:
#   OAUTH_ISSUER       OIDC issuer URL for JWT validation  (required)
#   CUSTOM_CA_CERT     path to PEM CA cert                  (optional)
#   SERVER_HOST        bind address                         (default: 127.0.0.1)
#   SERVER_PORT        bind port                            (default: 8181)

# ── Variables ──────────────────────────────────────────────────────────────────

CARGO       = cargo
CARGO_WATCH = cargo-watch

# Resolve the directory of THIS Makefile so targets work regardless of cwd.
THIS_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
MANIFEST  = --manifest-path $(THIS_DIR)Cargo.toml

# Shared env file — lives in examples/ (one level up), shared with www-server.
# Resolution order:
#   1. DOTENV_FILE (shell env or make override)
#   2. ../env.local  (default — examples/.env.local)
ENV_FILE  ?= $(or $(DOTENV_FILE),$(THIS_DIR)../.env.local)
ENV_SAMPLE = $(THIS_DIR)../.env.sample

WATCH_DELAY = 1
HOST ?= 127.0.0.1
PORT ?= 8181

# ── Colours ────────────────────────────────────────────────────────────────────

RED    = \033[0;31m
GREEN  = \033[0;32m
YELLOW = \033[1;33m
BLUE   = \033[0;34m
NC     = \033[0m

# ── Default target ─────────────────────────────────────────────────────────────

.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo -e "$(GREEN)api-server development commands$(NC)"
	@echo ""
	@echo -e "$(YELLOW)Setup:$(NC)"
	@echo "  make install       - Install cargo-watch"
	@echo "  make setup         - Create .env.local from .env.sample if absent"
	@echo ""
	@echo -e "$(YELLOW)Development:$(NC)"
	@echo "  make dev           - Watch-run with auto-reload on source changes"
	@echo "  make run           - Run the server once"
	@echo "  make watch         - Alias for 'make dev'"
	@echo ""
	@echo -e "$(YELLOW)Build:$(NC)"
	@echo "  make build         - Build in debug mode"
	@echo "  make release       - Build in release mode"
	@echo "  make clean         - Remove build artefacts"
	@echo ""
	@echo -e "$(YELLOW)Quality:$(NC)"
	@echo "  make test          - Run tests"
	@echo "  make test-watch    - Run tests with auto-reload"
	@echo "  make check         - cargo check"
	@echo "  make fmt           - cargo fmt"
	@echo "  make clippy        - cargo clippy"
	@echo "  make lint          - fmt + clippy + check"
	@echo ""
	@echo -e "$(YELLOW)Utilities:$(NC)"
	@echo "  make env           - Print active .env.local contents"
	@echo ""
	@echo -e "$(BLUE)Environment / overrides:$(NC)"
	@echo "  HOST=$(HOST)      (override: HOST=0.0.0.0 make run)"
	@echo "  PORT=$(PORT)      (override: PORT=9090 make run)"
	@echo "  ENV_FILE=$(ENV_FILE)"
	@echo "  DOTENV_FILE=<path> make run   (use a custom dotenv file)"
	@echo ""
	@echo -e "$(BLUE)Shared env file (examples/.env.local):$(NC)"
	@echo "  Shared between api-server and www-server."
	@echo "  Run 'make setup' (or www-server 'make setup') to create it."
	@echo "  Override with DOTENV_FILE=<path> make run"
	@echo ""
	@echo -e "$(BLUE)Required configuration (in shared .env.local):$(NC)"
	@echo "  OAUTH_ISSUER     OIDC issuer URL  (e.g. https://accounts.google.com)"
	@echo ""
	@echo -e "$(BLUE)Optional configuration:$(NC)"
	@echo "  CUSTOM_CA_CERT   Path to a PEM CA certificate for private OIDC providers"
	@echo "  SERVER_HOST      Bind address          (default: 127.0.0.1)"
	@echo "  SERVER_PORT      Bind port             (default: 8181)"

# ── install ────────────────────────────────────────────────────────────────────

.PHONY: install
install:
	@echo -e "$(BLUE)Checking for cargo-watch…$(NC)"
	@if ! command -v cargo-watch > /dev/null 2>&1; then \
		echo -e "$(YELLOW)Installing cargo-watch…$(NC)"; \
		$(CARGO) install cargo-watch; \
		echo -e "$(GREEN)✓ cargo-watch installed$(NC)"; \
	else \
		echo -e "$(GREEN)✓ cargo-watch already installed$(NC)"; \
	fi

# ── setup ──────────────────────────────────────────────────────────────────────

.PHONY: setup
setup:
	@if [ -n "$(DOTENV_FILE)" ]; then \
		echo -e "$(BLUE)Note: using custom env file DOTENV_FILE=$(DOTENV_FILE)$(NC)"; \
	fi
	@if [ ! -f "$(ENV_FILE)" ]; then \
		echo -e "$(YELLOW)Shared env file $(ENV_FILE) not found.$(NC)"; \
		echo -e "$(YELLOW)Run 'make setup' from examples/ or examples/www-server/ to create it,$(NC)"; \
		echo -e "$(YELLOW)or create it manually and set at least OAUTH_ISSUER.$(NC)"; \
		echo -e "$(YELLOW)Continuing without it — set DOTENV_FILE or create the file before running.$(NC)"; \
	else \
		echo -e "$(GREEN)✓ Shared env file found: $(ENV_FILE)$(NC)"; \
	fi

# ── dev (watch-run) ────────────────────────────────────────────────────────────

.PHONY: dev
dev: install setup
	@echo -e "$(GREEN)Starting api-server with hot-reload…$(NC)"
	@echo -e "$(BLUE)  Environment file : $(ENV_FILE)$(NC)"
	@echo -e "$(BLUE)  Server           : http://$(HOST):$(PORT)$(NC)"
	@echo -e "$(YELLOW)  Press Ctrl-C to stop$(NC)"
	@echo ""
	@if [ ! -f "$(ENV_FILE)" ]; then \
		echo -e "$(RED)Error: $(ENV_FILE) not found. Run 'make setup' first.$(NC)"; \
		exit 1; \
	fi
	@DOTENV_FILE="$(ENV_FILE)" \
	$(CARGO_WATCH) \
		--clear \
		--delay $(WATCH_DELAY) \
		--watch $(THIS_DIR)../src \
		--watch $(THIS_DIR)src \
		--watch $(THIS_DIR)Cargo.toml \
		--watch "$(ENV_FILE)" \
		--ignore "*.log" \
		--ignore "target/*" \
		--why \
		-x "run $(MANIFEST) -- --host $(HOST) --port $(PORT)"

.PHONY: watch
watch: dev

# ── run ────────────────────────────────────────────────────────────────────────

.PHONY: run
run: setup
	@echo -e "$(GREEN)Starting api-server…$(NC)"
	@if [ -n "$(DOTENV_FILE)" ]; then \
		echo -e "$(BLUE)Using custom dotenv file: $(DOTENV_FILE)$(NC)"; \
	fi
	@if [ ! -f "$(ENV_FILE)" ]; then \
		echo -e "$(RED)Error: $(ENV_FILE) not found. Run 'make setup' first.$(NC)"; \
		exit 1; \
	fi
	@DOTENV_FILE="$(ENV_FILE)" \
	$(CARGO) run $(MANIFEST) -- --host $(HOST) --port $(PORT)

# ── build ──────────────────────────────────────────────────────────────────────

.PHONY: build
build:
	@echo -e "$(BLUE)Building api-server (debug)…$(NC)"
	@$(CARGO) build $(MANIFEST)
	@echo -e "$(GREEN)✓ Build complete$(NC)"

.PHONY: release
release:
	@echo -e "$(BLUE)Building api-server (release)…$(NC)"
	@$(CARGO) build $(MANIFEST) --release
	@echo -e "$(GREEN)✓ Release build complete$(NC)"

.PHONY: clean
clean:
	@echo -e "$(YELLOW)Cleaning build artefacts…$(NC)"
	@$(CARGO) clean $(MANIFEST)
	@echo -e "$(GREEN)✓ Clean complete$(NC)"

# ── test ───────────────────────────────────────────────────────────────────────

.PHONY: test
test:
	@echo -e "$(BLUE)Running tests…$(NC)"
	@$(CARGO) test $(MANIFEST)

.PHONY: test-watch
test-watch: install
	@echo -e "$(GREEN)Running tests with hot-reload…$(NC)"
	@$(CARGO_WATCH) \
		--clear \
		--delay $(WATCH_DELAY) \
		--watch $(THIS_DIR)../src \
		--watch $(THIS_DIR)src \
		--watch $(THIS_DIR)Cargo.toml \
		-x "test $(MANIFEST)"

# ── code quality ───────────────────────────────────────────────────────────────

.PHONY: check
check:
	@echo -e "$(BLUE)Running cargo check…$(NC)"
	@$(CARGO) check $(MANIFEST)
	@echo -e "$(GREEN)✓ Check complete$(NC)"

.PHONY: fmt
fmt:
	@echo -e "$(BLUE)Formatting code…$(NC)"
	@$(CARGO) fmt $(MANIFEST)
	@echo -e "$(GREEN)✓ Format complete$(NC)"

.PHONY: clippy
clippy:
	@echo -e "$(BLUE)Running clippy…$(NC)"
	@$(CARGO) clippy $(MANIFEST) -- -D warnings
	@echo -e "$(GREEN)✓ Clippy complete$(NC)"

.PHONY: lint
lint: fmt clippy check
	@echo -e "$(GREEN)✓ All linting complete$(NC)"

.PHONY: all
all: clean lint build test
	@echo -e "$(GREEN)✓ Full build and test complete$(NC)"

# ── utilities ──────────────────────────────────────────────────────────────────

.PHONY: env
env:
	@echo -e "$(BLUE)Environment variables from $(ENV_FILE):$(NC)"
	@if [ -n "$(DOTENV_FILE)" ]; then \
		echo -e "$(BLUE)  (Using custom file via DOTENV_FILE)$(NC)"; \
	fi
	@if [ -f "$(ENV_FILE)" ]; then \
		grep -v '^#' "$(ENV_FILE)" | grep -v '^$$' | sed 's/^/  /'; \
	else \
		echo -e "$(YELLOW)  $(ENV_FILE) not found — run 'make setup' first$(NC)"; \
	fi

# ── shortcuts ──────────────────────────────────────────────────────────────────

.PHONY: d r t c
d: dev
r: run
t: test
c: check
