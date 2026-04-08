# www-server Makefile
#
# Self-contained Makefile for the www-server (OAuth2 / OIDC front-end).
#
# Usage (from examples/www-server/ or via `make -C www-server` from examples/):
#   make                    → help
#   make run                → run with default cache (cache-l1)
#   make dev                → watch-run with auto-reload
#   make run FEATURES=cache-l2
#   make run-pg
#   make pg-up
#   … see `make help` for the full list
#
# Env file — shared with api-server, lives in examples/ (one level up):
#   ../.env.local           default (created by 'make setup')
#   ../.env.sample          template (if present)
#
# Key variables (both servers read from the same file):
#   OAUTH_ISSUER            OIDC issuer URL for autodiscovery   (recommended)
#   OAUTH_CLIENT_ID         OAuth2 client ID                    (required)
#   OAUTH_CLIENT_SECRET     OAuth2 client secret                (required)
#   OAUTH_REDIRECT_URI      Callback URI                        (default: http://localhost:8080/auth/callback)
#   PRIVATE_COOKIE_KEY      Session encryption key              (change in prod!)
#   SERVER_HOST / SERVER_PORT
#   API_SERVER              upstream api-server base URL        (default: http://127.0.0.1:8181)

# ── Variables ──────────────────────────────────────────────────────────────────

CARGO       = cargo
CARGO_WATCH = cargo-watch

# Resolve the directory of THIS Makefile so all paths work regardless of cwd.
THIS_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
MANIFEST  = --manifest-path $(THIS_DIR)Cargo.toml

# Shared env file — lives in examples/ (one level up), shared with api-server.
# Resolution order:
#   1. DOTENV_FILE (shell env or make override)
#   2. ../env.local  (default — examples/.env.local)
#   3. fallback, checked only by setup
ENV_FILE   ?= $(or $(DOTENV_FILE),$(THIS_DIR)../.env.local)
ENV_SAMPLE  = $(THIS_DIR)../.env.sample

WATCH_DELAY = 1
HOST       ?= 127.0.0.1
PORT       ?= 8080

# ── Cache feature selection ────────────────────────────────────────────────────
# Select the cache backend at compile time via FEATURES.
# Possible values:
#   cache-l1          Moka in-process only (default, no external backend)
#   cache-l2          Redis only
#   cache-l1-l2       Two-tier: Moka L1 in front of Redis L2
#   cache-pg          PostgreSQL only
#   cache-l1-pg       Two-tier: Moka L1 in front of PostgreSQL L2  ← prod recommendation
#   cache-mysql       MySQL / MariaDB only
#   cache-l1-mysql    Two-tier: Moka L1 in front of MySQL L2
#   cache-sqlite      SQLite only  (no external server required)
#   cache-l1-sqlite   Two-tier: Moka L1 in front of SQLite L2
#
# Override on the command line:
#   make run FEATURES=cache-l2
#   make dev FEATURES=cache-l1-l2
FEATURES ?= cache-l1

# Docker Compose files (relative to THIS_DIR; docker/ lives alongside www-server/)
COMPOSE_DIR     = $(THIS_DIR)../docker
COMPOSE_FILE        ?= $(COMPOSE_DIR)/docker-compose.postgres.yml
COMPOSE_FILE_MYSQL  ?= $(COMPOSE_DIR)/docker-compose.mysql.yml
COMPOSE_FILE_REDIS  ?= $(COMPOSE_DIR)/docker-compose.redis.yml
COMPOSE_FILE_SQLITE ?= $(COMPOSE_DIR)/docker-compose.sqlite.yml
COMPOSE_FILE_L1     ?= $(COMPOSE_DIR)/docker-compose.l1.yml

# Translate FEATURES into the cargo flag pair used by all targets.
CARGO_FEATURES = --no-default-features --features $(FEATURES)

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
	@echo -e "$(GREEN)www-server development commands$(NC)"
	@echo ""
	@echo -e "$(YELLOW)Setup:$(NC)"
	@echo "  make install            - Install cargo-watch"
	@echo "  make setup              - Create .env.local from sample if absent"
	@echo ""
	@echo -e "$(YELLOW)Development (honours FEATURES variable):$(NC)"
	@echo "  make dev                - Watch-run with auto-reload  (FEATURES=$(FEATURES))"
	@echo "  make run                - Run once                    (FEATURES=$(FEATURES))"
	@echo "  make watch              - Alias for 'make dev'"
	@echo ""
	@echo -e "$(YELLOW)Cache-specific run shortcuts:$(NC)"
	@echo "  make run-l1             - Moka in-process only           (cache-l1)"
	@echo "  make run-redis          - Redis only                     (cache-l2)"
	@echo "  make run-l1-redis       - Moka L1 + Redis L2             (cache-l1-l2)"
	@echo "  make run-pg             - PostgreSQL only                (cache-pg)"
	@echo "  make run-l1-pg          - Moka L1 + PostgreSQL L2        (cache-l1-pg)"
	@echo "  make run-mysql          - MySQL only                     (cache-mysql)"
	@echo "  make run-l1-mysql       - Moka L1 + MySQL L2             (cache-l1-mysql)"
	@echo "  make run-sqlite         - SQLite only                    (cache-sqlite)"
	@echo "  make run-l1-sqlite      - Moka L1 + SQLite L2            (cache-l1-sqlite)"
	@echo ""
	@echo -e "$(YELLOW)Cache-specific dev (watch) shortcuts:$(NC)"
	@echo "  make dev-l1  / dev-redis  / dev-l1-redis"
	@echo "  make dev-pg  / dev-l1-pg"
	@echo "  make dev-mysql / dev-l1-mysql"
	@echo "  make dev-sqlite / dev-l1-sqlite"
	@echo ""
	@echo -e "$(YELLOW)Build:$(NC)"
	@echo "  make build              - Debug build     (FEATURES=$(FEATURES))"
	@echo "  make release            - Release build   (FEATURES=$(FEATURES))"
	@echo "  make clean              - Remove build artefacts"
	@echo ""
	@echo -e "$(YELLOW)Cache-specific build shortcuts:$(NC)"
	@echo "  make build-l1 / build-redis / build-l1-redis"
	@echo "  make build-pg / build-l1-pg"
	@echo "  make build-mysql / build-l1-mysql"
	@echo "  make build-sqlite / build-l1-sqlite"
	@echo ""
	@echo -e "$(YELLOW)Quality:$(NC)"
	@echo "  make test               - Run tests"
	@echo "  make test-watch         - Run tests with auto-reload"
	@echo "  make check              - cargo check"
	@echo "  make fmt                - cargo fmt"
	@echo "  make clippy             - cargo clippy"
	@echo "  make lint               - fmt + clippy + check"
	@echo "  make all                - clean + lint + build + test"
	@echo ""
	@echo -e "$(YELLOW)Docker (Redis):$(NC)"
	@echo "  make redis-up           - Start Redis 7 stack"
	@echo "  make redis-down         - Stop containers (data volume preserved)"
	@echo "  make redis-destroy      - Stop containers AND delete redis_data volume"
	@echo "  make redis-logs         - Follow service logs"
	@echo "  make redis-ps           - Show service status"
	@echo "  make redis-shell        - Open redis-cli shell"
	@echo ""
	@echo -e "$(YELLOW)Docker (PostgreSQL):$(NC)"
	@echo "  make pg-up              - Start PostgreSQL 18 + pg-vacuum-cron stack"
	@echo "  make pg-down            - Stop containers (data volume preserved)"
	@echo "  make pg-destroy         - Stop containers AND delete pg_data volume"
	@echo "  make pg-logs            - Follow service logs"
	@echo "  make pg-ps              - Show service status"
	@echo "  make pg-vacuum          - Run VACUUM ANALYZE manually (one-shot)"
	@echo "  make pg-psql            - Open psql shell"
	@echo ""
	@echo -e "$(YELLOW)Docker (MySQL):$(NC)"
	@echo "  make mysql-up           - Start MySQL 8 + mysql-optimize-cron stack"
	@echo "  make mysql-down         - Stop containers (data volume preserved)"
	@echo "  make mysql-destroy      - Stop containers AND delete mysql_data volume"
	@echo "  make mysql-logs         - Follow service logs"
	@echo "  make mysql-ps           - Show service status"
	@echo "  make mysql-optimize     - Run OPTIMIZE + ANALYZE manually (one-shot)"
	@echo "  make mysql-shell        - Open mysql shell"
	@echo ""
	@echo -e "$(YELLOW)Docker (SQLite):$(NC)"
	@echo "  make sqlite-up          - Start SQLite volume + sqlite-vacuum-cron sidecar"
	@echo "  make sqlite-down        - Stop containers (data volume preserved)"
	@echo "  make sqlite-destroy     - Stop containers AND delete sqlite_data volume"
	@echo "  make sqlite-logs        - Follow service logs"
	@echo "  make sqlite-ps          - Show service status"
	@echo "  make sqlite-vacuum      - Run VACUUM + PRAGMA optimize manually (one-shot)"
	@echo "  make sqlite-shell       - Open sqlite3 shell"
	@echo ""
	@echo -e "$(YELLOW)Docker (L1 — Moka in-process, no external backend):$(NC)"
	@echo "  make l1-up              - Start api-server + www-server (cache-l1)"
	@echo "  make l1-down            - Stop containers"
	@echo "  make l1-logs            - Follow service logs"
	@echo "  make l1-ps              - Show service status"
	@echo ""
	@echo -e "$(YELLOW)Utilities:$(NC)"
	@echo "  make env                - Print active .env.local contents"
	@echo "  make clean-all          - clean + remove .env (keeps .env.local)"
	@echo ""
	@echo -e "$(BLUE)Environment / overrides:$(NC)"
	@echo "  HOST=$(HOST)        (override: HOST=0.0.0.0 make run)"
	@echo "  PORT=$(PORT)        (override: PORT=3000 make run)"
	@echo "  FEATURES=$(FEATURES)   (override: FEATURES=cache-l2 make run)"
	@echo "  ENV_FILE=$(ENV_FILE)"
	@echo "  DOTENV_FILE=<path> make run  (use a custom dotenv file)"
	@echo ""
	@echo -e "$(BLUE)Shared env file (examples/.env.local):$(NC)"
	@echo "  Shared between www-server and api-server."
	@echo "  Created by 'make setup' in examples/.env.local"
	@echo "  Override with DOTENV_FILE=<path> make run"
	@echo ""
	@echo -e "$(BLUE)Cache feature summary:$(NC)"
	@echo "  cache-l1        Moka in-process only   (default, no external backend)"
	@echo "  cache-l2        Redis only"
	@echo "  cache-l1-l2     Moka L1 + Redis L2     (two-tier)"
	@echo "  cache-pg        PostgreSQL only"
	@echo "  cache-l1-pg     Moka L1 + PG L2        (two-tier, recommended for production)"
	@echo "  cache-mysql     MySQL/MariaDB only"
	@echo "  cache-l1-mysql  Moka L1 + MySQL L2     (two-tier)"
	@echo "  cache-sqlite    SQLite only             (no external server required)"
	@echo "  cache-l1-sqlite Moka L1 + SQLite L2    (two-tier)"

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
		if [ -f "$(ENV_SAMPLE)" ]; then \
			echo -e "$(YELLOW)Creating $(ENV_FILE) from $(ENV_SAMPLE)…$(NC)"; \
			cp "$(ENV_SAMPLE)" "$(ENV_FILE)"; \
			echo -e "$(GREEN)✓ $(ENV_FILE) created$(NC)"; \
			echo -e "$(YELLOW)⚠️  Edit $(ENV_FILE) with your OAuth2 credentials$(NC)"; \
		else \
			echo -e "$(YELLOW)Creating shared $(ENV_FILE)…$(NC)"; \
			printf '# Shared configuration — used by both www-server and api-server\n'        > "$(ENV_FILE)"; \
			printf '# Edit this file with your OIDC provider credentials.\n'                  >> "$(ENV_FILE)"; \
			printf '\n'                                                                        >> "$(ENV_FILE)"; \
			printf '# ── OIDC / OAuth2 ────────────────────────────────────────────────────\n' >> "$(ENV_FILE)"; \
			printf '\n'                                                                        >> "$(ENV_FILE)"; \
			printf '# Issuer URL for OIDC autodiscovery (recommended)\n'                      >> "$(ENV_FILE)"; \
			printf '# Used by both www-server (token flow) and api-server (JWT validation)\n' >> "$(ENV_FILE)"; \
			printf '# OAUTH_ISSUER=https://accounts.google.com\n'                             >> "$(ENV_FILE)"; \
			printf '\n'                                                                        >> "$(ENV_FILE)"; \
			printf '# Or supply endpoints manually (required when OAUTH_ISSUER is not set)\n' >> "$(ENV_FILE)"; \
			printf '# OAUTH_AUTHORIZATION_ENDPOINT=https://accounts.google.com/o/oauth2/auth\n' >> "$(ENV_FILE)"; \
			printf '# OAUTH_TOKEN_ENDPOINT=https://oauth2.googleapis.com/token\n'             >> "$(ENV_FILE)"; \
			printf '\n'                                                                        >> "$(ENV_FILE)"; \
			printf '# Credentials (required by www-server)\n'                                 >> "$(ENV_FILE)"; \
			printf 'OAUTH_CLIENT_ID=your-client-id-here\n'                                    >> "$(ENV_FILE)"; \
			printf 'OAUTH_CLIENT_SECRET=your-client-secret-here\n'                            >> "$(ENV_FILE)"; \
			printf '\n'                                                                        >> "$(ENV_FILE)"; \
			printf '# Callback URI (www-server)\n'                                            >> "$(ENV_FILE)"; \
			printf 'OAUTH_REDIRECT_URI=http://localhost:$(PORT)/auth/callback\n'              >> "$(ENV_FILE)"; \
			printf '\n'                                                                        >> "$(ENV_FILE)"; \
			printf '# Session encryption key — change this in production!\n'                  >> "$(ENV_FILE)"; \
			printf '# Generate with: openssl rand -base64 64\n'                               >> "$(ENV_FILE)"; \
			printf 'PRIVATE_COOKIE_KEY=change-this-to-a-secure-random-string\n'               >> "$(ENV_FILE)"; \
			printf '\n'                                                                        >> "$(ENV_FILE)"; \
			printf '# Scopes (www-server)\n'                                                  >> "$(ENV_FILE)"; \
			printf 'OAUTH_SCOPES=openid,email,profile\n'                                      >> "$(ENV_FILE)"; \
			printf '\n'                                                                        >> "$(ENV_FILE)"; \
			printf '# ── www-server ───────────────────────────────────────────────────────\n' >> "$(ENV_FILE)"; \
			printf 'SERVER_HOST=$(HOST)\n'                                                    >> "$(ENV_FILE)"; \
			printf 'SERVER_PORT=$(PORT)\n'                                                    >> "$(ENV_FILE)"; \
			printf '\n'                                                                        >> "$(ENV_FILE)"; \
			printf '# Upstream API server base URL (used by www-server reverse proxy)\n'      >> "$(ENV_FILE)"; \
			printf 'API_SERVER=http://127.0.0.1:8181\n'                                       >> "$(ENV_FILE)"; \
			printf '\n'                                                                        >> "$(ENV_FILE)"; \
			printf '# ── api-server ───────────────────────────────────────────────────────\n' >> "$(ENV_FILE)"; \
			printf '# SERVER_HOST=127.0.0.1\n'                                                >> "$(ENV_FILE)"; \
			printf '# SERVER_PORT=8181\n'                                                     >> "$(ENV_FILE)"; \
			printf '\n'                                                                        >> "$(ENV_FILE)"; \
			printf '# Optional: PEM CA certificate for private OIDC providers\n'              >> "$(ENV_FILE)"; \
			printf '# CUSTOM_CA_CERT=/path/to/ca.pem\n'                                       >> "$(ENV_FILE)"; \
			echo -e "$(GREEN)✓ $(ENV_FILE) created with defaults$(NC)"; \
			echo -e "$(YELLOW)⚠️  Edit $(ENV_FILE) with your OAuth2 credentials$(NC)"; \
		fi \
	else \
		echo -e "$(GREEN)✓ $(ENV_FILE) already exists$(NC)"; \
	fi

# ── dev (watch-run) ────────────────────────────────────────────────────────────

.PHONY: dev
dev: install setup
	@echo -e "$(GREEN)Starting www-server with hot-reload…$(NC)"
	@echo -e "$(BLUE)  Cache feature    : $(FEATURES)$(NC)"
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
		--watch $(THIS_DIR)../../src \
		--watch $(THIS_DIR)src \
		--watch $(THIS_DIR)Cargo.toml \
		--watch "$(ENV_FILE)" \
		--ignore "*.log" \
		--ignore "target/*" \
		--why \
		-x "run $(MANIFEST) $(CARGO_FEATURES) -- --host $(HOST) --port $(PORT)"

.PHONY: watch
watch: dev

# ── Cache-specific dev shortcuts ───────────────────────────────────────────────

.PHONY: dev-l1
dev-l1:
	@$(MAKE) dev FEATURES=cache-l1

.PHONY: dev-redis
dev-redis:
	@$(MAKE) dev FEATURES=cache-l2

.PHONY: dev-l1-redis
dev-l1-redis:
	@$(MAKE) dev FEATURES=cache-l1-l2

.PHONY: dev-pg
dev-pg:
	@$(MAKE) dev FEATURES=cache-pg

.PHONY: dev-l1-pg
dev-l1-pg:
	@$(MAKE) dev FEATURES=cache-l1-pg

.PHONY: dev-mysql
dev-mysql:
	@$(MAKE) dev FEATURES=cache-mysql

.PHONY: dev-l1-mysql
dev-l1-mysql:
	@$(MAKE) dev FEATURES=cache-l1-mysql

.PHONY: dev-sqlite
dev-sqlite:
	@$(MAKE) dev FEATURES=cache-sqlite

.PHONY: dev-l1-sqlite
dev-l1-sqlite:
	@$(MAKE) dev FEATURES=cache-l1-sqlite

# ── run ────────────────────────────────────────────────────────────────────────

.PHONY: run
run: setup
	@echo -e "$(GREEN)Starting www-server (cache: $(FEATURES))…$(NC)"
	@if [ -n "$(DOTENV_FILE)" ]; then \
		echo -e "$(BLUE)Using custom dotenv file: $(DOTENV_FILE)$(NC)"; \
	fi
	@if [ ! -f "$(ENV_FILE)" ]; then \
		echo -e "$(RED)Error: $(ENV_FILE) not found. Run 'make setup' first.$(NC)"; \
		exit 1; \
	fi
	@DOTENV_FILE="$(ENV_FILE)" \
	$(CARGO) run $(MANIFEST) $(CARGO_FEATURES) -- --host $(HOST) --port $(PORT)

# ── Cache-specific run shortcuts ───────────────────────────────────────────────

.PHONY: run-l1
run-l1:
	@$(MAKE) run FEATURES=cache-l1

.PHONY: run-redis
run-redis:
	@$(MAKE) run FEATURES=cache-l2

.PHONY: run-l1-redis
run-l1-redis:
	@$(MAKE) run FEATURES=cache-l1-l2

.PHONY: run-pg
run-pg:
	@$(MAKE) run FEATURES=cache-pg

.PHONY: run-l1-pg
run-l1-pg:
	@$(MAKE) run FEATURES=cache-l1-pg

.PHONY: run-mysql
run-mysql:
	@$(MAKE) run FEATURES=cache-mysql

.PHONY: run-l1-mysql
run-l1-mysql:
	@$(MAKE) run FEATURES=cache-l1-mysql

.PHONY: run-sqlite
run-sqlite:
	@$(MAKE) run FEATURES=cache-sqlite

.PHONY: run-l1-sqlite
run-l1-sqlite:
	@$(MAKE) run FEATURES=cache-l1-sqlite

# ── build ──────────────────────────────────────────────────────────────────────

.PHONY: build
build:
	@echo -e "$(BLUE)Building www-server (debug, cache: $(FEATURES))…$(NC)"
	@$(CARGO) build $(MANIFEST) $(CARGO_FEATURES)
	@echo -e "$(GREEN)✓ Build complete$(NC)"

.PHONY: release
release:
	@echo -e "$(BLUE)Building www-server (release, cache: $(FEATURES))…$(NC)"
	@$(CARGO) build $(MANIFEST) --release $(CARGO_FEATURES)
	@echo -e "$(GREEN)✓ Release build complete$(NC)"

.PHONY: clean
clean:
	@echo -e "$(YELLOW)Cleaning www-server build artefacts…$(NC)"
	@$(CARGO) clean $(MANIFEST)
	@echo -e "$(GREEN)✓ Clean complete$(NC)"

# ── Cache-specific build shortcuts ─────────────────────────────────────────────

.PHONY: build-l1
build-l1:
	@$(MAKE) build FEATURES=cache-l1

.PHONY: build-redis
build-redis:
	@$(MAKE) build FEATURES=cache-l2

.PHONY: build-l1-redis
build-l1-redis:
	@$(MAKE) build FEATURES=cache-l1-l2

.PHONY: build-pg
build-pg:
	@$(MAKE) build FEATURES=cache-pg

.PHONY: build-l1-pg
build-l1-pg:
	@$(MAKE) build FEATURES=cache-l1-pg

.PHONY: build-mysql
build-mysql:
	@$(MAKE) build FEATURES=cache-mysql

.PHONY: build-l1-mysql
build-l1-mysql:
	@$(MAKE) build FEATURES=cache-l1-mysql

.PHONY: build-sqlite
build-sqlite:
	@$(MAKE) build FEATURES=cache-sqlite

.PHONY: build-l1-sqlite
build-l1-sqlite:
	@$(MAKE) build FEATURES=cache-l1-sqlite

# ── test ───────────────────────────────────────────────────────────────────────

.PHONY: test
test:
	@echo -e "$(BLUE)Running www-server tests…$(NC)"
	@$(CARGO) test $(MANIFEST)

.PHONY: test-watch
test-watch: install
	@echo -e "$(GREEN)Running www-server tests with hot-reload…$(NC)"
	@$(CARGO_WATCH) \
		--clear \
		--delay $(WATCH_DELAY) \
		--watch $(THIS_DIR)../../src \
		--watch $(THIS_DIR)src \
		--watch $(THIS_DIR)Cargo.toml \
		-x "test $(MANIFEST)"

# ── code quality ───────────────────────────────────────────────────────────────

.PHONY: check
check:
	@echo -e "$(BLUE)Running cargo check (cache: $(FEATURES))…$(NC)"
	@$(CARGO) check $(MANIFEST) $(CARGO_FEATURES)
	@echo -e "$(GREEN)✓ Check complete$(NC)"

.PHONY: fmt
fmt:
	@echo -e "$(BLUE)Formatting www-server…$(NC)"
	@$(CARGO) fmt $(MANIFEST)
	@echo -e "$(GREEN)✓ Format complete$(NC)"

.PHONY: clippy
clippy:
	@echo -e "$(BLUE)Running clippy (cache: $(FEATURES))…$(NC)"
	@$(CARGO) clippy $(MANIFEST) $(CARGO_FEATURES) -- -D warnings
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
	@echo -e "$(BLUE)www-server environment variables from $(ENV_FILE):$(NC)"
	@if [ -n "$(DOTENV_FILE)" ]; then \
		echo -e "$(BLUE)  (Using custom file via DOTENV_FILE)$(NC)"; \
	fi
	@if [ -f "$(ENV_FILE)" ]; then \
		grep -v '^#' "$(ENV_FILE)" | grep -v '^$$' | sed 's/^/  /'; \
	else \
		echo -e "$(YELLOW)  $(ENV_FILE) not found — run 'make setup' first$(NC)"; \
	fi

.PHONY: clean-all
clean-all: clean
	@echo -e "$(YELLOW)Removing shared .env (keeps .env.local and .env.*.example files)…$(NC)"
	@rm -f "$(THIS_DIR)../.env"
	@echo -e "$(GREEN)✓ Deep clean complete$(NC)"

# ── Docker / L1 (Moka in-process, no external backend) ────────────────────────

.PHONY: l1-up
l1-up:
	@echo -e "$(GREEN)Starting L1-only stack (api-server + www-server, no external cache)…$(NC)"
	@if [ -f "$(ENV_FILE)" ]; then \
		docker compose --env-file "$(ENV_FILE)" -f $(COMPOSE_FILE_L1) up -d --build; \
	else \
		docker compose -f $(COMPOSE_FILE_L1) up -d --build; \
	fi
	@echo -e "$(GREEN)✓ Stack started. www-server available on port $${WWW_PORT:-8080}$(NC)"
	@echo -e "$(YELLOW)  Run 'make l1-logs' to follow service logs$(NC)"

.PHONY: l1-down
l1-down:
	@echo -e "$(YELLOW)Stopping L1 stack…$(NC)"
	@docker compose -f $(COMPOSE_FILE_L1) down
	@echo -e "$(GREEN)✓ Stack stopped$(NC)"

.PHONY: l1-logs
l1-logs:
	@docker compose -f $(COMPOSE_FILE_L1) logs --follow

.PHONY: l1-ps
l1-ps:
	@docker compose -f $(COMPOSE_FILE_L1) ps

# ── shortcuts ──────────────────────────────────────────────────────────────────

.PHONY: d r t c
d: dev
r: run
t: test
c: check

# ── Docker / Redis ─────────────────────────────────────────────────────────────

.PHONY: redis-up
redis-up:
	@echo -e "$(GREEN)Starting Redis 7 stack…$(NC)"
	@if [ -f "$(ENV_FILE)" ]; then \
		docker compose --env-file "$(ENV_FILE)" -f $(COMPOSE_FILE_REDIS) up -d; \
	else \
		docker compose -f $(COMPOSE_FILE_REDIS) up -d; \
	fi
	@echo -e "$(GREEN)✓ Stack started. Redis available on port $${REDIS_PORT:-6379}$(NC)"
	@echo -e "$(YELLOW)  Run 'make redis-logs' to follow service logs$(NC)"

.PHONY: redis-down
redis-down:
	@echo -e "$(YELLOW)Stopping Redis stack (data volume preserved)…$(NC)"
	@docker compose -f $(COMPOSE_FILE_REDIS) down
	@echo -e "$(GREEN)✓ Stack stopped$(NC)"

.PHONY: redis-destroy
redis-destroy:
	@echo -e "$(RED)Destroying Redis stack AND redis_data volume…$(NC)"
	@docker compose -f $(COMPOSE_FILE_REDIS) down --volumes
	@echo -e "$(GREEN)✓ Stack and volumes removed$(NC)"

.PHONY: redis-logs
redis-logs:
	@docker compose -f $(COMPOSE_FILE_REDIS) logs --follow

.PHONY: redis-ps
redis-ps:
	@docker compose -f $(COMPOSE_FILE_REDIS) ps

.PHONY: redis-shell
redis-shell:
	@docker compose -f $(COMPOSE_FILE_REDIS) exec redis redis-cli

# ── Docker / PostgreSQL ────────────────────────────────────────────────────────

.PHONY: pg-up
pg-up:
	@echo -e "$(GREEN)Starting PostgreSQL 18 + pg-vacuum-cron stack…$(NC)"
	@if [ -f "$(ENV_FILE)" ]; then \
		docker compose --env-file "$(ENV_FILE)" -f $(COMPOSE_FILE) up -d --build; \
	else \
		docker compose -f $(COMPOSE_FILE) up -d --build; \
	fi
	@echo -e "$(GREEN)✓ Stack started. PostgreSQL available on port $${POSTGRES_PORT:-5432}$(NC)"
	@echo -e "$(YELLOW)  Run 'make pg-logs' to follow service logs$(NC)"

.PHONY: pg-down
pg-down:
	@echo -e "$(YELLOW)Stopping PostgreSQL stack (data volume preserved)…$(NC)"
	@docker compose -f $(COMPOSE_FILE) down
	@echo -e "$(GREEN)✓ Stack stopped$(NC)"

.PHONY: pg-destroy
pg-destroy:
	@echo -e "$(RED)Destroying PostgreSQL stack AND pg_data volume…$(NC)"
	@docker compose -f $(COMPOSE_FILE) down --volumes
	@echo -e "$(GREEN)✓ Stack and volumes removed$(NC)"

.PHONY: pg-logs
pg-logs:
	@docker compose -f $(COMPOSE_FILE) logs --follow

.PHONY: pg-ps
pg-ps:
	@docker compose -f $(COMPOSE_FILE) ps

.PHONY: pg-vacuum
pg-vacuum:
	@echo -e "$(BLUE)Running manual VACUUM ANALYZE oidc_cache…$(NC)"
	@docker compose -f $(COMPOSE_FILE) exec postgres \
		psql \
			--username="$${POSTGRES_USER:-oidc_user}" \
			--dbname="$${POSTGRES_DB:-oidc_cache}" \
			--command="VACUUM ANALYZE oidc_cache; SELECT relname, n_dead_tup, n_live_tup, last_vacuum, last_analyze FROM pg_stat_user_tables WHERE relname = 'oidc_cache';"
	@echo -e "$(GREEN)✓ VACUUM ANALYZE complete$(NC)"

.PHONY: pg-psql
pg-psql:
	@docker compose -f $(COMPOSE_FILE) exec postgres \
		psql \
			--username="$${POSTGRES_USER:-oidc_user}" \
			--dbname="$${POSTGRES_DB:-oidc_cache}"

# ── Docker / MySQL ─────────────────────────────────────────────────────────────

.PHONY: mysql-up
mysql-up:
	@echo -e "$(GREEN)Starting MySQL 8 + mysql-optimize-cron stack…$(NC)"
	@if [ -f "$(ENV_FILE)" ]; then \
		docker compose --env-file "$(ENV_FILE)" -f $(COMPOSE_FILE_MYSQL) up -d --build; \
	else \
		docker compose -f $(COMPOSE_FILE_MYSQL) up -d --build; \
	fi
	@echo -e "$(GREEN)✓ Stack started. MySQL available on port $${MYSQL_PORT:-3306}$(NC)"
	@echo -e "$(YELLOW)  Run 'make mysql-logs' to follow service logs$(NC)"

.PHONY: mysql-down
mysql-down:
	@echo -e "$(YELLOW)Stopping MySQL stack (data volume preserved)…$(NC)"
	@docker compose -f $(COMPOSE_FILE_MYSQL) down
	@echo -e "$(GREEN)✓ Stack stopped$(NC)"

.PHONY: mysql-destroy
mysql-destroy:
	@echo -e "$(RED)Destroying MySQL stack AND mysql_data volume…$(NC)"
	@docker compose -f $(COMPOSE_FILE_MYSQL) down --volumes
	@echo -e "$(GREEN)✓ Stack and volumes removed$(NC)"

.PHONY: mysql-logs
mysql-logs:
	@docker compose -f $(COMPOSE_FILE_MYSQL) logs --follow

.PHONY: mysql-ps
mysql-ps:
	@docker compose -f $(COMPOSE_FILE_MYSQL) ps

.PHONY: mysql-optimize
mysql-optimize:
	@echo -e "$(BLUE)Running manual OPTIMIZE TABLE + ANALYZE TABLE oidc_cache…$(NC)"
	@docker compose -f $(COMPOSE_FILE_MYSQL) exec mysql \
		mysql \
			--user="$${MYSQL_USER:-oidc_user}" \
			--password="$${MYSQL_PASSWORD:-oidc_pass}" \
			--database="$${MYSQL_DATABASE:-oidc_cache}" \
			--execute="OPTIMIZE TABLE oidc_cache; ANALYZE TABLE oidc_cache; SELECT table_name, table_rows, ROUND(data_length/1024/1024,3) AS data_mb, ROUND(data_free/1024/1024,3) AS free_mb FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='oidc_cache';"
	@echo -e "$(GREEN)✓ OPTIMIZE + ANALYZE complete$(NC)"

.PHONY: mysql-shell
mysql-shell:
	@docker compose -f $(COMPOSE_FILE_MYSQL) exec mysql \
		mysql \
			--user="$${MYSQL_USER:-oidc_user}" \
			--password="$${MYSQL_PASSWORD:-oidc_pass}" \
			--database="$${MYSQL_DATABASE:-oidc_cache}"

# ── Docker / SQLite ────────────────────────────────────────────────────────────

.PHONY: sqlite-up
sqlite-up:
	@echo -e "$(GREEN)Starting SQLite volume + sqlite-vacuum-cron stack…$(NC)"
	@if [ -f "$(ENV_FILE)" ]; then \
		docker compose --env-file "$(ENV_FILE)" -f $(COMPOSE_FILE_SQLITE) up -d --build; \
	else \
		docker compose -f $(COMPOSE_FILE_SQLITE) up -d --build; \
	fi
	@echo -e "$(GREEN)✓ Stack started$(NC)"
	@echo -e "$(YELLOW)  Set SQLITE_URL=sqlite:////data/oidc_cache.db in .env.local$(NC)"
	@echo -e "$(YELLOW)  Run 'make sqlite-logs' to follow service logs$(NC)"

.PHONY: sqlite-down
sqlite-down:
	@echo -e "$(YELLOW)Stopping SQLite stack (data volume preserved)…$(NC)"
	@docker compose -f $(COMPOSE_FILE_SQLITE) down
	@echo -e "$(GREEN)✓ Stack stopped$(NC)"

.PHONY: sqlite-destroy
sqlite-destroy:
	@echo -e "$(RED)Destroying SQLite stack AND sqlite_data volume…$(NC)"
	@docker compose -f $(COMPOSE_FILE_SQLITE) down --volumes
	@echo -e "$(GREEN)✓ Stack and volumes removed$(NC)"

.PHONY: sqlite-logs
sqlite-logs:
	@docker compose -f $(COMPOSE_FILE_SQLITE) logs --follow

.PHONY: sqlite-ps
sqlite-ps:
	@docker compose -f $(COMPOSE_FILE_SQLITE) ps

.PHONY: sqlite-vacuum
sqlite-vacuum:
	@echo -e "$(BLUE)Running manual VACUUM + PRAGMA optimize on SQLite database…$(NC)"
	@docker compose -f $(COMPOSE_FILE_SQLITE) exec sqlite-vacuum-cron \
		su-exec cronuser /usr/local/bin/vacuum.sh
	@echo -e "$(GREEN)✓ VACUUM + PRAGMA optimize complete$(NC)"

.PHONY: sqlite-shell
sqlite-shell:
	@docker compose -f $(COMPOSE_FILE_SQLITE) run --rm sqlite-tools \
		sqlite3 /data/oidc_cache.db
