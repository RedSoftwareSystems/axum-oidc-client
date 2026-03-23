# Sample Server Development Makefile
# This Makefile provides convenient commands for development with hot-reloading

# Variables
CARGO = cargo
CARGO_WATCH = cargo-watch
# Allow override via environment variable
ENV_FILE ?= $(or $(DOTENV_FILE),.env.local)
ENV_SAMPLE = .env.sample
WATCH_DELAY = 1
PORT ?= 8080
HOST ?= 127.0.0.1

# ── Cache feature selection ────────────────────────────────────────────────────
# Select the cache backend at compile time via FEATURES.
# Possible values:
#   cache-l1        Moka in-process only (default, no Redis required)
#   cache-l2        Redis only
#   cache-l1-l2     Two-tier: Moka L1 in front of Redis L2
#   cache-pg        PostgreSQL only (no in-process L1 layer)
#   cache-l1-pg     Two-tier: Moka L1 in front of PostgreSQL L2
#   cache-mysql     MySQL / MariaDB only (no in-process L1 layer)
#   cache-l1-mysql  Two-tier: Moka L1 in front of MySQL L2
#
# Override on the command line:
#   make run FEATURES=cache-l2
#   make dev FEATURES=cache-l1-l2
#   make run-pg              # PostgreSQL-only cache
#   make run-l1-pg           # Moka L1 + PostgreSQL L2 (recommended production)
#   make run-mysql           # MySQL-only cache
#   make run-l1-mysql        # Moka L1 + MySQL L2 (recommended production)
#
FEATURES ?= cache-l1

# Docker Compose file for the PostgreSQL stack.
COMPOSE_FILE ?= docker/docker-compose.postgres.yml

# Docker Compose file for the MySQL stack.
COMPOSE_FILE_MYSQL ?= docker/docker-compose.mysql.yml

# Docker Compose file for the Redis stack.
COMPOSE_FILE_REDIS ?= docker/docker-compose.redis.yml

# Docker Compose file for the SQLite stack.
COMPOSE_FILE_SQLITE ?= docker/docker-compose.sqlite.yml
# Translate FEATURES into the cargo flag pair used by all targets below.
CARGO_FEATURES = --no-default-features --features $(FEATURES)

# ──────────────────────────────────────────────────────────────────────────────

# Color output
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[1;33m
BLUE = \033[0;34m
NC = \033[0m # No Color

# Default target
.PHONY: help
help:
	@echo -e "$(GREEN)Sample Server Development Commands$(NC)"
	@echo ""
	@echo -e "$(YELLOW)Setup:$(NC)"
	@echo "  make install         - Install cargo-watch and dependencies"
	@echo "  make setup           - Create .env.local from sample if it doesn't exist"
	@echo ""
	@echo -e "$(YELLOW)Development (generic – honours FEATURES variable):$(NC)"
	@echo "  make dev             - Run with cargo-watch (auto-reload on changes)"
	@echo "  make run             - Run without watching"
	@echo "  make watch           - Alias for 'make dev'"
	@echo ""
	@echo -e "$(YELLOW)Cache-specific shortcuts:$(NC)"
	@echo "  make run-redis       - Run with Redis-only cache        (cache-l2)"
	@echo "  make run-l1          - Run with Moka in-process cache   (cache-l1, no Redis needed)"
	@echo "  make run-l1-redis    - Run with two-tier cache          (cache-l1-l2)"
	@echo "  make run-pg          - Run with PostgreSQL-only cache      (cache-pg)"
	@echo "  make run-l1-pg       - Run with Moka L1 + PG L2 cache     (cache-l1-pg)"
	@echo "  make run-mysql       - Run with MySQL-only cache           (cache-mysql)"
	@echo "  make run-l1-mysql    - Run with Moka L1 + MySQL L2 cache  (cache-l1-mysql)"
	@echo "  make dev-redis       - Watch-run with Redis-only cache"
	@echo "  make dev-l1          - Watch-run with Moka in-process cache"
	@echo "  make dev-l1-redis    - Watch-run with two-tier cache"
	@echo "  make dev-pg          - Watch-run with PostgreSQL-only cache"
	@echo "  make dev-l1-pg       - Watch-run with Moka L1 + PostgreSQL L2 cache"
	@echo "  make dev-mysql       - Watch-run with MySQL-only cache"
	@echo "  make dev-l1-mysql    - Watch-run with Moka L1 + MySQL L2 cache"
	@echo "  make run-sqlite      - Run with SQLite-only cache          (cache-sqlite)"
	@echo "  make run-l1-sqlite   - Run with Moka L1 + SQLite L2 cache (cache-l1-sqlite)"
	@echo "  make dev-sqlite      - Watch-run with SQLite-only cache"
	@echo "  make dev-l1-sqlite   - Watch-run with Moka L1 + SQLite L2 cache"
	@echo "  make build-sqlite    - Build with SQLite-only cache"
	@echo "  make build-l1-sqlite - Build with Moka L1 + SQLite L2 cache"
	@echo "  make build-redis     - Build with Redis-only cache"
	@echo "  make build-l1        - Build with Moka in-process cache"
	@echo "  make build-l1-redis  - Build with two-tier cache"
	@echo "  make build-pg        - Build with PostgreSQL-only cache"
	@echo "  make build-l1-pg     - Build with Moka L1 + PostgreSQL L2 cache"
	@echo "  make build-mysql     - Build with MySQL-only cache"
	@echo "  make build-l1-mysql  - Build with Moka L1 + MySQL L2 cache"
	@echo ""
	@echo ""
	@echo -e "$(YELLOW)Docker (Redis):$(NC)"
	@echo "  make redis-up        - Start the Redis 7 stack"
	@echo "  make redis-down      - Stop and remove containers (data volume preserved)"
	@echo "  make redis-destroy   - Stop containers AND delete the redis_data volume"
	@echo "  make redis-logs      - Follow logs from all Redis Compose services"
	@echo "  make redis-ps        - Show status of Redis Compose services"
	@echo "  make redis-shell     - Open an interactive redis-cli shell inside the container"
	@echo ""
	@echo -e "$(YELLOW)Docker (PostgreSQL):$(NC)"
	@echo "  make pg-up           - Start the PostgreSQL 18 + pg-vacuum-cron stack"
	@echo "  make pg-down         - Stop and remove containers (data volume preserved)"
	@echo "  make pg-destroy      - Stop containers AND delete the pg_data volume"
	@echo "  make pg-logs         - Follow logs from all Docker Compose services"
	@echo "  make pg-ps           - Show status of Docker Compose services"
	@echo "  make pg-vacuum       - Run VACUUM ANALYZE manually (one-shot)"
	@echo "  make pg-psql         - Open a psql shell inside the postgres container"
	@echo ""
	@echo -e "$(YELLOW)Docker (MySQL):$(NC)"
	@echo "  make mysql-up        - Start the MySQL 8 + mysql-optimize-cron stack"
	@echo "  make mysql-down      - Stop and remove containers (data volume preserved)"
	@echo "  make mysql-destroy   - Stop containers AND delete the mysql_data volume"
	@echo "  make mysql-logs      - Follow logs from all MySQL Compose services"
	@echo "  make mysql-ps        - Show status of MySQL Compose services"
	@echo "  make mysql-optimize  - Run OPTIMIZE + ANALYZE manually (one-shot)"
	@echo "  make mysql-shell     - Open an interactive mysql shell inside the container"
	@echo ""
	@echo -e "$(YELLOW)Docker (SQLite):$(NC)"
	@echo "  make sqlite-up       - Create the SQLite data directory and volume"
	@echo "  make sqlite-down     - Stop and remove the SQLite container"
	@echo "  make sqlite-destroy  - Remove the SQLite data volume (destructive!)"
	@echo "  make sqlite-logs     - Follow logs from the SQLite Compose services"
	@echo "  make sqlite-ps       - Show status of SQLite Compose services"
	@echo "  make sqlite-vacuum   - Run VACUUM + PRAGMA optimize manually (one-shot)"
	@echo "  make sqlite-shell    - Open a sqlite3 shell on the cache database"
	@echo ""
	@echo -e "$(YELLOW)Build:$(NC)"
	@echo "  make build           - Build in debug mode (uses FEATURES=$(FEATURES))"
	@echo "  make release         - Build in release mode"
	@echo "  make clean           - Clean build artifacts"
	@echo ""
	@echo -e "$(YELLOW)Testing:$(NC)"
	@echo "  make test            - Run tests"
	@echo "  make test-watch      - Run tests with auto-reload"
	@echo ""
	@echo -e "$(YELLOW)Utilities:$(NC)"
	@echo "  make check           - Check code (cargo check)"
	@echo "  make fmt             - Format code"
	@echo "  make clippy          - Run clippy linter"
	@echo "  make env             - Show current environment variables"
	@echo ""
	@echo -e "$(YELLOW)Environment / overrides:$(NC)"
	@echo "  PORT=$(PORT)    (override with PORT=3000 make dev)"
	@echo "  HOST=$(HOST) (override with HOST=0.0.0.0 make dev)"
	@echo "  FEATURES=$(FEATURES)  (override with FEATURES=cache-l2 make run)"
	@echo "  ENV_FILE=$(ENV_FILE)  (override with DOTENV_FILE=.env.prod make dev)"
	@echo ""
	@echo -e "$(BLUE)Priority for .env files:$(NC)"
	@echo "  1. DOTENV_FILE environment variable (if set)"
	@echo "  2. .env.local (default)"
	@echo "  3. .env (fallback)"
	@echo ""
	@echo -e "$(BLUE)Cache feature summary:$(NC)"
	@echo "  cache-l1      Moka in-process only  (default, no external backend)"
	@echo "  cache-l2      Redis only            (requires Redis)     → use run-redis / dev-redis / build-redis"
	@echo "  cache-l1-l2   Moka L1 + Redis L2    (two-tier, requires Redis) → use run-l1-redis / dev-l1-redis / build-l1-redis"
	@echo "  cache-pg        PostgreSQL only       (requires PostgreSQL)"
	@echo "  cache-l1-pg     Moka L1 + PG L2       (two-tier, requires PostgreSQL)"
	@echo "  cache-mysql     MySQL/MariaDB only     (requires MySQL or MariaDB)"
	@echo "  cache-l1-mysql  Moka L1 + MySQL L2    (two-tier, requires MySQL or MariaDB)"
	@echo "  cache-sqlite    SQLite only            (no external server required)"
	@echo "  cache-l1-sqlite Moka L1 + SQLite L2    (two-tier, no external server)"

# Install cargo-watch if not already installed
.PHONY: install
install:
	@echo -e "$(BLUE)Checking for cargo-watch...$(NC)"
	@if ! command -v cargo-watch &> /dev/null; then \
		echo -e "$(YELLOW)Installing cargo-watch...$(NC)"; \
		$(CARGO) install cargo-watch; \
		echo -e "$(GREEN)✓ cargo-watch installed$(NC)"; \
	else \
		echo -e "$(GREEN)✓ cargo-watch already installed$(NC)"; \
	fi
	@echo -e "$(BLUE)Installing project dependencies...$(NC)"
	@$(CARGO) build
	@echo -e "$(GREEN)✓ Dependencies installed$(NC)"

# Setup environment file
.PHONY: setup
setup:
	@if [ -n "$(DOTENV_FILE)" ]; then \
		echo -e "$(BLUE)Note: Using custom env file from DOTENV_FILE=$(DOTENV_FILE)$(NC)"; \
	fi
	@if [ ! -f $(ENV_FILE) ]; then \
		if [ -f $(ENV_SAMPLE) ]; then \
			echo -e "$(YELLOW)Creating $(ENV_FILE) from $(ENV_SAMPLE)...$(NC)"; \
			cp $(ENV_SAMPLE) $(ENV_FILE); \
			echo -e "$(GREEN)✓ $(ENV_FILE) created$(NC)"; \
			echo -e "$(YELLOW)⚠️  Please edit $(ENV_FILE) with your OAuth2 credentials$(NC)"; \
		else \
			echo -e "$(YELLOW)Creating default $(ENV_FILE)...$(NC)"; \
			echo "# OAuth2 Configuration" > $(ENV_FILE); \
			echo "OAUTH_AUTHORIZATION_ENDPOINT=https://accounts.google.com/o/oauth2/auth" >> $(ENV_FILE); \
			echo "OAUTH_TOKEN_ENDPOINT=https://oauth2.googleapis.com/token" >> $(ENV_FILE); \
			echo "OAUTH_CLIENT_ID=your-client-id-here" >> $(ENV_FILE); \
			echo "OAUTH_CLIENT_SECRET=your-client-secret-here" >> $(ENV_FILE); \
			echo "OAUTH_REDIRECT_URI=http://localhost:$(PORT)/auth/callback" >> $(ENV_FILE); \
			echo "OAUTH_SCOPES=openid,email,profile" >> $(ENV_FILE); \
			echo "PRIVATE_COOKIE_KEY=change-this-to-a-secure-random-string" >> $(ENV_FILE); \
			echo "CODE_CHALLENGE_METHOD=S256" >> $(ENV_FILE); \
			echo "SERVER_HOST=$(HOST)" >> $(ENV_FILE); \
			echo "SERVER_PORT=$(PORT)" >> $(ENV_FILE); \
			echo -e "$(GREEN)✓ $(ENV_FILE) created with defaults$(NC)"; \
			echo -e "$(YELLOW)⚠️  Please edit $(ENV_FILE) with your OAuth2 credentials$(NC)"; \
		fi \
	else \
		echo -e "$(GREEN)✓ $(ENV_FILE) already exists$(NC)"; \
	fi

# Development server with hot-reloading
.PHONY: dev
dev: install setup
	@echo -e "$(GREEN)Starting development server with hot-reloading...$(NC)"
	@echo -e "$(BLUE)Configuration:$(NC)"
	@echo "  • Cache feature:  $(FEATURES)"
	@echo "  • Watching for file changes"
	@echo "  • Debounce delay: $(WATCH_DELAY) second"
	@echo "  • Environment file: $(ENV_FILE)"
	@echo "  • Server: http://$(HOST):$(PORT)"
	@echo ""
	@echo -e "$(YELLOW)Press Ctrl+C to stop$(NC)"
	@echo ""
	@if [ -n "$(DOTENV_FILE)" ]; then \
		echo -e "$(BLUE)Using custom dotenv file: $(DOTENV_FILE)$(NC)"; \
	fi
	@if [ -f $(ENV_FILE) ]; then \
		DOTENV_FILE=$(ENV_FILE) \
		$(CARGO_WATCH) \
			--clear \
			--delay $(WATCH_DELAY) \
			--watch ../../src \
			--watch src \
			--watch Cargo.toml \
			--watch $(ENV_FILE) \
			--ignore "*.log" \
			--ignore "target/*" \
			--why \
			-x "run $(CARGO_FEATURES) -- --host $(HOST) --port $(PORT)"; \
	else \
		echo -e "$(RED)Error: $(ENV_FILE) not found. Run 'make setup' first.$(NC)"; \
		exit 1; \
	fi

# ── Cache-specific dev targets ─────────────────────────────────────────────────
.PHONY: dev-redis
dev-redis:
	@$(MAKE) dev FEATURES=cache-l2

.PHONY: dev-l1
dev-l1:
	@$(MAKE) dev FEATURES=cache-l1

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

# Alias for dev
.PHONY: watch
watch: dev

# Run without watching
.PHONY: run
run: setup
	@echo -e "$(GREEN)Starting server (cache: $(FEATURES))...$(NC)"
	@if [ -n "$(DOTENV_FILE)" ]; then \
		echo -e "$(BLUE)Using custom dotenv file: $(DOTENV_FILE)$(NC)"; \
	fi
	@if [ -f $(ENV_FILE) ]; then \
		DOTENV_FILE=$(ENV_FILE) $(CARGO) run $(CARGO_FEATURES) -- --host $(HOST) --port $(PORT); \
	else \
		echo -e "$(RED)Error: $(ENV_FILE) not found. Run 'make setup' first.$(NC)"; \
		exit 1; \
	fi

# ── Cache-specific run targets ─────────────────────────────────────────────────
.PHONY: run-redis
run-redis:
	@$(MAKE) run FEATURES=cache-l2

.PHONY: run-l1
run-l1:
	@$(MAKE) run FEATURES=cache-l1

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

# Build commands
.PHONY: build
build:
	@echo -e "$(BLUE)Building in debug mode (cache: $(FEATURES))...$(NC)"
	@$(CARGO) build $(CARGO_FEATURES)
	@echo -e "$(GREEN)✓ Build complete$(NC)"

# ── Cache-specific build targets ───────────────────────────────────────────────
.PHONY: build-redis
build-redis:
	@$(MAKE) build FEATURES=cache-l2

.PHONY: build-l1
build-l1:
	@$(MAKE) build FEATURES=cache-l1

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

# ── Docker / Redis targets ─────────────────────────────────────────────────────

## Start the Redis 7 Docker Compose stack.
.PHONY: redis-up
redis-up:
	@echo -e "$(GREEN)Starting Redis 7 stack...$(NC)"
	@if [ -f $(ENV_FILE) ]; then \
		docker compose --env-file $(ENV_FILE) -f $(COMPOSE_FILE_REDIS) up -d; \
	else \
		docker compose -f $(COMPOSE_FILE_REDIS) up -d; \
	fi
	@echo -e "$(GREEN)✓ Stack started. Redis available on port $${REDIS_PORT:-6379}$(NC)"
	@echo -e "$(YELLOW)  Run 'make redis-logs' to follow service logs$(NC)"

## Stop the Redis stack but preserve the redis_data volume.
.PHONY: redis-down
redis-down:
	@echo -e "$(YELLOW)Stopping Redis Compose stack (data volume preserved)...$(NC)"
	@docker compose -f $(COMPOSE_FILE_REDIS) down
	@echo -e "$(GREEN)✓ Stack stopped$(NC)"

## Stop the Redis stack AND delete the redis_data volume (destructive).
.PHONY: redis-destroy
redis-destroy:
	@echo -e "$(RED)Destroying Redis Compose stack AND redis_data volume...$(NC)"
	@docker compose -f $(COMPOSE_FILE_REDIS) down --volumes
	@echo -e "$(GREEN)✓ Stack and volumes removed$(NC)"

## Follow logs from all Redis Compose services (Ctrl-C to stop).
.PHONY: redis-logs
redis-logs:
	@docker compose -f $(COMPOSE_FILE_REDIS) logs --follow

## Show the status of all Redis Compose services.
.PHONY: redis-ps
redis-ps:
	@docker compose -f $(COMPOSE_FILE_REDIS) ps

## Open an interactive redis-cli shell inside the redis container.
.PHONY: redis-shell
redis-shell:
	@docker compose -f $(COMPOSE_FILE_REDIS) exec redis redis-cli

# ── Docker / PostgreSQL targets ────────────────────────────────────────────────

## Start the PostgreSQL 18 + pg-vacuum-cron Docker Compose stack.
## On first run this creates the pg_data volume and runs the init SQL scripts.
.PHONY: pg-up
pg-up:
	@echo -e "$(GREEN)Starting PostgreSQL 18 + pg-vacuum-cron stack...$(NC)"
	@if [ -f $(ENV_FILE) ]; then \
		docker compose --env-file $(ENV_FILE) -f $(COMPOSE_FILE) up -d --build; \
	else \
		docker compose -f $(COMPOSE_FILE) up -d --build; \
	fi
	@echo -e "$(GREEN)✓ Stack started. PostgreSQL available on port $${POSTGRES_PORT:-5432}$(NC)"
	@echo -e "$(YELLOW)  Run 'make pg-logs' to follow service logs$(NC)"

## Stop the stack but preserve the pg_data volume.
.PHONY: pg-down
pg-down:
	@echo -e "$(YELLOW)Stopping Docker Compose stack (data volume preserved)...$(NC)"
	@docker compose -f $(COMPOSE_FILE) down
	@echo -e "$(GREEN)✓ Stack stopped$(NC)"

## Stop the stack AND delete the pg_data volume (destructive — all cache data lost).
.PHONY: pg-destroy
pg-destroy:
	@echo -e "$(RED)Destroying Docker Compose stack AND pg_data volume...$(NC)"
	@docker compose -f $(COMPOSE_FILE) down --volumes
	@echo -e "$(GREEN)✓ Stack and volumes removed$(NC)"

## Follow logs from all Compose services (Ctrl-C to stop).
.PHONY: pg-logs
pg-logs:
	@docker compose -f $(COMPOSE_FILE) logs --follow

## Show the status of all Compose services.
.PHONY: pg-ps
pg-ps:
	@docker compose -f $(COMPOSE_FILE) ps

## Run a one-shot VACUUM ANALYZE on oidc_cache (useful for testing/debugging).
.PHONY: pg-vacuum
pg-vacuum:
	@echo -e "$(BLUE)Running manual VACUUM ANALYZE oidc_cache...$(NC)"
	@docker compose -f $(COMPOSE_FILE) exec postgres \
		psql \
			--username="$${POSTGRES_USER:-oidc_user}" \
			--dbname="$${POSTGRES_DB:-oidc_cache}" \
			--command="VACUUM ANALYZE oidc_cache; SELECT relname, n_dead_tup, n_live_tup, last_vacuum, last_analyze FROM pg_stat_user_tables WHERE relname = 'oidc_cache';"
	@echo -e "$(GREEN)✓ VACUUM ANALYZE complete$(NC)"

## Open an interactive psql shell inside the postgres container.
.PHONY: pg-psql
pg-psql:
	@docker compose -f $(COMPOSE_FILE) exec postgres \
		psql \
			--username="$${POSTGRES_USER:-oidc_user}" \
			--dbname="$${POSTGRES_DB:-oidc_cache}"

# ── Docker / MySQL targets ─────────────────────────────────────────────────────

## Start the MySQL 8 + mysql-optimize-cron Docker Compose stack.
## On first run this creates the mysql_data volume and runs the init SQL scripts.
.PHONY: mysql-up
mysql-up:
	@echo -e "$(GREEN)Starting MySQL 8 + mysql-optimize-cron stack...$(NC)"
	@if [ -f $(ENV_FILE) ]; then \
		docker compose --env-file $(ENV_FILE) -f $(COMPOSE_FILE_MYSQL) up -d --build; \
	else \
		docker compose -f $(COMPOSE_FILE_MYSQL) up -d --build; \
	fi
	@echo -e "$(GREEN)✓ Stack started. MySQL available on port $${MYSQL_PORT:-3306}$(NC)"
	@echo -e "$(YELLOW)  Run 'make mysql-logs' to follow service logs$(NC)"

## Stop the MySQL stack but preserve the mysql_data volume.
.PHONY: mysql-down
mysql-down:
	@echo -e "$(YELLOW)Stopping MySQL Compose stack (data volume preserved)...$(NC)"
	@docker compose -f $(COMPOSE_FILE_MYSQL) down
	@echo -e "$(GREEN)✓ Stack stopped$(NC)"

## Stop the MySQL stack AND delete the mysql_data volume (destructive).
.PHONY: mysql-destroy
mysql-destroy:
	@echo -e "$(RED)Destroying MySQL Compose stack AND mysql_data volume...$(NC)"
	@docker compose -f $(COMPOSE_FILE_MYSQL) down --volumes
	@echo -e "$(GREEN)✓ Stack and volumes removed$(NC)"

## Follow logs from all MySQL Compose services (Ctrl-C to stop).
.PHONY: mysql-logs
mysql-logs:
	@docker compose -f $(COMPOSE_FILE_MYSQL) logs --follow

## Show the status of all MySQL Compose services.
.PHONY: mysql-ps
mysql-ps:
	@docker compose -f $(COMPOSE_FILE_MYSQL) ps

## Run a one-shot OPTIMIZE TABLE + ANALYZE TABLE on oidc_cache (useful for testing/debugging).
.PHONY: mysql-optimize
mysql-optimize:
	@echo -e "$(BLUE)Running manual OPTIMIZE TABLE + ANALYZE TABLE oidc_cache...$(NC)"
	@docker compose -f $(COMPOSE_FILE_MYSQL) exec mysql \
		mysql \
			--user="$${MYSQL_USER:-oidc_user}" \
			--password="$${MYSQL_PASSWORD:-oidc_pass}" \
			--database="$${MYSQL_DATABASE:-oidc_cache}" \
			--execute="OPTIMIZE TABLE oidc_cache; ANALYZE TABLE oidc_cache; SELECT table_name, table_rows, ROUND(data_length/1024/1024,3) AS data_mb, ROUND(data_free/1024/1024,3) AS free_mb FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='oidc_cache';"
	@echo -e "$(GREEN)✓ OPTIMIZE + ANALYZE complete$(NC)"

## Open an interactive mysql shell inside the mysql container.
.PHONY: mysql-shell
mysql-shell:
	@docker compose -f $(COMPOSE_FILE_MYSQL) exec mysql \
		mysql \
			--user="$${MYSQL_USER:-oidc_user}" \
			--password="$${MYSQL_PASSWORD:-oidc_pass}" \
			--database="$${MYSQL_DATABASE:-oidc_cache}"

# ── Docker / SQLite targets ────────────────────────────────────────────────────
#
# SQLite needs no server — the database is a plain file on disk.
# These targets manage a named Docker volume (`sqlite_data`) and a bind-mount
# directory so the cache file survives container restarts.
#
# The docker-compose.sqlite.yml file mounts the volume at /data inside the
# app container.  Set SQLITE_URL=sqlite:////data/oidc_cache.db in .env.local
# to point the sample-server at that path.

## Start the SQLite volume + sqlite-vacuum-cron sidecar.
.PHONY: sqlite-up
sqlite-up:
	@echo -e "$(GREEN)Starting SQLite volume + sqlite-vacuum-cron stack...$(NC)"
	@if [ -f $(ENV_FILE) ]; then \
		docker compose --env-file $(ENV_FILE) -f $(COMPOSE_FILE_SQLITE) up -d --build; \
	else \
		docker compose -f $(COMPOSE_FILE_SQLITE) up -d --build; \
	fi
	@echo -e "$(GREEN)✓ Stack started$(NC)"
	@echo -e "$(YELLOW)  Set SQLITE_URL=sqlite:////data/oidc_cache.db in .env.local$(NC)"
	@echo -e "$(YELLOW)  Run 'make sqlite-logs' to follow service logs$(NC)"

## Stop the SQLite stack (data volume preserved).
.PHONY: sqlite-down
sqlite-down:
	@echo -e "$(YELLOW)Stopping SQLite Compose stack (data volume preserved)...$(NC)"
	@docker compose -f $(COMPOSE_FILE_SQLITE) down
	@echo -e "$(GREEN)✓ Stack stopped$(NC)"

## Stop the SQLite stack AND delete the sqlite_data volume (destructive).
.PHONY: sqlite-destroy
sqlite-destroy:
	@echo -e "$(RED)Destroying SQLite Compose stack AND sqlite_data volume...$(NC)"
	@docker compose -f $(COMPOSE_FILE_SQLITE) down --volumes
	@echo -e "$(GREEN)✓ Stack and volumes removed$(NC)"

## Follow logs from all SQLite Compose services (Ctrl-C to stop).
.PHONY: sqlite-logs
sqlite-logs:
	@docker compose -f $(COMPOSE_FILE_SQLITE) logs --follow

## Show status of all SQLite Compose services.
.PHONY: sqlite-ps
sqlite-ps:
	@docker compose -f $(COMPOSE_FILE_SQLITE) ps

## Run a one-shot VACUUM + PRAGMA optimize on the SQLite database (useful for testing/debugging).
.PHONY: sqlite-vacuum
sqlite-vacuum:
	@echo -e "$(BLUE)Running manual VACUUM + PRAGMA optimize on SQLite database...$(NC)"
	@docker compose -f $(COMPOSE_FILE_SQLITE) exec sqlite-vacuum-cron \
		su-exec cronuser /usr/local/bin/vacuum.sh
	@echo -e "$(GREEN)✓ VACUUM + PRAGMA optimize complete$(NC)"

## Open an interactive sqlite3 shell on the cache database.
.PHONY: sqlite-shell
sqlite-shell:
	@docker compose -f $(COMPOSE_FILE_SQLITE) run --rm sqlite-tools \
		sqlite3 /data/oidc_cache.db

.PHONY: release
release:
	@echo -e "$(BLUE)Building in release mode (cache: $(FEATURES))...$(NC)"
	@$(CARGO) build --release $(CARGO_FEATURES)
	@echo -e "$(GREEN)✓ Release build complete$(NC)"

.PHONY: clean
clean:
	@echo -e "$(YELLOW)Cleaning build artifacts...$(NC)"
	@$(CARGO) clean
	@echo -e "$(GREEN)✓ Clean complete$(NC)"

# Testing
.PHONY: test
test:
	@echo -e "$(BLUE)Running tests...$(NC)"
	@$(CARGO) test

.PHONY: test-watch
test-watch: install
	@echo -e "$(GREEN)Running tests with hot-reloading...$(NC)"
	@$(CARGO_WATCH) \
		--clear \
		--delay $(WATCH_DELAY) \
		--watch ../../src \
		--watch src \
		--watch Cargo.toml \
		-x test

# Code quality
.PHONY: check
check:
	@echo -e "$(BLUE)Running cargo check (cache: $(FEATURES))...$(NC)"
	@$(CARGO) check $(CARGO_FEATURES)
	@echo -e "$(GREEN)✓ Check complete$(NC)"

.PHONY: fmt
fmt:
	@echo -e "$(BLUE)Formatting code...$(NC)"
	@$(CARGO) fmt
	@echo -e "$(GREEN)✓ Format complete$(NC)"

.PHONY: clippy
clippy:
	@echo -e "$(BLUE)Running clippy (cache: $(FEATURES))...$(NC)"
	@$(CARGO) clippy $(CARGO_FEATURES) -- -D warnings
	@echo -e "$(GREEN)✓ Clippy complete$(NC)"

# Show environment variables
.PHONY: env
env:
	@echo -e "$(BLUE)Environment variables from $(ENV_FILE):$(NC)"
	@if [ -n "$(DOTENV_FILE)" ]; then \
		echo -e "$(BLUE)  (Using custom file via DOTENV_FILE)$(NC)"; \
	fi
	@if [ -f $(ENV_FILE) ]; then \
		grep -v '^#' $(ENV_FILE) | grep -v '^$$' | sed 's/^/  /'; \
	else \
		echo -e "$(YELLOW)$(ENV_FILE) not found$(NC)"; \
	fi

# Quick development shortcuts
.PHONY: d
d: dev

.PHONY: r
r: run

.PHONY: t
t: test

.PHONY: c
c: check

# Combination commands
.PHONY: lint
lint: fmt clippy check
	@echo -e "$(GREEN)✓ All linting complete$(NC)"

.PHONY: all
all: clean lint build test
	@echo -e "$(GREEN)✓ Full build and test complete$(NC)"

# Clean all including .env files (use with caution)
.PHONY: clean-all
clean-all: clean
	@echo -e "$(YELLOW)Removing .env files (except .env.sample and .env.example)...$(NC)"
	@rm -f .env
	@echo -e "$(YELLOW)Note: .env.local preserved for security$(NC)"
	@echo -e "$(GREEN)✓ Deep clean complete$(NC)"

.DEFAULT_GOAL := help
