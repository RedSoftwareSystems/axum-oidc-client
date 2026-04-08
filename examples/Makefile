# Examples — Docker Compose Makefile
#
# Manages the Docker Compose stacks for the axum-oidc-client examples.
# All cargo / development targets live in the sub-Makefiles:
#   www-server/Makefile   → make -C www-server help
#   api-server/Makefile   → make -C api-server help
#
# Env file — shared between www-server and api-server:
#   examples/.env.local   default (created by 'make setup' in either sub-dir)
#   Override: DOTENV_FILE=<path> make <target>
#
# Usage:
#   make                   → this help
#   make l1-up             → start L1-only stack (no external backend)
#   make pg-up             → start PostgreSQL stack
#   make redis-up          → start Redis stack
#   make mysql-up          → start MySQL stack
#   make sqlite-up         → start SQLite stack

# ── Variables ──────────────────────────────────────────────────────────────────

# Shared env file — lives in examples/, passed to every docker compose call.
ENV_FILE ?= $(or $(DOTENV_FILE),.env.local)

# Host-side port exposed by www-server (override: WWW_PORT=9090 make l1-up)
WWW_PORT ?= 8080

# Docker Compose file paths
DOCKER_DIR          = docker
COMPOSE_L1          = $(DOCKER_DIR)/docker-compose.l1.yml
COMPOSE_REDIS       = $(DOCKER_DIR)/docker-compose.redis.yml
COMPOSE_POSTGRES    = $(DOCKER_DIR)/docker-compose.postgres.yml
COMPOSE_MYSQL       = $(DOCKER_DIR)/docker-compose.mysql.yml
COMPOSE_SQLITE      = $(DOCKER_DIR)/docker-compose.sqlite.yml

# Internal helper: run docker compose with the shared env file when it exists.
define dc
	$(if $(wildcard $(ENV_FILE)), \
		docker compose --env-file "$(ENV_FILE)" -f $(1), \
		docker compose -f $(1))
endef

# ── Colours ────────────────────────────────────────────────────────────────────

RED    = \033[0;31m
GREEN  = \033[0;32m
YELLOW = \033[1;33m
BLUE   = \033[0;34m
NC     = \033[0m

# ── Default target ─────────────────────────────────────────────────────────────

.DEFAULT_GOAL := help

# ── help ───────────────────────────────────────────────────────────────────────

.PHONY: help
help:
	@echo -e "$(GREEN)Examples — Docker Compose targets$(NC)"
	@echo -e "$(BLUE)For cargo targets (run, dev, build, test, …) use the sub-Makefiles:$(NC)"
	@echo "  make -C www-server help"
	@echo "  make -C api-server help"
	@echo ""
	@echo -e "$(YELLOW)L1 — Moka in-process (no external backend):$(NC)"
	@echo "  make l1-up           - Build and start api-server + www-server"
	@echo "  make l1-down         - Stop containers"
	@echo "  make l1-logs         - Follow logs"
	@echo "  make l1-ps           - Show service status"
	@echo ""
	@echo -e "$(YELLOW)Redis:$(NC)"
	@echo "  make redis-up        - Build and start Redis + api-server + www-server"
	@echo "  make redis-down      - Stop containers (data volume preserved)"
	@echo "  make redis-destroy   - Stop containers AND delete redis_data volume"
	@echo "  make redis-logs      - Follow logs"
	@echo "  make redis-ps        - Show service status"
	@echo "  make redis-shell     - Open redis-cli shell"
	@echo ""
	@echo -e "$(YELLOW)PostgreSQL:$(NC)"
	@echo "  make pg-up           - Build and start PostgreSQL + api-server + www-server"
	@echo "  make pg-down         - Stop containers (data volume preserved)"
	@echo "  make pg-destroy      - Stop containers AND delete pg_data volume"
	@echo "  make pg-logs         - Follow logs"
	@echo "  make pg-ps           - Show service status"
	@echo "  make pg-vacuum       - Run VACUUM ANALYZE manually (one-shot)"
	@echo "  make pg-psql         - Open psql shell"
	@echo ""
	@echo -e "$(YELLOW)MySQL:$(NC)"
	@echo "  make mysql-up        - Build and start MySQL + api-server + www-server"
	@echo "  make mysql-down      - Stop containers (data volume preserved)"
	@echo "  make mysql-destroy   - Stop containers AND delete mysql_data volume"
	@echo "  make mysql-logs      - Follow logs"
	@echo "  make mysql-ps        - Show service status"
	@echo "  make mysql-optimize  - Run OPTIMIZE + ANALYZE manually (one-shot)"
	@echo "  make mysql-shell     - Open mysql shell"
	@echo ""
	@echo -e "$(YELLOW)SQLite:$(NC)"
	@echo "  make sqlite-up       - Build and start SQLite + api-server + www-server"
	@echo "  make sqlite-down     - Stop containers (data volume preserved)"
	@echo "  make sqlite-destroy  - Stop containers AND delete sqlite_data volume"
	@echo "  make sqlite-logs     - Follow logs"
	@echo "  make sqlite-ps       - Show service status"
	@echo "  make sqlite-vacuum   - Run VACUUM + PRAGMA optimize manually (one-shot)"
	@echo "  make sqlite-shell    - Open sqlite3 shell"
	@echo ""
	@echo -e "$(BLUE)Variable overrides:$(NC)"
	@echo "  WWW_PORT=$(WWW_PORT)        host-side port for www-server"
	@echo "  DOTENV_FILE=<path>    shared env file (default: $(ENV_FILE))"

# ── L1 (Moka in-process, no external backend) ─────────────────────────────────

.PHONY: l1-up
l1-up:
	@echo -e "$(GREEN)Starting L1 stack (api-server + www-server, no external cache)…$(NC)"
	@$(call dc,$(COMPOSE_L1)) up -d --build
	@echo -e "$(GREEN)✓ Stack started — http://localhost:$(WWW_PORT)$(NC)"
	@echo -e "$(YELLOW)  Run 'make l1-logs' to follow service logs$(NC)"

.PHONY: l1-down
l1-down:
	@echo -e "$(YELLOW)Stopping L1 stack…$(NC)"
	@$(call dc,$(COMPOSE_L1)) down
	@echo -e "$(GREEN)✓ Stopped$(NC)"

.PHONY: l1-logs
l1-logs:
	@$(call dc,$(COMPOSE_L1)) logs --follow

.PHONY: l1-ps
l1-ps:
	@$(call dc,$(COMPOSE_L1)) ps

# ── Redis ──────────────────────────────────────────────────────────────────────

.PHONY: redis-up
redis-up:
	@echo -e "$(GREEN)Starting Redis stack…$(NC)"
	@$(call dc,$(COMPOSE_REDIS)) up -d --build
	@echo -e "$(GREEN)✓ Stack started — http://localhost:$(WWW_PORT)$(NC)"
	@echo -e "$(YELLOW)  Run 'make redis-logs' to follow service logs$(NC)"

.PHONY: redis-down
redis-down:
	@echo -e "$(YELLOW)Stopping Redis stack (data volume preserved)…$(NC)"
	@$(call dc,$(COMPOSE_REDIS)) down
	@echo -e "$(GREEN)✓ Stopped$(NC)"

.PHONY: redis-destroy
redis-destroy:
	@echo -e "$(RED)Destroying Redis stack AND redis_data volume…$(NC)"
	@$(call dc,$(COMPOSE_REDIS)) down --volumes
	@echo -e "$(GREEN)✓ Stack and volumes removed$(NC)"

.PHONY: redis-logs
redis-logs:
	@$(call dc,$(COMPOSE_REDIS)) logs --follow

.PHONY: redis-ps
redis-ps:
	@$(call dc,$(COMPOSE_REDIS)) ps

.PHONY: redis-shell
redis-shell:
	@$(call dc,$(COMPOSE_REDIS)) exec redis redis-cli

# ── PostgreSQL ─────────────────────────────────────────────────────────────────

.PHONY: pg-up
pg-up:
	@echo -e "$(GREEN)Starting PostgreSQL stack…$(NC)"
	@$(call dc,$(COMPOSE_POSTGRES)) up -d --build
	@echo -e "$(GREEN)✓ Stack started — http://localhost:$(WWW_PORT)$(NC)"
	@echo -e "$(YELLOW)  Run 'make pg-logs' to follow service logs$(NC)"

.PHONY: pg-down
pg-down:
	@echo -e "$(YELLOW)Stopping PostgreSQL stack (data volume preserved)…$(NC)"
	@$(call dc,$(COMPOSE_POSTGRES)) down
	@echo -e "$(GREEN)✓ Stopped$(NC)"

.PHONY: pg-destroy
pg-destroy:
	@echo -e "$(RED)Destroying PostgreSQL stack AND pg_data volume…$(NC)"
	@$(call dc,$(COMPOSE_POSTGRES)) down --volumes
	@echo -e "$(GREEN)✓ Stack and volumes removed$(NC)"

.PHONY: pg-logs
pg-logs:
	@$(call dc,$(COMPOSE_POSTGRES)) logs --follow

.PHONY: pg-ps
pg-ps:
	@$(call dc,$(COMPOSE_POSTGRES)) ps

.PHONY: pg-vacuum
pg-vacuum:
	@echo -e "$(BLUE)Running manual VACUUM ANALYZE oidc_cache…$(NC)"
	@$(call dc,$(COMPOSE_POSTGRES)) exec postgres \
		psql \
			--username="$${POSTGRES_USER:-oidc_user}" \
			--dbname="$${POSTGRES_DB:-oidc_cache}" \
			--command="VACUUM ANALYZE oidc_cache; SELECT relname, n_dead_tup, n_live_tup, last_vacuum, last_analyze FROM pg_stat_user_tables WHERE relname = 'oidc_cache';"
	@echo -e "$(GREEN)✓ VACUUM ANALYZE complete$(NC)"

.PHONY: pg-psql
pg-psql:
	@$(call dc,$(COMPOSE_POSTGRES)) exec postgres \
		psql \
			--username="$${POSTGRES_USER:-oidc_user}" \
			--dbname="$${POSTGRES_DB:-oidc_cache}"

# ── MySQL ──────────────────────────────────────────────────────────────────────

.PHONY: mysql-up
mysql-up:
	@echo -e "$(GREEN)Starting MySQL stack…$(NC)"
	@$(call dc,$(COMPOSE_MYSQL)) up -d --build
	@echo -e "$(GREEN)✓ Stack started — http://localhost:$(WWW_PORT)$(NC)"
	@echo -e "$(YELLOW)  Run 'make mysql-logs' to follow service logs$(NC)"

.PHONY: mysql-down
mysql-down:
	@echo -e "$(YELLOW)Stopping MySQL stack (data volume preserved)…$(NC)"
	@$(call dc,$(COMPOSE_MYSQL)) down
	@echo -e "$(GREEN)✓ Stopped$(NC)"

.PHONY: mysql-destroy
mysql-destroy:
	@echo -e "$(RED)Destroying MySQL stack AND mysql_data volume…$(NC)"
	@$(call dc,$(COMPOSE_MYSQL)) down --volumes
	@echo -e "$(GREEN)✓ Stack and volumes removed$(NC)"

.PHONY: mysql-logs
mysql-logs:
	@$(call dc,$(COMPOSE_MYSQL)) logs --follow

.PHONY: mysql-ps
mysql-ps:
	@$(call dc,$(COMPOSE_MYSQL)) ps

.PHONY: mysql-optimize
mysql-optimize:
	@echo -e "$(BLUE)Running manual OPTIMIZE TABLE + ANALYZE TABLE oidc_cache…$(NC)"
	@$(call dc,$(COMPOSE_MYSQL)) exec mysql \
		mysql \
			--user="$${MYSQL_USER:-oidc_user}" \
			--password="$${MYSQL_PASSWORD:-oidc_pass}" \
			--database="$${MYSQL_DATABASE:-oidc_cache}" \
			--execute="OPTIMIZE TABLE oidc_cache; ANALYZE TABLE oidc_cache;"
	@echo -e "$(GREEN)✓ OPTIMIZE + ANALYZE complete$(NC)"

.PHONY: mysql-shell
mysql-shell:
	@$(call dc,$(COMPOSE_MYSQL)) exec mysql \
		mysql \
			--user="$${MYSQL_USER:-oidc_user}" \
			--password="$${MYSQL_PASSWORD:-oidc_pass}" \
			--database="$${MYSQL_DATABASE:-oidc_cache}"

# ── SQLite ─────────────────────────────────────────────────────────────────────

.PHONY: sqlite-up
sqlite-up:
	@echo -e "$(GREEN)Starting SQLite stack…$(NC)"
	@$(call dc,$(COMPOSE_SQLITE)) up -d --build
	@echo -e "$(GREEN)✓ Stack started — http://localhost:$(WWW_PORT)$(NC)"
	@echo -e "$(YELLOW)  Run 'make sqlite-logs' to follow service logs$(NC)"

.PHONY: sqlite-down
sqlite-down:
	@echo -e "$(YELLOW)Stopping SQLite stack (data volume preserved)…$(NC)"
	@$(call dc,$(COMPOSE_SQLITE)) down
	@echo -e "$(GREEN)✓ Stopped$(NC)"

.PHONY: sqlite-destroy
sqlite-destroy:
	@echo -e "$(RED)Destroying SQLite stack AND sqlite_data volume…$(NC)"
	@$(call dc,$(COMPOSE_SQLITE)) down --volumes
	@echo -e "$(GREEN)✓ Stack and volumes removed$(NC)"

.PHONY: sqlite-logs
sqlite-logs:
	@$(call dc,$(COMPOSE_SQLITE)) logs --follow

.PHONY: sqlite-ps
sqlite-ps:
	@$(call dc,$(COMPOSE_SQLITE)) ps

.PHONY: sqlite-vacuum
sqlite-vacuum:
	@echo -e "$(BLUE)Running manual VACUUM + PRAGMA optimize on SQLite database…$(NC)"
	@$(call dc,$(COMPOSE_SQLITE)) exec sqlite-vacuum-cron \
		su-exec cronuser /usr/local/bin/vacuum.sh
	@echo -e "$(GREEN)✓ VACUUM + PRAGMA optimize complete$(NC)"

.PHONY: sqlite-shell
sqlite-shell:
	@$(call dc,$(COMPOSE_SQLITE)) run --rm sqlite-tools \
		sqlite3 /data/oidc_cache.db
