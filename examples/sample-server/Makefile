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
	@echo "  make install       - Install cargo-watch and dependencies"
	@echo "  make setup         - Create .env.local from sample if it doesn't exist"
	@echo ""
	@echo -e "$(YELLOW)Development:$(NC)"
	@echo "  make dev           - Run with cargo-watch (auto-reload on changes)"
	@echo "  make run           - Run without watching"
	@echo "  make watch         - Alias for 'make dev'"
	@echo ""
	@echo -e "$(YELLOW)Build:$(NC)"
	@echo "  make build         - Build in debug mode"
	@echo "  make release       - Build in release mode"
	@echo "  make clean         - Clean build artifacts"
	@echo ""
	@echo -e "$(YELLOW)Testing:$(NC)"
	@echo "  make test          - Run tests"
	@echo "  make test-watch    - Run tests with auto-reload"
	@echo ""
	@echo -e "$(YELLOW)Utilities:$(NC)"
	@echo "  make check         - Check code (cargo check)"
	@echo "  make fmt           - Format code"
	@echo "  make clippy        - Run clippy linter"
	@echo "  make env           - Show current environment variables"
	@echo ""
	@echo -e "$(YELLOW)Environment:$(NC)"
	@echo "  PORT=$(PORT) (override with PORT=3000 make dev)"
	@echo "  HOST=$(HOST) (override with HOST=0.0.0.0 make dev)"
	@echo "  ENV_FILE=$(ENV_FILE) (override with DOTENV_FILE=.env.prod make dev)"
	@echo ""
	@echo -e "$(BLUE)Priority for .env files:$(NC)"
	@echo "  1. DOTENV_FILE environment variable (if set)"
	@echo "  2. .env.local (default)"
	@echo "  3. .env (fallback)"

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
			-x "run -- --host $(HOST) --port $(PORT)"; \
	else \
		echo -e "$(RED)Error: $(ENV_FILE) not found. Run 'make setup' first.$(NC)"; \
		exit 1; \
	fi

# Alias for dev
.PHONY: watch
watch: dev

# Run without watching
.PHONY: run
run: setup
	@echo -e "$(GREEN)Starting server...$(NC)"
	@if [ -n "$(DOTENV_FILE)" ]; then \
		echo -e "$(BLUE)Using custom dotenv file: $(DOTENV_FILE)$(NC)"; \
	fi
	@if [ -f $(ENV_FILE) ]; then \
		DOTENV_FILE=$(ENV_FILE) $(CARGO) run -- --host $(HOST) --port $(PORT); \
	else \
		echo -e "$(RED)Error: $(ENV_FILE) not found. Run 'make setup' first.$(NC)"; \
		exit 1; \
	fi

# Build commands
.PHONY: build
build:
	@echo -e "$(BLUE)Building in debug mode...$(NC)"
	@$(CARGO) build
	@echo -e "$(GREEN)✓ Build complete$(NC)"

.PHONY: release
release:
	@echo -e "$(BLUE)Building in release mode...$(NC)"
	@$(CARGO) build --release
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
	@echo -e "$(BLUE)Running cargo check...$(NC)"
	@$(CARGO) check
	@echo -e "$(GREEN)✓ Check complete$(NC)"

.PHONY: fmt
fmt:
	@echo -e "$(BLUE)Formatting code...$(NC)"
	@$(CARGO) fmt
	@echo -e "$(GREEN)✓ Format complete$(NC)"

.PHONY: clippy
clippy:
	@echo -e "$(BLUE)Running clippy...$(NC)"
	@$(CARGO) clippy -- -D warnings
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
