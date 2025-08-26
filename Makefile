# CyberShield Makefile
# ====================

# Load environment variables from .env file
ifneq (,$(wildcard ./.env))
    include .env
    export
endif

# Default target
.DEFAULT_GOAL := help

# Colors for output
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[0;33m
BLUE = \033[0;34m
PURPLE = \033[0;35m
CYAN = \033[0;36m
NC = \033[0m # No Color

# Docker compose file path
COMPOSE_FILE = deployment/docker-compose.yaml

.PHONY: help
help: ## Show this help message
	@echo "$(CYAN)CyberShield Development Commands$(NC)"
	@echo "=================================="
	@echo ""
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "$(GREEN)%-20s$(NC) %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Environment setup
.PHONY: check-env
check-env: ## Check if .env file exists and required variables are set
	@echo "$(BLUE)🔍 Checking environment configuration...$(NC)"
	@if [ ! -f .env ]; then \
		echo "$(RED)❌ Error: .env file not found$(NC)"; \
		echo "$(YELLOW)💡 Copy .env.template to .env and configure your variables$(NC)"; \
		exit 1; \
	fi
	@echo "$(GREEN)✅ .env file found$(NC)"
	@echo "$(BLUE)📋 Required variables check:$(NC)"
	@for var in POSTGRES_DB POSTGRES_USER POSTGRES_PASSWORD MINIO_ACCESS_KEY MINIO_SECRET_KEY; do \
		if [ -z "$$(eval echo \$$$$var)" ]; then \
			echo "$(RED)❌ $$var is not set$(NC)"; \
			exit 1; \
		else \
			echo "$(GREEN)✅ $$var is configured$(NC)"; \
		fi; \
	done

# Service management
.PHONY: up
up: check-env ## Start all services
	@echo "$(BLUE)🚀 Starting CyberShield services...$(NC)"
	@docker-compose -f $(COMPOSE_FILE) up -d
	@echo "$(GREEN)✅ Services started successfully!$(NC)"
	@$(MAKE) status

.PHONY: down
down: ## Stop all services
	@echo "$(YELLOW)🛑 Stopping CyberShield services...$(NC)"
	@docker-compose -f $(COMPOSE_FILE) down
	@echo "$(GREEN)✅ Services stopped successfully!$(NC)"

.PHONY: restart
restart: down up ## Restart all services

.PHONY: status
status: ## Show service status
	@echo "$(BLUE)📊 Service Status:$(NC)"
	@docker-compose -f $(COMPOSE_FILE) ps

.PHONY: logs
logs: ## Show logs for all services
	@docker-compose -f $(COMPOSE_FILE) logs -f

.PHONY: logs-postgres
logs-postgres: ## Show PostgreSQL logs
	@docker-compose -f $(COMPOSE_FILE) logs -f postgres

.PHONY: logs-redis
logs-redis: ## Show Redis logs
	@docker-compose -f $(COMPOSE_FILE) logs -f redis

.PHONY: logs-milvus
logs-milvus: ## Show Milvus logs
	@docker-compose -f $(COMPOSE_FILE) logs -f milvus

# Database operations
.PHONY: db-connect
db-connect: ## Connect to PostgreSQL database
	@docker-compose -f $(COMPOSE_FILE) exec postgres psql -U $(POSTGRES_USER) -d $(POSTGRES_DB)

.PHONY: redis-cli
redis-cli: ## Connect to Redis CLI
	@docker-compose -f $(COMPOSE_FILE) exec redis redis-cli

# Cleanup operations
.PHONY: clean
clean: ## Stop services and remove volumes (data will be lost!)
	@echo "$(RED)⚠️  This will remove all data volumes!$(NC)"
	@read -p "Are you sure? (y/N): " confirm && [ "$$confirm" = "y" ]
	@echo "$(YELLOW)🗑️  Removing services and volumes...$(NC)"
	@docker-compose -f $(COMPOSE_FILE) down -v
	@docker volume prune -f
	@echo "$(GREEN)✅ Cleanup completed$(NC)"

.PHONY: clean-images
clean-images: ## Remove unused Docker images
	@echo "$(YELLOW)🗑️  Cleaning unused Docker images...$(NC)"
	@docker image prune -f
	@echo "$(GREEN)✅ Image cleanup completed$(NC)"

# Health checks
.PHONY: health
health: ## Check health of all services
	@echo "$(BLUE)🏥 Health Check Status:$(NC)"
	@echo "$(CYAN)PostgreSQL:$(NC)"
	@docker-compose -f $(COMPOSE_FILE) exec postgres pg_isready -U $(POSTGRES_USER) || echo "$(RED)❌ PostgreSQL unhealthy$(NC)"
	@echo "$(CYAN)Redis:$(NC)"
	@docker-compose -f $(COMPOSE_FILE) exec redis redis-cli ping || echo "$(RED)❌ Redis unhealthy$(NC)"
	@echo "$(CYAN)Milvus:$(NC)"
	@nc -z localhost 19530 2>/dev/null && echo "$(GREEN)✅ Milvus healthy$(NC)" || echo "$(RED)❌ Milvus unhealthy$(NC)"

# Application commands
.PHONY: install
install: ## Install Python dependencies
	@echo "$(BLUE)📦 Installing Python dependencies...$(NC)"
	@pip install -e ".[dev,testing,frontend]"
	@echo "$(GREEN)✅ Dependencies installed$(NC)"

.PHONY: test
test: ## Run tests
	@echo "$(BLUE)🧪 Running tests...$(NC)"
	@python -m pytest tests/ -v

.PHONY: lint
lint: ## Run code linting
	@echo "$(BLUE)🔍 Running linting...$(NC)"
	@ruff check .
	@ruff format --check .

.PHONY: format
format: ## Format code
	@echo "$(BLUE)✨ Formatting code...$(NC)"
	@ruff format .

.PHONY: server
server: check-env ## Start FastAPI server
	@echo "$(BLUE)🚀 Starting CyberShield server...$(NC)"
	@python server/main.py

.PHONY: frontend
frontend: check-env ## Start Streamlit frontend
	@echo "$(BLUE)🎨 Starting CyberShield frontend...$(NC)"
	@cd frontend && python run_streamlit.py

# Data operations
.PHONY: ingest-data
ingest-data: ## Ingest cybersecurity data into Milvus
	@echo "$(BLUE)📊 Ingesting cybersecurity data...$(NC)"
	@python data/milvus_ingestion.py
	@echo "$(GREEN)✅ Data ingestion completed$(NC)"

.PHONY: view-data
view-data: ## Launch interactive Milvus data viewer
	@echo "$(BLUE)👁️  Launching Milvus data viewer...$(NC)"
	@python tests/milvus/interactive_milvus_viewer.py

# Development shortcuts
.PHONY: dev
dev: up install ## Full development setup (services + dependencies)
	@echo "$(GREEN)🎉 Development environment ready!$(NC)"
	@echo ""
	@echo "$(CYAN)📋 Next steps:$(NC)"
	@echo "  • Run '$(GREEN)make server$(NC)' to start the API server"
	@echo "  • Run '$(GREEN)make frontend$(NC)' to start the web interface"
	@echo "  • Run '$(GREEN)make test$(NC)' to run the test suite"

.PHONY: prod-check
prod-check: test lint ## Run production readiness checks
	@echo "$(GREEN)✅ Production checks completed$(NC)"

# Documentation
.PHONY: docs-serve
docs-serve: ## Serve GitHub Pages documentation locally
	@echo "$(BLUE)📚 Starting local documentation server...$(NC)"
	@echo "$(YELLOW)📋 Installing Jekyll dependencies...$(NC)"
	@cd docs && bundle install --quiet
	@echo "$(BLUE)🌐 Serving documentation at http://localhost:4000$(NC)"
	@cd docs && bundle exec jekyll serve --livereload --host=0.0.0.0 --port=4000

.PHONY: docs-build
docs-build: ## Build documentation for production
	@echo "$(BLUE)🔨 Building documentation...$(NC)"
	@cd docs && bundle install --quiet
	@cd docs && bundle exec jekyll build
	@echo "$(GREEN)✅ Documentation built in docs/_site/$(NC)"

# Quick reference
.PHONY: endpoints
endpoints: ## Show service endpoints
	@echo "$(CYAN)🔗 Service Endpoints:$(NC)"
	@echo "  • $(GREEN)Redis:$(NC)          localhost:6379"
	@echo "  • $(GREEN)PostgreSQL:$(NC)     localhost:5432"
	@echo "  • $(GREEN)Milvus:$(NC)         localhost:19530"
	@echo "  • $(GREEN)MinIO:$(NC)          localhost:9000"
	@echo "  • $(GREEN)Pulsar:$(NC)         localhost:6650"
	@echo "  • $(GREEN)Etcd:$(NC)           localhost:2379"
	@echo ""
	@echo "$(CYAN)📚 Documentation:$(NC)"
	@echo "  • $(GREEN)Local Docs:$(NC)     http://localhost:4000 (run 'make docs-serve')"
	@echo "  • $(GREEN)Live Docs:$(NC)      https://chintamanil.github.io/cybershield/"