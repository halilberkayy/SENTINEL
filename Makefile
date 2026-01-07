.PHONY: help install test lint format clean run docker-up docker-down migrations migrate

# Colors for output
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[1;33m
RED := \033[0;31m
NC := \033[0m # No Color

help: ## Show this help message
	@echo "$(BLUE)Enterprise Vulnerability Scanner v5.0.0$(NC)"
	@echo "$(GREEN)Available commands:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(YELLOW)%-20s$(NC) %s\n", $$1, $$2}'

# Installation & Setup
install: ## Install dependencies with Poetry
	@echo "$(BLUE)Installing dependencies...$(NC)"
	poetry install
	@echo "$(GREEN)✓ Dependencies installed$(NC)"

install-dev: ## Install development dependencies
	@echo "$(BLUE)Installing dev dependencies...$(NC)"
	poetry install --with dev
	@echo "$(GREEN)✓ Dev dependencies installed$(NC)"

setup: ## Quick setup (Poetry + Docker services + DB)
	@echo "$(BLUE)Running quick setup...$(NC)"
	chmod +x quick-setup.sh
	./quick-setup.sh

# Code Quality
lint: ## Run all linters (ruff, black, mypy)
	@echo "$(BLUE)Running linters...$(NC)"
	poetry run ruff check src tests
	poetry run black --check src tests
	poetry run isort --check-only src tests
	poetry run mypy src
	@echo "$(GREEN)✓ Linting complete$(NC)"

format: ## Format code with black and isort
	@echo "$(BLUE)Formatting code...$(NC)"
	poetry run black src tests
	poetry run isort src tests
	@echo "$(GREEN)✓ Code formatted$(NC)"

type-check: ## Run MyPy type checking
	@echo "$(BLUE)Running type checks...$(NC)"
	poetry run mypy src
	@echo "$(GREEN)✓ Type checking complete$(NC)"

# Security
security: ## Run security scans (bandit, safety)
	@echo "$(BLUE)Running security scans...$(NC)"
	poetry run bandit -r src -f json -o bandit-report.json || true
	poetry run safety check || true
	@echo "$(GREEN)✓ Security scan complete$(NC)"

# Testing
test: ## Run all tests
	@echo "$(BLUE)Running tests...$(NC)"
	poetry run pytest tests/ -v
	@echo "$(GREEN)✓ Tests complete$(NC)"

test-unit: ## Run unit tests only
	@echo "$(BLUE)Running unit tests...$(NC)"
	poetry run pytest tests/unit/ -v
	@echo "$(GREEN)✓ Unit tests complete$(NC)"

test-integration: ## Run integration tests
	@echo "$(BLUE)Running integration tests...$(NC)"
	poetry run pytest tests/integration/ -v
	@echo "$(GREEN)✓ Integration tests complete$(NC)"

test-coverage: ## Run tests with coverage report
	@echo "$(BLUE)Running tests with coverage...$(NC)"
	poetry run pytest tests/ --cov=src --cov-report=html --cov-report=term
	@echo "$(GREEN)✓ Coverage report generated: htmlcov/index.html$(NC)"

test-watch: ## Run tests in watch mode
	poetry run pytest-watch tests/

# Application
run: ## Run the CLI scanner
	@echo "$(BLUE)Starting CLI scanner...$(NC)"
	poetry run python scanner.py

run-api: ## Run the API server
	@echo "$(BLUE)Starting API server...$(NC)"
	poetry run scanner-api

run-gui: ## Run the GUI scanner
	@echo "$(BLUE)Starting GUI scanner...$(NC)"
	poetry run python gui_scanner.py

run-web: ## Run the web interface
	@echo "$(BLUE)Starting web interface...$(NC)"
	poetry run python web_app.py

# Docker
docker-build: ## Build Docker image
	@echo "$(BLUE)Building Docker image...$(NC)"
	docker build -f docker/Dockerfile -t scanner:latest .
	@echo "$(GREEN)✓ Docker image built$(NC)"

docker-up: ## Start all Docker services
	@echo "$(BLUE)Starting Docker services...$(NC)"
	docker-compose -f docker/docker-compose.yml up -d
	@echo "$(GREEN)✓ Services started$(NC)"
	@echo "$(YELLOW)API: http://localhost:8000$(NC)"
	@echo "$(YELLOW)Grafana: http://localhost:3000$(NC)"
	@echo "$(YELLOW)Prometheus: http://localhost:9090$(NC)"

docker-down: ## Stop all Docker services
	@echo "$(BLUE)Stopping Docker services...$(NC)"
	docker-compose -f docker/docker-compose.yml down
	@echo "$(GREEN)✓ Services stopped$(NC)"

docker-logs: ## Show Docker logs
	docker-compose -f docker/docker-compose.yml logs -f

docker-ps: ## Show running Docker containers
	docker-compose -f docker/docker-compose.yml ps

docker-clean: ## Clean Docker containers and volumes
	@echo "$(RED)Cleaning Docker resources...$(NC)"
	docker-compose -f docker/docker-compose.yml down -v
	@echo "$(GREEN)✓ Docker cleaned$(NC)"

# Database
db-init: ## Initialize database
	@echo "$(BLUE)Initializing database...$(NC)"
	poetry run python -c "import asyncio; from src.core.database import init_database; asyncio.run(init_database('postgresql://scanner:scanner@localhost:5432/scanner'))"
	@echo "$(GREEN)✓ Database initialized$(NC)"

db-migrate: ## Run database migrations
	@echo "$(BLUE)Running migrations...$(NC)"
	poetry run alembic upgrade head
	@echo "$(GREEN)✓ Migrations applied$(NC)"

db-migration: ## Create new migration (usage: make db-migration MSG="description")
	@echo "$(BLUE)Creating migration...$(NC)"
	poetry run alembic revision --autogenerate -m "$(MSG)"
	@echo "$(GREEN)✓ Migration created$(NC)"

db-downgrade: ## Rollback last migration
	@echo "$(BLUE)Rolling back migration...$(NC)"
	poetry run alembic downgrade -1
	@echo "$(GREEN)✓ Migration rolled back$(NC)"

db-reset: ## Reset database (drop and recreate)
	@echo "$(RED)Resetting database...$(NC)"
	docker-compose -f docker/docker-compose.yml down postgres -v
	docker-compose -f docker/docker-compose.yml up -d postgres
	sleep 3
	$(MAKE) db-init
	@echo "$(GREEN)✓ Database reset$(NC)"

# Cleanup
clean: ## Clean build artifacts and cache
	@echo "$(BLUE)Cleaning build artifacts...$(NC)"
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/ htmlcov/ .coverage coverage.xml
	@echo "$(GREEN)✓ Cleaned$(NC)"

clean-logs: ## Clean log files
	@echo "$(BLUE)Cleaning logs...$(NC)"
	rm -rf output/logs/*.log
	rm -rf logs/*.log
	@echo "$(GREEN)✓ Logs cleaned$(NC)"

clean-reports: ## Clean scan reports
	@echo "$(BLUE)Cleaning reports...$(NC)"
	rm -rf output/reports/*
	@echo "$(GREEN)✓ Reports cleaned$(NC)"

clean-all: clean clean-logs clean-reports docker-clean ## Clean everything

# CI/CD
ci: lint security test ## Run full CI pipeline locally
	@echo "$(GREEN)✓ CI pipeline complete$(NC)"

pre-commit: format lint test-unit ## Run pre-commit checks
	@echo "$(GREEN)✓ Pre-commit checks passed$(NC)"

# Monitoring
metrics: ## Open Prometheus metrics
	@echo "$(BLUE)Opening Prometheus...$(NC)"
	open http://localhost:9090

grafana: ## Open Grafana dashboards
	@echo "$(BLUE)Opening Grafana...$(NC)"
	open http://localhost:3000

api-docs: ## Open API documentation
	@echo "$(BLUE)Opening API docs...$(NC)"
	open http://localhost:8000/api/docs

# Health checks
health: ## Check service health
	@echo "$(BLUE)Checking service health...$(NC)"
	@curl -s http://localhost:8000/health | jq . || echo "$(RED)API not running$(NC)"

ready: ## Check service readiness
	@echo "$(BLUE)Checking service readiness...$(NC)"
	@curl -s http://localhost:8000/ready | jq . || echo "$(RED)API not ready$(NC)"

# Development
dev: docker-up run-api ## Start development environment

watch: ## Watch for file changes and run tests
	poetry run ptw tests/

shell: ## Start Python shell with project context
	poetry run python

# Documentation
docs: ## Generate documentation
	@echo "$(BLUE)Generating documentation...$(NC)"
	poetry run mkdocs build
	@echo "$(GREEN)✓ Documentation generated$(NC)"

docs-serve: ## Serve documentation locally
	poetry run mkdocs serve

# Info
version: ## Show version info
	@echo "$(BLUE)Enterprise Vulnerability Scanner$(NC)"
	@echo "Version: $(GREEN)5.0.0$(NC)"
	@poetry --version
	@python --version

status: ## Show project status
	@echo "$(BLUE)Project Status:$(NC)"
	@echo "  Git branch: $(GREEN)$$(git branch --show-current)$(NC)"
	@echo "  Last commit: $$(git log -1 --pretty=format:'%h - %s')"
	@echo ""
	@echo "$(BLUE)Docker Services:$(NC)"
	@docker-compose -f docker/docker-compose.yml ps || echo "  $(YELLOW)Docker not running$(NC)"

# Default target
.DEFAULT_GOAL := help
