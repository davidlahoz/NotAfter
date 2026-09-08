# NotAfter — development tasks.
#
# `make dev` runs the app on 127.0.0.1 with header-based authentication.
# Everything else is what CI runs.

PYTHON  ?= python3.12
VENV    ?= .venv
BIN     := $(VENV)/bin
COMPOSE ?= docker compose

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	 | awk 'BEGIN{FS=":.*?## "}{printf "  \033[1m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: setup
setup: ## Create the virtual environment and install everything
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -r requirements-dev.txt
	cd web && npm ci

.PHONY: build-web
build-web: ## Build the browser bundle into app/static/
	cd web && npm run build

.PHONY: dev
dev: build-web ## Run the app locally (AUTH_MODE=dev, bound to 127.0.0.1)
	AUTH_MODE=dev \
	DATABASE_URL=sqlite:///./notafter.db \
	EDITOR_EMAILS=$${EDITOR_EMAILS:-dev@example.org} \
	BASE_URL=http://127.0.0.1:8000 \
	$(BIN)/uvicorn app.main:build --factory --host 127.0.0.1 --port 8000 --reload

.PHONY: test
test: ## Run the test suite
	$(BIN)/pytest

.PHONY: lint
lint: ## Lint and type-check everything
	$(BIN)/ruff check app tests alembic
	$(BIN)/ruff format --check app tests
	$(BIN)/mypy app
	cd web && npx tsc --noEmit

.PHONY: format
format: ## Reformat the Python source
	$(BIN)/ruff format app tests
	$(BIN)/ruff check --fix app tests

.PHONY: audit
audit: ## Check dependencies for known vulnerabilities
	$(BIN)/pip-audit -r requirements.txt --strict
	cd web && npm audit --omit=dev

.PHONY: migrate
migrate: ## Apply database migrations
	$(BIN)/alembic upgrade head

.PHONY: migration
migration: ## Create a migration from model changes (make migration m="what changed")
	$(BIN)/alembic revision --autogenerate -m "$(m)"

.PHONY: build
build: ## Build the container image
	$(COMPOSE) build

.PHONY: up
up: ## Start the stack
	$(COMPOSE) up -d

.PHONY: down
down: ## Stop the stack
	$(COMPOSE) down

.PHONY: logs
logs: ## Follow the container logs
	$(COMPOSE) logs -f notafter

.PHONY: check
check: lint test audit ## Everything CI runs

.PHONY: clean
clean: ## Remove caches and build artefacts
	rm -rf .pytest_cache .mypy_cache .ruff_cache
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
