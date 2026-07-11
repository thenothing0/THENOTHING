.DEFAULT_GOAL := help
SHELL := /bin/bash

# ── Install ────────────────────────────────────────────────────
.PHONY: install dev

install:  ## Install hydra-security (runtime only)
	pip install -e .

dev:  ## Install with dev dependencies
	pip install -e ".[dev]"

# ── Test ───────────────────────────────────────────────────────
.PHONY: test test-cov

test:  ## Run test suite (offline, no Kali)
	pytest tests/ -x -q

test-cov:  ## Run tests with coverage report
	pytest tests/ --cov=hydra --cov=mcp_server --cov-report=term-missing

# ── Lint ───────────────────────────────────────────────────────
.PHONY: lint lint-fix

lint:  ## Run ruff linter
	ruff check mcp_server.py tests hydra/knowledge hydra/capabilities hydra/recon_fusion

lint-fix:  ## Auto-fix lint issues
	ruff check --fix hydra/ tests/ mcp_server.py

# ── Build ──────────────────────────────────────────────────────
.PHONY: build check clean

build:  ## Build sdist and wheel
	python -m build

check:  ## Validate built distributions
	twine check dist/*

clean:  ## Remove build artifacts
	rm -rf dist/ build/ *.egg-info hydra_security.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

# ── Docker ─────────────────────────────────────────────────────
.PHONY: docker docker-slim

docker:  ## Build full Docker image (MCP server)
	docker build --target mcp-server -t hydra:mcp .

docker-slim:  ## Build slim Docker image (no Go tools)
	docker build --target slim -t hydra:slim .

# ── Smoke ──────────────────────────────────────────────────────
.PHONY: smoke tools

smoke:  ## Run smoke test (build + install + verify in temp venv)
	bash scripts/smoke_test.sh

tools:  ## Check available security tools
	python -m hydra --check-tools

# ── Help ───────────────────────────────────────────────────────
.PHONY: help

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
