.PHONY: help install install-dev test lint format build clean smoke docker-build docker-run

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install in production mode
	pip install .

install-dev: ## Install in development mode with all extras
	pip install -e .
	pip install pytest ruff mypy

test: ## Run all tests
	python -m pytest tests/ -v

lint: ## Run linter
	python -m ruff check src/ tests/

format: ## Auto-format code
	python -m ruff format src/ tests/

build: ## Build distribution packages
	python -m build

clean: ## Remove build artifacts
	rm -rf dist/ build/ *.egg-info src/*.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

smoke: ## Run CLI smoke test
	PYTHONPATH=src python -m offshore_migrator.cli migrate --source examples --output /tmp/odm_smoke --password test --dry-run --no-progress
	@echo "Smoke test passed."

docker-build: ## Build Docker image
	docker build -t offshore-data-migrator .

docker-run: ## Run migration in Docker (mount data/ and output/)
	docker run --rm -v $(PWD)/data:/data -v $(PWD)/output:/output \
		offshore-data-migrator migrate --source /data --output /output
