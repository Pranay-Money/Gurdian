.PHONY: help dev test build lint format generate-types clean install-api install-extension install-ml train eval retrain drift blocklist retention

# Default target
help:
	@echo "Guardian Monorepo - Available targets:"
	@echo ""
	@echo "Development:"
	@echo "  make dev           - Start API + DB + Redis (docker-compose)"
	@echo "  make dev-api       - Start API only (requires running DB/Redis)"
	@echo "  make dev-extension - Build extension in watch mode"
	@echo ""
	@echo "Testing:"
	@echo "  make test          - Run all tests (API + Extension + ML)"
	@echo "  make test-api      - Run API tests only"
	@echo "  make test-extension - Run extension tests only"
	@echo "  make test-ml       - Run ML tests only"
	@echo ""
	@echo "Building:"
	@echo "  make build         - Build all packages (extension + API + ML)"
	@echo "  build-extension    - Build Chrome extension (production)"
	@echo "  build-api          - Build API Docker image"
	@echo ""
	@echo "Code Quality:"
	@echo "  make lint          - Run linters (ruff, mypy, eslint)"
	@echo "  make format        - Format code (ruff, prettier)"
	@echo "  make generate-types - Generate TypeScript types from OpenAPI"
	@echo ""
	@echo "ML Pipeline:"
	@echo "  make train         - Full ML pipeline: ingest -> features -> train -> eval -> export"
	@echo "  make eval          - Evaluate existing model on test data"
	@echo "  make train-synthetic - Quick train with synthetic data (for CI)"
	@echo "  make ml-shortcut-check - Run shortcut feature detection only"
	@echo ""
	@echo "Jobs (Feedback Loop & Monitoring):"
	@echo "  make retrain       - Run retrain job with feedback loop (merge feeds, time split, gates)"
	@echo "  make drift         - Run drift monitor (score distribution, block rate, feature drift)"
	@echo "  make blocklist     - Generate blocklist delta for extension sync"
	@echo "  make retention     - Run data retention cleanup (delete old cases)"
	@echo ""
	@echo "Utilities:"
	@echo "  make clean         - Clean build artifacts"
	@echo "  make install       - Install all dependencies"

# ============================================================================
# Development
# ============================================================================

dev:
	docker-compose up --build

dev-api:
	cd api && uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload

dev-extension:
	cd extension && npm run dev

# ============================================================================
# Testing
# ============================================================================

test: test-api test-extension test-ml

test-api:
	cd api && python -m pytest tests/ -v --cov=src --cov-report=term-missing

test-extension:
	cd extension && npm test

test-ml:
	cd ml && python -m pytest tests/ -v --cov=src --cov-report=term-missing

# ============================================================================
# Building
# ============================================================================

build: build-extension build-api

build-extension:
	cd extension && npm run build

build-api:
	docker build -t guardian-api:latest ./api

# ============================================================================
# Code Quality
# ============================================================================

lint: lint-api lint-extension

lint-api:
	cd api && ruff check src tests && mypy src

lint-extension:
	cd extension && npm run lint

format: format-api format-extension

format-api:
	cd api && ruff format src tests

format-extension:
	cd extension && npx prettier --write "src/**/*.{ts,tsx,json,css,html}"

generate-types:
	@echo "Generating TypeScript types from OpenAPI..."
	cd extension && npx openapi-typescript ../api/openapi.yaml -o src/shared/api-types.ts

# ============================================================================
# ML Pipeline
# ============================================================================

# Full training pipeline: ingest -> features -> train -> eval -> export
train:
	cd ml && python -m guardian_ml.pipeline

# Evaluate existing model on test data
eval:
	cd ml && python -m guardian_ml.pipeline --eval-only --model-path ../api/ml/models/model.joblib --test-data ml/data/snapshots/latest/urls.jsonl

# Quick training with synthetic data (for CI testing)
train-synthetic:
	cd ml && python -m guardian_ml.components.model_training

# Legacy targets (kept for compatibility)
train-ml:
	cd ml && python -m guardian_ml.components.model_training

train-ml-data:
	@if [ -z "$(DATA)" ]; then echo "Usage: make train-ml-data DATA=path/to/data.jsonl"; exit 1; fi
	cd ml && python -m guardian_ml.components.data_ingestion && python -m guardian_ml.components.model_training

train-ml-pipeline:
	cd ml && python -m guardian_ml.pipeline

eval-ml:
	cd ml && python -m pytest tests/ -v --cov=src --cov-report=term-missing -k "not test_pipeline"

eval-ml-full:
	cd ml && python -m pytest tests/ -v --cov=src --cov-report=term-missing

eval-ml-pipeline:
	cd ml && python -m guardian_ml.pipeline --eval-only

# Shortcut check only
ml-shortcut-check:
	cd ml && python -c "
from guardian_ml.components.feature_engineering import FeatureEngineer, FeatureConfig
from guardian_ml.components.data_ingestion import DataIngestion
import numpy as np
from pathlib import Path

# Create minimal test data
test_urls = [
    'https://www.google.com/search?q=test',
    'http://malicious.tk/login.php',
    'https://github.com/user/repo',
    'http://paypal.phishing-site.ml/verify',
] * 250
test_labels = [0, 1, 0, 1] * 250

engineer = FeatureEngineer(FeatureConfig())
X = engineer.fit_transform(test_urls, test_labels)
y = np.array(test_labels)
print('Feature matrix shape:', X.shape)
print('Shortcut check completed during fit (check logs)')
"

# ============================================================================
# Installation
# ============================================================================

install: install-api install-extension install-ml

install-api:
	cd api && pip install -e ".[dev,ml]"

install-extension:
	cd extension && npm install

install-ml:
	cd ml && pip install -e ".[dev]"

# ============================================================================
# Cleanup
# ============================================================================

clean:
	rm -rf extension/dist extension/node_modules
	rm -rf api/__pycache__ api/src/__pycache__ api/tests/__pycache__ api/.pytest_cache api/.mypy_cache api/.ruff_cache
	rm -rf ml/__pycache__ ml/src/__pycache__ ml/tests/__pycache__ ml/.pytest_cache ml/.mypy_cache ml/.ruff_cache
	rm -rf .pytest_cache .mypy_cache .ruff_cache
	docker-compose down -v 2>/dev/null || true

# ============================================================================
# Pre-commit
# ============================================================================

pre-commit-install:
	cd api && pre-commit install
	cd extension && npx husky install 2>/dev/null || true
	cd ml && pre-commit install

pre-commit-run:
	cd api && pre-commit run --all-files
	cd extension && npx lint-staged 2>/dev/null || true
	cd ml && pre-commit run --all-files

# ============================================================================
# Jobs (Feedback Loop & Monitoring)
# ============================================================================

# Retrain job - full feedback loop with promotion gates
retrain:
	cd api && python -m src.jobs.retrain

# Drift monitor - check score distribution and block rate shifts
drift:
	cd api && python -m src.jobs.drift_monitor

# Blocklist generation - create delta for extension sync
blocklist:
	cd api && python -m src.jobs.blocklist

# Retention cleanup - delete old cases per retention policy
retention:
	cd api && python -m src.jobs.retention

# Run all jobs sequentially (for testing)
jobs: blocklist retention drift retrain