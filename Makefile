.PHONY: up down reset ps logs db-init topics index seed data verify bootstrap test lint format clean help

COMPOSE = docker compose -p cybersentry

help:
	@echo "CyberSentry M1 Automation Targets:"
	@echo "  make up         - Start infrastructure stack and wait for healthy"
	@echo "  make down       - Stop infrastructure stack"
	@echo "  make reset      - Tear down stack and remove persistent volumes"
	@echo "  make ps         - Show container status and health"
	@echo "  make logs       - Tail container logs"
	@echo "  make db-init    - Re-apply database schema inside PostgreSQL container"
	@echo "  make topics     - Provision Kafka message topics"
	@echo "  make index      - Apply OpenSearch index template and ISM policy"
	@echo "  make seed       - Seed ATT&CK catalogue, rules, assets, and detections"
	@echo "  make data       - Download sample datasets and STIX references"
	@echo "  make verify     - Execute full Milestone 1 verification suite"
	@echo "  make bootstrap  - One-shot sequence: up -> topics -> index -> seed -> verify"
	@echo "  make test       - Run pytest test suite"
	@echo "  make lint       - Run black and flake8 linters"
	@echo "  make format     - Reformat code with black"
	@echo "  make clean      - Clean Python bytecode caches"

up:
	$(COMPOSE) up -d --wait --wait-timeout 300
	@echo "Stack is healthy and operational."

down:
	$(COMPOSE) down

reset:
	$(COMPOSE) down -v

ps:
	$(COMPOSE) ps

logs:
	$(COMPOSE) logs -f --tail=100

db-init:
	$(COMPOSE) exec -T postgres sh -c 'psql -U "$$POSTGRES_USER" -d "$$POSTGRES_DB" -f /docker-entrypoint-initdb.d/01_init.sql'

topics:
	bash scripts/create_topics.sh

index:
	bash scripts/create_index.sh

seed:
	python scripts/seed_db.py

data:
	python scripts/download_datasets.py

verify:
	python scripts/verify_m1.py

bootstrap: up topics index seed verify

test:
	python -m pytest tests/ -v

lint:
	black --check . && flake8 .

format:
	black .

clean:
	python -c "import shutil, pathlib; [shutil.rmtree(p) for p in pathlib.Path('.').rglob('__pycache__')]"

# ---- M2 targets (Milestone 2) ----
-include .env
export
PY   := PYTHONPATH=ml/src python
PKG  := cybersentry
PSQL := docker compose exec -T postgres psql -U $${POSTGRES_USER:-sentry}

mlflow-up:
	$(PSQL) -tc "SELECT 1 FROM pg_database WHERE datname='mlflow'" | grep -q 1 \
	  || $(PSQL) -c "CREATE DATABASE mlflow"
	docker compose exec -T minio sh -c \
	  "mc alias set l http://localhost:9000 $${MINIO_ROOT_USER:-minioadmin} $${MINIO_ROOT_PASSWORD:-minioadmin} \
	   && mc mb -p l/mlflow-artifacts" || true
	docker compose -f docker-compose.yml -f docker-compose.mlflow.yml up -d mlflow

migrate-m2:
	$(PSQL) -d $${POSTGRES_DB:-cybersentry} < db/migrations/002_m2_predictions.sql

extract:
	$(PY) -m $(PKG).split

test-m2:
	PYTHONPATH=ml/src pytest -q ml/tests/test_m2_leakage.py

baseline:
	$(PY) -m $(PKG).baseline

train:
	$(PY) -m $(PKG).train

hpo:
	$(PY) -m $(PKG).hpo --trials 30

evaluate:
	$(PY) -m $(PKG).evaluate

promote:
	$(PY) -m $(PKG).promote

writeback:
	$(PY) -m $(PKG).writeback

verify-m2:
	$(PY) scripts/verify_m2.py

m2: extract test-m2 train evaluate promote writeback verify-m2

.PHONY: mlflow-up migrate-m2 extract test-m2 baseline train hpo evaluate promote writeback verify-m2 m2