.PHONY: up down reset ps logs db-init topics index seed data verify bootstrap test lint format clean help services-build services-up services-down

COMPOSE = docker compose -p cybersentry

help:
	@echo "CyberSentry Automation Targets:"
	@echo "  make up             - Start infrastructure stack and wait for healthy"
	@echo "  make down           - Stop infrastructure stack"
	@echo "  make reset          - Tear down stack and remove persistent volumes"
	@echo "  make ps             - Show container status and health"
	@echo "  make logs           - Tail container logs"
	@echo "  make db-init        - Re-apply database schema inside PostgreSQL container"
	@echo "  make topics         - Provision Kafka message topics"
	@echo "  make index          - Apply OpenSearch index template and ISM policy"
	@echo "  make seed           - Seed ATT&CK catalogue, rules, assets, and detections"
	@echo "  make data           - Download sample datasets and STIX references"
	@echo "  make verify         - Execute full verification suite"
	@echo "  make bootstrap      - One-shot sequence: up -> topics -> index -> seed -> verify"
	@echo "  make services-build - Build microservice images from root context"
	@echo "  make services-up    - Start microservices with app profile"
	@echo "  make services-down  - Stop microservices"
	@echo "  make test           - Run pytest test suite"
	@echo "  make lint           - Run black and flake8 linters"
	@echo "  make format         - Reformat code with black"
	@echo "  make clean          - Clean Python bytecode caches"

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

services-build:
	$(COMPOSE) --profile app build

services-up:
	$(COMPOSE) --profile app up -d

services-down:
	$(COMPOSE) --profile app down

test:
	python -m pytest tests/ -v

lint:
	black --check . && flake8 .

format:
	black .

clean:
	python -c "import shutil, pathlib; [shutil.rmtree(p) for p in pathlib.Path('.').rglob('__pycache__')]"