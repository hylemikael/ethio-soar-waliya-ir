# ==============================================================================
# Ethio-SOAR (Waliya-IR) Deployment & Operations Makefile
# ==============================================================================

.PHONY: help validate-config build up down restart logs ps migrate health test backup restore list-backups verify-backup redis-status redis-reinit

help:
	@echo "Ethio-SOAR (Waliya-IR) Operations Management"
	@echo "Usage: make [target]"
	@echo ""
	@echo "Deployment & Management:"
	@echo "  validate-config  Validate .env deployment configuration"
	@echo "  build            Build all container images (backend, worker, frontend)"
	@echo "  up               Start all production containers in background"
	@echo "  down             Stop and remove containers (preserves database volumes)"
	@echo "  restart          Restart all application services"
	@echo "  logs             Tail container logs across all services"
	@echo "  ps               List status of running containers"
	@echo "  migrate          Apply pending database migrations"
	@echo "  health           Check health and readiness endpoints"
	@echo "  test             Run test regression suites (backend, agent, sim)"
	@echo ""
	@echo "Disaster Recovery & Resilience:"
	@echo "  backup           Generate verified PostgreSQL backup with SHA-256 manifest"
	@echo "  restore          Restore latest backup to safe target (waliya_recovery)"
	@echo "  list-backups     List and inspect all backups and their health status"
	@echo "  verify-backup    Cryptographically verify the latest backup file"
	@echo "  redis-status     Check Redis stream health, AOF persistence, and consumer groups"
	@echo "  redis-reinit     Ensure required Redis telemetry stream consumer groups exist"

validate-config:
	@backend/.venv/bin/python3 scripts/validate_config.py --env-file .env

build:
	@echo "[*] Building Ethio-SOAR container images..."
	docker compose build

up:
	@echo "[*] Starting Ethio-SOAR production stack..."
	docker compose up -d
	@echo "[+] Services started. Access the UI at http://localhost:8080"

down:
	@echo "[*] Gracefully stopping Ethio-SOAR containers..."
	docker compose down

restart:
	@echo "[*] Restarting services..."
	docker compose restart

logs:
	docker compose logs -f

ps:
	docker compose ps

migrate:
	@echo "[*] Running Alembic database migrations..."
	docker compose run --rm migration

health:
	@echo "[*] Evaluating platform health..."
	@curl -s -i http://localhost:8080/healthz | head -n 5
	@echo ""
	@curl -s http://localhost:8080/api/v1/health/readiness | jq . || curl -s http://localhost:8080/api/v1/health/readiness
	@echo ""

test:
	@echo "[*] Executing backend test suite..."
	backend/.venv/bin/pytest backend/tests/
	@echo "[*] Executing agent sensor test suite..."
	PYTHONPATH=agent/src backend/.venv/bin/pytest agent/tests/
	@echo "[*] Executing simulator test suite..."
	PYTHONPATH=sim/src:backend/src backend/.venv/bin/pytest sim/tests/

backup:
	@echo "[*] Running Ethio-SOAR database backup workflow..."
	@./scripts/backup_db.sh

restore:
	@echo "[*] Restoring database to safe target (waliya_recovery)..."
	@./scripts/restore_db.sh

list-backups:
	@backend/.venv/bin/python3 scripts/manage_backups.py list

verify-backup:
	@LATEST=$$(ls -1t backups/*.dump 2>/dev/null | head -n 1); \
	if [ -z "$$LATEST" ]; then \
		echo "[-] No backup files found in backups/"; \
		exit 1; \
	fi; \
	backend/.venv/bin/python3 scripts/manage_backups.py verify "$$LATEST"

redis-status:
	@backend/.venv/bin/python3 scripts/redis_recovery.py status

redis-reinit:
	@backend/.venv/bin/python3 scripts/redis_recovery.py reinit-groups
