# Ethio-SOAR (Waliya-IR)

> **Waliya-IR** is a Linux-first Security Operations, Threat Detection, Investigation, and Automated Incident Response (SOAR) platform.

---

## 1. Architecture Overview

Waliya-IR is designed as a high-throughput **modular monolith** with clear internal separation of concerns:

- **Central Server:** FastAPI + Pydantic v2 + SQLAlchemy (Async ORM) + asyncpg.
- **Relational Storage:** PostgreSQL 18 with relational models and JSONB payloads.
- **Stream Distribution:** Redis Streams for resilient event ingestion and detection worker coordination.
- **Entity Correlation:** Bounded in-memory NetworkX correlation engine for entity graph discovery and investigation visualization.
- **Agent Command Channel:** Outbound HTTPS polling, HMAC-SHA256 signed payloads, nonce/replay protection, and strictly allowlisted response adapters.
- **Audit Subsystem:** Cryptographically verifiable SHA-256 hash-chained audit ledger.
- **Analyst Workspaces:** React + TypeScript + Vite + Tailwind CSS single-page interface covering four core workspaces:
  1. **Command Overview & Live Telemetry**
  2. **Incident Investigation & Forensics**
  3. **Detection & Behavioral Analytics**
  4. **SOAR Playbooks & Audit Ledger**

---

## 2. Directory Structure

```text
ethio-soar-waliya-ir/
├── backend/
│   ├── pyproject.toml              # Backend project configuration & dependencies
│   ├── .env.example                # Example environment variables
│   ├── src/
│   │   └── waliya/                 # Core Python package
│   │       ├── main.py             # FastAPI entrypoint & application factory
│   │       ├── config.py           # Pydantic Settings configuration
│   │       ├── contracts.py        # Strict Pydantic v2 data contracts
│   │       ├── api/                # HTTP API routes (health, ingest, agent, etc.)
│   │       ├── core/               # Shared security, logging & cryptography utils
│   │       ├── db/                 # Database models and async session management
│   │       ├── telemetry/          # Telemetry processing & normalization
│   │       ├── detection/          # Versioned rule engine & condition matchers
│   │       ├── analytics/          # Streaming EWMA & rolling Z-score baselines
│   │       ├── correlation/        # Bounded NetworkX entity relationship graph
│   │       ├── incidents/          # Correlated incident lifecycle management
│   │       ├── agent_c2/           # Outbound HTTPS agent polling & HMAC signer
│   │       ├── soar/               # Playbook execution & response state machine
│   │       └── audit/              # SHA-256 hash-chained audit ledger service
│   ├── alembic.ini                 # Database migration configuration
│   ├── alembic/                    # Migration scripts
│   └── tests/                      # Automated unit, contract, and integration tests
├── frontend/                       # React + TypeScript + Vite + Tailwind CSS UI
├── docs/
│   └── architecture/               # Technical specs, security model, and API contracts
├── docker-compose.yml              # Local PostgreSQL 18 & Redis infrastructure
├── .gitignore                      # Git exclusion rules
└── README.md                       # Platform documentation
```

---

## 3. Deployment Architecture & Service Inventory

Ethio-SOAR (Waliya-IR) is deployable as a cohesive, production-hardened container stack orchestrated via Docker Compose:

| Service | Container Name | Role & Responsibility | Internal Port | Host Port / Route |
| :--- | :--- | :--- | :--- | :--- |
| **Frontend** | `waliya_frontend` | Production Nginx reverse-proxy & React Single-Page Application | 80 | `http://localhost:8080` (configurable via `WALIYA_PORT`) |
| **Backend** | `waliya_backend` | FastAPI application server hosting REST endpoints and SSE telemetry | 8000 | Reverse-proxied via `waliya_frontend` (`/api/`) |
| **Worker** | `waliya_worker` | Background Telemetry Consumer daemon evaluating detection rules and EWMA | N/A | Subscribes to Redis Stream `stream:telemetry:raw` |
| **Migration** | `waliya_migration` | One-shot Alembic migration runner executing schema updates | N/A | Completes before `backend` and `worker` start |
| **Database** | `waliya_postgres` | PostgreSQL 18 relational storage with durable volume `waliya_pgdata` | 5432 | `127.0.0.1:5432` (internal network binding) |
| **Stream Cache**| `waliya_redis` | Redis 7 streaming engine with AOF persistence in `waliya_redisdata` | 6379 | `127.0.0.1:6380` (internal network binding) |

---

## 4. Reproducible Production Installation

Follow this deterministic, step-by-step workflow to install and start the Ethio-SOAR platform.

### Step 1: Clone Repository & Prepare Configuration
```bash
# Copy the production environment configuration template
cp .env.example .env

# Generate cryptographically secure keys (example using openssl)
SECRET_KEY=$(openssl rand -hex 32)
ADMIN_KEY=$(openssl rand -hex 24)
PEPPER=$(openssl rand -hex 24)
POSTGRES_PASS=$(openssl rand -hex 16)
REDIS_PASS=$(openssl rand -hex 16)

# Update .env with generated secrets and explicit origins
sed -i "s/replace-with-a-cryptographically-secure-random-32-char-key/$SECRET_KEY/" .env
sed -i "s/replace-with-a-secure-admin-api-key-min-16-chars/$ADMIN_KEY/" .env
sed -i "s/replace-with-a-random-pepper-min-16-chars/$PEPPER/" .env
sed -i "s/replace-with-a-strong-postgres-password/$POSTGRES_PASS/g" .env
sed -i "s/replace-with-a-strong-redis-password/$REDIS_PASS/g" .env
```

### Step 2: Validate Deployment Configuration
Validate configuration settings prior to startup:
```bash
python3 scripts/validate_config.py --env-file .env
# Or via Makefile:
make validate-config
```
> [!NOTE]
> In production mode (`WALIYA_ENV=production`), the application enforces fail-fast validation: insecure default keys, wildcard CORS origins, or invalid connection URLs will prevent boot.

### Step 3: Build Container Images
Build the production multi-stage container images:
```bash
docker compose build
# Or via Makefile:
make build
```

### Step 4: Start Platform Stack
Start the infrastructure, execute migrations, and launch application services:
```bash
docker compose up -d
# Or via Makefile:
make up
```

The startup sequence guarantees that:
1. `postgres` and `redis` pass their healthchecks (`pg_isready` and `redis-cli ping`).
2. `migration` applies any pending Alembic revisions (`alembic upgrade head`) and exits with code 0 (`service_completed_successfully`).
3. `backend` and `worker` start only after migrations complete, preventing replica schema race conditions.
4. `frontend` starts and establishes the Nginx reverse proxy once `backend` passes its liveness healthcheck.

### Step 5: Verify Platform Health & Readiness
Query the diagnostic endpoints to verify operational readiness:
```bash
# Query frontend healthz
curl -i http://localhost:8080/healthz

# Query backend readiness probe through the reverse proxy
curl http://localhost:8080/api/v1/health/readiness

# Query authenticated administrative diagnostics
curl -H "X-API-Key: <YOUR_ADMIN_KEY>" http://localhost:8080/api/v1/health/diagnostics
```

### Step 6: Log Inspection & Safe Shutdown
```bash
# Stream aggregated container logs
docker compose logs -f

# View running container status
docker compose ps

# Gracefully stop the application (preserves database and cache volumes)
docker compose down
```

---

## 5. Local Development Workflow

For local development without full Docker container builds:

### Prerequisites
- Python 3.11+ (Python 3.14 compatible)
- Node.js 20+ & npm 9+
- Docker (for local PostgreSQL and Redis dependencies)

### Local Development Quickstart
```bash
# 1. Start local PostgreSQL and Redis infrastructure only
docker compose up -d postgres redis

# 2. Setup backend virtual environment
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
alembic -c alembic.ini upgrade head
uvicorn waliya.main:app --host 127.0.0.1 --port 8000 --reload

# 3. Start background worker (in a separate terminal)
source backend/.venv/bin/activate
python3 -m waliya.worker

# 4. Start frontend Vite development server
cd frontend
npm install
npm run dev
```

---

## 6. Monitored Agent & Simulator Deployment Considerations

- **Host Sensor Agent (`waliya_agent`):** Monitored endpoint sensors run on target Linux machines, initiating outbound HTTPS polling to `POST /api/v1/agents/{agent_id}/poll`. Agents are never packaged into the server's Docker Compose stack.
- **Purple-Team Simulator (`waliya_sim`):** Used strictly for adversary emulation testing and MITRE ATT&CK coverage validation. The simulator is isolated and does not execute in production Compose stacks.

---

## 7. Disaster Recovery, Backups & Operational Resilience

Ethio-SOAR provides comprehensive disaster recovery procedures, automated backup generation with SHA-256 manifests, isolated restore sandboxing, and Redis stream recovery tooling.

For full architectural details, RPO/RTO objectives, and failure runbooks, refer to [docs/DISASTER_RECOVERY.md](docs/DISASTER_RECOVERY.md).

### Quick Operational Commands

| Operation | Command | Description |
| :--- | :--- | :--- |
| **Backup Database** | `make backup` | Executes native `pg_dump -Fc` with `umask 077` and generates SHA-256 `.meta.json` |
| **Restore Database** | `make restore` | Restores latest backup safely into isolated target `waliya_recovery` |
| **List Backups** | `make list-backups` | Displays tabular view of backups, revisions, sizes, and health status |
| **Verify Backup** | `make verify-backup` | Verifies SHA-256 checksum and TOC archive readability of the latest backup |
| **Redis Stream Status** | `make redis-status` | Inspects stream lengths, AOF persistence status, and consumer group PEL |
| **Redis Re-initialize** | `make redis-reinit` | Ensures required stream consumer groups exist on telemetry streams |

### Safe Restoration Safeguards
To prevent catastrophic accidental overwrites, the restore tool defaults to the isolated database `waliya_recovery`. Overwriting the live production database (`waliya_ir`) requires an explicit confirmation flag:
```bash
./scripts/restore_db.sh --target-db waliya_ir --confirm-production-overwrite
```
