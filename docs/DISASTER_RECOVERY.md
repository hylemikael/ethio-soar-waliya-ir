# Ethio-SOAR (Waliya-IR) Disaster Recovery & Operational Resilience Guide

This guide establishes the disaster recovery architecture, recovery objectives, operational runbooks, and automated tooling for Ethio-SOAR (Waliya-IR).

---

## 1. State Classification & Persistence Architecture

Ethio-SOAR categorizes system state across three architectural tiers to guarantee zero data loss and rapid recovery:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   State Classification Architecture                    │
└────────────────────────────────────────────────────────────────────────┘
        ▲                                                ▲
        │                                                │
┌───────┴────────────────────────┐       ┌───────────────┴──────────────┐
│  Tier 1: Durable Source of     │       │  Tier 2: In-Flight Stream    │
│  Truth (PostgreSQL 16/18)      │       │  Buffer & Cache (Redis 7)    │
├────────────────────────────────┤       ├──────────────────────────────┤
│ • Security Findings & Incidents│       │ • In-flight telemetry streams│
│ • Attack & Correlation Graphs  │       │   (stream:telemetry:raw)     │
│ • SHA-256 Chained Audit Ledger │       │ • Dead-letter queue          │
│ • SOAR Response Playbooks      │       │   (stream:telemetry:dlq)     │
│ • Outbound Notification Outbox │       │ • Active consumer group lag  │
│ • Volume: waliya_pgdata        │       │ • Append-Only File (AOF)     │
│ • Tooling: scripts/backup_db.sh│       │ • Volume: waliya_redisdata   │
│            scripts/restore_db.sh│      │ • Tooling: redis_recovery.py │
└────────────────────────────────┘       └──────────────────────────────┘
                                 ▲
                                 │
                 ┌───────────────┴──────────────┐
                 │  Tier 3: Distributed Edge    │
                 │  Buffers (Host Sensors)      │
                 ├──────────────────────────────┤
                 │ • Local SQLite ring buffer   │
                 │   on monitored endpoints     │
                 │ • Automatic store-and-forward│
                 │   during platform outages    │
                 └──────────────────────────────┘
```

### Tier 1: Durable Source of Truth (PostgreSQL)
- **Engine:** PostgreSQL 16 (in container `waliya_postgres`) with persistent volume `waliya_pgdata`.
- **Contents:** Incident records, forensic artifacts, normalized event findings, MITRE ATT&CK correlation graphs, immutable SHA-256 chained audit ledgers, response executions, and outbound integration outbox.
- **Durability Guarantee:** Synchronous write-ahead logging (WAL) to disk. All security transactions are committed prior to HTTP acknowledgement.
- **Recovery Priority:** **Highest (Critical).**

### Tier 2: In-Flight Stream Buffer & Ephemeral Cache (Redis)
- **Engine:** Redis 7 (in container `waliya_redis`) with persistent volume `waliya_redisdata`.
- **Contents:** In-flight raw telemetry streams (`stream:telemetry:raw`), dead-letter streams (`stream:telemetry:dlq`), consumer group offsets (`waliya_detection_group`), sliding-window rate limiters, and distributed worker locks.
- **Durability Guarantee:** Append-Only File (`appendonly yes`) enabled, capturing every stream insertion.
- **Recovery Priority:** **High.** If Redis data is lost, consumer groups are automatically recreated, and unacknowledged telemetry is safely retransmitted from endpoint local buffers without corrupting backend state.

### Tier 3: Edge Ingestion Buffers (Host Sensors)
- **Engine:** Local SQLite storage in `waliya_agent/buffer/queue.py`.
- **Contents:** Buffered security telemetry collected on endpoints when backend connectivity is offline.
- **Durability Guarantee:** Persistent local spooling with backoff re-transmission upon connection restoration.

---

## 2. Recovery Objectives

| Metric | Target | Description |
| :--- | :--- | :--- |
| **Recovery Point Objective (RPO)** | **< 1 hour** (Scheduled) / **0 seconds** (Edge Buffers) | Maximum acceptable data loss window. Automated periodic backups bound PostgreSQL loss to < 1 hour, while edge agent buffers prevent loss of live security telemetry during platform outages. |
| **Recovery Time Objective (RTO)** | **< 15 minutes** | Maximum allowable downtime from disaster declaration to restored, verified operational status. Automated restore and checksum validation take under 3 minutes for typical enterprise databases. |

---

## 3. Automated Backup Architecture (`scripts/backup_db.sh`)

PostgreSQL backups are executed via `scripts/backup_db.sh` using native PostgreSQL custom-archive compression (`pg_dump -Fc`).

### Key Features
1. **Container-Aware Execution:** Automatically detects running `waliya_postgres` containers and invokes container-native `pg_dump` to eliminate client-server version mismatches.
2. **Cryptographic SHA-256 Manifest:** Generates a companion `<backup_file>.meta.json` recording backup byte size, UTC timestamp, Alembic head schema revision, and SHA-256 checksum.
3. **Archive Pre-Validation:** Executes an immediate `pg_restore --list` table-of-contents check against the generated dump before finalizing.
4. **Restrictive Permissions:** Enforces `umask 077` creating files with mode `0600` and the backup directory with mode `0700`.
5. **Automated Retention Management:** Automatically purges older backup files exceeding the retention limit (default: 10 backups).
6. **Git Protection:** The `backups/` directory, `*.dump`, and `*.sql.gz` patterns are explicitly excluded in `.gitignore`.

### Operational Usage
```bash
# Generate backup with default settings (retaining 10 recent backups)
./scripts/backup_db.sh

# Or via Makefile:
make backup

# Custom parameters:
./scripts/backup_db.sh --output-dir /opt/backups --keep 30 --db-name waliya_ir
```

### Metadata Manifest Example
```json
{
  "backup_filename": "waliya_ir_backup_20261025_162150.dump",
  "created_at_utc": "2026-10-25T16:21:52Z",
  "database_name": "waliya_ir",
  "format": "custom (pg_dump -Fc)",
  "size_bytes": 2694538,
  "sha256_checksum": "a8c08ef1bc5de330f6b3dbba805fc867a54a7376c94443ef21f92e22cba277ea",
  "alembic_head_revision": "0015_performance_indexes",
  "verification_status": "VERIFIED_VALID",
  "dump_tool_version": "pg_dump (PostgreSQL) 16.15"
}
```

---

## 4. Safe Restore Architecture (`scripts/restore_db.sh`)

PostgreSQL restoration is handled through `scripts/restore_db.sh` with multiple layers of safety validation.

### Multi-Stage Safety Workflow
1. **Pre-Restore Checksum Verification:** Calculates the SHA-256 hash of the archive and matches it against the companion `.meta.json`. Rejects corrupted or altered backups.
2. **Table of Contents (TOC) Inspection:** Inspects archive readability using `pg_restore --list`.
3. **Safe Target Isolation:** Defaults to restoring into an isolated sandbox database: `waliya_recovery`.
4. **Accidental Overwrite Safeguard:** If an operator specifies the live database (`waliya_ir` or `production`), the script **immediately halts with exit code 2** unless explicitly supplied with `--confirm-production-overwrite`.
5. **Active Connection Termination:** Safely terminates stale connection pools before initiating schema restoration.
6. **Post-Restore Integrity Verification:** Queries the restored database to confirm table counts and verify that `alembic_version` matches the expected head schema.

### Operational Usage

#### Scenario A: Safe Sandbox Restoration (Default & Verification)
```bash
# Restore latest backup to waliya_recovery for audit or inspection
./scripts/restore_db.sh

# Or via Makefile:
make restore

# Specify a specific backup file
./scripts/restore_db.sh --backup-file backups/waliya_ir_backup_20261025_162150.dump --target-db waliya_staging
```

#### Scenario B: Primary Production Overwrite (Disaster Recovery Only)
> [!CAUTION]
> This command overwrites the primary production database `waliya_ir`. Active sessions will be terminated and schema overwritten.

```bash
./scripts/restore_db.sh --backup-file backups/waliya_ir_backup_20261025_162150.dump \
  --target-db waliya_ir \
  --confirm-production-overwrite
```

---

## 5. Backup Inspection & Management Utility (`scripts/manage_backups.py`)

A specialized Python utility provides fast administrative visibility and cryptographic auditing of all stored backups.

### Commands
```bash
# Tabular summary of all backups, sizes, revisions, and health
python3 scripts/manage_backups.py list
# Or via Makefile:
make list-backups

# Cryptographic verification of a backup file
python3 scripts/manage_backups.py verify backups/waliya_ir_backup_20261025_162150.dump
# Or verify latest via Makefile:
make verify-backup
```

### Output Example
```text
==============================================================================================================
BACKUP FILE                            SIZE (MB)  ALEMBIC REV              CHECKSUM     ARCHIVE    STATUS
==============================================================================================================
waliya_ir_backup_20261025_162150.dump  2.57       0015_performance_indexes PASS         VALID      HEALTHY
==============================================================================================================
```

---

## 6. Redis Streaming Recovery & Diagnostics (`scripts/redis_recovery.py`)

Redis Streams serve as the event highway between HTTP ingestion and detection workers. The `scripts/redis_recovery.py` tool provides stream inspection and recovery automation.

### Commands

#### 1. Inspect Stream Health & Persistence
```bash
python3 scripts/redis_recovery.py status
# Or via Makefile:
make redis-status
```
Reports:
- Redis server connectivity (`PONG`)
- AOF persistence state (`aof_enabled`, `aof_last_bgrewrite_status`, file size)
- Stream message counts (`stream:telemetry:raw`, `stream:telemetry:dlq`)
- Consumer group subscriptions, pending message count (PEL), and consumer counts

#### 2. Re-Initialize Consumer Groups
```bash
python3 scripts/redis_recovery.py reinit-groups
# Or via Makefile:
make redis-reinit
```
Ensures that the required consumer group `waliya_detection_group` exists on `stream:telemetry:raw` and `stream:telemetry:dlq` using the `MKSTREAM` flag. Safe to execute idempotently (ignores `BUSYGROUP` errors).

#### 3. Inspect Stuck In-Flight Telemetry (Pending Entries List)
```bash
python3 scripts/redis_recovery.py check-pel
```
Identifies unacknowledged telemetry items held by stalled workers, displaying idle time in seconds and delivery attempt counts.

---

## 7. Container Runtime Resilience Configuration

To prevent out-of-memory cascades and resource starvation, resource limits and reservations are declared in `docker-compose.yml`:

| Service | CPU Limit | Memory Limit | Memory Reservation | Stop Signal | Stop Grace Period |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `postgres` | 2.0 | 1024 MB | 256 MB | `SIGINT` (Fast Shutdown) | 30s |
| `redis` | 1.5 | 512 MB | 128 MB | `SIGTERM` | 30s |
| `backend` | 2.0 | 1024 MB | 256 MB | `SIGTERM` | 30s |
| `worker` | 2.0 | 1024 MB | 256 MB | `SIGTERM` | 30s |
| `frontend` | 1.0 | 256 MB | 64 MB | `SIGQUIT` | 15s |
| `migration` | 1.0 | 512 MB | N/A | `SIGTERM` | 10s |

### Graceful Shutdown Sequence
When `docker compose down` or `make down` is executed:
1. Nginx stops accepting new HTTP connections and finishes active requests within 15 seconds (`SIGQUIT`).
2. FastAPI (`backend`) finishes in-flight requests and closes database connection pools cleanly (`SIGTERM`, 30s grace).
3. Telemetry worker (`worker`) acknowledges current stream items or releases them back to PEL (`SIGTERM`, 30s grace).
4. PostgreSQL flushes dirty buffers and writes shutdown checkpoints (`SIGINT`, 30s grace).
5. Redis flushes AOF buffers to disk (`SIGTERM`, 30s grace).

---

## 8. Operational Failure Runbooks

### Runbook 1: PostgreSQL Volume Loss or Catastrophic Corruption
1. **Stop platform services:**
   ```bash
   make down
   ```
2. **Inspect available backups and verify integrity:**
   ```bash
   make list-backups
   make verify-backup
   ```
3. **Recreate storage container:**
   ```bash
   docker compose up -d postgres
   ```
4. **Restore schema and data to production database:**
   ```bash
   ./scripts/restore_db.sh --target-db waliya_ir --confirm-production-overwrite
   ```
5. **Start remaining application stack:**
   ```bash
   make up
   ```
6. **Verify platform health:**
   ```bash
   make health
   ```

### Runbook 2: Redis Stream Desynchronization or Node Crash
1. **Verify Redis persistence status:**
   ```bash
   make redis-status
   ```
2. **Re-initialize consumer groups on streams:**
   ```bash
   make redis-reinit
   ```
3. **Inspect pending entries list for stalled items:**
   ```bash
   python3 scripts/redis_recovery.py check-pel
   ```
4. **Restart worker container:**
   ```bash
   docker compose restart worker
   ```

### Runbook 3: Database Schema Migration Rollback / Recovery
1. **Inspect current schema revision:**
   ```bash
   docker exec -it waliya_postgres psql -U waliya_user -d waliya_ir -c "SELECT version_num FROM alembic_version;"
   ```
2. **Restore pre-migration snapshot to `waliya_recovery` to inspect historical state:**
   ```bash
   ./scripts/restore_db.sh --target-db waliya_recovery
   ```
3. **Execute selective data export or schema rollback as required.**

---

## 9. Verification & Automated Test Coverage

The disaster recovery procedures are covered by automated integration tests in:
`backend/tests/integration/test_disaster_recovery_and_backups.py`

Run the disaster recovery test suite:
```bash
backend/.venv/bin/pytest backend/tests/integration/test_disaster_recovery_and_backups.py -v
```
Verified test scenarios include:
- Native backup execution and manifest generation.
- Checksum validation and tamper detection.
- Restoration into isolated sandbox target database.
- Prevention of accidental production overwrite without explicit flag.
- Retention policy pruning.
- Redis consumer group re-initialization.
