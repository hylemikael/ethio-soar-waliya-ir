# Ethio-SOAR (Waliya-IR) — Final Independent Engineering Audit Report

**Date of Audit:** October 25, 2026
**Auditor Role:** Independent Lead Auditor, Principal Security Engineer & DevSecOps Architect
**Project Workspace:** `/home/hailax/Desktop/ethio-soar-waliya-ir`
**Git Branch:** `main` (commit state: clean working tree, untracked files preserved)
**Overall Verdict:** **`PASS WITH LIMITATIONS`**

---

## 1. Executive Summary & Audit Verdict

An independent, rigorous, evidence-based engineering audit was conducted on the completed **Ethio-SOAR (Waliya-IR)** platform across its core subsystems:
- Operational visibility and Docker daemon reliability
- Production security controls and secret hygiene (SEC-01 through SEC-08)
- Log redaction and sensitive data masking
- Database backup, SHA-256 integrity verification, and safe disaster recovery
- Test suite integrity and pass rates (reconciling previous 425 vs 426 claims)
- Live container and host service health checks

### Audit Verdict: `PASS WITH LIMITATIONS`

| Area | Status | Summary Evidence |
| :--- | :---: | :--- |
| **Backend Test Suite** | **PASS** | 321 / 321 tests passing (including 7 disaster recovery tests) |
| **Agent Sensor Suite** | **PASS** | 62 / 62 tests passing |
| **Simulator Suite** | **PASS** | 42 / 42 tests passing |
| **Frontend Production Build** | **PASS** | Clean build via `tsc && vite build` (501 kB JS bundle, 0 errors) |
| **Total Automated Tests** | **PASS** | **425 automated tests passed (100% pass rate)** |
| **Database Backup & Restore** | **PASS** | Container-native PostgreSQL 16.15 `pg_dump`, SHA-256 verified, safe restore into `waliya_audit_verification_db` verified |
| **Security Controls (SEC-01–08)** | **PASS** | Docs disabled in prod (404), security headers enforced, 500 errors sanitized, secrets excluded from frontend bundle |
| **Log Redaction** | **PASS (FIXED)** | Discovered and fixed unredacted single quotes, unquoted values, and DB/Redis URI credentials |
| **Docker Compose Daemon** | **PASS WITH LIMITATIONS** | Host dockerd mutex contention diagnosed (caused by foreign container `poip_fastapi`). Container build requires pre-built images in airgapped environments. |
| **TLS / In-Transit Encryption** | **LIMITATION** | Nginx terminates HTTP on loopback `127.0.0.1:8080`. External production deployment requires TLS termination at ingress/edge. |

---

## 2. Docker Reliability Diagnosis & Deployment Behavior

### 2.1 The Issue
Previous audit runs observed severe command hangs and timeouts when running unconstrained Docker commands such as `docker ps` and `docker info`.

### 2.2 Host Resource Audit
Host resources were inspected to rule out hardware starvation:
- **RAM:** 7.1 GiB total, 2.5 GiB free/available. No swap exhaustion.
- **Disk:** 457 GiB total, 303 GiB available (31% utilization). No disk space exhaustion.
- **CPU:** 4 physical cores, load average ~3.5.

### 2.3 Root Cause Analysis
Examination of system logs (`journalctl -u docker.service`) and low-level container inspect calls revealed:
1. **Unrelated Host Container in Infinite Crash-Loop:**
   A foreign container from a separate project on the host (`poip_fastapi`, container ID `aa5244667a74`, configured with `restart: unless-stopped`) had crashed **2,069 times**, continuously triggering `events.TaskDelete` in `libcontainerd`.
2. **Missing Image Lookups:**
   The host Docker daemon was simultaneously logging repeated network lookup failures for `poip-platform-worker`.
3. **Internal Daemon Mutex Contention:**
   Unscoped commands like `docker ps` and `docker info` acquire global daemon locks, causing them to stall behind the rapid crash-restart cycle of the foreign container.

### 2.4 Resolution & Verification
- Rather than running destructive host-level actions (e.g. killing foreign processes or restarting dockerd), Ethio-SOAR operational scripts (`scripts/backup_db.sh` and `scripts/restore_db.sh`) were hardened to use scoped, non-blocking inspect commands:
  ```bash
  docker inspect -f '{{.State.Running}}' "${CONTAINER_NAME}" 2>/dev/null
  ```
- **Observed Result:** Container checks for `waliya_postgres` and `waliya_redis` now respond in **0.05 seconds**, completely eliminating execution timeouts.

### 2.5 Deployment Behavior in Sandboxed / Airgapped Environments
- `docker compose build backend` was executed and timed out trying to reach `pypi.org` (`[Errno 101] Network is unreachable`).
- **Audit Finding:** The host workspace is an offline/airgapped environment without outbound internet access to PyPI.
- **Deployment Status:**
  - PostgreSQL (`waliya_postgres`, 16-alpine) and Redis (`waliya_redis`, 7-alpine) run directly and reliably from local cached Docker images.
  - Backend, worker, and frontend run natively via pre-installed virtualenvs (`backend/.venv`), pre-built node modules (`frontend/node_modules`), and compiled production bundles (`frontend/dist`).
  - For airgapped container deployments, production images must be pre-built and transferred via `docker load < image.tar`.

---

## 3. Code Verification & Production Security Hardening

All security claims from Phase 12 were audited directly against source code and confirmed with runtime test evidence.

### 3.1 Verification Matrix (SEC-01 through SEC-08)

| Control ID | Claim | Source Location | Verification Method | Status |
| :--- | :--- | :--- | :--- | :---: |
| **SEC-01** | Public API docs disabled in production | `backend/src/waliya/main.py` lines 86–95 | Queried `/docs`, `/redoc`, and `/api/v1/openapi.json` with `WALIYA_ENV=production`. Returned HTTP 404. | **VERIFIED** |
| **SEC-02** | Security response headers enforced | `backend/src/waliya/main.py` lines 61–75 | Verified `SecurityHeadersMiddleware`: emits `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: strict-origin-when-cross-origin`, and `Permissions-Policy`. | **VERIFIED** |
| **SEC-03** | Unhandled exception sanitization | `backend/src/waliya/main.py` lines 122–148 | Verified global exception handler catches unhandled 500 errors and returns sanitized JSON with `correlation_id` and `X-Request-ID`. Stack traces are withheld from clients. | **VERIFIED** |
| **SEC-04** | Sensitive data log redaction | `backend/src/waliya/observability/correlation.py` | Discovered regex gaps in original filter; enhanced rules to scrub single quotes, unquoted key-values, and DB/Redis URI passwords. Verified via tests. | **FIXED & VERIFIED** |
| **SEC-05** | Web server hardening (Nginx) | `frontend/nginx.conf` | Verified `server_tokens off;`, `client_max_body_size 10M;`, and custom error pages for 500, 502, 503, 504. | **VERIFIED** |
| **SEC-06** | Bounded local port binding | `docker-compose.yml` line 187 | Verified frontend port binds to `${WALIYA_BIND_HOST:-127.0.0.1}:${WALIYA_PORT:-8080}:80`. PostgreSQL and Redis bind strictly to `127.0.0.1`. | **VERIFIED** |
| **SEC-07** | Non-root and privilege containment | `docker-compose.yml` & `Dockerfile` | All 6 services enforce `security_opt: ["no-new-privileges:true"]`. Backend Dockerfile creates unprivileged user `waliya` (UID/GID 10001). | **VERIFIED** |
| **SEC-08** | Frontend static bundle secret hygiene | `frontend/dist/` assets | Audited compiled bundle via `grep -rnE "(insecure-dev|supersecret|pepper)" frontend/dist/`. Exactly 0 matches found. | **VERIFIED** |

### 3.2 Security Defect Discovered and Repaired: Log Redaction Enhancement

**Vulnerability:**
The original `SensitiveDataFilter` in `backend/src/waliya/observability/correlation.py` only matched double-quoted key-value patterns (e.g. `password="secret"`). It failed to redact:
1. Single-quoted values: `api_key='abc123secret'`
2. Unquoted assignment values: `token=supersecret123`
3. Connection URIs with credentials: `postgresql+asyncpg://waliya_user:waliya_dev_password@postgres:5432/waliya_ir`

**Remediation:**
Updated `backend/src/waliya/observability/correlation.py` with expanded regex patterns (`SENSITIVE_RULES`) and an updated `redact_text()` function handling single quotes, unquoted tokens, and connection URL passwords:
```python
SENSITIVE_RULES = [
    # Key-value pairs (double or single quoted)
    re.compile(
        rf"""(?i)\b(?:{SENSITIVE_FIELD_NAMES})\b\s*(?:[:=]|=>)\s*["']([^"']+)["']""",
    ),
    # Key-value pairs (unquoted tokens)
    re.compile(
        rf"""(?i)\b(?:{SENSITIVE_FIELD_NAMES})\b\s*(?:[:=]|=>)\s*([^\s,;}})]+)""",
    ),
    # Connection URIs with embedded passwords: scheme://user:password@host
    re.compile(
        r"""(?i)\b([a-z0-9+_-]+://[^:\s/@]+:)([^@\s/]+)(@[^:\s/@]+)""",
    ),
]
```
Added unit and integration test assertions in `test_phase12_production_security_hardening.py` to continuously verify all three redaction cases.

---

## 4. Database Backup, Integrity & Disaster Recovery Verification

### 4.1 Backup Execution
Executed `./scripts/backup_db.sh` using container-native PostgreSQL 16.15 `pg_dump`:
```bash
./scripts/backup_db.sh
```
**Outcome:**
- Backup archive created: `backups/waliya_ir_backup_20261025_174518.dump` (3,223,971 bytes / 3.07 MB).
- File permissions set to `0600` (`-rw-------`), directory permissions `0700`.
- Manifest created: `backups/waliya_ir_backup_20261025_174518.dump.meta.json` with SHA-256 hash `d5f19067be25fd556a3e1c667ef4b89ebc1146747d2b45e9eeeb73a6e60b1388`.
- Detected Alembic revision in backup: `0015_performance_indexes`.

### 4.2 Protection Against Production Overwrite
Executed:
```bash
./scripts/restore_db.sh --target-db waliya_ir
```
**Observed Output:**
```
[-] ERROR: Refusing to restore over active database 'waliya_ir'.
    Safety guardrail prevents accidental production data destruction.
```
**Outcome:** Command halted with exit code `2`. Production database was protected.

### 4.3 Safe Restoration into Isolated Database
Restored the backup into a designated verification database:
```bash
./scripts/restore_db.sh --target-db waliya_audit_verification_db
```
**Observed Output:**
```
[*] Restoring from backup: /home/hailax/Desktop/ethio-soar-waliya-ir/backups/waliya_ir_backup_20261025_174518.dump
    Target Database:       waliya_audit_verification_db
[+] Target database 'waliya_audit_verification_db' created successfully.
[+] Backup archive format verified via pg_restore --list.
[*] Restoring database schema and data...
[+] Database restore completed successfully into 'waliya_audit_verification_db'.
[*] Verifying restored database integrity...
    Table count:           21
    Alembic revision:      0015_performance_indexes
[SUCCESS] Verification passed! Target database 'waliya_audit_verification_db' is intact.
```
- Restored tables verified: all 21 core tables present (including `agents`, `events`, `findings`, `incidents`, `threat_indicators`, `playbooks`, `response_actions`, `audit_ledger`, etc.).
- Schema version verified: `0015_performance_indexes`.
- Post-audit cleanup: `waliya_audit_verification_db` dropped cleanly.

### 4.4 Backup CLI Tools Verification
- `manage_backups.py list`: Correctly displayed table of all backups, checksum status (`PASS`), archive health (`VALID`), and status (`HEALTHY`).
- `manage_backups.py verify`: Executed cryptographic SHA-256 and PostgreSQL archive structure verification: `[SUCCESS] Backup file passed all integrity checks.`
- `redis_recovery.py status`: Verified Redis connectivity, AOF persistence (`AOF Enabled = True`, `AOF Rewrite Status: ok`), and telemetry streams.
- `redis_recovery.py reinit-groups`: Confirmed consumer groups `waliya_detection_group` exist on `stream:telemetry:raw` and `stream:telemetry:dlq`.

---

## 5. Reconciled Test Counts & Pass Status

Previous Phase 12 documentation cited both 425 and 426 tests. This discrepancy was audited and reconciled.

### 5.1 Test Discrepancy Reconciliation
- **Automated pytest test functions:**
  - Backend pytest suite: **321 tests** (this *includes* the 7 disaster recovery tests in `backend/tests/integration/test_disaster_recovery_and_backups.py`).
  - Agent sensor pytest suite: **62 tests**.
  - Simulator pytest suite: **42 tests**.
  - **Total automated test count:** $321 + 62 + 42 = \mathbf{425}$ tests.
- **Why "426" appeared in previous summaries:**
  The previous summary table listed the **Frontend Production Build** (`npm run build`) as a 4th line item with "1 passed", resulting in $425 + 1 = 426$ verified verification items. The actual number of executable test cases is **425**.

### 5.2 Test Execution Results

```
================================================================================
TEST SUITE                 TOTAL   PASSED   FAILED   SKIPPED   DURATION
================================================================================
Backend Integration & Unit   321      321        0         0    84.51s
Agent Sensors & C2 Client     62       62        0         0     3.58s
Adversarial Simulator         42       42        0         0    17.92s
--------------------------------------------------------------------------------
TOTAL PYTEST TESTS           425      425        0         0   106.01s
Frontend Production Build      1        1        0         0    27.77s
================================================================================
OVERALL RESULT: 100% PASS (0 failures, 0 regressions, 0 skipped)
================================================================================
```

### 5.3 Test Isolation Defects Identified & Fixed During Audit
During the audit run, two subtle test-isolation issues were identified and resolved:
1. **`test_dry_run_makes_no_database_changes` (Threat Intel Sync):**
   The test used a static IP (`198.51.100.88`). If another test (such as `test_threat_intel_and_asset_api`) inserted an indicator with that IP into the persistent database, the dry-run assertion (`assert res.scalar_one_or_none() is None`) failed.
   *Fix:* Generated a dynamic test IP and performed a pre-cleanup in `test_threat_intel_sync_service.py`.
2. **`test_threat_indicator_lifecycle_and_duplicate_prevention`:**
   The test asserted `len(items) == 2` against `/api/v1/threat-intel/indicators?search={unique_ip}`. Because `search` performs an ILIKE substring search (`%search%`), a 2-digit octet (e.g. `203.0.113.18`) matched longer existing IPs (`203.0.113.183`, etc.).
   *Fix:* Filtered exact IP matches in the response (`exact_items = [i for i in items if i["value"] == unique_ip]`) and added post-test cleanup.

---

## 6. Live Stack Inspection & Health Endpoints

### 6.1 Uvicorn Backend Direct Verification
The backend server was started against live PostgreSQL and Redis instances:
```bash
backend/.venv/bin/uvicorn waliya.main:app --host 127.0.0.1 --port 8000
```
- **Liveness Endpoint:**
  ```bash
  curl -s -i http://127.0.0.1:8000/api/v1/health/liveness
  ```
  **Response:**
  ```http
  HTTP/1.1 200 OK
  content-type: application/json
  x-content-type-options: nosniff
  x-frame-options: SAMEORIGIN
  referrer-policy: strict-origin-when-cross-origin
  permissions-policy: geolocation=(), camera=(), microphone=()
  x-request-id: req_4eef4db2748a

  {"status":"UP","timestamp":"2026-10-25T17:51:16.735301Z","version":"2.0.0"}
  ```

- **Readiness Endpoint:**
  ```bash
  curl -s -i http://127.0.0.1:8000/api/v1/health/readiness
  ```
  **Response:**
  ```http
  HTTP/1.1 200 OK
  content-type: application/json
  x-content-type-options: nosniff
  x-frame-options: SAMEORIGIN
  x-request-id: req_90de67d0bd76

  {"status":"READY","timestamp":"2026-10-25T17:51:21.629435Z","checks":{"database":"CONNECTED","redis":"CONNECTED"}}
  ```

---

## 7. Modified Files & Rationale

| File Path | Nature of Change | Rationale |
| :--- | :--- | :--- |
| `backend/src/waliya/observability/correlation.py` | Defect Fix | Expanded `SensitiveDataFilter` to mask single-quoted secrets, unquoted parameters, and database/redis connection URI passwords. |
| `backend/tests/integration/test_phase12_production_security_hardening.py` | Test Enhancement | Added test assertions covering single-quote, unquoted, and URI password redaction. |
| `scripts/backup_db.sh` | Performance & Reliability Fix | Replaced unconstrained `docker ps` with scoped `docker inspect` to eliminate Docker daemon hangs caused by foreign host containers. |
| `scripts/restore_db.sh` | Performance & Reliability Fix | Replaced `docker ps` with scoped `docker inspect` for instant container health verification. |
| `backend/tests/unit/test_threat_intel_sync_service.py` | Test Isolation Fix | Replaced static test IP with dynamic value and pre-cleanup to prevent cross-test state collisions. |
| `backend/tests/integration/test_threat_intel_and_asset_api.py` | Test Isolation Fix | Enforced exact IP matching on substring search and added post-test indicator cleanup. |

---

## 8. Remaining Operational Risks & Production Limitations

1. **Airgapped Container Builds:**
   The workspace cannot pull from public PyPI during `docker build`. In disconnected or airgapped environments, production container images should be pre-built and imported using `docker load` or an enterprise internal registry.
2. **In-Transit TLS Encryption:**
   The platform's Nginx configuration is currently set up for HTTP reverse proxying on loopback `127.0.0.1:8080`. For production access across networks, operators must terminate TLS (HTTPS) via a cloud ingress controller, edge load balancer, or Let's Encrypt / Certbot reverse proxy.
3. **Foreign Host Processes:**
   The host machine contains an unrelated container (`poip_fastapi`) in an active crash loop. While Ethio-SOAR scripts have been insulated against this via scoped `docker inspect` calls, host administrators should stop or remove the crashing container (`docker rm -f aa5244667a74`) to maintain general daemon hygiene.

---

## 9. Local Operation & Inspection Commands

### Start Core Infrastructure (Docker)
```bash
docker compose up -d postgres redis
```

### Validate Environment Configuration
```bash
make validate-config
```

### Run Database Migrations
```bash
backend/.venv/bin/alembic -c backend/alembic.ini upgrade head
```

### Start Backend API Server
```bash
backend/.venv/bin/uvicorn waliya.main:app --host 127.0.0.1 --port 8000
```

### Start Background Telemetry Worker
```bash
PYTHONPATH=backend/src backend/.venv/bin/python -m waliya.worker
```

### Run Automated Regression Test Suite
```bash
make test
```

### Create and Verify Database Backup
```bash
make backup
make verify-backup
make list-backups
```

### Check Redis Streaming Status
```bash
make redis-status
```

---

## 10. Final Audit Verdict

The Ethio-SOAR (Waliya-IR) platform achieves **`PASS WITH LIMITATIONS`**.

The software architecture, database integrity, telemetry ingestion, incident correlation, threat intelligence integration, SOAR response engine, disaster recovery tooling, and 425 automated tests are verified, robust, and functional. Once deployed behind an HTTPS reverse proxy with pre-loaded container images, the system is ready for production operation.
