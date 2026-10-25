# Waliya-IR Operational Runbook

**Version:** 2.0.0
**Target Platform:** Linux-First SOAR & Incident Response Platform
**Scope:** Backend Services, Linux Endpoint Agent, Purple-Team Simulation (`waliya-sim`), and Analyst Dashboard

---

## 1. Environment & Architecture Overview

Waliya-IR operates as a distributed threat detection and automated response platform with five operational components:
- **FastAPI Core Backend (`backend/`):** REST & C2 endpoints, session auth, detection rules, SOAR playbooks, and simulation management.
- **PostgreSQL 16+ Database:** Storage for events, findings, incidents, agents, playbooks, simulation runs, and SHA-256 hash-chained audit ledger.
- **Redis 7+ Streams & Cache:** Event streaming (`stream:telemetry:raw`), sliding-window state (`waliya:win:...`), and EWMA behavioral baselines.
- **Linux Endpoint Agent (`waliya-agent`):** Standalone telemetry collector and HMAC-authenticated command execution client.
- **Deterministic Purple-Team Simulator (`waliya-sim`):** Safe, side-effect-free CLI tool for closed-loop validation of detection rules and MITRE ATT&CK coverage.
- **React Analyst Console (`frontend/`):** 5 operational workspaces for SOC operations, investigation, detection engineering, SOAR playbooks, and purple-team validation.

---

## 2. Platform Startup & Deployment

### 2.1 Database & Redis Infrastructure
Ensure PostgreSQL and Redis are running:
```bash
# Check PostgreSQL status
sudo systemctl status postgresql
# Verify database connection
psql -h 127.0.0.1 -U postgres -d waliya_ir -c "SELECT 1;"

# Check Redis status
redis-cli -p 6380 -a waliya_redis_dev_secret ping
# Expected output: PONG
```

### 2.2 Database Migrations
Apply all schema migrations (including simulation isolation columns):
```bash
cd backend
.venv/bin/alembic upgrade head
```

### 2.3 Starting Backend API & Consumer Worker
```bash
cd backend
# Terminal 1: Core API Server
.venv/bin/uvicorn waliya.main:app --host 0.0.0.0 --port 8000 --reload

# Terminal 2: Telemetry Consumer Worker (Processes Redis Streams -> Findings)
.venv/bin/python -m waliya.telemetry.consumer_worker
```

### 2.4 Starting Frontend Dashboard
```bash
cd frontend
npm install
npm run dev
# Dashboard accessible at http://127.0.0.1:5173
```

---

## 3. Operating Waliya-Sim: Purple-Team Simulation CLI

`waliya-sim` generates controlled, deterministic security telemetry scenarios that mirror real adversary techniques without executing malicious payloads on disk or over the network.

### 3.1 Listing Registered Scenarios
```bash
# Formatted table view
waliya-sim list

# Machine-readable JSON
waliya-sim list --json
```

**Available Scenarios:**
1. `brute-force` (T1110.001): Excessive Authentication Failures ($\ge 5$ failures in 300s).
2. `web-shell` (T1505.003): Suspicious Web File Creation (`.php`, `.jsp` in web directory).
3. `port-scan` (T1046): Network Port-Scan Behavior ($\ge 10$ distinct destination ports in 60s).
4. `priv-esc` (T1548.003): Suspicious Privilege Escalation Execution (non-root `sudo`, `pkexec`, `doas`).

### 3.2 Side-Effect-Free Preview Mode
Always verify generated synthetic payloads prior to submission:
```bash
# Positive detection preview (triggers threshold)
waliya-sim preview brute-force

# Negative boundary preview (sub-threshold, must not alert)
waliya-sim preview brute-force --negative

# Machine-readable preview
waliya-sim preview web-shell --json
```
*Guaranteed zero network requests, zero file touches, and zero shell executions.*

### 3.3 Executing Simulations Against Waliya-IR
Execute positive and negative test cases against a running backend:
```bash
# Positive detection run (expects alert + incident)
waliya-sim run brute-force \
    --url http://127.0.0.1:8000 \
    --agent-id <AGENT_UUID> \
    --agent-token <AGENT_TOKEN> \
    --admin-key <ADMIN_KEY>

# Negative boundary run (expects zero alerts)
waliya-sim run brute-force --negative \
    --url http://127.0.0.1:8000 \
    --agent-id <AGENT_UUID> \
    --agent-token <AGENT_TOKEN> \
    --admin-key <ADMIN_KEY>
```

### 3.4 Checking MITRE ATT&CK Validation Matrix
Inspect platform detection validation status directly from CLI:
```bash
waliya-sim matrix --url http://127.0.0.1:8000 --admin-key <ADMIN_KEY>
```
Rules achieve `YES` validation status only when their positive detection test passes AND their negative boundary test succeeds (preventing false-positive prone rules from falsely claiming validation).

### 3.5 Managing Local Simulation Reports
```bash
# Inspect a specific report
waliya-sim report <RUN_ID>

# Clean local simulation report cache without touching database
waliya-sim clean
```

---

## 4. Production vs Simulation Isolation Invariants

Waliya-IR enforces multi-layer isolation guarantees:

| Layer | Real Security Operations | Purple-Team Simulation | Hard Enforcement Guarantee |
| :--- | :--- | :--- | :--- |
| **Database** | `is_simulation = False` | `is_simulation = True` | Indexed boolean columns on `findings` and `incidents`. |
| **Correlation** | Merges by host/entity | Merges *only* within same `simulation_run_id` | Real and synthetic findings can never merge into the same incident. |
| **Redis Windows** | `waliya:win:...` | `waliya:win:sim:{run_id}:...` | Sliding-window threshold counts never cross-contaminate between runs or real events. |
| **Deduplication** | `{rule_id}:{entity}` | `sim:{run_id}:{rule_id}:{entity}` | Synthetic tests never suppress real operational alerts. |
| **SOAR Actions** | Live response allowed | `dry_run = True` mandatory | Playbook executions on simulated incidents are forced to dry-run mode. |
| **Network IP** | Production CIDRs | RFC 5737 (`198.51.100.0/24`) | Synthetic events are strictly restricted to reserved documentation IP blocks. |

---

## 5. Troubleshooting & Operational Recovery

### 5.1 Redis Stream Consumer Worker Lag
If telemetry events are queued but findings are not appearing:
```bash
# Check stream length
redis-cli -p 6380 -a waliya_redis_dev_secret XLEN stream:telemetry:raw

# Check consumer group pending entries
redis-cli -p 6380 -a waliya_redis_dev_secret XPENDING stream:telemetry:raw telemetry_workers
```
*Remediation:* Restart the consumer worker process. Incomplete or dead-letter events are automatically routed to `stream:telemetry:dlq` after 3 failed delivery attempts.

### 5.2 Verifying Audit Ledger Integrity
If unauthorized database changes are suspected:
```bash
curl -s -X GET http://127.0.0.1:8000/api/v1/audit/verify \
    -H "Authorization: Bearer <TOKEN>"
```
The endpoint recalculates SHA-256 hash chains across all ledger entries from Genesis. Any modified or deleted record will be reported with its exact sequence number and failure details.

---

## 6. Known Limitations & Future Work

1. **In-Memory NetworkX Graph TTL:** The attack graph correlation engine uses an in-memory sliding window (default: 60 minutes). Graph state does not survive backend server restarts; incidents persist in PostgreSQL, but active entity topology is reconstructed from stored event records on demand.
2. **Single-Node Redis Dependency:** High-throughput production deployments require Redis Cluster or Sentinel configuration for high availability of telemetry streams and sliding windows.
3. **Simulated Linux Response Adapters:** While `waliya-agent` supports real Linux `iptables` and `/proc` process termination, response actions against simulated incidents are restricted to `dry_run = True` by design. Future releases will provide containerized virtual sandbox targets for safe live containment testing.
4. **MITRE ATT&CK Matrix Scope:** Currently, 4 representative behavioral scenarios are registered (`T1110.001`, `T1505.003`, `T1046`, `T1548.003`). Future roadmap includes expanding coverage to lateral movement (`T1021.002`), persistence (`T1053.003`), and credential dumping (`T1003.008`).
