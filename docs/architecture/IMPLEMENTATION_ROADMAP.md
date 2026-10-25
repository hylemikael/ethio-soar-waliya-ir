# Implementation Roadmap & Sprint Work Packages
**Project:** Ethio-SOAR (Waliya-IR)
**Status:** Locked / Approved (Phase 1 — Step 2)

---

## 1. Five-Day Engineering Plan

```text
+------------------------------------------------------------------------------------------+
|  DAY 1: System Foundations, Relational Models, Contracts & Cryptographic Ledger          |
|  DAY 2: Ingestion Pipeline, Versioned Rules Engine & Streaming Behavioral Analytics      |
|  DAY 3: Bounded In-Memory NetworkX Graph Correlation & Correlated Incident Lifecycle     |
|  DAY 4: Outbound HTTPS Agent C2, HMAC Command Signer & Closed-Loop Verification          |
|  DAY 5: Four Operational Workspaces UI, Purple-Team 'waliya-sim' CLI & Final Validation  |
+------------------------------------------------------------------------------------------+
```

---

### Day 1: System Foundations, Data Models & Cryptographic Ledger
- **Objective:** Establish the bedrock infrastructure, asynchronous database connectivity, and tamper-evident audit ledger.
- **Deliverables:**
  - Python virtual environment setup and dependency locking (`pyproject.toml`).
  - Strict Pydantic v2 data contracts (`waliya.contracts`).
  - SQLAlchemy 2.0 Async ORM models (`waliya.db.models`) and initial Alembic migration.
  - SHA-256 Hash-Chained Audit Ledger service (`waliya.audit.ledger`) with concurrency-safe append and verification logic.
  - FastAPI application factory with `/api/v1/health/liveness` and `/api/v1/health/readiness`.
- **Testing Requirements:** 100% test coverage for contract validation, hash-chain generation, and tamper detection.

---

### Day 2: Ingestion Pipeline, Rules Engine & Behavioral Analytics
- **Objective:** Ingest multi-source telemetry, evaluate deterministic rules, and compute statistical streaming baselines.
- **Deliverables:**
  - Telemetry normalization pipeline (`waliya.telemetry.normalizer`) for FIM, Process, Auth, and Network events.
  - Redis Stream publisher and consumer group worker daemon.
  - Versioned Detection Rule Engine (`waliya.detection.engine`) with AST condition parsing and event deduplication.
  - Streaming EWMA and rolling Z-score anomaly calculator (`waliya.analytics.streaming`).
  - Seed detection rules: `RULE-FIM-004-WEBSHELL`, `RULE-AUTH-001-BRUTEFORCE`, `RULE-NET-001-PORTSCAN`, `RULE-PROC-001-PRIVILEGE-ESC`.
- **Testing Requirements:** Synthetic telemetry test vectors exercising rules, deduplication windows, and statistical anomaly triggers.

---

### Day 3: Bounded NetworkX Correlation & Incident Forensics
- **Objective:** Ingest entities into an in-memory graph, discover multi-stage attack paths, and generate correlated incidents.
- **Deliverables:**
  - Bounded in-memory NetworkX graph manager (`waliya.correlation.graph`) with TTL sliding-window eviction.
  - Entity extraction linking `Host`, `User`, `IP`, `Process`, and `File` nodes.
  - Correlated Incident Manager (`waliya.incidents.manager`) aggregating related findings into single incidents.
  - Incident timeline generator and immutable SHA-256 evidence manifest hashing.
  - Native node-and-edge JSON export for graph visualization (`/api/v1/incidents/{id}/graph`).
- **Testing Requirements:** Multi-stage attack scenario tests proving related events group into a single incident with connected graph components.

---

### Day 4: Secure Agent C2, HMAC Command Channel & Closed-Loop Verification
- **Objective:** Deploy endpoint agent daemon, dispatch signed response actions, and verify containment state.
- **Deliverables:**
  - Standalone Linux endpoint agent daemon (`waliya-agent`) with outbound HTTPS polling and FIM sensor.
  - SOAR Command Engine (`waliya.soar.engine`) with allowlisted actions: `BLOCK_IP`, `ISOLATE_HOST`, `TERMINATE_PROCESS`.
  - Canonical JSON serialization and HMAC-SHA256 signature generator with nonce/expiry replay protection.
  - Two-Stage Closed-Loop Verification state machine (`REQUESTED` $\to$ `QUEUED` $\to$ `EXECUTED` $\to$ `VERIFYING` $\to$ `VERIFIED_CONTAINED`).
- **Testing Requirements:** Unit and integration tests for signature validation, replay attack rejection, allowlist enforcement, and state transitions.

---

### Day 5: Operational UI Workspaces, `waliya-sim` CLI & Competition Validation
- **Objective:** Deliver the analyst web interface, execute purple-team attack simulations, and measure MTTD/response latency.
- **Deliverables:**
  - React + TypeScript + Vite + Tailwind CSS frontend covering 4 operational workspaces:
    1. Command Overview & Live Telemetry
    2. Incident Investigation & Forensics (Timeline + Interactive Graph)
    3. Detection Rules & Behavioral Analytics
    4. SOAR Playbooks & Audit Ledger
  - `waliya-sim` CLI simulation tool mapped to MITRE ATT&CK techniques (T1110, T1059, T1046) with trace IDs.
  - End-to-end competition demonstration proving live attack detection, graph correlation, playbook containment, and audit integrity verification.
- **Testing Requirements:** End-to-end integration test exercising simulation $\to$ detection $\to$ incident $\to$ response $\to$ verification $\to$ audit ledger.
