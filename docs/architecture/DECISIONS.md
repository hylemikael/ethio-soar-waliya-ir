# Architecture Decision Records (ADRs)
**Project:** Ethio-SOAR (Waliya-IR)
**Status:** Locked / Approved (Phase 1 — Step 2)

---

## ADR-001: Modular Monolith Architecture
- **Context:** Security operations platforms require tight coordination across ingestion, detection, correlation, and response. Microservice architectures introduce significant network serialization overhead, eventual consistency failures, and deployment complexity.
- **Decision:** Build Waliya-IR as a high-performance **modular monolith** in Python 3.14 / FastAPI. Modules (`telemetry`, `detection`, `analytics`, `correlation`, `soar`, `agent_c2`, `audit`) maintain strict internal encapsulation, communicated through defined service interfaces and Pydantic contracts.
- **Consequence:** High execution velocity, zero inter-service network latency for local graph correlation, unified database transactions, and simplified deployment without Kubernetes or multi-repo overhead.

---

## ADR-002: PostgreSQL 18 with Hybrid Relational & JSONB Storage
- **Context:** Relational entities (Agents, Incidents, Detection Rules, Playbooks, Audit Ledger) require strict foreign key integrity, ACID guarantees, and indexing. However, security telemetry and graph snapshots are schema-diverse.
- **Decision:** Utilize **PostgreSQL 18** with SQLAlchemy 2.0 Async ORM. Relational schemas govern core entities, while PostgreSQL `JSONB` is used for normalized event payloads, rule condition ASTs, and evidence snapshots.
- **Consequence:** Eliminates the need for OpenSearch or secondary document stores for core operations while maintaining full ACID compliance and GIN indexing on event attributes.

---

## ADR-003: Redis Streams for Resilient Event Distribution
- **Context:** Decoupling high-velocity event ingestion from CPU-intensive detection rules and statistical modeling prevents API request thread pool starvation.
- **Decision:** Employ **Redis Streams** as an event distribution and worker coordination layer. Ingestion routes append events to `stream:telemetry:raw`; background worker consumer groups process events, evaluate detection rules, and acknowledge (`XACK`) upon completion.
- **Consequence:** Guarantees at-least-once delivery, enables worker scaling, provides consumer recovery via `XPENDING`/`XCLAIM`, and bounds stream size via `MAXLEN ~`.

---

## ADR-004: Bounded In-Memory NetworkX Correlation Engine
- **Context:** Graph correlation is essential for uncovering multi-stage attack paths (e.g., Reconnaissance $\to$ Brute Force $\to$ Lateral Movement $\to$ C2). Dedicated graph databases (e.g., Neo4j) introduce substantial infrastructure overhead.
- **Decision:** Implement an in-memory `networkx.DiGraph` correlation engine bounded by a sliding time window (e.g., 60 minutes) or scoped to active incident entities. Persist graph snapshots to PostgreSQL JSONB upon incident creation/update.
- **Consequence:** Microsecond-level graph traversal (DFS/BFS, shortest path, degree centrality) without dedicated graph infrastructure. Bounded memory pruning prevents Out-Of-Memory (OOM) conditions.

---

## ADR-005: Outbound HTTPS Agent Polling & HMAC-SHA256 Command Security
- **Context:** Inbound management ports (e.g., listening SSH or REST daemons on endpoints) create dangerous attack surfaces that adversaries can exploit for remote code execution.
- **Decision:** Endpoints initiate **strictly outbound HTTPS connections** to the SOAR server to submit telemetry and poll for tasks (`/api/v1/agents/{id}/tasks/poll`). Commands dispatched by the server are signed using **HMAC-SHA256** with per-agent secret keys, incorporating nonces, monotonic sequence counters, and short expiration windows.
- **Consequence:** Zero open inbound ports on monitored Linux hosts. Replay attacks are cryptographically impossible. Unknown or tampered commands are rejected at the agent boundary.

---

## ADR-006: Two-Stage Closed-Loop Containment Verification
- **Context:** Traditional SOAR platforms mark incidents "contained" immediately upon command execution returning exit code 0. If a malicious process respawns or firewall rules are flushed, the security team is misled.
- **Decision:** Enforce a strict multi-state verification state machine (`REQUESTED` $\to$ `QUEUED` $\to$ `EXECUTED` $\to$ `VERIFYING` $\to$ `VERIFIED_CONTAINED`). Marking an incident contained requires post-action telemetry verification collected over a configurable observation window. If evidence is ambiguous, status transitions to `VERIFICATION_INCONCLUSIVE`.
- **Consequence:** Eliminates the false containment fallacy and ensures auditable operational safety.

---

## ADR-007: Cryptographic SHA-256 Hash-Chained Audit Ledger
- **Context:** Compliance and incident response investigations require tamper-evident records of all administrative actions, playbook executions, and rule modifications.
- **Decision:** Implement a blockchain-like SHA-256 hash-chained audit ledger table. Each record's hash is computed as $\text{SHA-256}(\text{prev\_hash} \,\|\, \text{timestamp} \,\|\, \text{actor} \,\|\, \text{action} \,\|\, \text{payload})$. Append operations are transactionally serialized. A verification endpoint re-computes and validates chain continuity.
- **Consequence:** Any retroactive database modification or record deletion breaks the hash chain and is immediately detectable.

---

## ADR-008: Streaming Statistical Baselines (EWMA / Z-Score) over Online ML
- **Context:** Online machine learning algorithms (like incremental Isolation Forests) suffer from catastrophic forgetting, non-explainable scores, high operational complexity, and susceptibility to adversarial poisoning during initial training.
- **Decision:** Deploy Exponentially Weighted Moving Average (EWMA) and rolling variance/Z-score tracking for streaming behavioral telemetry (connection frequencies, failed logins).
- **Consequence:** Mathematically proven, explainable, lightweight anomaly scores with bounded memory footprint and instant operational availability.

---

## ADR-009: Pydantic v2 Strict Contracts & Immutability
- **Context:** Security data pipelines must reject malformed inputs early and prevent type confusion or parameter injection vulnerabilities.
- **Decision:** All platform data schemas are implemented using **Pydantic v2** with `ConfigDict(frozen=True, extra='forbid')` where appropriate, explicit field length limits, timezone-aware datetime validation, and strict typing.
- **Consequence:** High-speed Rust-backed validation, prevention of payload smuggling, and guaranteed API/internal schema consistency.

---

## ADR-010: React + TypeScript + Vite + Tailwind CSS for Workspaces
- **Context:** Security analysts require a high-density, responsive interface capable of rendering live telemetry streams, investigation graph canvases, and playbook workflows without UI lag.
- **Decision:** Build a single-page application (SPA) with React 19, TypeScript, Vite, and Tailwind CSS, structured around four primary operational workspaces.
- **Consequence:** Type-safe API communication, rapid build cycles, modern dark-mode security aesthetic, and component modularity.
