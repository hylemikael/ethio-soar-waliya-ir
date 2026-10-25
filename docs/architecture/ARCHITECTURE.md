# Technical Architecture Specification
**Project:** Ethio-SOAR (Waliya-IR)
**Version:** 2.0.0 (Foundation Scaffold)
**Status:** Architecture Specification & Contract Locking

---

## 1. System Overview

**Waliya-IR** is an enterprise-grade, Linux-first Security Operations, Threat Detection, Investigation, and Automated Incident Response (SOAR) platform.

```
+-----------------------------------------------------------------------------------------------------+
|                                          WALIYA-IR CORE ENGINE                                      |
+-----------------------------------------------------------------------------------------------------+
|                                                                                                     |
|  [ Linux Endpoints ] -- Outbound HTTPS (HMAC-SHA256) --> [ Agent C2 Gateway ]                      |
|  [ Syslog / Weblogs] -- JSON/REST Ingest --------------> [ Ingestion & Normalizer ]                |
|                                                                    |                                |
|                                                                    v                                |
|                                                    [ Redis Streams: stream:telemetry ]              |
|                                                                    |                                |
|                                        +---------------------------+---------------------------+    |
|                                        |                                                       |    |
|                                        v                                                       v    |
|                          [ Detection Rule Engine ]                               [ Behavioral EWMA] |
|                          - Versioned YAML/JSON                                   - Streaming Mean   |
|                          - MITRE ATT&CK Mappings                                 - Rolling Variance |
|                          - Deduplication Cache                                   - Z-Score Anomaly  |
|                                        |                                                       |    |
|                                        +---------------------------+---------------------------+    |
|                                                                    |                                |
|                                                                    v                                |
|                                                [ Bounded NetworkX Graph Engine ]                    |
|                                                - Sliding 60-min window                              |
|                                                - Entity nodes (Host, User, IP, Proc, File)          |
|                                                - Edge relations (AUTH, SPAWN, CONNECT, MODIFY)      |
|                                                                    |                                |
|                                                                    v                                |
|                                                [ Correlated Incident Management ]                   |
|                                                - Multi-stage event aggregation                      |
|                                                - Composite risk scoring                             |
|                                                - SHA-256 evidence package hashing                   |
|                                                                    |                                |
|                                        +---------------------------+---------------------------+    |
|                                        |                                                       |    |
|                                        v                                                       v    |
|                            [ SOAR Response Engine ]                                [ Audit Ledger ] |
|                            - Allowlisted Actions                                   - SHA-256 Chained|
|                            - Approval Gates / Dry-Run                              - Tamper-Evident |
|                            - Two-Stage Closed-Loop Check                           - Serialized Tx  |
|                                                                                                     |
+-----------------------------------------------------------------------------------------------------+
|                                            STORAGE LAYER                                            |
|                  PostgreSQL 18 (Relational Core + JSONB Polymorphic Payloads)                       |
+-----------------------------------------------------------------------------------------------------+
|                                           ANALYST UI (SPA)                                          |
|                React + TypeScript + Vite + Tailwind CSS (4 Operational Workspaces)                  |
+-----------------------------------------------------------------------------------------------------+
```

---

## 2. Core Subsystems

### 2.1 Ingestion & Normalization (`waliya.telemetry`)
- Validates inbound event batches using Pydantic v2 `SecurityEventEnvelope`.
- Normalizes disparate telemetry sources into standard semantic entities:
  - `FILE_INTEGRITY`: Path, hashes (SHA-256), size, permissions, owner.
  - `PROCESS_EXECUTION`: PID, PPID, executable path, command line, user, environment hashes.
  - `AUTHENTICATION`: Service (SSH, sudo, PAM), user, source IP, success/failure.
  - `NETWORK_CONNECTION`: Source/destination IP/port, protocol, socket state.
- Emits normalized events into Redis Stream `stream:telemetry:raw`.

### 2.2 Detection Engine (`waliya.detection`)
- Evaluates versioned detection rules defined as structured condition trees (no dynamic `eval` or arbitrary code execution).
- Tracks sliding event occurrence windows to detect multi-event thresholds (e.g., $\ge 5$ failed logins within 60s).
- Implements event deduplication keys to suppress duplicate alerts within defined suppression windows.

### 2.3 Streaming Behavioral Analytics (`waliya.analytics`)
- Computes real-time streaming Exponentially Weighted Moving Average (EWMA) and rolling variance for rate metrics:
  $$\mu_t = \alpha \cdot x_t + (1 - \alpha) \cdot \mu_{t-1}$$
  $$\sigma_t^2 = (1 - \alpha) \cdot \left(\sigma_{t-1}^2 + \alpha \cdot (x_t - \mu_{t-1})^2\right)$$
  $$Z_t = \frac{x_t - \mu_t}{\sqrt{\sigma_t^2 + \epsilon}}$$
- Generates explainable anomaly observations containing baseline parameters and statistical deviation without heavy black-box ML overhead.

### 2.4 Bounded Graph Correlation & Attack Graph Engine (`waliya.correlation` & `waliya.incidents.graph_service`)
- **Evidence-Backed Security Entities:**
  - **Entity Types:** `Host`, `User`, `IPAddress`, `Process`, `File`, `Alert` (Detection Findings), and `Indicator` (Threat Intelligence Matches).
  - **Directed Relationships:** `AUTHENTICATED_TO`, `SPAWNED`, `MODIFIED`, `CONNECTED_TO`, `ACCESSED`, `TRIGGERED`, `ASSOCIATED_WITH`.
  - **Verifiable Provenance:** Every relationship stores exact supporting event IDs (`evidence_event_ids`), confidence score (0.0 - 1.0), source provenance tag (e.g. `telemetry:sshd`, `detection_rule`, `threat_intel`), and timestamps.
  - **Zero-Invention Invariant:** Never creates connections from unverified associations; filters out loopback interfaces (`127.0.0.1`, `::1`, `localhost`) and placeholder/unknown identities.
- **Bounded In-Memory Graph Management (`EntityGraphManager`):**
  - Powered by `networkx.DiGraph` with configurable capacity ceilings (`DEFAULT_MAX_NODES = 5000`, `DEFAULT_MAX_EDGES = 25000`) and a 60-minute sliding correlation window.
  - Capacity eviction prunes degree-0 orphaned nodes first, followed by LRU eviction based on `last_seen` timestamps.
  - Fully deterministic exports: nodes sorted by entity ID and edges sorted by `(source, target, relation)`.
- **Directed Attack Path Discovery & Cycle Safety:**
  - Automated detection of attack progressions connecting entry nodes (external IPs, authentications, threat indicators) to impacted targets (sensitive files, execution trees, triggered alerts).
  - Enforces strict depth cutoffs (`max_depth: 1..6`) and path count ceilings (`max_paths: 1..20`) to prevent combinatorial explosion.
  - Cycle-safe path evaluation ensures cyclic graphs (e.g. pivoting loops) terminate cleanly without recursion errors.
- **Incident Attack Graph Reconstruction (`IncidentGraphService`):**
  - Authoritative, reproducible reconstruction of an incident's complete attack graph directly from persisted PostgreSQL `FindingModel` and `EventModel` records.
  - Enriches incident graph snapshots with specific attack progression steps, hop counts, step-level confidences, and severity ratings.
  - Exposes deterministic endpoints: `GET /api/v1/incidents/{id}/attack-paths` and `POST /api/v1/incidents/{id}/graph/refresh`.

### 2.5 Evidence-Backed MITRE ATT&CK Mapping & Investigation Intelligence (`waliya.detection.mitre_catalog` & `waliya.incidents.mitre_service`)
- **Authoritative Versioned Local Catalog (`v15.1`):**
  - Offline reference catalog covering enterprise Linux adversary techniques and sub-techniques (e.g. `T1059.004` Unix Shell, `T1548.003` Sudo Abuse, `T1110.001` Password Guessing, `T1505.003` Web Shell, `T1046` Network Service Discovery, `T1078.003` Local Accounts, `T1071.001` Web Protocols, `T1021.004` SSH, `T1003.008` /etc/shadow, etc.).
  - Zero runtime LLM hallucination and zero external internet dependency.
  - Deterministic fallback for uncataloged valid technique IDs.
- **Explainable 3-State Mapping System:**
  - `MAPPED`: Finding is tagged with explicit technique ID(s) and validated by actual stored sensor event evidence (`evidence_event_ids`).
  - `UNMAPPED`: Finding was triggered by behavioral anomaly (EWMA) or heuristic rule without explicit MITRE tags; reported transparently as unmapped to avoid speculative categorization.
  - `INSUFFICIENT_EVIDENCE`: Technique is tagged in incident/feed metadata or speculative rule, but zero underlying telemetry event records exist in the incident repository.
- **Incident Coverage Consolidation & Deduplication:**
  - Multiple findings supporting the same technique ID are consolidated: takes maximum confidence, computes union of supporting `finding_ids` and `evidence_event_ids`, and compiles structured rationales.
  - Groups techniques across official ATT&CK tactics (Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Command and Control, Impact).
- **Attack Path Step Enrichment:**
  - Correlated attack path steps (`AttackPathStep`) are enriched with `mitre_techniques: List[MitreTechniqueMapping]`, linking graph progression steps directly to ATT&CK tactics and evidence provenance.
- **Transparent Boundaries & Disclosed Limitations:**
  - Explicitly documents that technique coverage represents detected and evidence-backed activity only, does not imply absence of activity in unmonitored systems, and does not assert causal or chronological sequence.
- **API Endpoint:**
  - `GET /api/v1/incidents/{incident_id}/mitre-coverage` -> `IncidentAttackCoverageResponse` (Admin authenticated).

### 2.5 Correlated Incident Management (`waliya.incidents`)
- Aggregates related alerts sharing correlated entities into unified Incident records.
- Computes composite risk scores from severity, asset criticality, and graph centrality.
- Generates immutable SHA-256 evidence package digests for forensics.

### 2.6 SOAR, Governed Response Plans & Closed-Loop Response (`waliya.soar` & `waliya.agent_c2`)
- **Strict Allowlisted Action Registry (`ResponseActionRegistry`):**
  - Declares 7 authoritative response operations with explicit parameter schemas, timeouts, and reversibility:
    - `COLLECT_FORENSIC_ARTIFACT` (READ_ONLY, pre-approved default)
    - `BLOCK_IP` / `UNBLOCK_IP` (REVERSIBLE, approval mandated)
    - `RESTORE_HOST` (REVERSIBLE, approval mandated)
    - `ISOLATE_HOST` (CONTAINMENT, approval mandated)
    - `TERMINATE_PROCESS` (DESTRUCTIVE, approval mandated)
    - `QUARANTINE_FILE` (DESTRUCTIVE, approval mandated)
  - Arbitrary commands, custom shell scripts, and untyped actions are rejected at schema validation time.
- **Governed Response Plan Lifecycle (`ResponsePlanService`):**
  - Manages approval-gated plans transitioning through a formal finite state machine:
    $$\text{DRAFT} \longrightarrow \text{PENDING\_APPROVAL} \longrightarrow \text{APPROVED} \longrightarrow \text{EXECUTING} \longrightarrow \begin{cases} \text{SUCCEEDED} \\ \text{FAILED} \end{cases}$$
    $$\text{Alternative terminations: } \text{CANCELLED (from DRAFT/PENDING/APPROVED)}, \quad \text{REJECTED (from PENDING\_APPROVAL)}$$
  - Any direct jump from `DRAFT` to `EXECUTING` is rejected with `InvalidLifecycleTransitionError`.
- **Cryptographic Approval Hash Integrity (`approval_hash`):**
  - When a plan is submitted or approved, a canonical SHA-256 digest of the action payload is calculated and stored.
  - At execution time, the engine recomputes the canonical hash of the action sequence. If any parameter, target agent, or action type was tampered with, execution is aborted immediately.
- **Separation-of-Duties & Administrative Provenance:**
  - Tracks `created_by`, `approved_by`, `rejected_by`, and `cancelled_by` with timestamps and mandatory justification text.
  - Transparently records whether separation-of-duties was honored (`created_by != approved_by`) in the SHA-256 audit ledger.
- **Idempotency Guarantee (`idempotency_key`):**
  - Supports client-provided idempotency keys. Re-submitting an execution request for a plan with the same idempotency key returns the existing execution receipt without duplicating commands.
- **Simulation Boundary Enforcement:**
  - Plans created for synthetic incidents (`is_simulation = True` or `[SIMULATION]` prefix) are strictly constrained to `dry_run = True`. Even if an analyst or API request specifies `dry_run = False`, the engine forcibly overrides to dry-run mode, preventing live host containment or firewall rule alteration on production hosts during purple-team exercises.
- **Signed Command Envelopes & Verification:**
  - Signs command envelopes with per-agent HMAC-SHA256 secret keys, UUID nonces, monotonic sequence numbers, and 60-second expiration.
  - Requires two-stage closed-loop containment verification:
    1. **Receipt:** Agent verifies HMAC, executes action, reports initial status.
    2. **Observation & Verification:** Agent probes OS state after observation window (e.g. 10s) and submits post-action telemetry. Incident transitions to `VERIFIED_CONTAINED` only if state confirms containment.

### 2.7 SHA-256 Hash-Chained Audit Ledger (`waliya.audit`)
- Maintains a tamper-evident audit ledger table where every record references the prior record's SHA-256 hash:
  $$\text{RecordHash}_n = \text{SHA-256}\Big(\text{RecordHash}_{n-1} \,\|\, \text{Timestamp} \,\|\, \text{Actor} \,\|\, \text{Action} \,\|\, \text{CanonicalPayload}\Big)$$
- Transactionally serializes ledger appends using PostgreSQL table locks during write operations.
- Exposes an audit verification endpoint (`GET /api/v1/audit/verify`) that recalculates the entire ledger and validates chain continuity.

### 2.8 Purple-Team Simulation & Validation Framework (`waliya_sim` & `waliya.api.routes.simulations`)
- Deterministic, repeatable security validation framework for testing detection pipeline integrity without executing offensive payloads.
- **Strict Real-vs-Simulation Isolation Guarantees:**
  - **Schema Isolation:** `findings` and `incidents` tables enforce indexed `is_simulation: bool` and `simulation_run_id: str` columns.
  - **Sliding-Window Cache Partitioning:** Stateful multi-event sliding windows in Redis are namespaced (`waliya:win:sim:{run_id}:...`), preventing synthetic events from polluting production threshold tracking or cross-contaminating between test runs.
  - **Alert Deduplication Separation:** Finding suppression keys use `sim:{run_id}:{rule_id}:{entity}`, ensuring synthetic dry-runs never suppress real production alerts.
  - **Correlation Separation Invariants:** Synthetic findings strictly correlate only with other findings sharing the same `simulation_run_id`. Real findings never merge into simulated incidents, and simulated findings never merge into real production incidents.
  - **Playbook Safety Enforcement:** Any playbook execution initiated against a simulated incident is forcefully downgraded to `dry_run = True`, eliminating accidental endpoint disruption or real iptables containment.
  - **Entity Safety:** All synthetic entities strictly use RFC 5737 reserved test subnets (`198.51.100.0/24`) and synthetic user/host prefixes (`sim-admin-`, `sim-sensor-`).
  - **Coverage Truthfulness:** Detection rule validation in the MITRE ATT&CK matrix requires passing both positive trigger tests AND negative boundary tests (`pos == "VALIDATED" and neg != "FAILED"`).

### 2.9 Threat Intelligence & Asset Context Foundation (`waliya.threat_intel` & `waliya.api.routes.assets`)
- **Strict Offline Observable Matching:** Real-time offline matching of observed IP addresses, domain names, URLs, and file hashes (SHA-256) against active indicators without performing external network lookups or live DNS/HTTP queries.
- **Canonical Observable Normalization:** Enforces RFC 5952 IPv6 compression, IPv4 validation, stripped domain normalization, lowercase SHA-256 validation, and standard URL parsing to prevent bypass through formatting variants.
- **Multi-Feed Provenance & Deduplication:** Enforces composite uniqueness `(indicator_type, value, source)` allowing distinct threat feeds (e.g., MISP, AlienVault) to maintain independent confidences, expiration dates, and metadata for identical indicators.
- **Administrative Asset Criticality:** Decouples sensor telemetry from business asset context (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). Endpoint sensors cannot self-assign criticality; metadata is maintained by administrators via authenticated REST endpoints and logged to the SHA-256 audit ledger.
- **Explicit Unassigned Criticality:** Unannotated endpoints are explicitly tracked as `UNASSIGNED` with $+0.0$ risk bonus, preventing silent coercion to `LOW`.
- **Bounded Risk Elevation:** Threat indicator matches contribute a bounded risk adjustment ($\le +15.0$), and asset criticality adjusts score transparently ($\le +10.0$), with full human-readable decision rationales persisted in incident explanations.

### 2.10 Threat Intelligence Feed Ingestion & Operational Refresh (`waliya.threat_intel`)
- **Read-Only External Provider Connectors:** Extensible, strictly read-only connectors for community threat intelligence feeds (`ThreatFox`, `URLhaus`) fetching fresh indicators over verified HTTPS connections without submitting internal observables or downloading malware samples.
- **Provider-Specific Normalization & Mapping:** Maps external indicators directly into canonical Waliya-IR schemas:
  - *ThreatFox:* Extracts IPv4/IPv6 from `ip:port`, maps payload types (`DOMAIN`, `URL`, `SHA256`), preserves provider confidence scores $(0-100)$ and malware families as taxonomy tags.
  - *URLhaus:* Ingests malicious URLs, tracks online status (`is_active = False` for offline samples), applies documented policy confidence (60) with `policy:default_confidence` tags.
- **Controlled Synchronization Pipeline (`ThreatIntelSyncService`):** Orchestrates synchronization with idempotent database upserts (`ON CONFLICT (indicator_type, value, source) DO UPDATE ...`), minimum refresh intervals (default 15 minutes), dry-run preview capabilities, and detailed diagnostics.
- **Source Provenance Isolation:** Independent indicators from different feeds remain isolated; ThreatFox indicators never overwrite or corrupt URLhaus indicators or analyst-submitted records.
- **Operational CLI (`waliya-ti`):** Command-line tool providing commands `waliya-ti feeds list`, `status`, `sync [--feed <id>|all] [--dry-run] [--force]`, `history`, `decay`, and `indicators [list|activate|deactivate|expire|extend]`.
- **SOC Feed Health Workspace:** A dedicated tab in the Detection & Analytics workspace displaying real-time feed connectivity, health status cards, active indicator counts, sync execution history, and dry-run/manual sync triggers.

### 2.11 Threat Intelligence Lifecycle, Confidence Decay & Investigation Integration (`waliya.threat_intel` & `waliya.incidents`)
- **Deterministic Confidence Decay (`ThreatIntelDecayService`):**
  - Stale indicators (unrefreshed for $\ge 14$ days) undergo deterministic, idempotent confidence decay in steps (default $-10$ points every 7 days).
  - Enforces a minimum confidence floor (default $\ge 10$) preventing indicators from decaying into negative or zero confidence.
  - Idempotency is guaranteed via `last_decayed_at` timestamps on `threat_indicators`. Running decay repeatedly in the same interval applies zero change.
  - Supports dry-run simulation mode and logs all decay executions with exact delta metrics to the SHA-256 audit ledger (`THREAT_INTEL_DECAY_RUN`).
- **High-Performance In-Memory LRU/TTL Cache:**
  - `ThreatIntelMatcher` caches active observable lookups in-memory (capacity: 4096 entries, TTL: 60 seconds) to avoid per-event database queries on high-throughput telemetry streams.
  - Filters out local loopback and non-routable targets (`127.0.0.1`, `::1`, `localhost`) to prevent false positive containment or internal noise.
  - Explicit cache invalidation (`clear_cache()`) is executed on feed syncs, indicator lifecycle changes, manual updates, and decay runs.
- **Closed-Loop Incident Investigation Workspace:**
  - The Incident Investigation workspace provides a 5th dedicated tab: "Threat Intelligence".
  - Correlates all telemetry observables with live indicator statuses, displaying original match confidence, live confidence, active/expired status, indicator category, threat actor, and provenance.
  - The Risk Explanation modal explicitly breaks down the composite score, displaying the exact Threat Intel bonus ($\le +15.0$) and Asset Criticality adjustment alongside rule weights.
  - Investigation API endpoint: `GET /api/v1/incidents/{incident_id}/threat-intel`.

### 2.12 Unified Incident Reconstruction & Cross-Layer Forensic Integrity (`waliya.incidents.reconstruction_service`)
- **Deterministic Chronological Timeline Synthesis:**
  - Unifies raw telemetry events, detection rule findings, and threat intelligence matches into a single chronological timeline.
  - Orders observations strictly by recorded UTC timestamps, with stable secondary tie-breaking on item identifiers (`item_id`) to eliminate nondeterministic rendering.
  - Preserves exact source timestamps without fabricating timestamps for incomplete evidence.
- **Strict Distinction Between Factual Telemetry and Analytic Interpretations:**
  - Direct telemetry events are explicitly tagged as `is_interpretation = False` (direct observed evidence).
  - Detection rule alerts and behavioral anomalies are tagged as `is_interpretation = True` (analytic interpretations), preventing analysts from mistaking correlation hypotheses for proven ground truth.
- **Observed Chronology vs. Candidate Attack Progression:**
  - Enforces architectural and visual separation between observed chronological arrival and graph-derived attack paths.
  - Attack paths discovered by the graph traversal engine are explicitly classified as `candidate_progressions` with mandatory disclaimers noting that structural reachability does not prove a single confirmed causal execution chain.
- **Automated Cross-Layer Consistency Validator (`IncidentConsistencyValidator`):**
  - Executes 12 deterministic, non-destructive integrity checks on every reconstruction request:
    1. Valid graph edge entity references.
    2. Explicit graph edge provenance and evidence event IDs.
    3. Proper incident scoping of all evidence references.
    4. Attack path step entity and relation validity.
    5. ATT&CK technique mapping against authoritative local catalog.
    6. Resolution of all mapped findings and backing evidence events.
    7. Mathematical agreement between coverage counts and findings.
    8. Preservation of distinct supporting findings and events during deduplication.
    9. Verification that graph snapshots belong strictly to the target incident.
    10. Simulation boundary isolation (`is_simulation` consistency).
    11. Authoritative handling of empty or stale graph snapshots.
    12. Immutability of evidence timestamps during reconstruction.
  - Validation produces diagnostic reports without altering incident state, risk scores, or database records.
- **Transparent Evidentiary Boundaries & Incomplete Records:**
  - Explicitly enumerates and reports incomplete evidence: findings without raw event payloads, events without ATT&CK technique mappings, unconnected entities in the graph, and known monitoring boundaries.
- **REST API Endpoint:**
  - `GET /api/v1/incidents/{incident_id}/reconstruction` (Admin authenticated, bounded timeline limit default 200).

### 2.13 Response Governance & Approval Gates (`waliya.soar.plan_service`, `waliya.soar.action_registry`)
- **Authoritative Action Registry (`ACTION_REGISTRY`):**
  - Defines 7 allowlisted actions across 4 risk classifications (`READ_ONLY`, `REVERSIBLE`, `CONTAINMENT`, `DESTRUCTIVE`).
  - Sets default approval policies, execution timeouts, max retries, reversibility, and validated parameter schemas.
  - Arbitrary commands, dynamic code loading, and unrestricted shells are strictly rejected.
- **Governed Response Plan Lifecycle:**
  - Strict 8-state finite state machine (`DRAFT`, `PENDING_APPROVAL`, `APPROVED`, `EXECUTING`, `SUCCEEDED`, `FAILED`, `REJECTED`, `CANCELLED`).
  - Canonical SHA-256 `approval_hash` guarantees action definitions cannot be modified between approval and execution.
  - Separation of duties tracking records whether approving actor differs from plan author.

### 2.14 Reliable Response Execution Engine & Adapter Integration (`waliya.soar.execution_engine`, `waliya.soar.adapters`)
- **Trusted Execution Boundary & Concurrency Control:**
  - Pre-execution validation verifies plan lifecycle state (`APPROVED`), re-evaluates approval hash integrity, re-validates all parameters, and checks target agent availability.
  - Concurrency control utilizes database row-level locking (`with_for_update()`) on `ResponsePlanModel` to prevent race conditions from concurrent duplicate executions.
- **Three Distinct Execution Modes:**
  - `DRY_RUN`: Resolves to `DryRunResponseAdapter`. Zero side effects on hosts or networks; returns exit code 0 and dry-run receipts.
  - `SIMULATION`: Synthetic simulation incidents (flagged `is_simulation` or prefixed) force `dry_run = True` and preserve `simulation_run_id`.
  - `PRODUCTION`: Explicit operational execution mode. Target agents must be verified ONLINE (fails closed if REVOKED/OFFLINE). Resolves allowlisted actions to `LinuxHostResponseAdapter`.
- **Bounded Timeouts, Outcomes Classification & Destructive Safety:**
  - Each action step is bounded by `asyncio.wait_for(...)` using `ActionMetadata.default_timeout_seconds`.
  - State machine outcomes accurately distinguish `EXECUTED` (success), `FAILED` (clean failure), `TIMED_OUT` (timeout), and `OUTCOME_UNCERTAIN` (ambiguous side-effect state).
  - **Critical Invariant:** Actions classified as `DESTRUCTIVE` (`TERMINATE_PROCESS`, `QUARANTINE_FILE`) or steps with `is_uncertain = True` are strictly never retried automatically.
- **Durable Execution Receipts & Audit Ledger:**
  - Persists structured execution receipts on `ResponseActionModel` and overall summary on `ResponsePlanModel.execution_summary`.
  - Tamper-evident audit ledger entries record complete execution lifecycles (`RESPONSE_PLAN_EXECUTING`, `RESPONSE_ACTION_EXECUTED`, `RESPONSE_ACTION_TIMED_OUT`, `RESPONSE_ACTION_FAILED`, `RESPONSE_PLAN_EXECUTED`, `RESPONSE_PLAN_FAILED`) with zero leaked credentials or agent secret keys.
- **Safe Reconciliation of Interrupted Executions:**
  - If execution is interrupted by a server restart or crash while in `EXECUTING` state, `POST /api/v1/soar/plans/{plan_id}/reconcile` transitions unconfirmed actions to `OUTCOME_UNCERTAIN`, marks the plan `FAILED` with `has_uncertain_outcomes: True`, and records `RESPONSE_PLAN_RECONCILED` in the audit ledger without deleting historical receipts.

### 2.15 External Integrations & Outbound Security Notifications (`waliya.integrations`)
- **Explicit Administrative Destination Management:**
  - External endpoints must be explicitly configured and authorized by administrators (`NotificationDestinationModel`). Arbitrary user-controlled or event-controlled URLs cannot trigger outbound requests.
  - Subscribed events support granular event types: `INCIDENT_CREATED`, `INCIDENT_STATUS_CHANGED`, `DETECTION_FINDING_CREATED`, `THREAT_INTEL_MATCHED`, `RESPONSE_PLAN_STATE_CHANGED`, or `*`.
- **SSRF Defense and Outbound Network Security (`waliya.integrations.network_security`):**
  - Two-stage destination validation: at destination configuration time and immediately pre-delivery.
  - HTTPS is mandatory for outbound notifications (HTTP allowed only in test environments).
  - Strict rejection of embedded credentials (`user:pass@host`), malformed URLs, and non-standard schemes.
  - Comprehensive IP address resolution via `socket.getaddrinfo`: validates all resolved addresses against prohibited ranges:
    * Loopback (`127.0.0.0/8`, `::1`)
    * Private RFC 1918 networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`)
    * Link-Local (`169.254.0.0/16`, `fe80::/10`)
    * Cloud Metadata Service IPs (`169.254.169.254`, `fd00:ec2::254`) unconditionally blocked.
    * Multicast, broadcast, reserved, and unspecified address ranges.
  - **Redirect Protection:** Automatic HTTP redirects strictly disabled (`follow_redirects=False`) to prevent open redirect SSRF bypasses.
  - **Bounded Egress Timeouts & Payload Sizing:** Connect timeout 5s, read timeout 10s, max response body read capped at 16 KB.
- **Request Signing & Delivery Authenticity (`waliya.integrations.signing`):**
  - Destination signing secrets are encrypted at rest using Fernet with master platform key (`settings.SECRET_KEY`). Secrets are never displayed in plaintext or returned by API endpoints.
  - Outbound requests are signed using standard HMAC-SHA256 calculated over the exact canonical UTF-8 JSON bytes transmitted:
    `signature = hmac.new(secret_bytes, canonical_payload_bytes, hashlib.sha256).hexdigest()`.
  - Delivery headers include: `X-Waliya-Signature`, `X-Waliya-Delivery-Id`, `X-Waliya-Timestamp`, `X-Waliya-Event-Type`.
  - Constant-time verification (`hmac.compare_digest`) prevents timing attacks. Receivers enforce timestamp freshness windows to eliminate replay attacks.
- **Normalized Data Minimization (`waliya.integrations.payloads`):**
  - Structured, versioned JSON payload contracts (`NotificationPayload`, version `1.0`).
  - Sensitive data strictly excluded: zero raw telemetry, zero full forensic memory dumps, zero credentials, tokens, or private keys, zero unredacted internal tracebacks.
- **Durable Delivery Engine & Bounded Exponential Retries (`waliya.integrations.delivery_service`):**
  - Durable PostgreSQL storage (`NotificationDeliveryModel`) guarantees pending and retrying deliveries survive application restarts.
  - Explicit state machine: `PENDING` -> `DELIVERING` -> `DELIVERED` (on 2xx) | `RETRY_SCHEDULED` (on 5xx/timeout) | `PERMANENTLY_FAILED` (on 4xx client errors or exhausted retry limit).
  - Retry policy uses exponential backoff with jitter (`backoff = min(1800, base * 2^(attempt-1) + jitter)`), bounded by `max_attempts = 5`.
  - Receivers can safely deduplicate repeated deliveries using the immutable `delivery_id`.
- **Notification Loop Prevention:**
  - Delivery failures never generate new security incidents or findings.
  - Delivery status updates do not trigger outbound notification recursion.
  - Delivery errors and diagnostics are sanitized before storage and logging.

### 2.16 Authenticated External Security Event Ingestion & Normalization (`waliya.integrations.inbound_service`, `waliya.integrations.normalization`)
- **Explicit Inbound Source Governance:**
  - Inbound external events must originate from an explicitly provisioned, administrative source (`InboundSourceModel`). Unregistered or disabled sources are rejected at the edge with `403 FORBIDDEN` or `404 NOT FOUND`.
  - Configurable source profiles include `GENERIC`, `EDR` (endpoint detection and response), and `SIEM` (central log aggregators).
  - Permitted event types filtering ensures sources can only emit authorized categories (e.g., `EXTERNAL_ALERT`, `PROCESS_EXECUTION`).
- **Cryptographic Authentication & Replay Protection:**
  - Inbound webhook deliveries authenticate via HMAC-SHA256 signatures (`X-Waliya-Signature` or `X-Signature`) calculated over raw request body bytes.
  - Signing shared secrets are encrypted at rest using Fernet and never disclosed via API responses or logs (`has_shared_secret: True`).
  - Strict timestamp freshness verification (`X-Waliya-Timestamp` or `X-Timestamp`) rejects any payload deviating by more than 300 seconds ($\pm 5$ minutes) from server UTC time.
  - Constant-time signature comparison (`hmac.compare_digest`) neutralizes timing-attack vectors.
- **Attack Surface Minimization & Payload Hardening:**
  - Maximum inbound request body capped at 1 MB (`1,048,576` bytes).
  - Maximum object nesting depth capped at 5 levels to prevent recursive stack exhaustion attacks.
  - Prohibits command execution injection keys (`__exec__`, `shell_cmd`, `eval`, `raw_command`, `system_exec`, `bash_c`, `cmd_exec`, `__import__`).
  - Prohibits internal system control keys (`approval_hash`, `agent_token`, `enrollment_token`, `auth_hash`, `private_key`).
- **Semantic Normalization & Identity Shielding:**
  - Disparate vendor fields mapped to standard semantic event structure (`EventTypeEnum.EXTERNAL_ALERT`).
  - Multi-format severity scoring mapped defensively into standard `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL` tiers (defaulting safely to `MEDIUM`).
  - **Agent Impersonation Shield:** Inbound events are assigned `agent_id = None` and `source = "external:<source_id>"`. Inbound claims can never impersonate enrolled agent telemetry.
  - Provenance tagging enforces `is_external = True` and `is_simulation = False`.
- **Persistent Deduplication & Concurrency Isolation:**
  - Deduplication tracked durably in PostgreSQL via `InboundEventDedupModel` with compound unique index on `(source_id, external_event_id)`.
  - Replayed alerts return idempotent `202 DUPLICATE` with existing internal event ID without duplicating rows or re-emitting to streaming queues.
  - Cross-source isolation ensures identical event IDs from distinct sources do not collide.
- **Strict Response Safety (Preserving Phase 9 Controls):**
  - External events route exclusively through standard ingestion pipelines (`stream:telemetry:raw` -> `TelemetryConsumerWorker`) for detection rules, anomaly tracking, and incident correlation.
  - Inbound events **NEVER** automatically execute response plans, invoke containment adapters, or bypass Phase 9 authorization and approval controls.

### 2.17 Closed-Loop Integration Interoperability & Security Boundary Verification (`waliya.integrations`)
- **Closed-Loop Integration Architecture:**
  - Authenticated external security events enter through `POST /api/v1/integrations/inbound/{slug}/events`.
  - Inbound authentication verifies source enablement, 300-second timestamp freshness window, and HMAC-SHA256 signature using Fernet-decrypted shared secret.
  - Normalization validates schema, bounds payload (max 1 MB, max depth 5), suppresses prohibited command and platform keys, and enforces external provenance (`agent_id = None`, `is_external = True`).
  - Deduplication confirms `(source_id, external_event_id)` uniqueness in PostgreSQL.
  - Accepted events enter the authoritative telemetry stream `stream:telemetry:raw`.
  - `TelemetryConsumerWorker` consumes events, evaluates detection rules, EWMA baselines, and threat intelligence observables.
  - Correlated findings produce or update incidents via `IncidentCorrelationService`.
  - Spawned incidents and findings trigger data-minimized notification queueing (`build_incident_created_payload`) into `notification_deliveries`.
  - Outbound delivery engine (`NotificationDeliveryService.dispatch_delivery` / `POST /deliveries/dispatch`) validates egress destination via two-stage SSRF check, computes outbound HMAC-SHA256 signature, and dispatches to configured external webhooks.
- **Loop Suppression & Non-Recursion:**
  - Outbound notification failures and retries NEVER generate internal findings, incidents, or outbound notifications.
  - Delivery history queries and administrative actions are strictly isolated from telemetry pipelines.
- **Strict Response Safety Guarantee:**
  - Neither inbound external alerts nor outbound notification delivery receipts can trigger automated response actions (`ISOLATE_HOST`, `TERMINATE_PROCESS`) or bypass Phase 9 response-plan approval gates.

### 2.18 Production Observability, Health Monitoring & Operational Diagnostics (`waliya.observability`)
- **Probing & Diagnostic Boundary Separation:**
  - **Public Liveness Probe (`GET /api/v1/health/liveness`):** Process responsiveness only. Ultra-lightweight, zero external dependencies, no database queries, zero configuration disclosure. Returns `200 UP`.
  - **Public Readiness Probe (`GET /api/v1/health/readiness`):** Evaluates downstream connectivity to PostgreSQL and Redis stream cache. Returns `200 READY` or `503 NOT_READY` with minimal high-level status without leaking connection strings, credentials, or internal topology.
  - **Administrative System Diagnostics (`GET /api/v1/health/diagnostics`):** Protected by administrative authorization (`verify_admin_key`). Performs multi-tier operational diagnostics across databases, Redis streams, telemetry workers, threat intelligence sync, inbound and outbound integration queues, and SOAR execution state.
  - **Operational Metrics (`GET /api/v1/health/metrics`):** Protected by administrative authorization. Returns strictly bounded, low-cardinality in-memory performance counters and request latency averages.
- **Background Worker Heartbeat & Consumer Lag Diagnostics:**
  - `TelemetryConsumerWorker` records heartbeat timestamps and batch counters to Redis (`waliya:workers:heartbeat:{group_name}:{consumer_name}`) on every batch iteration with a 180s TTL.
  - Evaluates worker status: `HEALTHY` ($\le 60\text{s}$ old, lag $\le 500$), `DEGRADED` ($60\text{s}-120\text{s}$ old or lag $> 500$), `UNHEALTHY` ($> 120\text{s}$ old or dead when stream has pending messages).
  - Explicitly represents `UNKNOWN` or `UNAVAILABLE` when monitoring data is missing (preventing false-positive healthy indicators).
- **Correlation ID Tracking & Sensitive Data Redaction:**
  - `CorrelationIdMiddleware` extracts incoming `X-Request-ID` / `X-Correlation-ID` or generates a sanitized `req_{uuid4().hex[:12]}`.
  - Propagates request ID through `contextvars.ContextVar` across async processing boundaries and returns it in `X-Request-ID` HTTP response headers.
  - `SensitiveDataFilter` scrubs passwords, tokens, API keys, private keys, and Bearer authorization tokens from structured log records and format strings.
- **Operational Backlogs & Stalled Workflow Detection:**
  - Synthesizes queue lengths: Redis stream length, consumer group lag, Pending Entries List (PEL), outbound notification queue (pending, retrying, dead-letter DLQ), and inbound deduplication cache.
  - Detects hung operations: response plans stuck in `EXECUTING` $> 15\text{m}$, response actions in `OUTCOME_UNCERTAIN`, outbox entries pending $> 5\text{m}$, and stale threat intelligence feeds.
- **Monitoring Invariants & Response Safety Preservation:**
  - Health checks never trigger autonomous host/agent restarts, containment actions, or network quarantine.
  - A successful health probe never automatically marks an incident resolved or modifies risk scores.
  - Observability components are fully decoupled from response execution triggers.

### 2.19 Performance Hardening, Backpressure & Bounded Processing
- **Database Index Optimization & Query Path Acceleration:**
  - Added six strategic composite indexes in PostgreSQL (`0015_performance_indexes`) targeting hot filtering and sort paths:
    1. `ix_findings_incident_timestamp` on `findings(incident_id, timestamp)` for forensic timeline queries.
    2. `ix_findings_dedup_key_timestamp` on `findings(dedup_key, timestamp)` for rapid sliding-window alert deduplication.
    3. `ix_incidents_status_last_seen` on `incidents(status, last_seen)` for status-filtered incident triage queries.
    4. `ix_event_outbox_status_created_at` on `event_outbox(status, created_at)` for outbox polling and delivery dispatch.
    5. `ix_notification_deliveries_status_next_attempt` on `notification_deliveries(status, next_attempt_at)` for retry scheduling.
    6. `ix_threat_indicators_type_val_active` on `threat_indicators(indicator_type, value, is_active)` for O(1) indicator lookups.
- **In-Memory Rule Caching with TTL:**
  - `TelemetryConsumerWorker` caches active detection rules in-memory for 60 seconds (`time.monotonic()` TTL) with session-detached objects (`make_transient`), eliminating redundant database roundtrips per telemetry batch while ensuring zero detached-instance session errors.
- **Batched Stream Inspection & Poison-Pill DLQ Protection:**
  - Replaced per-message pending checks with a single batched `xpending_range(min, max, count)` query per message batch, reducing Redis network calls by up to 95%.
  - Poison messages exceeding `MAX_DELIVERIES=5` are automatically extracted and routed to `stream:telemetry:dlq` with detailed diagnostic metadata, immediately acknowledging the stream entry to prevent consumer head-of-line blocking.
  - Reclaims abandoned consumer messages periodically (every 30 seconds) rather than on every polling tick, preventing PEL contention under high load.
- **Resource Ceilings & Bounded Query Defense:**
  - Active candidate incidents for correlation are strictly bounded to 100 recent candidates (`.limit(100)`), preventing unbounded temporal query growth.
  - Incident attack graphs enforce hard ceilings: `MAX_GRAPH_NODES = 500` and `MAX_GRAPH_EDGES = 1000`, and forensic timeline queries are bounded to 500 records (`.limit(500)`).
- **HTTP Client Connection Reuse & Outbound Backpressure:**
  - `NotificationDeliveryService.process_pending_deliveries` creates and reuses a single managed `httpx.AsyncClient` across each delivery batch, closing it upon batch completion. This reuses connection pools, avoids socket exhaustion, and avoids redundant TLS handshakes.
- **Frontend Polling Backpressure Protection:**
  - `SoarAuditLedger` enforces an in-flight polling guard (`isPollingRef`) across background data refresh intervals, preventing overlapping poll floods when backend services experience transient latency.

### 2.20 Reliability Audit, Adversarial Failure Resilience & Controlled Bounds (Phase 11 Prompt 3)
- **Incident Correlation Candidate Window Correctness:**
  - Bounding active incident candidates to 100 recent rows by `last_seen DESC` protects query latency under normal operations. However, during high-velocity updates from unrelated incidents, an older active incident matching an incoming event's non-host entities could be pushed outside the top 100.
  - To prevent incorrect incident splitting or missed correlations, `IncidentCorrelationService` applies a two-tier query strategy:
    1. First, retrieve up to 100 candidate active incidents ordered by `last_seen DESC`.
    2. If and only if the candidate set saturates the 100 limit, execute a targeted query for active incidents matching any of the event's non-host entities (`user`, `ip`, `container`), capped at `.limit(50)`.
    3. Merge candidates deterministically by ID. When $< 100$ active candidates exist, exactly one query executes.
- **Forensic & Graph Truncation Disclosure:**
  - Resource ceilings (`MAX_GRAPH_NODES = 500`, `MAX_GRAPH_EDGES = 1000`, `timeline limit = 500`) must never create the illusion of complete forensics when data exceeds limits.
  - `IncidentGraphService.build_graph_snapshot` exposes `is_truncated: bool`, `node_ceiling: int`, and `edge_ceiling: int` within `snapshot.stats`.
  - `get_incident_evidence` endpoint returns `is_truncated: bool` and `item_ceiling: int` within the evidence manifest, ensuring analysts and downstream systems know whether historical evidence reached the safety ceiling.
- **Poison-Pill Isolation & Transactional Rollback Safety:**
  - Corrupt or malformed messages (missing IDs, non-UUID event IDs, malformed JSON) in Redis streams are trapped, safely forwarded to `stream:telemetry:dlq` with failure diagnostics, and acknowledged in the primary stream to prevent poison loops.
  - In the event of an unhandled database commit failure or worker rollback, stream messages remain unacknowledged in the Pending Entries List (PEL) for subsequent automated recovery, guaranteeing zero event loss.
- **Stalled Execution Reconciliation Invariant:**
  - When background response execution is interrupted by worker crashes or node reboots, `ResponsePlanService.reconcile_plan` reconciles stalled plans by transitioning incomplete actions to `OUTCOME_UNCERTAIN` and failing the plan.
  - Unverified actions are NEVER automatically re-dispatched to endpoints upon service recovery.

### 2.21 Production Deployment Topology & Container Architecture (Phase 12 Prompt 1)
- **Container Service Inventory & Role Separation:**
  - `waliya_frontend`: Alpine-based Nginx reverse proxy serving the compiled React/TypeScript SPA and reverse-proxying `/api/` traffic to the backend API server. Exposes only public port `${WALIYA_PORT:-8080}`.
  - `waliya_backend`: Multi-stage Python 3.11-slim container running FastAPI under Uvicorn (`0.0.0.0:8000`). Operates as an unprivileged user (`uid 10001, gid 10001`), with no compiler tools in the runtime image.
  - `waliya_worker`: Telemetry consumer worker daemon running `python -m waliya.worker` with graceful `SIGTERM`/`SIGINT` trapping to allow active batches to commit and acknowledge prior to termination.
  - `waliya_migration`: One-shot container executing `alembic -c alembic.ini upgrade head` directly after database readiness.
  - `waliya_postgres`: PostgreSQL 18 relational storage with durable data volume `waliya_pgdata`.
  - `waliya_redis`: Redis 7 streaming engine with AOF persistence in `waliya_redisdata`.
- **Deterministic Service Dependency Sequencing:**
  - Services use native Docker Compose healthcheck conditions:
    1. `postgres` (`pg_isready`) and `redis` (`redis-cli ping`) reach `service_healthy`.
    2. `migration` runs to completion (`service_completed_successfully`).
    3. `backend` and `worker` boot concurrently only after migrations succeed, preventing schema migration races.
    4. `frontend` starts only once `backend` passes its `/api/v1/health/liveness` probe.
- **Fail-Fast Configuration Enforcement:**
  - In `production` mode, `Settings` enforces non-default, high-entropy values for `WALIYA_SECRET_KEY` ($\ge 32$ chars), `WALIYA_ADMIN_API_KEY` ($\ge 16$ chars), and `WALIYA_AGENT_TOKEN_PEPPER` ($\ge 16$ chars), forbidding wildcard CORS origins (`*`) and invalid URI schemes.
- **Network & Host Isolation:**
  - All inter-container communication occurs over an internal bridge network (`waliya_network`). PostgreSQL and Redis are bound only to `127.0.0.1` on the host for local development convenience and are never exposed publicly.
- **Durable Storage & Graceful Termination:**
  - Bounded container logging (`json-file`, `max-size: 10m`, `max-file: 3`) prevents disk exhaustion.
  - Backend and worker processes handle `SIGTERM` with `stop_grace_period: 30s` to complete in-flight transactions safely.

---

## 3. Five Operational Workspaces

1. **Command Overview & Live Telemetry:** Real-time event counter, agent fleet health, latest alerts, and streaming telemetry log.
2. **Incident Investigation & Forensics:** Searchable incident list, chronological attack timeline, interactive entity graph canvas, forensic evidence manifests, and threat intelligence correlation tab.
3. **Detection & Behavioral Analytics:** Versioned detection rules catalog, rule dry-run simulator, streaming EWMA behavioral baselines, and Threat Intelligence Feed Health monitor.
4. **SOAR Playbooks & Audit Ledger:** Playbook execution status, manual action approval gates, dry-run toggles, and cryptographically verified SHA-256 audit ledger.
5. **Purple-Team Validation & MITRE Coverage:** Historical simulation run inspection, detailed execution telemetry logs, latency metrics, and real-time MITRE ATT&CK rule validation matrix.
