# API Contracts & Interface Specification
**Project:** Ethio-SOAR (Waliya-IR)
**Base URL:** `/api/v1`
**Protocol:** HTTPS / JSON
**Status:** Locked / Approved (Phase 1 — Step 2)

---

## 1. Authentication & Security Headers

The API enforces strict authentication boundaries across public, agent, and analyst operations:

| Scope | Authentication Mechanism | Headers |
| :--- | :--- | :--- |
| **Public / Liveness** | None | None |
| **Readiness** | Authenticated Operator / Localhost | Optional Bearer Token |
| **Agent Channel** | Per-Agent Bearer Token | `Authorization: Bearer <agent_api_token>`<br>`X-Agent-ID: <uuid>` |
| **Analyst Operations** | JWT Bearer Token | `Authorization: Bearer <jwt_token>` |

---

## 2. API Endpoints Specification

### 2.1 System Health & Diagnostics
#### `GET /api/v1/health/liveness`
- **Auth:** None (Public)
- **Description:** Verifies that the FastAPI process is running and accepting HTTP requests. Does not leak internal secrets or configurations.
- **Response 200 OK:**
  ```json
  {
    "status": "UP",
    "timestamp": "2026-10-22T14:50:00Z",
    "version": "2.0.0"
  }
  ```

#### `GET /api/v1/health/readiness`
- **Auth:** Operator Token / Internal
- **Description:** Checks downstream connectivity to PostgreSQL 18 and Redis. Returns HTTP 503 if dependencies are unreachable.
- **Response 200 OK / 503 Service Unavailable:**
  ```json
  {
    "status": "READY",
    "timestamp": "2026-10-22T14:50:00Z",
    "checks": {
      "database": "CONNECTED",
      "redis": "CONNECTED"
    }
  }
  ```

---

### 2.2 Telemetry Ingestion
#### `POST /api/v1/telemetry/ingest`
- **Auth:** Agent Bearer Token
- **Description:** Ingests a batch of normalized security events from an authorized endpoint.
- **Request Body (`EventBatchRequest`):**
  ```json
  {
    "batch_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "agent_id": "e3b0c442-98fc-1c14-9afb-4c7bf697a211",
    "events": [
      {
        "event_id": "7b587e9d-1144-48f8-b118-2c351543884d",
        "event_type": "FILE_INTEGRITY",
        "severity": "HIGH",
        "timestamp": "2026-10-22T14:49:50Z",
        "source": "waliya-agent-fim",
        "payload": {
          "file_path": "/var/www/html/shell.php",
          "action": "CREATED",
          "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "size_bytes": 1024,
          "is_executable": false
        }
      }
    ]
  }
  ```
- **Response 202 Accepted:**
  ```json
  {
    "batch_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "processed_count": 1,
    "status": "QUEUED"
  }
  ```
- **Failure Codes:** `400 Bad Request` (schema failure), `401 Unauthorized`, `422 Unprocessable Entity`.

---

### 2.3 Secure Agent C2 Protocol

#### `POST /api/v1/agents/{agent_id}/heartbeat`
- **Auth:** Agent Bearer Token
- **Request Body (`AgentHeartbeatRequest`):**
  ```json
  {
    "hostname": "linux-prod-node-01",
    "primary_ip": "10.0.10.5",
    "os_version": "Ubuntu 26.04.1 LTS",
    "agent_version": "2.0.0",
    "metrics": {
      "cpu_percent": 12.4,
      "memory_used_mb": 512
    }
  }
  ```
- **Response 200 OK:**
  ```json
  {
    "status": "ACK",
    "server_time": "2026-10-22T14:50:00Z",
    "pending_tasks": 1
  }
  ```

#### `POST /api/v1/agents/{agent_id}/tasks/poll`
- **Auth:** Agent Bearer Token
- **Request Body (`TaskPollRequest`):**
  ```json
  {
    "last_sequence": 4,
    "supported_actions": ["ISOLATE_HOST", "BLOCK_IP", "TERMINATE_PROCESS"]
  }
  ```
- **Response 200 OK (`CommandEnvelopeResponse`):**
  ```json
  {
    "command_id": "4d16111a-1d54-48f8-b391-2c1a1144884d",
    "agent_id": "e3b0c442-98fc-1c14-9afb-4c7bf697a211",
    "action": "BLOCK_IP",
    "parameters": {
      "ip_address": "198.51.100.42",
      "direction": "BOTH"
    },
    "sequence": 5,
    "nonce": "a4d3c2b1-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
    "issued_at": "2026-10-22T14:50:00Z",
    "expires_at": "2026-10-22T14:51:00Z",
    "signature": "8f4a7c2b... (HMAC-SHA256)"
  }
  ```

#### `POST /api/v1/agents/{agent_id}/receipts`
- **Auth:** Agent Bearer Token
- **Request Body (`ExecutionReceiptRequest`):**
  ```json
  {
    "command_id": "4d16111a-1d54-48f8-b391-2c1a1144884d",
    "status": "EXECUTED",
    "exit_code": 0,
    "output": "iptables rule added successfully",
    "executed_at": "2026-10-22T14:50:04Z"
  }
  ```
- **Response 200 OK:** `{"status": "RECEIPT_RECORDED"}`

#### `POST /api/v1/agents/{agent_id}/verification`
- **Auth:** Agent Bearer Token
- **Request Body (`VerificationTelemetryRequest`):**
  ```json
  {
    "command_id": "4d16111a-1d54-48f8-b391-2c1a1144884d",
    "observed_state": {
      "firewall_rule_present": true,
      "traffic_dropped_packets": 14
    },
    "verified_at": "2026-10-22T14:50:14Z"
  }
  ```
- **Response 200 OK:**
  ```json
  {
    "verification_status": "VERIFIED_CONTAINED"
  }
  ```

---

### 2.4 Incident Investigation & Graph API
#### `GET /api/v1/incidents`
- **Auth:** Analyst JWT
- **Query Params:** `status`, `severity`, `limit`, `offset`
- **Response 200 OK:** Array of incident summaries.

#### `GET /api/v1/incidents/{incident_id}/graph`
- **Auth:** Analyst JWT
- **Response 200 OK (`GraphSnapshotResponse`):**
  ```json
  {
    "incident_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
    "nodes": [
      {"id": "host:linux-prod-01", "type": "Host", "label": "linux-prod-01", "properties": {}},
      {"id": "ip:198.51.100.42", "type": "IPAddress", "label": "198.51.100.42", "properties": {}}
    ],
    "edges": [
      {"source": "ip:198.51.100.42", "target": "host:linux-prod-01", "relation": "CONNECTED_TO", "weight": 1.0}
    ]
  }
  ```

---

### 2.5 Audit Ledger API
#### `GET /api/v1/audit/verify`
- **Auth:** Analyst JWT / Admin
- **Description:** Cryptographically re-computes the SHA-256 hash chain across all records and returns verification results.
- **Response 200 OK:**
  ```json
  {
    "verified": true,
    "total_records": 152,
    "genesis_hash": "0000000000000000000000000000000000000000000000000000000000000000",
    "latest_hash": "a4d3f56e... (SHA256)",
    "tamper_detected": false,
    "broken_index": null
  }
  ```
