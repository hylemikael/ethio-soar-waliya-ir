# Waliya-IR Standalone Linux Endpoint Agent

The **Waliya-IR Agent** (`waliya-agent`) is a lightweight, production-minded Linux endpoint security sensor and automated response runner. It gathers native Linux security telemetry, buffers events locally in a bounded durable queue during network drops, securely transmits telemetry over outbound HTTPS, and verifies signed C2 containment commands with strict replay and tampering defense.

---

## Key Architectural Principles

1. **Strictly Outbound HTTPS (Zero Inbound Ports):**
   - The agent never binds or listens on any network port or socket on the endpoint.
   - All server communications (heartbeat, telemetry upload, task polling, execution receipts) occur strictly over outbound HTTPS.
2. **Cryptographic HMAC-SHA256 Command Verification:**
   - Every response action dispatched by the server is signed with a unique per-agent HMAC-SHA256 secret key over a canonical JSON representation.
   - The agent independently verifies the signature in constant time before parsing or executing commands.
3. **Replay & Sequence Monotonicity Defense:**
   - A persistent SQLite database (`replay_defense.db`) tracks the highest sequence number and observed nonces.
   - Any replayed, duplicate, out-of-order, or expired command is immediately rejected and recorded.
4. **Bounded Buffering & Backpressure:**
   - Collected events are stored in a local SQLite queue (`events.db`) with an explicit capacity limit (default: 5,000 events).
   - If the management server is unreachable, events remain securely buffered. If capacity is exceeded, an automated drop-oldest policy prevents unbounded memory or disk growth.
5. **Safe Dry-Run by Default & Containment Separation:**
   - Real response actions are strictly **disabled by default** (`enable_response_actions: false`). All actions default to safe dry-run simulations.
   - Successful command execution (`status: EXECUTED`, exit code 0) is **never confused with successful containment**.
   - Execution receipts (`/receipts`) and positive containment verification telemetry (`/verification`) are strictly decoupled across two distinct lifecycle phases.
6. **PID Reuse Defense & Network Protection:**
   - Process termination commands verify process executable name, `/proc/[pid]/comm`, and command line before signaling to prevent killing recycled PIDs.
   - Network blocking explicitly refuses to block loopback (`127.0.0.0/8`, `::1`), link-local, multicast, broadcast, or the management server IP.
   - Forensic artifact collection strictly validates paths against directory traversal (`..`, `/etc`, `/root`).

---

## Telemetry Collectors

| Collector | Source | Normalization | Visibility & Limitations |
| :--- | :--- | :--- | :--- |
| **File Integrity (FIM)** | Configured filesystem paths (`fim_paths`) | `FILE_INTEGRITY` (`CREATED`, `MODIFIED`, `DELETED`, SHA-256) | Scans configured directories, debounces rapid modifications, skips virtual filesystems (`/proc`, `/sys`), and respects symlink boundaries without following external links. Large files (>25MB) avoid full SHA hashing to prevent I/O saturation. |
| **Process Activity** | `/proc/[pid]/` (`stat`, `cmdline`, `exe`, `status`) | `PROCESS_EXECUTION` (`pid`, `ppid`, `exe`, `cmdline`, `username`) | Snapshot-based polling. Detects newly spawned and persistent processes. Note: Ephemeral processes executing and exiting between polling intervals (e.g., sub-second commands) require kernel eBPF tracing. |
| **Authentication** | `/var/log/auth.log` or `/var/log/secure` | `AUTHENTICATION` (`service`, `user`, `src_ip`, `status: SUCCESS/FAILURE`) | Tails auth logs from persistent seek offset, detects log rotation (inode changes or truncation), and normalizes SSH and PAM events. Gracefully handles unreadable logs if permissions are missing. |
| **Network Sockets** | `/proc/net/tcp` & `/proc/net/tcp6` | `NETWORK_CONNECTION` (`src_ip`, `src_port`, `dst_ip`, `dst_port`, `direction`) | Decodes hex socket tables into IPv4/IPv6 endpoints, tracks TCP connection states (`ESTABLISHED`, `SYN_SENT`, `LISTEN`). Extremely fast microsecond port scans between polls require kernel packet filtering. |

---

## Installation & CLI Usage

### 1. Requirements
- Python 3.10+
- Linux operating system (Ubuntu/Debian, RHEL/Rocky, Fedora, Arch)

### 2. Quick Start & Foreground Testing

```bash
# Validate configuration file
waliya-agent verify-config --config /path/to/waliya-agent.yaml

# Run agent in foreground
waliya-agent run --config /path/to/waliya-agent.yaml
```

### 3. Environment Variable Configuration

All settings can be specified through environment variables instead of a file:

```bash
export WALIYA_AGENT_SERVER_URL="https://waliya.internal.sec:8000"
export WALIYA_AGENT_ID="3c1bdddb-c4b6-4eea-98d2-e24a56f3b8f7"
export WALIYA_AGENT_API_TOKEN="soar-agent-token-example"
export WALIYA_AGENT_SIGNING_SECRET="agent-hmac-secret-example"
export WALIYA_AGENT_STATE_DIR="/var/lib/waliya-agent"
export WALIYA_AGENT_LOG_LEVEL="INFO"

waliya-agent run
```

---

## Running as an Unprivileged System Service

For production deployments, the agent should run as an isolated system user with read access to system logs.

### 1. Create Dedicated Service User
```bash
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/waliya-agent -m -G adm waliya-agent
```
*(Note: Adding to the `adm` group grants read permissions to `/var/log/auth.log` on Debian/Ubuntu).*

### 2. Configure State and Config Directories
```bash
sudo mkdir -p /etc/waliya /var/lib/waliya-agent
sudo cp waliya-agent.example.yaml /etc/waliya/waliya-agent.yaml
sudo chown -R waliya-agent:waliya-agent /etc/waliya /var/lib/waliya-agent
sudo chmod 600 /etc/waliya/waliya-agent.yaml
sudo chmod 700 /var/lib/waliya-agent
```

### 3. Example Systemd Service Unit (`/etc/systemd/system/waliya-agent.service`)

```ini
[Unit]
Description=Waliya-IR Linux Endpoint Security Sensor
Documentation=https://github.com/waliya-ir/waliya-agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=waliya-agent
Group=waliya-agent
WorkingDirectory=/var/lib/waliya-agent
ExecStart=/usr/local/bin/waliya-agent run --config /etc/waliya/waliya-agent.yaml
Restart=always
RestartSec=5s

# Hardening Directives
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/waliya-agent
ReadOnlyPaths=/var/log/auth.log
PrivateTmp=true
NoNewPrivileges=true
CapabilityBoundingSet=CAP_DAC_READ_SEARCH

[Install]
WantedBy=multi-user.target
```

---

## Defensive Response Actions & Elevated Privileges

If `response.enable_response_actions: true` is configured on an endpoint, the agent requires narrowly scoped elevated capabilities for real system actions:

| Action | Required Linux Capability | Operational Safeguards |
| :--- | :--- | :--- |
| **`BLOCK_IP` / `UNBLOCK_IP`** | `CAP_NET_ADMIN` | Scoped to dedicated `WALIYA_BLOCK_IN` and `WALIYA_BLOCK_OUT` chains. Enforces rejection of loopback, link-local, multicast, broadcast, and the management server IP. |
| **`TERMINATE_PROCESS`** | `CAP_KILL` | Uses race-free Linux `pidfd` (`os.pidfd_open` / `signal.pidfd_send_signal`). Revalidates executable name via `/proc/[pid]/comm` to prevent recycled PID execution. |
| **`COLLECT_FORENSIC_ARTIFACT`** | None (Runs unprivileged) | Restricted to `LOGS`, `PROC_MAP`, and `SOCKET_TABLE`. Output files enforced to `chmod 0600` inside `forensic_artifact_dir`. Path traversal and symlink escapes strictly blocked. |

### Systemd Capabilities for Response Actions
When real response actions are explicitly permitted on an endpoint, add ambient capabilities to the service unit:
```ini
AmbientCapabilities=CAP_NET_ADMIN CAP_KILL
CapabilityBoundingSet=CAP_NET_ADMIN CAP_KILL CAP_DAC_READ_SEARCH
```

---

## Operational Scope and Known Limitations

1. **Ephemeral Process Execution:**
   - The process collector polls `/proc` at configured intervals (default: 5.0s). Short-lived processes that execute and exit in sub-second windows may not be captured. Full visibility into sub-second commands requires kernel eBPF/auditd instrumentation.
2. **Transient Network Connections:**
   - Network socket telemetry samples active TCP connections from `/proc/net/tcp`. Ephemeral port probes that open and close between polling cycles require kernel netfilter logging.
3. **Physical Memory Dumps:**
   - Full physical memory acquisition (`MEMORY_DUMP`) is intentionally omitted. Safely dumping RAM without causing kernel panics or unbounded disk exhaustion requires dedicated kernel-space modules (such as LiME). Diagnostic memory analysis is bounded to process maps and `/proc` telemetry.
4. **Containment Proof Separation:**
   - Command return code 0 indicates only that the agent executed the command envelope. Containment is independently evaluated by the backend verification engine against kernel iptables tables and OS process state.
