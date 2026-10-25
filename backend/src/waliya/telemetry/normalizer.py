"""Telemetry normalization and semantic validation.

Validates and standardizes heterogeneous security event payloads from Linux sensors
into predictable, typed structures suitable for detection engineering and graph correlation.
"""

import json
from typing import Any, Dict
from uuid import UUID

from fastapi import HTTPException, status

from waliya.contracts import EventTypeEnum, SecurityEventEnvelope

# Maximum allowed size for raw event payload (64 KB)
MAX_PAYLOAD_SIZE_BYTES = 64 * 1024

# Prohibited keys that might indicate command injection or payload tampering
PROHIBITED_PAYLOAD_KEYS = {
    "__exec__",
    "shell_cmd",
    "eval",
    "raw_command",
    "system_exec",
    "bash_c",
}


def normalize_event(event: SecurityEventEnvelope, agent_id: UUID) -> Dict[str, Any]:
    """Validate, sanitize, and normalize an individual security event.

    Args:
        event: Validated Pydantic SecurityEventEnvelope.
        agent_id: UUID of the authenticated submitting agent.

    Returns:
        Standardized dictionary containing normalized semantic fields.

    Raises:
        HTTPException: If payload exceeds limits or fails semantic validation.
    """
    # 1. Enforce payload size limit
    payload_str = json.dumps(event.payload)
    if len(payload_str.encode("utf-8")) > MAX_PAYLOAD_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Event {event.event_id} payload exceeds maximum allowed size of {MAX_PAYLOAD_SIZE_BYTES} bytes",
        )

    # 2. Prevent arbitrary command injection through telemetry fields
    for prohibited in PROHIBITED_PAYLOAD_KEYS:
        if prohibited in event.payload:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Prohibited telemetry attribute '{prohibited}' detected in event {event.event_id}",
            )

    normalized: Dict[str, Any] = {
        "event_id": str(event.event_id),
        "agent_id": str(agent_id),
        "event_type": event.event_type.value,
        "severity": event.severity.value,
        "timestamp": event.timestamp.isoformat(),
        "source": event.source,
    }

    raw = event.payload

    # 3. Type-specific semantic normalization
    if event.event_type == EventTypeEnum.FILE_INTEGRITY:
        file_path = str(raw.get("file_path", "")).strip()
        if not file_path:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"FILE_INTEGRITY event {event.event_id} requires a non-empty 'file_path'",
            )
        action = str(raw.get("action", "MODIFIED")).upper()
        sha256 = raw.get("sha256")
        if sha256 and isinstance(sha256, str):
            sha256 = sha256.strip().lower()

        normalized["attributes"] = {
            "file_path": file_path,
            "action": action,
            "sha256": sha256,
            "size_bytes": raw.get("size_bytes"),
            "is_executable": bool(raw.get("is_executable", False)),
            "user": raw.get("user") or raw.get("username"),
        }

    elif event.event_type == EventTypeEnum.PROCESS_EXECUTION:
        pid = raw.get("pid")
        exe = str(raw.get("exe", "")).strip()
        if not pid or not isinstance(pid, int) or pid <= 0:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"PROCESS_EXECUTION event {event.event_id} requires a positive integer 'pid'",
            )
        normalized["attributes"] = {
            "pid": pid,
            "ppid": raw.get("ppid"),
            "exe": exe,
            "cmdline": str(raw.get("cmdline", "")).strip()[:1024],
            "username": str(raw.get("username", "unknown")).strip(),
            "sha256": str(raw.get("sha256", "")).lower() or None,
        }

    elif event.event_type == EventTypeEnum.AUTHENTICATION:
        service = str(raw.get("service", "pam")).strip().lower()
        user = str(raw.get("user", "")).strip()
        auth_status = str(raw.get("status", "FAILURE")).upper()
        if auth_status not in ["SUCCESS", "FAILURE"]:
            auth_status = "FAILURE"

        normalized["attributes"] = {
            "service": service,
            "user": user,
            "src_ip": str(raw.get("src_ip", "")).strip() or None,
            "status": auth_status,
        }

    elif event.event_type == EventTypeEnum.NETWORK_CONNECTION:
        src_ip = str(raw.get("src_ip", "")).strip()
        dst_ip = str(raw.get("dst_ip", "")).strip()
        dst_port = raw.get("dst_port")
        if dst_port is not None and (not isinstance(dst_port, int) or not (1 <= dst_port <= 65535)):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"NETWORK_CONNECTION event {event.event_id} has invalid 'dst_port'; must be 1-65535",
            )
        normalized["attributes"] = {
            "src_ip": src_ip or None,
            "src_port": raw.get("src_port"),
            "dst_ip": dst_ip or None,
            "dst_port": dst_port,
            "protocol": str(raw.get("protocol", "TCP")).upper(),
            "direction": str(raw.get("direction", "OUTBOUND")).upper(),
        }

    elif event.event_type == EventTypeEnum.SYSTEM_LOG:
        message = str(raw.get("message", "")).strip()
        if not message:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"SYSTEM_LOG event {event.event_id} requires a non-empty 'message'",
            )
        normalized["attributes"] = {
            "facility": str(raw.get("facility", "daemon")),
            "level": str(raw.get("level", "INFO")).upper(),
            "message": message[:4096],
        }

    else:
        normalized["attributes"] = dict(raw)

    # Preserve backward-compatible simulation markers if present in raw payload
    if raw.get("is_simulation"):
        normalized["is_simulation"] = True
        normalized["attributes"]["is_simulation"] = True
        if "simulation_run_id" in raw:
            normalized["simulation_run_id"] = str(raw["simulation_run_id"])
            normalized["attributes"]["simulation_run_id"] = str(raw["simulation_run_id"])
        if "trace_id" in raw:
            normalized["trace_id"] = str(raw["trace_id"])
            normalized["attributes"]["trace_id"] = str(raw["trace_id"])

    return normalized
