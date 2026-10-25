"""Inbound external security event normalization and semantic validation.

Validates, sanitizes, and maps incoming events from external security sources
(GENERIC, EDR, SIEM) into standard Waliya-IR telemetry event structures.
"""

from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import UUID

from fastapi import HTTPException, status

from waliya.contracts import EventTypeEnum, SeverityEnum
from waliya.db.models import InboundSourceModel

logger = logging.getLogger("waliya.integrations.normalization")

MAX_INBOUND_PAYLOAD_BYTES = 1024 * 1024  # 1 MB maximum request body size
MAX_NESTING_DEPTH = 5
MAX_FIELD_LENGTH = 4096

PROHIBITED_PAYLOAD_KEYS: Set[str] = {
    "__exec__",
    "shell_cmd",
    "eval",
    "raw_command",
    "system_exec",
    "bash_c",
    "cmd_exec",
    "__import__",
}

INTERNAL_RESERVED_KEYS: Set[str] = {
    "approval_hash",
    "is_approved",
    "authorized_by",
    "execution_mode",
    "agent_token",
    "enrollment_token",
    "revocation_reason",
}


class NormalizationError(ValueError):
    """Raised when an external event cannot be normalized due to schema or type errors."""
    pass


def check_nesting_depth_and_prohibited_keys(data: Any, current_depth: int = 1) -> None:
    """Recursively verify that payload nesting does not exceed depth limit

    and does not contain prohibited command-execution keys.
    """
    if current_depth > MAX_NESTING_DEPTH:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Payload exceeds maximum allowed nesting depth of {MAX_NESTING_DEPTH}",
        )

    if isinstance(data, dict):
        for k, v in data.items():
            k_str = str(k).strip()
            if k_str in PROHIBITED_PAYLOAD_KEYS:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Prohibited attribute '{k_str}' detected in external payload",
                )
            if k_str in INTERNAL_RESERVED_KEYS:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Forbidden attempt to set internal platform attribute '{k_str}'",
                )
            check_nesting_depth_and_prohibited_keys(v, current_depth + 1)

    elif isinstance(data, list):
        if len(data) > 1000:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Payload collection exceeds maximum length of 1000 items",
            )
        for item in data:
            check_nesting_depth_and_prohibited_keys(item, current_depth + 1)


def parse_event_timestamp(raw_ts: Any) -> datetime:
    """Defensively parse incoming timestamp across ISO 8601, Unix epoch, or numeric formats.

    Defaults to UTC now if omitted or completely invalid.
    """
    if not raw_ts:
        return datetime.now(timezone.utc)

    if isinstance(raw_ts, datetime):
        return raw_ts if raw_ts.tzinfo else raw_ts.replace(tzinfo=timezone.utc)

    if isinstance(raw_ts, (int, float)):
        # Determine if seconds or milliseconds
        ts_val = float(raw_ts)
        if ts_val > 1e11:  # Milliseconds epoch
            ts_val = ts_val / 1000.0
        try:
            return datetime.fromtimestamp(ts_val, tz=timezone.utc)
        except Exception:
            return datetime.now(timezone.utc)

    if isinstance(raw_ts, str):
        raw_str = raw_ts.strip()
        # Handle trailing Z
        if raw_str.endswith("Z"):
            raw_str = raw_str[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(raw_str)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            pass

        # Try common numeric string
        try:
            ts_float = float(raw_str)
            if ts_float > 1e11:
                ts_float = ts_float / 1000.0
            return datetime.fromtimestamp(ts_float, tz=timezone.utc)
        except Exception:
            pass

    return datetime.now(timezone.utc)


def normalize_severity(raw_severity: Any) -> str:
    """Normalize vendor severity strings or scores to internal SeverityEnum."""
    if raw_severity is None:
        return SeverityEnum.MEDIUM.value

    # Numeric score mapping
    if isinstance(raw_severity, (int, float)):
        score = float(raw_severity)
        if score >= 80 or (score >= 8 and score <= 10):
            return SeverityEnum.CRITICAL.value
        elif score >= 60 or (score >= 6 and score < 8):
            return SeverityEnum.HIGH.value
        elif score >= 40 or (score >= 4 and score < 6):
            return SeverityEnum.MEDIUM.value
        elif score >= 20 or (score >= 2 and score < 4):
            return SeverityEnum.LOW.value
        else:
            return SeverityEnum.INFORMATIONAL.value

    s = str(raw_severity).strip().upper()
    if s in (SeverityEnum.CRITICAL.value, "CRIT", "SEVERE", "FATAL", "EMERGENCY"):
        return SeverityEnum.CRITICAL.value
    elif s in (SeverityEnum.HIGH.value, "ERROR", "ERR", "MAJOR"):
        return SeverityEnum.HIGH.value
    elif s in (SeverityEnum.MEDIUM.value, "MED", "WARN", "WARNING", "MODERATE"):
        return SeverityEnum.MEDIUM.value
    elif s in (SeverityEnum.LOW.value, "NOTICE", "MINOR"):
        return SeverityEnum.LOW.value
    elif s in (SeverityEnum.INFORMATIONAL.value, "INFO", "INFORMATIONAL", "DEBUG", "AUDIT"):
        return SeverityEnum.INFORMATIONAL.value

    # Defensive default for unknown text
    return SeverityEnum.MEDIUM.value


def map_event_type(raw_type: Optional[str]) -> str:
    """Map external event type string to an internal EventTypeEnum value."""
    if not raw_type:
        return EventTypeEnum.EXTERNAL_ALERT.value

    clean = str(raw_type).strip().upper()
    if clean in ("PROCESS_EXECUTION", "PROCESS", "EXEC"):
        return EventTypeEnum.PROCESS_EXECUTION.value
    elif clean in ("FILE_INTEGRITY", "FILE", "FIM"):
        return EventTypeEnum.FILE_INTEGRITY.value
    elif clean in ("NETWORK_CONNECTION", "NETWORK", "NETFLOW", "CONNECTION"):
        return EventTypeEnum.NETWORK_CONNECTION.value
    elif clean in ("AUTHENTICATION", "AUTH", "LOGON", "LOGIN"):
        return EventTypeEnum.AUTHENTICATION.value
    elif clean in ("SYSTEM_LOG", "SYSLOG", "LOG"):
        return EventTypeEnum.SYSTEM_LOG.value
    elif clean in ("EXTERNAL_ALERT", "ALERT", "DETECTION", "INCIDENT"):
        return EventTypeEnum.EXTERNAL_ALERT.value

    # Default to EXTERNAL_ALERT for unrecognized categories
    return EventTypeEnum.EXTERNAL_ALERT.value


class NormalizedExternalEvent:
    """Standardized representation of a validated external security event."""

    def __init__(
        self,
        external_event_id: str,
        source_id: str,
        provider_type: str,
        event_type: str,
        severity: str,
        timestamp: datetime,
        title: str,
        description: str,
        attributes: Dict[str, Any],
        raw_metadata: Dict[str, Any],
    ):
        self.external_event_id = external_event_id
        self.source_id = source_id
        self.provider_type = provider_type
        self.event_type = event_type
        self.severity = severity
        self.timestamp = timestamp
        self.title = title
        self.description = description
        self.attributes = attributes
        self.raw_metadata = raw_metadata

    def to_normalized_payload(self) -> Dict[str, Any]:
        """Produce the standardized dictionary stored in EventModel.normalized_payload."""
        return {
            "external_source": self.source_id,
            "external_event_id": self.external_event_id,
            "provider_type": self.provider_type,
            "is_external": True,
            "is_simulation": False,  # Strict simulation isolation
            "provenance": "EXTERNAL",
            "event_type": self.event_type,
            "severity": self.severity,
            "timestamp": self.timestamp.isoformat(),
            "title": self.title,
            "description": self.description,
            "attributes": self.attributes,
        }


def normalize_inbound_security_event(
    source: InboundSourceModel,
    raw_payload: Dict[str, Any],
    fallback_external_id: Optional[str] = None,
) -> NormalizedExternalEvent:
    """Validate and normalize an incoming external security event payload based on source provider profile.

    Supports:
    - GENERIC: Standard Waliya External Security Event Schema
    - EDR: Endpoint Detection and Response alert profile
    - SIEM: Security Information and Event Management alert profile

    Raises:
        HTTPException: On malformed schema, prohibited keys, or unsupported provider types.
    """
    check_nesting_depth_and_prohibited_keys(raw_payload)

    provider = (source.provider_type or "GENERIC").upper().strip()

    if provider == "GENERIC":
        return _normalize_generic_profile(source, raw_payload, fallback_external_id)
    elif provider == "EDR":
        return _normalize_edr_profile(source, raw_payload, fallback_external_id)
    elif provider == "SIEM":
        return _normalize_siem_profile(source, raw_payload, fallback_external_id)
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported inbound provider type '{provider}' for source '{source.source_id}'. Supported: GENERIC, EDR, SIEM",
        )


def _normalize_generic_profile(
    source: InboundSourceModel,
    payload: Dict[str, Any],
    fallback_id: Optional[str],
) -> NormalizedExternalEvent:
    """Map standard Waliya external security event format."""
    ext_id = (
        payload.get("external_event_id")
        or payload.get("id")
        or payload.get("event_id")
        or fallback_id
    )
    if not ext_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="GENERIC payload missing required 'external_event_id' or 'id'",
        )

    ext_id_str = str(ext_id).strip()[:128]
    ev_type = map_event_type(payload.get("event_type") or payload.get("type"))
    sev = normalize_severity(payload.get("severity"))
    ts = parse_event_timestamp(payload.get("timestamp") or payload.get("event_time"))

    title = str(payload.get("title") or payload.get("summary") or "External Security Event").strip()[:256]
    description = str(payload.get("description") or payload.get("details") or "").strip()[:2048]

    # Clean attributes
    raw_attrs = payload.get("attributes")
    attrs: Dict[str, Any] = {}
    if isinstance(raw_attrs, dict):
        for k, v in raw_attrs.items():
            if str(k) not in INTERNAL_RESERVED_KEYS and str(k) not in PROHIBITED_PAYLOAD_KEYS:
                attrs[str(k)] = v

    # Retain observables if placed at top-level
    for obs in ("src_ip", "dst_ip", "file_hash", "sha256", "user", "username", "file_path", "process_name", "domain", "hostname"):
        if obs in payload and obs not in attrs:
            attrs[obs] = payload[obs]

    raw_meta = payload.get("raw_metadata") or {}
    if not isinstance(raw_meta, dict):
        raw_meta = {}

    return NormalizedExternalEvent(
        external_event_id=ext_id_str,
        source_id=source.source_id,
        provider_type="GENERIC",
        event_type=ev_type,
        severity=sev,
        timestamp=ts,
        title=title,
        description=description,
        attributes=attrs,
        raw_metadata=raw_meta,
    )


def _normalize_edr_profile(
    source: InboundSourceModel,
    payload: Dict[str, Any],
    fallback_id: Optional[str],
) -> NormalizedExternalEvent:
    """Map EDR alert format (e.g. CrowdStrike/Defender/SentinelOne style detection)."""
    ext_id = (
        payload.get("detection_id")
        or payload.get("alert_id")
        or payload.get("id")
        or fallback_id
    )
    if not ext_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="EDR payload missing required 'detection_id' or 'alert_id'",
        )

    ext_id_str = str(ext_id).strip()[:128]
    ev_type = EventTypeEnum.EXTERNAL_ALERT.value
    sev = normalize_severity(payload.get("severity") or payload.get("severity_score") or payload.get("threat_level"))
    ts = parse_event_timestamp(
        payload.get("created_timestamp")
        or payload.get("timestamp")
        or payload.get("detection_time")
    )

    tactic = payload.get("tactic") or payload.get("technique")
    title_raw = payload.get("detection_name") or payload.get("rule_name") or payload.get("title") or "EDR Endpoint Detection"
    if tactic:
        title = f"EDR: {tactic} - {title_raw}"[:256]
    else:
        title = f"EDR: {title_raw}"[:256]

    description = str(payload.get("description") or payload.get("behavior_description") or "").strip()[:2048]

    # Map EDR observables
    attrs: Dict[str, Any] = {
        "hostname": payload.get("device_name") or payload.get("hostname"),
        "device_id": payload.get("device_id") or payload.get("sensor_id"),
        "process_name": payload.get("file_name") or payload.get("process_name"),
        "cmdline": payload.get("cmdline") or payload.get("command_line"),
        "sha256": payload.get("sha256") or payload.get("file_hash"),
        "file_path": payload.get("file_path") or payload.get("filepath"),
        "user": payload.get("user_name") or payload.get("username"),
        "src_ip": payload.get("local_ip") or payload.get("src_ip"),
        "dst_ip": payload.get("remote_ip") or payload.get("dst_ip"),
        "technique_id": payload.get("technique_id") or payload.get("mitre_id"),
    }
    # Remove None values
    attrs = {k: v for k, v in attrs.items() if v is not None}

    # Add extra vendor fields if provided
    extra = payload.get("details") or payload.get("attributes") or {}
    if isinstance(extra, dict):
        for k, v in extra.items():
            if k not in attrs and k not in INTERNAL_RESERVED_KEYS:
                attrs[k] = v

    return NormalizedExternalEvent(
        external_event_id=ext_id_str,
        source_id=source.source_id,
        provider_type="EDR",
        event_type=ev_type,
        severity=sev,
        timestamp=ts,
        title=title,
        description=description,
        attributes=attrs,
        raw_metadata=payload,
    )


def _normalize_siem_profile(
    source: InboundSourceModel,
    payload: Dict[str, Any],
    fallback_id: Optional[str],
) -> NormalizedExternalEvent:
    """Map SIEM correlation alert format (e.g. Splunk/Elastic/QRadar style alert)."""
    ext_id = (
        payload.get("log_id")
        or payload.get("event_id")
        or payload.get("alert_id")
        or payload.get("id")
        or fallback_id
    )
    if not ext_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="SIEM payload missing required 'log_id' or 'alert_id'",
        )

    ext_id_str = str(ext_id).strip()[:128]
    ev_type = EventTypeEnum.EXTERNAL_ALERT.value
    sev = normalize_severity(payload.get("severity") or payload.get("urgency") or payload.get("priority"))
    ts = parse_event_timestamp(
        payload.get("@timestamp")
        or payload.get("timestamp")
        or payload.get("event_time")
    )

    sig_name = payload.get("rule_name") or payload.get("search_name") or payload.get("signature") or "SIEM Correlation Alert"
    title = f"SIEM: {sig_name}"[:256]
    description = str(payload.get("description") or payload.get("message") or "").strip()[:2048]

    # Map SIEM observables
    attrs: Dict[str, Any] = {
        "src_ip": payload.get("src_ip") or payload.get("source_ip") or payload.get("src"),
        "dst_ip": payload.get("dest_ip") or payload.get("destination_ip") or payload.get("dst"),
        "src_port": payload.get("src_port") or payload.get("source_port"),
        "dst_port": payload.get("dest_port") or payload.get("destination_port"),
        "user": payload.get("user") or payload.get("user_name") or payload.get("account"),
        "hostname": payload.get("host") or payload.get("hostname") or payload.get("dvc"),
        "protocol": payload.get("protocol") or payload.get("proto"),
        "sha256": payload.get("sha256") or payload.get("hash"),
        "rule_id": payload.get("rule_id") or payload.get("signature_id"),
    }
    attrs = {k: v for k, v in attrs.items() if v is not None}

    # Add extra context
    extra = payload.get("result") or payload.get("event") or payload.get("attributes") or {}
    if isinstance(extra, dict):
        for k, v in extra.items():
            if k not in attrs and k not in INTERNAL_RESERVED_KEYS:
                attrs[k] = v

    return NormalizedExternalEvent(
        external_event_id=ext_id_str,
        source_id=source.source_id,
        provider_type="SIEM",
        event_type=ev_type,
        severity=sev,
        timestamp=ts,
        title=title,
        description=description,
        attributes=attrs,
        raw_metadata=payload,
    )
