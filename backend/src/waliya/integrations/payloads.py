"""Normalized notification payload schemas and data-minimization builders."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class NotificationEventType(str, Enum):
    """Supported external notification event types."""
    INCIDENT_CREATED = "INCIDENT_CREATED"
    INCIDENT_STATUS_CHANGED = "INCIDENT_STATUS_CHANGED"
    DETECTION_FINDING_CREATED = "DETECTION_FINDING_CREATED"
    THREAT_INTEL_MATCHED = "THREAT_INTEL_MATCHED"
    RESPONSE_PLAN_STATE_CHANGED = "RESPONSE_PLAN_STATE_CHANGED"
    TEST_NOTIFICATION = "TEST_NOTIFICATION"


class NotificationPayload(BaseModel):
    """Canonical versioned schema for outbound security notifications.

    Designed with strict data minimization: excludes raw telemetry, full memory dumps,
    credentials, private keys, and detailed internal execution tracebacks.
    """
    schema_version: str = Field(default="1.0", description="Contract schema version")
    delivery_id: UUID = Field(default_factory=uuid4, description="Unique delivery UUID for receiver deduplication")
    event_type: str = Field(..., description="Notification event type")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Event generation UTC timestamp",
    )
    incident_id: Optional[UUID] = Field(default=None, description="Associated security incident UUID")
    event_id: Optional[str] = Field(default=None, description="Underlying domain event or finding ID")
    severity: Optional[str] = Field(default=None, description="Severity rating (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL)")
    summary: str = Field(..., description="Concise human-readable notification summary")
    source: str = Field(default="waliya-ir", description="Originating platform subsystem")
    correlation_id: Optional[str] = Field(default=None, description="Trace or correlation identifier")
    details: Dict[str, Any] = Field(default_factory=dict, description="Structured, minimized event details")
    is_test: bool = Field(default=False, description="Flag indicating whether this is an administrative test notification")


def build_incident_created_payload(
    incident_id: UUID,
    title: str,
    severity: str,
    composite_risk_score: float,
    status: str,
    first_seen: datetime,
    last_seen: datetime,
    affected_entities: List[str],
    mitre_attack_ids: List[str],
    delivery_id: Optional[UUID] = None,
) -> NotificationPayload:
    """Build a minimized payload for a newly spawned security incident."""
    # Data minimization: provide entity count and at most 5 non-sensitive entity labels
    entity_sample = affected_entities[:5] if affected_entities else []

    return NotificationPayload(
        delivery_id=delivery_id or uuid4(),
        event_type=NotificationEventType.INCIDENT_CREATED.value,
        timestamp=datetime.now(timezone.utc),
        incident_id=incident_id,
        event_id=str(incident_id),
        severity=severity,
        summary=f"New {severity} incident created: {title}",
        source="waliya.incidents.correlation",
        details={
            "title": title,
            "status": status,
            "risk_score": round(composite_risk_score, 2),
            "first_seen": first_seen.isoformat() if first_seen else None,
            "last_seen": last_seen.isoformat() if last_seen else None,
            "entity_count": len(affected_entities),
            "entities_sample": entity_sample,
            "mitre_attack_ids": mitre_attack_ids[:10],
        },
    )


def build_incident_status_changed_payload(
    incident_id: UUID,
    title: str,
    previous_status: str,
    new_status: str,
    updated_at: datetime,
    note: Optional[str] = None,
    delivery_id: Optional[UUID] = None,
) -> NotificationPayload:
    """Build a minimized payload for an incident status transition."""
    return NotificationPayload(
        delivery_id=delivery_id or uuid4(),
        event_type=NotificationEventType.INCIDENT_STATUS_CHANGED.value,
        timestamp=updated_at,
        incident_id=incident_id,
        event_id=str(incident_id),
        summary=f"Incident '{title}' status transitioned from {previous_status} to {new_status}",
        source="waliya.incidents.lifecycle",
        details={
            "previous_status": previous_status,
            "new_status": new_status,
            "note": note,
        },
    )


def build_detection_finding_created_payload(
    finding_id: UUID,
    rule_id: Optional[str],
    rule_name: str,
    severity: str,
    confidence: float,
    observed_entity: Optional[str],
    incident_id: Optional[UUID] = None,
    delivery_id: Optional[UUID] = None,
) -> NotificationPayload:
    """Build a minimized payload for a high-priority detection finding."""
    return NotificationPayload(
        delivery_id=delivery_id or uuid4(),
        event_type=NotificationEventType.DETECTION_FINDING_CREATED.value,
        timestamp=datetime.now(timezone.utc),
        incident_id=incident_id,
        event_id=str(finding_id),
        severity=severity,
        summary=f"Detection finding: {rule_name} on {observed_entity or 'Host'}",
        source="waliya.detection.rule_engine",
        details={
            "rule_id": rule_id,
            "rule_name": rule_name,
            "confidence": round(confidence, 2),
            "observed_entity": observed_entity,
        },
    )


def build_threat_intel_matched_payload(
    indicator_type: str,
    observable: str,
    source: str,
    severity: str,
    confidence: int,
    threat_category: Optional[str] = None,
    incident_id: Optional[UUID] = None,
    delivery_id: Optional[UUID] = None,
) -> NotificationPayload:
    """Build a minimized payload for an active threat intelligence observable match."""
    return NotificationPayload(
        delivery_id=delivery_id or uuid4(),
        event_type=NotificationEventType.THREAT_INTEL_MATCHED.value,
        timestamp=datetime.now(timezone.utc),
        incident_id=incident_id,
        severity=severity,
        summary=f"Active threat intelligence match: {indicator_type} from {source}",
        source="waliya.threat_intel.matcher",
        details={
            "indicator_type": indicator_type,
            "observable": observable,
            "feed_source": source,
            "confidence": confidence,
            "threat_category": threat_category,
        },
    )


def build_response_plan_state_changed_payload(
    plan_id: UUID,
    plan_number: int,
    title: str,
    status: str,
    risk_level: str,
    dry_run: bool,
    actions_count: int,
    incident_id: UUID,
    delivery_id: Optional[UUID] = None,
) -> NotificationPayload:
    """Build a minimized payload for a response plan lifecycle transition."""
    return NotificationPayload(
        delivery_id=delivery_id or uuid4(),
        event_type=NotificationEventType.RESPONSE_PLAN_STATE_CHANGED.value,
        timestamp=datetime.now(timezone.utc),
        incident_id=incident_id,
        event_id=str(plan_id),
        summary=f"Response Plan #{plan_number} transitioned to {status}",
        source="waliya.soar.plan_service",
        details={
            "plan_id": str(plan_id),
            "plan_number": plan_number,
            "title": title,
            "status": status,
            "risk_level": risk_level,
            "dry_run": dry_run,
            "actions_count": actions_count,
        },
    )


def build_test_notification_payload(
    destination_id: UUID,
    destination_name: str,
    delivery_id: Optional[UUID] = None,
) -> NotificationPayload:
    """Build a designated administrative test payload for verifying webhook connectivity."""
    return NotificationPayload(
        delivery_id=delivery_id or uuid4(),
        event_type=NotificationEventType.TEST_NOTIFICATION.value,
        timestamp=datetime.now(timezone.utc),
        summary=f"Administrative test notification to destination '{destination_name}'",
        source="waliya.integrations.test",
        is_test=True,
        details={
            "destination_id": str(destination_id),
            "destination_name": destination_name,
            "test_message": "Ethio-SOAR (Waliya-IR) outbound integration connectivity verified successfully.",
        },
    )
