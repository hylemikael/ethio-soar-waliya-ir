"""SQLAlchemy 2.0 ORM models for Waliya-IR.

Implements core entities:
1. AgentModel
2. EventModel
3. RuleModel
4. FindingModel
5. IncidentModel
6. ThreatIndicatorModel
7. PlaybookModel
8. PlaybookRunModel
9. ResponseActionModel
10. AuditLedgerModel
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    JSON,
    Sequence,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from waliya.db.session import Base

# Universal JSON type supporting PostgreSQL JSONB and standard JSON fallback
JSONType = JSONB().with_variant(JSON, "sqlite")


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


class AgentModel(Base):
    """Monitored endpoint sensors."""
    __tablename__ = "agents"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    hostname: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    os_family: Mapped[str] = mapped_column(String(64), default="linux", nullable=False)
    os_version: Mapped[str] = mapped_column(String(128), nullable=False)
    primary_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    mac_address: Mapped[str] = mapped_column(String(32), nullable=False)
    agent_version: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="ONLINE", index=True, nullable=False)
    api_token_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    secret_key_enc: Mapped[str] = mapped_column(Text, nullable=False)
    last_heartbeat: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    # Relationships
    events: Mapped[List["EventModel"]] = relationship("EventModel", back_populates="agent")
    actions: Mapped[List["ResponseActionModel"]] = relationship("ResponseActionModel", back_populates="agent")
    asset_context: Mapped[Optional["AssetContextModel"]] = relationship(
        "AssetContextModel", back_populates="agent", uselist=False, cascade="all, delete-orphan"
    )


class EventModel(Base):
    """Raw and normalized security telemetry events."""
    __tablename__ = "events"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    agent_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("agents.id", ondelete="SET NULL"), index=True, nullable=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), index=True, default="INFORMATIONAL", nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    source: Mapped[str] = mapped_column(String(128), nullable=False)
    raw_payload: Mapped[Dict[str, Any]] = mapped_column(JSONType, nullable=False)
    normalized_payload: Mapped[Dict[str, Any]] = mapped_column(JSONType, nullable=False)

    # Relationships
    agent: Mapped[Optional["AgentModel"]] = relationship("AgentModel", back_populates="events")
    findings: Mapped[List["FindingModel"]] = relationship("FindingModel", back_populates="event")
    outbox_entries: Mapped[List["EventOutboxModel"]] = relationship("EventOutboxModel", back_populates="event", cascade="all, delete-orphan")


class RuleModel(Base):
    """Detection rules catalog with versioning."""
    __tablename__ = "rules"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    rule_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    conditions: Mapped[List[Dict[str, Any]]] = mapped_column(JSONType, nullable=False)
    mitre_attack_ids: Mapped[List[str]] = mapped_column(JSONType, default=list, nullable=False)
    dedup_window_seconds: Mapped[int] = mapped_column(Integer, default=300, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    # Relationships
    findings: Mapped[List["FindingModel"]] = relationship("FindingModel", back_populates="rule")


class FindingModel(Base):
    """Alert findings generated by detection rules or behavioral analytics."""
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    rule_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("rules.id", ondelete="SET NULL"), nullable=True)
    event_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"), nullable=False)
    agent_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("agents.id", ondelete="SET NULL"), nullable=True)
    incident_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"), index=True, nullable=True)
    severity: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    explanation: Mapped[Dict[str, Any]] = mapped_column(JSONType, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, default=utc_now)
    dedup_key: Mapped[Optional[str]] = mapped_column(String(255), index=True, nullable=True)
    is_simulation: Mapped[bool] = mapped_column(Boolean, default=False, index=True, nullable=False)
    simulation_run_id: Mapped[Optional[str]] = mapped_column(String(64), index=True, nullable=True)

    __table_args__ = (
        UniqueConstraint("event_id", "dedup_key", name="uq_findings_event_dedup"),
        Index("ix_findings_incident_timestamp", "incident_id", "timestamp"),
        Index("ix_findings_dedup_key_timestamp", "dedup_key", "timestamp"),
    )

    # Relationships
    rule: Mapped[Optional["RuleModel"]] = relationship("RuleModel", back_populates="findings")
    event: Mapped["EventModel"] = relationship("EventModel", back_populates="findings")
    incident: Mapped[Optional["IncidentModel"]] = relationship("IncidentModel", back_populates="findings")


incident_number_seq = Sequence("incidents_incident_number_seq")


class IncidentModel(Base):
    """Correlated security incidents."""
    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    incident_number: Mapped[int] = mapped_column(
        BigInteger,
        incident_number_seq,
        server_default=incident_number_seq.next_value(),
        unique=True,
        index=True,
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="OPEN", index=True, nullable=False)
    composite_risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    assigned_to: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    entity_graph_snapshot: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONType, nullable=True)
    evidence_manifest_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    affected_entities: Mapped[List[str]] = mapped_column(JSONType, default=list, nullable=False)
    mitre_attack_ids: Mapped[List[str]] = mapped_column(JSONType, default=list, nullable=False)
    risk_explanation: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONType, nullable=True)
    update_history: Mapped[List[Dict[str, Any]]] = mapped_column(JSONType, default=list, nullable=False)
    is_simulation: Mapped[bool] = mapped_column(Boolean, default=False, index=True, nullable=False)
    simulation_run_id: Mapped[Optional[str]] = mapped_column(String(64), index=True, nullable=True)

    __table_args__ = (
        Index("ix_incidents_status_last_seen", "status", "last_seen"),
    )

    # Relationships
    findings: Mapped[List["FindingModel"]] = relationship("FindingModel", back_populates="incident")
    playbook_runs: Mapped[List["PlaybookRunModel"]] = relationship("PlaybookRunModel", back_populates="incident")
    actions: Mapped[List["ResponseActionModel"]] = relationship("ResponseActionModel", back_populates="incident")
    response_plans: Mapped[List["ResponsePlanModel"]] = relationship("ResponsePlanModel", back_populates="incident")


class ThreatIndicatorModel(Base):
    """Threat intelligence indicators."""
    __tablename__ = "threat_indicators"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    indicator_type: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    value: Mapped[str] = mapped_column(String(512), index=True, nullable=False)
    source: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    source_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    confidence: Mapped[int] = mapped_column(Integer, default=50, index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), default="MEDIUM", nullable=False)
    threat_category: Mapped[Optional[str]] = mapped_column(String(64), index=True, nullable=True)
    threat_actor: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    tags: Mapped[List[str]] = mapped_column(JSONType, default=list, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), index=True, nullable=True)
    last_decayed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    __table_args__ = (
        UniqueConstraint("indicator_type", "value", "source", name="uq_threat_indicators_type_value_source"),
        Index("ix_threat_indicators_type_val_active", "indicator_type", "value", "is_active"),
    )


class FeedConfigurationModel(Base):
    """External threat intelligence feed configurations."""
    __tablename__ = "threat_intel_feeds"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    feed_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=False, index=True, nullable=False)
    refresh_interval_minutes: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    last_sync_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_successful_sync_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[str] = mapped_column(String(32), default="NEVER_RUN", nullable=False)
    last_error_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    config_options: Mapped[Dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)


class FeedSyncRunModel(Base):
    """Execution history and provenance logs for feed synchronizations."""
    __tablename__ = "threat_intel_sync_runs"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    feed_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True, nullable=False)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="RUNNING", index=True, nullable=False)
    is_dry_run: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    fetched_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    normalized_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    inserted_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    updated_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    skipped_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    rejected_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    deactivated_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    diagnostics: Mapped[Dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)
    triggered_by: Mapped[str] = mapped_column(String(128), default="cli:manual", nullable=False)


class AssetContextModel(Base):
    """Administrative and business context for monitored endpoint assets."""
    __tablename__ = "asset_contexts"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    agent_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"), unique=True, index=True, nullable=False
    )
    criticality: Mapped[str] = mapped_column(String(32), default="LOW", index=True, nullable=False)
    environment: Mapped[Optional[str]] = mapped_column(String(64), index=True, nullable=True)
    asset_group: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    owner: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    business_unit: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    network_zone: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    tags: Mapped[List[str]] = mapped_column(JSONType, default=list, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)
    updated_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    # Relationships
    agent: Mapped["AgentModel"] = relationship("AgentModel", back_populates="asset_context")


class PlaybookModel(Base):
    """SOAR response playbooks."""
    __tablename__ = "playbooks"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    trigger_conditions: Mapped[List[Dict[str, Any]]] = mapped_column(JSONType, default=list, nullable=False)
    action_steps: Mapped[List[Dict[str, Any]]] = mapped_column(JSONType, nullable=False)
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True, nullable=False)

    # Relationships
    runs: Mapped[List["PlaybookRunModel"]] = relationship("PlaybookRunModel", back_populates="playbook")


class PlaybookRunModel(Base):
    """Execution instances of playbooks."""
    __tablename__ = "playbook_runs"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    playbook_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("playbooks.id", ondelete="CASCADE"), nullable=False)
    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="RUNNING", index=True, nullable=False)
    dry_run: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    executed_by: Mapped[str] = mapped_column(String(128), nullable=False)
    start_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    end_time: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    output_summary: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONType, nullable=True)

    # Relationships
    playbook: Mapped["PlaybookModel"] = relationship("PlaybookModel", back_populates="runs")
    incident: Mapped["IncidentModel"] = relationship("IncidentModel", back_populates="playbook_runs")
    actions: Mapped[List["ResponseActionModel"]] = relationship("ResponseActionModel", back_populates="playbook_run")


response_plan_number_seq = Sequence("response_plans_plan_number_seq")


class ResponsePlanModel(Base):
    """Governed incident response plans with approval gates and lifecycle tracking."""
    __tablename__ = "response_plans"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    plan_number: Mapped[int] = mapped_column(
        BigInteger,
        response_plan_number_seq,
        server_default=response_plan_number_seq.next_value(),
        index=True,
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="DRAFT", index=True, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(32), default="CONTAINMENT", nullable=False)
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    actions: Mapped[List[Dict[str, Any]]] = mapped_column(JSONType, nullable=False)
    approval_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    dry_run: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_simulation: Mapped[bool] = mapped_column(Boolean, default=False, index=True, nullable=False)
    simulation_run_id: Mapped[Optional[str]] = mapped_column(String(64), index=True, nullable=True)
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    approved_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    approval_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    rejected_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    rejection_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cancelled_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    cancellation_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    idempotency_key: Mapped[Optional[str]] = mapped_column(String(64), index=True, nullable=True)
    execution_summary: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONType, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    # Relationships
    incident: Mapped["IncidentModel"] = relationship("IncidentModel", back_populates="response_plans")
    actions_rel: Mapped[List["ResponseActionModel"]] = relationship("ResponseActionModel", back_populates="response_plan")


class ResponseActionModel(Base):
    """Allowlisted response actions dispatched to agents."""
    __tablename__ = "response_actions"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    command_id: Mapped[uuid.UUID] = mapped_column(unique=True, index=True, default=uuid.uuid4)
    playbook_run_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("playbook_runs.id", ondelete="SET NULL"), nullable=True)
    response_plan_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("response_plans.id", ondelete="SET NULL"), nullable=True)
    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True, nullable=False)
    agent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"), index=True, nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    parameters: Mapped[Dict[str, Any]] = mapped_column(JSONType, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="REQUESTED", index=True, nullable=False)
    nonce: Mapped[uuid.UUID] = mapped_column(unique=True, default=uuid.uuid4)
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    signature: Mapped[str] = mapped_column(String(64), nullable=False)
    execution_receipt: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONType, nullable=True)
    verification_result: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONType, nullable=True)
    requested_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    approved_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    approval_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    agent: Mapped["AgentModel"] = relationship("AgentModel", back_populates="actions")
    incident: Mapped["IncidentModel"] = relationship("IncidentModel", back_populates="actions")
    playbook_run: Mapped[Optional["PlaybookRunModel"]] = relationship("PlaybookRunModel", back_populates="actions")
    response_plan: Mapped[Optional["ResponsePlanModel"]] = relationship("ResponsePlanModel", back_populates="actions_rel")


class AuditLedgerModel(Base):
    """Cryptographically chained, tamper-evident audit records."""
    __tablename__ = "audit_ledger"

    sequence_number: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    id: Mapped[uuid.UUID] = mapped_column(unique=True, index=True, default=uuid.uuid4)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    actor_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    actor_role: Mapped[str] = mapped_column(String(64), default="ANALYST", nullable=False)
    action: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    target_entity: Mapped[str] = mapped_column(String(128), nullable=False)
    canonical_payload: Mapped[str] = mapped_column(Text, nullable=False)
    previous_hash: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    current_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)


class EventOutboxModel(Base):
    """Transactional outbox for reliable asynchronous event publication."""
    __tablename__ = "event_outbox"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    event_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"), index=True, nullable=False)
    stream_name: Mapped[str] = mapped_column(String(128), default="stream:telemetry:raw", index=True, nullable=False)
    payload: Mapped[Dict[str, Any]] = mapped_column(JSONType, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="PENDING", index=True, nullable=False)
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    published_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    stream_message_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        Index("ix_event_outbox_status_created_at", "status", "created_at"),
    )

    # Relationships
    event: Mapped["EventModel"] = relationship("EventModel", back_populates="outbox_entries")


class SimulationRunModel(Base):
    """Auditable purple-team simulation execution and detection validation records."""
    __tablename__ = "simulation_runs"

    run_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    trace_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    scenario_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    scenario_name: Mapped[str] = mapped_column(String(128), nullable=False)
    mitre_attack_ids: Mapped[List[str]] = mapped_column(JSONType, default=list, nullable=False)
    target_rule_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    is_negative_test: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    status: Mapped[str] = mapped_column(String(32), index=True, default="REGISTERED", nullable=False)
    start_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    end_time: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    events_submitted_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    events_accepted_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    expected_detection: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    observed_detection: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    matching_finding_ids: Mapped[List[str]] = mapped_column(JSONType, default=list, nullable=False)
    matching_incident_ids: Mapped[List[str]] = mapped_column(JSONType, default=list, nullable=False)
    latency_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    latency_notes: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error_detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_simulation: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)


class NotificationDestinationModel(Base):
    """Explicitly configured external outbound webhook destinations."""
    __tablename__ = "notification_destinations"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    destination_url: Mapped[str] = mapped_column(String(512), nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True, nullable=False)
    subscribed_events: Mapped[List[str]] = mapped_column(JSONType, default=list, nullable=False)
    signing_secret_enc: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    created_by: Mapped[str] = mapped_column(String(128), default="admin", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)
    last_delivery_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_delivery_status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    last_delivery_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    deliveries: Mapped[List["NotificationDeliveryModel"]] = relationship(
        "NotificationDeliveryModel",
        back_populates="destination",
        cascade="all, delete-orphan",
    )


class NotificationDeliveryModel(Base):
    """Durable delivery records tracking notification lifecycle and backoff."""
    __tablename__ = "notification_deliveries"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    destination_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("notification_destinations.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    delivery_id: Mapped[uuid.UUID] = mapped_column(default=uuid.uuid4, unique=True, index=True, nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    event_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="PENDING", index=True, nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    next_attempt_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), index=True, nullable=True)
    payload: Mapped[Dict[str, Any]] = mapped_column(JSONType, nullable=False)
    response_status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    response_time_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)
    delivered_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_notification_deliveries_status_next_attempt", "status", "next_attempt_at"),
    )

    # Relationships
    destination: Mapped["NotificationDestinationModel"] = relationship(
        "NotificationDestinationModel",
        back_populates="deliveries",
    )


class InboundSourceModel(Base):
    """Explicitly configured external inbound event sources."""
    __tablename__ = "inbound_sources"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    source_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    provider_type: Mapped[str] = mapped_column(String(32), default="GENERIC", nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True, nullable=False)
    auth_type: Mapped[str] = mapped_column(String(32), default="HMAC_SHA256", nullable=False)
    shared_secret_enc: Mapped[str] = mapped_column(String(512), nullable=False)
    permitted_event_types: Mapped[Optional[List[str]]] = mapped_column(JSONType, default=list, nullable=True)
    total_events_received: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_events_accepted: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_events_rejected: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_events_deduplicated: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_received_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_by: Mapped[str] = mapped_column(String(128), default="admin", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    # Relationships
    dedup_records: Mapped[List["InboundEventDedupModel"]] = relationship(
        "InboundEventDedupModel",
        back_populates="source",
        cascade="all, delete-orphan",
    )


class InboundEventDedupModel(Base):
    """Persistent deduplication record for inbound security events from external sources."""
    __tablename__ = "inbound_event_dedup"
    __table_args__ = (
        UniqueConstraint("source_id", "external_event_id", name="uq_inbound_source_external_event"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    source_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("inbound_sources.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    external_event_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    internal_event_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("events.id", ondelete="SET NULL"),
        nullable=True,
    )
    status: Mapped[str] = mapped_column(String(32), default="ACCEPTED", nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Relationships
    source: Mapped["InboundSourceModel"] = relationship(
        "InboundSourceModel",
        back_populates="dedup_records",
    )
    event: Mapped[Optional["EventModel"]] = relationship(
        "EventModel",
        foreign_keys=[internal_event_id],
    )


class UserModel(Base):
    """Platform operators, security analysts, and administrators."""
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    full_name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    password_algo: Mapped[str] = mapped_column(String(32), default="pbkdf2_sha256", nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="ANALYST", index=True, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True, nullable=False)
    is_mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_secret_encrypted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    mfa_recovery_codes_encrypted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    password_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    # Relationships
    reset_tokens: Mapped[List["PasswordResetTokenModel"]] = relationship(
        "PasswordResetTokenModel",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    revoked_sessions: Mapped[List["RevokedSessionModel"]] = relationship(
        "RevokedSessionModel",
        back_populates="user",
        cascade="all, delete-orphan",
    )


class PasswordResetTokenModel(Base):
    """Cryptographic single-use password recovery tokens."""
    __tablename__ = "password_reset_tokens"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    is_used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    user: Mapped["UserModel"] = relationship("UserModel", back_populates="reset_tokens")


class RevokedSessionModel(Base):
    """Server-side session invalidation registry."""
    __tablename__ = "revoked_sessions"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    session_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=True,
    )
    reason: Mapped[str] = mapped_column(String(64), default="LOGOUT", nullable=False)
    revoked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)

    user: Mapped[Optional["UserModel"]] = relationship("UserModel", back_populates="revoked_sessions")
