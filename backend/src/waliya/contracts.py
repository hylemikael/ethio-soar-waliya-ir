"""Strict Pydantic v2 data contracts for Waliya-IR.

This module locks the schemas for telemetry events, agent C2 communication,
detection rules, graph snapshots, incident lifecycle, SOAR actions, and audit ledger.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Union
from uuid import UUID, uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)


# ==============================================================================
# 1. CORE ENUMS
# ==============================================================================

class SeverityEnum(str, Enum):
    """Normalized security severity levels."""
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventTypeEnum(str, Enum):
    """Normalized telemetry event types."""
    FILE_INTEGRITY = "FILE_INTEGRITY"
    PROCESS_EXECUTION = "PROCESS_EXECUTION"
    AUTHENTICATION = "AUTHENTICATION"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    SYSTEM_LOG = "SYSTEM_LOG"
    EXTERNAL_ALERT = "EXTERNAL_ALERT"


class AgentStatusEnum(str, Enum):
    """Endpoint agent lifecycle states."""
    ONLINE = "ONLINE"
    DEGRADED = "DEGRADED"
    OFFLINE = "OFFLINE"
    REVOKED = "REVOKED"


class IncidentStatusEnum(str, Enum):
    """Incident investigation lifecycle states."""
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class ResponseActionEnum(str, Enum):
    """Strictly allowlisted endpoint response actions.
    Arbitrary shell commands are explicitly forbidden.
    """
    ISOLATE_HOST = "ISOLATE_HOST"
    RESTORE_HOST = "RESTORE_HOST"
    BLOCK_IP = "BLOCK_IP"
    UNBLOCK_IP = "UNBLOCK_IP"
    TERMINATE_PROCESS = "TERMINATE_PROCESS"
    QUARANTINE_FILE = "QUARANTINE_FILE"
    COLLECT_FORENSIC_ARTIFACT = "COLLECT_FORENSIC_ARTIFACT"
    RECOVER_WEBSITE_FILE = "RECOVER_WEBSITE_FILE"


class ResponseStateEnum(str, Enum):
    """Closed-loop containment and response state machine states."""
    REQUESTED = "REQUESTED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    QUEUED = "QUEUED"
    RECEIVED = "RECEIVED"
    EXECUTED = "EXECUTED"
    VERIFYING = "VERIFYING"
    VERIFIED_CONTAINED = "VERIFIED_CONTAINED"
    VERIFICATION_INCONCLUSIVE = "VERIFICATION_INCONCLUSIVE"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    OUTCOME_UNCERTAIN = "OUTCOME_UNCERTAIN"
    EXPIRED = "EXPIRED"
    REJECTED = "REJECTED"


class ExecutionModeEnum(str, Enum):
    """Operational execution modes for response actions."""
    DRY_RUN = "DRY_RUN"
    SIMULATION = "SIMULATION"
    PRODUCTION = "PRODUCTION"


class ResponsePlanStatusEnum(str, Enum):
    """Lifecycle states for governed incident response plans."""
    DRAFT = "DRAFT"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    REJECTED = "REJECTED"
    CANCELLED = "CANCELLED"


class ActionRiskClassificationEnum(str, Enum):
    """Standardized operational risk classification for response actions."""
    READ_ONLY = "READ_ONLY"
    REVERSIBLE = "REVERSIBLE"
    CONTAINMENT = "CONTAINMENT"
    DESTRUCTIVE = "DESTRUCTIVE"


class EntityTypeEnum(str, Enum):
    """Types of security entities in the correlation graph."""
    HOST = "Host"
    USER = "User"
    IP_ADDRESS = "IPAddress"
    PROCESS = "Process"
    FILE = "File"
    ALERT = "Alert"
    INDICATOR = "Indicator"


class RelationTypeEnum(str, Enum):
    """Types of relationships between security entities."""
    AUTHENTICATED_TO = "AUTHENTICATED_TO"
    SPAWNED = "SPAWNED"
    MODIFIED = "MODIFIED"
    CONNECTED_TO = "CONNECTED_TO"
    ACCESSED = "ACCESSED"
    TRIGGERED = "TRIGGERED"
    ASSOCIATED_WITH = "ASSOCIATED_WITH"


class MitreMappingStateEnum(str, Enum):
    """Classification state for MITRE ATT&CK technique mapping."""
    MAPPED = "MAPPED"
    UNMAPPED = "UNMAPPED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class ReconstructionItemTypeEnum(str, Enum):
    """Type of observation in an incident reconstruction timeline."""
    EVENT = "EVENT"
    FINDING = "FINDING"
    THREAT_INTEL = "THREAT_INTEL"


class IndicatorTypeEnum(str, Enum):
    """Threat intelligence indicator types."""
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    DOMAIN = "DOMAIN"
    SHA256 = "SHA256"
    URL = "URL"
    # Legacy aliases
    IP = "IP"
    FILE_HASH_SHA256 = "FILE_HASH_SHA256"


class AssetCriticalityEnum(str, Enum):
    """Standardized asset criticality scale."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AssetEnvironmentEnum(str, Enum):
    """Asset deployment environment."""
    PRODUCTION = "PRODUCTION"
    STAGING = "STAGING"
    DEVELOPMENT = "DEVELOPMENT"
    DMZ = "DMZ"
    CORPORATE = "CORPORATE"
    LAB = "LAB"


# ==============================================================================
# 2. TELEMETRY & EVENT CONTRACTS
# ==============================================================================

class BaseContract(BaseModel):
    """Base model enforcing strict Pydantic v2 settings."""
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )


class SecurityEventEnvelope(BaseContract):
    """Immutable envelope encapsulating an individual normalized security event."""
    event_id: UUID = Field(default_factory=uuid4, description="Unique event identifier")
    event_type: EventTypeEnum = Field(..., description="Categorized telemetry type")
    severity: SeverityEnum = Field(default=SeverityEnum.INFORMATIONAL, description="Assessed severity")
    timestamp: datetime = Field(..., description="Event observation timestamp (UTC)")
    source: str = Field(..., min_length=2, max_length=128, description="Originating sensor or collector")
    agent_id: Optional[UUID] = Field(default=None, description="Originating agent UUID if applicable")
    payload: Dict[str, Any] = Field(..., description="Validated event-specific data payload")

    @field_validator("timestamp")
    @classmethod
    def validate_utc_timestamp(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            # Assume UTC if not provided
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)


class EventBatchRequest(BaseContract):
    """Batch ingestion request payload."""
    batch_id: UUID = Field(default_factory=uuid4, description="Unique batch identifier")
    agent_id: UUID = Field(..., description="Submitting agent identifier")
    events: List[SecurityEventEnvelope] = Field(..., min_length=1, max_length=1000, description="List of events")


class EventBatchResponse(BaseContract):
    """Batch ingestion confirmation response."""
    batch_id: UUID
    processed_count: int = Field(..., ge=0)
    status: Literal["QUEUED", "PROCESSED", "PARTIAL_REJECT"] = "QUEUED"


# ==============================================================================
# 3. AGENT IDENTITY, HEALTH & HEARTBEAT
# ==============================================================================

class AgentRegistrationRequest(BaseContract):
    """Endpoint registration payload."""
    hostname: str = Field(..., min_length=1, max_length=255)
    os_family: str = Field(default="linux", max_length=64)
    os_version: str = Field(..., max_length=128)
    primary_ip: str = Field(..., max_length=45)
    mac_address: str = Field(..., max_length=32)
    agent_version: str = Field(..., max_length=32)


class AgentRegistrationResponse(BaseContract):
    """Registration confirmation returning per-agent credentials."""
    agent_id: UUID
    api_token: str = Field(..., description="Agent bearer API token")
    agent_secret: str = Field(..., description="Per-agent HMAC signing secret (shown only once)")
    registered_at: datetime


class AgentMetrics(BaseContract):
    """Performance telemetry reported by agent."""
    cpu_percent: float = Field(..., ge=0.0, le=100.0)
    memory_used_mb: int = Field(..., ge=0)


class AgentHeartbeatRequest(BaseContract):
    """Outbound heartbeat emitted periodically by agents."""
    hostname: str = Field(..., min_length=1, max_length=255)
    primary_ip: str = Field(..., max_length=45)
    os_version: str = Field(..., max_length=128)
    agent_version: str = Field(..., max_length=32)
    metrics: AgentMetrics


class AgentHeartbeatResponse(BaseContract):
    """Heartbeat response confirming health and notifying of pending tasks."""
    status: Literal["ACK"] = "ACK"
    server_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    pending_tasks: int = Field(default=0, ge=0)


# ==============================================================================
# 4. DETECTION RULES & ANOMALY CONTRACTS
# ==============================================================================

class RuleCondition(BaseContract):
    """Single condition evaluation unit."""
    field: str = Field(..., min_length=1, max_length=128, description="Target field in event payload")
    operator: Literal["EQUALS", "NOT_EQUALS", "CONTAINS", "STARTS_WITH", "ENDS_WITH", "IN", "REGEX_MATCH", "GREATER_THAN", "LESS_THAN"]
    value: Any = Field(..., description="Expected value or pattern")


class DetectionRuleSchema(BaseContract):
    """Versioned detection rule specification."""
    rule_id: str = Field(..., min_length=3, max_length=64, pattern=r"^RULE-[A-Z0-9_-]+$", description="Stable rule identifier")
    version: int = Field(default=1, ge=1, description="Incremental version number")
    name: str = Field(..., min_length=3, max_length=255)
    description: str = Field(..., min_length=10, max_length=2000)
    severity: SeverityEnum = Field(..., description="Default rule severity")
    event_type: EventTypeEnum = Field(..., description="Target event category")
    conditions: List[RuleCondition] = Field(..., min_length=1, description="List of conditions (AND logic)")
    mitre_attack_ids: List[str] = Field(default_factory=list, description="Associated MITRE ATT&CK technique IDs")
    dedup_window_seconds: int = Field(default=300, ge=10, le=86400, description="Suppression window for identical matches")
    is_active: bool = Field(default=True)


class RuleEvaluationResult(BaseContract):
    """Outcome of evaluating an event against a rule."""
    matched: bool
    rule_id: str
    rule_version: int
    matched_conditions: List[str] = Field(default_factory=list)
    explanation: str


class AnomalyExplanation(BaseContract):
    """Explainable statistical anomaly observation."""
    metric_name: str
    observed_value: float
    baseline_mean: float
    baseline_std: float
    z_score: float
    threshold: float
    alpha: float = Field(default=0.1, description="EWMA decay factor")
    decision_reason: str = Field(default="", description="Human-readable decision explanation")


class AnomalyObservation(BaseContract):
    """Container for detected statistical anomaly."""
    observation_id: UUID = Field(default_factory=uuid4)
    agent_id: Optional[UUID] = None
    metric: str
    explanation: AnomalyExplanation
    severity: SeverityEnum
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ==============================================================================
# 5. THREAT INTELLIGENCE & ASSET CONTEXT CONTRACTS
# ==============================================================================

class ThreatIndicatorSchema(BaseContract):
    """Threat intelligence indicator."""
    indicator_id: UUID = Field(default_factory=uuid4)
    indicator_type: IndicatorTypeEnum
    value: str = Field(..., min_length=1, max_length=512)
    confidence: int = Field(default=50, ge=0, le=100)
    source: str = Field(..., min_length=2, max_length=128)
    threat_actor: Optional[str] = Field(default=None, max_length=128)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None


class ThreatIndicatorCreate(BaseContract):
    """Payload for creating a new threat indicator."""
    indicator_type: IndicatorTypeEnum
    value: str = Field(..., min_length=1, max_length=512)
    source: str = Field(..., min_length=2, max_length=128)
    source_id: Optional[str] = Field(default=None, max_length=128)
    confidence: int = Field(default=50, ge=0, le=100)
    severity: SeverityEnum = SeverityEnum.MEDIUM
    threat_category: Optional[str] = Field(default=None, max_length=64)
    threat_actor: Optional[str] = Field(default=None, max_length=128)
    tags: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    is_active: bool = True


class ThreatIndicatorUpdate(BaseContract):
    """Payload for updating an existing threat indicator."""
    confidence: Optional[int] = Field(default=None, ge=0, le=100)
    severity: Optional[SeverityEnum] = None
    threat_category: Optional[str] = Field(default=None, max_length=64)
    threat_actor: Optional[str] = Field(default=None, max_length=128)
    tags: Optional[List[str]] = None
    description: Optional[str] = None
    last_seen: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    is_active: Optional[bool] = None


class ThreatIndicatorResponse(BaseContract):
    """Standard threat indicator representation."""
    id: UUID
    indicator_type: str
    value: str
    source: str
    source_id: Optional[str] = None
    confidence: int
    severity: str
    threat_category: Optional[str] = None
    threat_actor: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    last_decayed_at: Optional[datetime] = None
    is_active: bool
    created_at: datetime
    updated_at: datetime


class ThreatIndicatorExtendExpiryRequest(BaseContract):
    """Payload to extend an indicator's expiration deadline."""
    extension_days: Optional[int] = Field(default=None, ge=1, le=365)
    new_expires_at: Optional[datetime] = None


class ThreatIndicatorDecayRequest(BaseContract):
    """Configuration for deterministic, bounded indicator confidence decay."""
    stale_days: int = Field(default=14, ge=1, le=365)
    decay_points: int = Field(default=10, ge=1, le=50)
    decay_interval_days: int = Field(default=7, ge=1, le=90)
    min_confidence: int = Field(default=10, ge=0, le=50)
    dry_run: bool = False
    indicator_type: Optional[IndicatorTypeEnum] = None
    source: Optional[str] = Field(default=None, max_length=128)


class ThreatIndicatorDecayedItem(BaseContract):
    """Record of an individual decayed indicator."""
    indicator_id: UUID
    value: str
    indicator_type: str
    source: str
    previous_confidence: int
    new_confidence: int
    intervals_decayed: int
    last_decayed_at: datetime


class ThreatIndicatorDecayResponse(BaseContract):
    """Summary of a deterministic decay run."""
    total_evaluated: int
    decayed_count: int
    unaffected_count: int
    is_dry_run: bool
    stale_days_threshold: int
    decay_points_per_interval: int
    decay_interval_days: int
    min_confidence: int
    decayed_indicators: List[ThreatIndicatorDecayedItem] = Field(default_factory=list)


class IncidentThreatIntelMatch(BaseContract):
    """Traceable threat intelligence match linked to an incident."""
    indicator_id: UUID
    indicator_type: str
    value: str
    observable: str
    source: str
    source_id: Optional[str] = None
    confidence_at_match: int
    current_confidence: int
    severity: str
    threat_category: Optional[str] = None
    threat_actor: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    last_decayed_at: Optional[datetime] = None
    is_active: bool
    is_expired: bool
    matched_at: datetime
    investigative_note: str
    provenance_label: str
    match_classification: Literal["CONFIRMED_MATCH", "HEURISTIC_OBSERVABLE"] = "CONFIRMED_MATCH"


class IncidentThreatIntelSummary(BaseContract):
    """Comprehensive threat intelligence context for incident investigation."""
    incident_id: UUID
    incident_number: int
    has_threat_intel: bool
    total_matched_indicators: int
    max_confidence: int
    threat_intel_bonus: float
    confirmed_matches_count: int
    heuristic_findings_count: int
    matches: List[IncidentThreatIntelMatch] = Field(default_factory=list)
    decision_reason: str



class ThreatIndicatorListResponse(BaseContract):
    """Paginated threat indicators list response."""
    items: List[ThreatIndicatorResponse]
    total: int
    limit: int
    offset: int


class ThreatIndicatorBatchImportRequest(BaseContract):
    """Bounded batch import of threat indicators."""
    indicators: List[ThreatIndicatorCreate] = Field(..., min_length=1, max_length=500)


class ThreatIndicatorBatchImportResponse(BaseContract):
    """Result summary of a batch threat intelligence import."""
    total_received: int
    imported_count: int
    updated_count: int
    rejected_count: int
    errors: List[Dict[str, Any]] = Field(default_factory=list)


class IndicatorMatchRequest(BaseContract):
    """Request to match an observable against stored threat indicators."""
    observable: str = Field(..., min_length=1, max_length=512)
    indicator_type: Optional[IndicatorTypeEnum] = None


class IndicatorMatchItem(BaseContract):
    """Detailed indicator match result item."""
    observable: str
    indicator_id: UUID
    indicator_type: str
    value: str
    source: str
    source_id: Optional[str] = None
    confidence: int
    severity: str
    threat_category: Optional[str] = None
    threat_actor: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    matched_at: datetime
    investigative_note: str


class IndicatorMatchResponse(BaseContract):
    """Response containing matches for a queried observable."""
    observable: str
    matched: bool
    matches_count: int
    matches: List[IndicatorMatchItem] = Field(default_factory=list)


class AssetContextCreateOrUpdate(BaseContract):
    """Payload to create or update an asset's administrative context."""
    criticality: AssetCriticalityEnum
    environment: Optional[AssetEnvironmentEnum] = None
    asset_group: Optional[str] = Field(default=None, max_length=128)
    description: Optional[str] = None
    owner: Optional[str] = Field(default=None, max_length=128)
    business_unit: Optional[str] = Field(default=None, max_length=128)
    network_zone: Optional[str] = Field(default=None, max_length=128)
    tags: List[str] = Field(default_factory=list)


class AssetContextResponse(BaseContract):
    """Administrative context for an asset."""
    id: UUID
    agent_id: UUID
    criticality: AssetCriticalityEnum
    environment: Optional[AssetEnvironmentEnum] = None
    asset_group: Optional[str] = None
    description: Optional[str] = None
    owner: Optional[str] = None
    business_unit: Optional[str] = None
    network_zone: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime
    updated_by: Optional[str] = None


class AssetDetailResponse(BaseContract):
    """Combined operational and administrative asset representation."""
    agent_id: UUID
    hostname: str
    primary_ip: str
    mac_address: str
    os_family: str
    os_version: str
    agent_version: str
    status: str
    last_heartbeat: Optional[datetime] = None
    registered_at: Optional[datetime] = None
    context: Optional[AssetContextResponse] = None
    is_critical: bool = False


class AssetListResponse(BaseContract):
    """Paginated asset inventory response."""
    items: List[AssetDetailResponse]
    total: int
    limit: int
    offset: int


class FeedConfigurationResponse(BaseContract):
    """External threat intelligence feed configuration record."""
    id: UUID
    feed_id: str
    provider: str
    name: str
    description: Optional[str] = None
    is_enabled: bool
    refresh_interval_minutes: int
    last_sync_at: Optional[datetime] = None
    last_successful_sync_at: Optional[datetime] = None
    last_status: str
    last_error_summary: Optional[str] = None
    config_options: Dict[str, Any] = Field(default_factory=dict)
    indicators_count: Optional[int] = None
    created_at: datetime
    updated_at: datetime


class FeedConfigurationUpdate(BaseContract):
    """Update payload for administrative feed configuration."""
    is_enabled: Optional[bool] = None
    refresh_interval_minutes: Optional[int] = Field(default=None, ge=5, le=10080)
    config_options: Optional[Dict[str, Any]] = None
    description: Optional[str] = None


class FeedSyncRequest(BaseContract):
    """Request payload to trigger feed synchronization."""
    dry_run: bool = False
    force: bool = False


class FeedSyncRunResponse(BaseContract):
    """Threat intelligence feed synchronization execution record."""
    id: UUID
    feed_id: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    status: str
    is_dry_run: bool
    fetched_count: int
    normalized_count: int
    inserted_count: int
    updated_count: int
    skipped_count: int
    rejected_count: int
    deactivated_count: int
    error_summary: Optional[str] = None
    diagnostics: Dict[str, Any] = Field(default_factory=dict)
    triggered_by: str


class FeedSyncRunListResponse(BaseContract):
    """Paginated list of feed synchronization run records."""
    items: List[FeedSyncRunResponse]
    total: int
    limit: int
    offset: int


# ==============================================================================
# 6. GRAPH CORRELATION CONTRACTS
# ==============================================================================

class GraphNode(BaseContract):
    """Entity node in correlation graph."""
    id: str = Field(..., min_length=1, max_length=255, description="Composite ID: e.g. 'host:web-01'")
    type: EntityTypeEnum
    label: str = Field(..., min_length=1, max_length=255)
    properties: Dict[str, Any] = Field(default_factory=dict)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    observation_count: int = Field(default=1, ge=1)
    evidence_count: int = Field(default=0, ge=0)


class GraphEdge(BaseContract):
    """Directed relationship between entity nodes."""
    source: str = Field(..., min_length=1, max_length=255)
    target: str = Field(..., min_length=1, max_length=255)
    relation: RelationTypeEnum
    weight: float = Field(default=1.0, ge=0.0)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    provenance: str = Field(default="telemetry", max_length=64)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    evidence_event_ids: List[str] = Field(default_factory=list)
    properties: Dict[str, Any] = Field(default_factory=dict)


class MitreTechniqueMapping(BaseContract):
    """Authoritative, evidence-backed mapping to a MITRE ATT&CK technique."""
    technique_id: str = Field(..., min_length=2, max_length=32)
    technique_name: str = Field(..., min_length=2, max_length=128)
    tactics: List[str] = Field(default_factory=list)
    mapping_state: MitreMappingStateEnum = MitreMappingStateEnum.MAPPED
    confidence: int = Field(default=80, ge=0, le=100)
    finding_ids: List[UUID] = Field(default_factory=list)
    evidence_event_ids: List[UUID] = Field(default_factory=list)
    rationale: str = Field(..., min_length=1)
    reference_url: Optional[str] = None


class AttackPathStep(BaseContract):
    """Single step in an attack progression path."""
    step_order: int = Field(..., ge=1)
    source: str = Field(..., min_length=1, max_length=255)
    target: str = Field(..., min_length=1, max_length=255)
    relation: RelationTypeEnum
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    timestamp: Optional[datetime] = None
    evidence_event_ids: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    mitre_techniques: List[MitreTechniqueMapping] = Field(default_factory=list)


class AttackPath(BaseContract):
    """Discovered or correlated attack path spanning multiple entities."""
    path_id: str = Field(default_factory=lambda: uuid4().hex[:12])
    entry_node: str = Field(..., min_length=1, max_length=255)
    target_node: str = Field(..., min_length=1, max_length=255)
    hop_count: int = Field(..., ge=1)
    risk_severity: SeverityEnum = SeverityEnum.MEDIUM
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    steps: List[AttackPathStep] = Field(default_factory=list)
    summary: str = ""


class GraphSnapshot(BaseContract):
    """Bounded subgraph snapshot for incident visualization and attack graph analysis."""
    incident_id: Optional[UUID] = Field(default=None)
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    attack_paths: List[AttackPath] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    stats: Dict[str, Any] = Field(default_factory=dict)


class EntityNeighborsResponse(BaseContract):
    """Bounded 1-hop or k-hop neighborhood around an entity."""
    entity: GraphNode
    neighbors: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    degree: int = 0
    in_degree: int = 0
    out_degree: int = 0


class CorrelationPathResponse(BaseContract):
    """Simple directed attack paths found between two entities."""
    source: str
    target: str
    paths: List[AttackPath] = Field(default_factory=list)
    total_paths_found: int = 0


class UnmappedFindingSummary(BaseContract):
    """Summary of an incident finding lacking explicit MITRE ATT&CK technique mappings."""
    finding_id: UUID
    rule_id: str
    finding_title: str
    reason: str
    evidence_event_ids: List[UUID] = Field(default_factory=list)


class IncidentAttackCoverageResponse(BaseContract):
    """Comprehensive, evidence-backed MITRE ATT&CK coverage summary for an incident."""
    incident_id: UUID
    catalog_version: str
    distinct_techniques_count: int = Field(default=0, ge=0)
    mapped_findings_count: int = Field(default=0, ge=0)
    unmapped_findings_count: int = Field(default=0, ge=0)
    insufficient_evidence_count: int = Field(default=0, ge=0)
    tactics: Dict[str, List[MitreTechniqueMapping]] = Field(default_factory=dict)
    techniques: List[MitreTechniqueMapping] = Field(default_factory=list)
    unmapped_findings: List[UnmappedFindingSummary] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)


class ReconstructionObservationItem(BaseContract):
    """Deterministic chronological observation in an incident reconstruction."""
    item_id: str
    item_type: ReconstructionItemTypeEnum
    timestamp: Optional[datetime] = None
    title: str
    severity: SeverityEnum = SeverityEnum.MEDIUM
    source: str
    is_interpretation: bool = False
    associated_entity_ids: List[str] = Field(default_factory=list)
    associated_graph_edges: List[str] = Field(default_factory=list)
    mitre_techniques: List[MitreTechniqueMapping] = Field(default_factory=list)
    evidence_event_ids: List[str] = Field(default_factory=list)
    finding_ids: List[str] = Field(default_factory=list)
    explanation: str = ""
    raw_attributes: Dict[str, Any] = Field(default_factory=dict)
    data_gaps: List[str] = Field(default_factory=list)


class ReconstructionAttackProgression(BaseContract):
    """Candidate attack progression path derived from graph reachability."""
    path_id: str
    entry_node: str
    target_node: str
    hop_count: int
    risk_severity: SeverityEnum = SeverityEnum.MEDIUM
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    disclaimer: str = "Candidate graph traversal; indicates reachability but does not prove a single causal execution sequence."
    steps: List[AttackPathStep] = Field(default_factory=list)


class ReconstructionCoverageSummary(BaseContract):
    """Statistical summary of observations and correlation coverage."""
    total_observations: int = 0
    chronological_events_count: int = 0
    correlated_findings_count: int = 0
    threat_intel_matches_count: int = 0
    mapped_techniques_count: int = 0
    unmapped_findings_count: int = 0
    insufficient_evidence_count: int = 0
    graph_entities_count: int = 0
    graph_edges_count: int = 0
    candidate_attack_paths_count: int = 0


class ReconstructionIncompleteEvidence(BaseContract):
    """Explicit disclosure of gaps, missing links, and unmapped records."""
    findings_without_events: List[str] = Field(default_factory=list)
    events_without_mitre: int = 0
    unconnected_entities: List[str] = Field(default_factory=list)
    uncertainties: List[str] = Field(default_factory=list)


class CrossLayerConsistencyReport(BaseContract):
    """Verification results across graph, ATT&CK, findings, and events."""
    is_consistent: bool = True
    checks_run: int = 12
    inconsistencies: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)


class IncidentReconstructionResponse(BaseContract):
    """Unified evidence-backed incident reconstruction combining timeline, graph, ATT&CK, and integrity validation."""
    incident_id: UUID
    incident_number: int
    incident_title: str
    severity: SeverityEnum
    status: IncidentStatusEnum
    first_observed_at: Optional[datetime] = None
    last_observed_at: Optional[datetime] = None
    timeline: List[ReconstructionObservationItem] = Field(default_factory=list)
    candidate_progressions: List[ReconstructionAttackProgression] = Field(default_factory=list)
    coverage_summary: ReconstructionCoverageSummary
    incomplete_evidence: ReconstructionIncompleteEvidence
    consistency_report: CrossLayerConsistencyReport
    limitations: List[str] = Field(default_factory=list)


# ==============================================================================
# 7. INCIDENT INVESTIGATION & EVIDENCE
# ==============================================================================

class EvidenceItem(BaseContract):
    """Individual piece of forensic evidence linked to an incident."""
    evidence_id: UUID = Field(default_factory=uuid4)
    evidence_type: str = Field(..., max_length=64)
    sha256_hash: str = Field(..., pattern=r"^[a-fA-F0-9]{64}$", description="SHA-256 digest of artifact")
    description: str = Field(..., max_length=1000)
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EvidenceManifest(BaseContract):
    """Tamper-evident manifest of evidence collected for an incident."""
    incident_id: UUID
    items: List[EvidenceItem] = Field(default_factory=list)
    manifest_hash: str = Field(..., pattern=r"^[a-fA-F0-9]{64}$", description="SHA-256 digest over item hashes")


class IncidentSummary(BaseContract):
    """High-level incident representation."""
    incident_id: UUID
    incident_number: int
    title: str = Field(..., max_length=255)
    severity: SeverityEnum
    status: IncidentStatusEnum
    composite_risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    findings_count: int = Field(default=0, ge=0)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    is_simulation: bool = False
    simulation_run_id: Optional[str] = None


class IncidentDetail(IncidentSummary):
    """Detailed incident response including graph and evidence."""
    description: str
    assigned_to: Optional[str] = None
    affected_entities: List[str] = Field(default_factory=list)
    mitre_attack_ids: List[str] = Field(default_factory=list)
    risk_explanation: Dict[str, Any] = Field(default_factory=dict)
    update_history: List[Dict[str, Any]] = Field(default_factory=list)
    graph_snapshot: Optional[GraphSnapshot] = None
    evidence_manifest: Optional[EvidenceManifest] = None


# ==============================================================================
# 8. SOAR PLAYBOOKS & SECURE COMMAND CHANNEL
# ==============================================================================

# Specific validated parameter schemas for allowlisted response actions

class IsolateHostParams(BaseContract):
    direction: Literal["INBOUND", "OUTBOUND", "ALL"] = "ALL"
    allowed_subnets: List[str] = Field(default_factory=list)


class RestoreHostParams(BaseContract):
    flush_rules: bool = True


class BlockIpParams(BaseContract):
    ip_address: str = Field(..., max_length=45)
    direction: Literal["IN", "OUT", "BOTH"] = "BOTH"


class UnblockIpParams(BaseContract):
    ip_address: str = Field(..., max_length=45)


class TerminateProcessParams(BaseContract):
    pid: int = Field(..., gt=0)
    process_name: str = Field(..., min_length=1, max_length=255)
    kill_tree: bool = False


class QuarantineFileParams(BaseContract):
    file_path: str = Field(..., min_length=1, max_length=1024)
    quarantine_directory: str = Field(default="/var/quarantine/waliya")


class CollectForensicParams(BaseContract):
    artifact_type: Literal["LOGS", "PROC_MAP", "SOCKET_TABLE"]
    destination_path: Optional[str] = None


class RecoverWebsiteFileParams(BaseContract):
    target_file: str = Field(..., min_length=1, max_length=1024)
    backup_file: str = Field(..., min_length=1, max_length=1024)
    expected_hash: str = Field(..., min_length=64, max_length=64)
    quarantine_directory: Optional[str] = Field(default=None)
    web_root: Optional[str] = Field(default=None)


ActionParameters = Union[
    IsolateHostParams,
    RestoreHostParams,
    BlockIpParams,
    UnblockIpParams,
    TerminateProcessParams,
    QuarantineFileParams,
    CollectForensicParams,
    RecoverWebsiteFileParams,
]


class CommandEnvelope(BaseContract):
    """Cryptographically signed command envelope dispatched to an agent."""
    command_id: UUID = Field(default_factory=uuid4, description="Unique command identifier")
    agent_id: UUID = Field(..., description="Target agent UUID")
    action: ResponseActionEnum = Field(..., description="Strictly allowlisted action")
    parameters: Dict[str, Any] = Field(..., description="Action parameters dictionary")
    sequence: int = Field(..., ge=1, description="Monotonic sequence number for target agent")
    nonce: UUID = Field(default_factory=uuid4, description="Replay protection nonce")
    issued_at: datetime = Field(..., description="Command issuance timestamp")
    expires_at: datetime = Field(..., description="Strict expiration deadline")
    signature_version: int = Field(default=1, description="Signature format version")
    signature: str = Field(..., pattern=r"^[a-fA-F0-9]{64}$", description="HMAC-SHA256 signature")

    @model_validator(mode="after")
    def validate_expiration(self) -> "CommandEnvelope":
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be strictly greater than issued_at")
        return self


class TaskPollRequest(BaseContract):
    """Agent request polling for queued commands."""
    last_sequence: int = Field(default=0, ge=0)
    supported_actions: List[ResponseActionEnum] = Field(default_factory=list)


class ExecutionReceiptRequest(BaseContract):
    """Initial execution result returned by agent upon running command."""
    command_id: UUID
    status: Literal["EXECUTED", "FAILED"]
    exit_code: int
    output: str = Field(default="", max_length=4096)
    dry_run: bool = Field(default=False, description="Whether execution was in simulated dry-run mode")
    executed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class VerificationTelemetryRequest(BaseContract):
    """Post-action verification telemetry submitted after observation window."""
    command_id: UUID
    observed_state: Dict[str, Any] = Field(..., description="Observed OS state (e.g., iptables rules, /proc check)")
    verified_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class VerificationResultResponse(BaseContract):
    """Server determination of containment status."""
    command_id: UUID
    status: ResponseStateEnum
    explanation: str


# ==============================================================================
# 9. PLAYBOOKS
# ==============================================================================

class PlaybookActionStep(BaseContract):
    step_id: str
    action: ResponseActionEnum
    parameters: Dict[str, Any]
    requires_approval: bool = False
    timeout_seconds: int = 30


class PlaybookSchema(BaseContract):
    playbook_id: UUID = Field(default_factory=uuid4)
    name: str = Field(..., min_length=3, max_length=255)
    description: str = Field(..., max_length=2000)
    trigger_conditions: List[RuleCondition] = Field(default_factory=list)
    action_steps: List[PlaybookActionStep] = Field(..., min_length=1)
    requires_approval: bool = True
    is_active: bool = True


class PlaybookRunSummary(BaseContract):
    run_id: UUID
    playbook_id: UUID
    incident_id: UUID
    status: Literal["PENDING_APPROVAL", "RUNNING", "COMPLETED", "FAILED", "ABORTED"]
    dry_run: bool = False
    executed_by: str
    start_time: datetime
    end_time: Optional[datetime] = None


class ResponsePlanActionItem(BaseContract):
    """Individual action specification within a governed response plan."""
    action: ResponseActionEnum
    parameters: Dict[str, Any]
    agent_id: UUID
    requires_approval: bool = True
    risk_level: Optional[ActionRiskClassificationEnum] = None
    description: Optional[str] = None


class ResponsePlanCreateRequest(BaseContract):
    """Payload to create an approval-gated response plan for an incident."""
    incident_id: UUID
    title: str = Field(..., min_length=3, max_length=255)
    description: Optional[str] = None
    actions: List[ResponsePlanActionItem] = Field(..., min_length=1, max_length=20)
    dry_run: bool = Field(default=True, description="Default to dry-run mode for safety")
    submit_for_approval: bool = Field(default=False, description="Whether to submit immediately to PENDING_APPROVAL")


class ResponsePlanApprovalRequest(BaseContract):
    """Payload for approving or rejecting a response plan."""
    reason: str = Field(..., min_length=3, max_length=1000, description="Authorization justification")


class ResponsePlanCancelRequest(BaseContract):
    """Payload for cancelling a response plan."""
    reason: str = Field(..., min_length=3, max_length=1000, description="Cancellation reason")


class ResponsePlanExecuteRequest(BaseContract):
    """Payload to trigger execution of an approved response plan."""
    dry_run: Optional[bool] = Field(default=None, description="Override dry-run if approved for live execution")
    idempotency_key: Optional[str] = Field(default=None, max_length=64, description="Client idempotency key")


class ResponsePlanReconcileRequest(BaseContract):
    """Payload to manually reconcile an interrupted or stalled response plan."""
    reason: str = Field(..., min_length=3, max_length=1000, description="Mandatory reconciliation justification")


class ResponsePlanResponse(BaseContract):
    """Full detail of a governed response plan record."""
    id: UUID
    plan_number: int
    title: str
    description: Optional[str] = None
    incident_id: UUID
    status: ResponsePlanStatusEnum
    risk_level: ActionRiskClassificationEnum
    requires_approval: bool
    actions: List[Dict[str, Any]]
    approval_hash: Optional[str] = None
    dry_run: bool
    is_simulation: bool
    simulation_run_id: Optional[str] = None
    created_by: str
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    approval_reason: Optional[str] = None
    rejected_by: Optional[str] = None
    rejection_reason: Optional[str] = None
    cancelled_by: Optional[str] = None
    cancellation_reason: Optional[str] = None
    idempotency_key: Optional[str] = None
    execution_summary: Optional[Dict[str, Any]] = None
    action_commands: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class ActionRegistryEntryResponse(BaseContract):
    """Metadata entry for an allowlisted action type in the registry."""
    action_type: ResponseActionEnum
    risk_classification: ActionRiskClassificationEnum
    default_requires_approval: bool
    default_timeout_seconds: int
    max_retries: int
    is_reversible: bool
    description: str
    parameter_fields: List[str]


# ==============================================================================
# 10. TAMPER-EVIDENT AUDIT LEDGER
# ==============================================================================

class AuditLedgerRecord(BaseContract):
    """Cryptographically chained audit ledger entry."""
    sequence_number: int = Field(..., ge=0, description="Strictly increasing integer sequence")
    record_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(..., description="UTC timestamp of the audited operation")
    actor_id: str = Field(..., min_length=1, max_length=128)
    actor_role: str = Field(default="ANALYST", max_length=64)
    action: str = Field(..., min_length=2, max_length=128)
    target_entity: str = Field(..., min_length=2, max_length=128)
    canonical_payload: str = Field(..., description="Deterministic canonical JSON payload string")
    previous_hash: str = Field(..., pattern=r"^[a-fA-F0-9]{64}$", description="SHA-256 of record N-1")
    current_hash: str = Field(..., pattern=r"^[a-fA-F0-9]{64}$", description="SHA-256 of this record")


class AuditVerificationResponse(BaseContract):
    """Result of audit ledger verification check."""
    verified: bool
    total_records: int
    genesis_hash: str
    latest_hash: Optional[str] = None
    tamper_detected: bool = False
    broken_sequence: Optional[int] = None


# ==============================================================================
# 11. SYSTEM HEALTH & DIAGNOSTICS
# ==============================================================================

class LivenessResponse(BaseContract):
    status: Literal["UP"] = "UP"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    version: str = "2.0.0"


class ReadinessCheckItem(str, Enum):
    CONNECTED = "CONNECTED"
    DISCONNECTED = "DISCONNECTED"
    DEGRADED = "DEGRADED"


class ReadinessResponse(BaseContract):
    status: Literal["READY", "NOT_READY"]
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    checks: Dict[str, ReadinessCheckItem]


class DependencyHealthStatus(str, Enum):
    """Operational health status of platform dependencies and components."""
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNHEALTHY = "UNHEALTHY"
    UNKNOWN = "UNKNOWN"
    UNAVAILABLE = "UNAVAILABLE"


class DependencyHealthItem(BaseContract):
    """Health item for an individual subsystem or external dependency."""
    name: str
    status: DependencyHealthStatus
    latency_ms: Optional[float] = None
    message: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class WorkerHealthItem(BaseContract):
    """Health and lag tracking for background consumer workers."""
    worker_id: str
    group_name: str
    status: DependencyHealthStatus
    last_heartbeat: Optional[datetime] = None
    heartbeat_age_seconds: Optional[float] = None
    processed_count: int = Field(default=0, ge=0)
    error_count: int = Field(default=0, ge=0)
    stream_lag: Optional[int] = Field(default=None, ge=0)
    pending_pel_count: Optional[int] = Field(default=None, ge=0)


class OperationalBacklogsSummary(BaseContract):
    """Bounded operational backlogs across telemetry, inbound and outbound integration queues."""
    telemetry_stream_length: int = Field(default=0, ge=0)
    telemetry_stream_lag: int = Field(default=0, ge=0)
    telemetry_pel_size: int = Field(default=0, ge=0)
    outbound_notifications_pending: int = Field(default=0, ge=0)
    outbound_notifications_retrying: int = Field(default=0, ge=0)
    outbound_notifications_dead_letter: int = Field(default=0, ge=0)
    inbound_events_dedup_cached: int = Field(default=0, ge=0)


class StalledOperationsSummary(BaseContract):
    """Stalled, hung, or uncertain operations requiring operational attention."""
    stalled_executing_plans_count: int = Field(default=0, ge=0)
    uncertain_actions_count: int = Field(default=0, ge=0)
    stalled_outbox_notifications_count: int = Field(default=0, ge=0)
    stale_threat_intel_feeds_count: int = Field(default=0, ge=0)
    details: Optional[List[Dict[str, Any]]] = None


class SystemDiagnosticsResponse(BaseContract):
    """Authenticated administrative diagnostic overview of all platform dependencies and queues."""
    status: DependencyHealthStatus
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    uptime_seconds: float = Field(default=0.0, ge=0.0)
    dependencies: Dict[str, DependencyHealthItem] = Field(default_factory=dict)
    telemetry_workers: List[WorkerHealthItem] = Field(default_factory=list)
    backlogs: OperationalBacklogsSummary = Field(default_factory=OperationalBacklogsSummary)
    stalled_operations: StalledOperationsSummary = Field(default_factory=StalledOperationsSummary)


class OperationalMetricsResponse(BaseContract):
    """Bounded operational counters and performance metrics."""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    http_requests_total: Dict[str, int] = Field(default_factory=dict)
    avg_request_duration_ms: float = Field(default=0.0, ge=0.0)
    telemetry_processed_total: int = Field(default=0, ge=0)
    telemetry_errors_total: int = Field(default=0, ge=0)
    inbound_events_total: Dict[str, int] = Field(default_factory=dict)
    outbound_deliveries_total: Dict[str, int] = Field(default_factory=dict)


# ==============================================================================
# 12. SYSTEM OVERVIEW CONTRACTS
# ==============================================================================

class AgentHealthSummary(BaseContract):
    total: int = Field(default=0, ge=0)
    online: int = Field(default=0, ge=0)
    degraded: int = Field(default=0, ge=0)
    offline: int = Field(default=0, ge=0)
    revoked: int = Field(default=0, ge=0)
    last_heartbeat: Optional[datetime] = None


class EventDistributionSummary(BaseContract):
    total_last_24h: int = Field(default=0, ge=0)
    by_type: Dict[str, int] = Field(default_factory=dict)


class FindingsSeveritySummary(BaseContract):
    total: int = Field(default=0, ge=0)
    by_severity: Dict[str, int] = Field(default_factory=dict)


class IncidentActivityItem(BaseContract):
    incident_id: UUID
    incident_number: int
    title: str
    severity: SeverityEnum
    status: IncidentStatusEnum
    composite_risk_score: float
    findings_count: int = 0
    last_seen: Optional[datetime] = None
    is_simulation: bool = False


class IncidentsOverviewSummary(BaseContract):
    total: int = Field(default=0, ge=0)
    open_count: int = Field(default=0, ge=0)
    investigating_count: int = Field(default=0, ge=0)
    contained_count: int = Field(default=0, ge=0)
    resolved_count: int = Field(default=0, ge=0)
    closed_count: int = Field(default=0, ge=0)
    by_severity: Dict[str, int] = Field(default_factory=dict)
    recent_activity: List[IncidentActivityItem] = Field(default_factory=list)


class PipelineHealthSummary(BaseContract):
    stream_name: str = "stream:telemetry:raw"
    stream_length: Optional[int] = None
    stream_status: str = "HEALTHY"
    outbox_pending: int = Field(default=0, ge=0)
    outbox_failed: int = Field(default=0, ge=0)
    outbox_published: int = Field(default=0, ge=0)


class RulesOverviewSummary(BaseContract):
    total_rules: int = Field(default=0, ge=0)
    active_rules: int = Field(default=0, ge=0)


class RecentActionItem(BaseContract):
    command_id: UUID
    action: ResponseActionEnum
    status: ResponseStateEnum
    issued_at: datetime
    agent_id: UUID


class ResponseOutcomesSummary(BaseContract):
    total_actions: int = Field(default=0, ge=0)
    by_status: Dict[str, int] = Field(default_factory=dict)
    recent_actions: List[RecentActionItem] = Field(default_factory=list)


class SystemOverviewResponse(BaseContract):
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    security_posture: Literal["NORMAL", "ELEVATED", "CRITICAL"] = "NORMAL"
    posture_reason: str = "No critical active threats detected"
    agents: AgentHealthSummary
    events_24h: EventDistributionSummary
    findings: FindingsSeveritySummary
    incidents: IncidentsOverviewSummary
    pipeline: PipelineHealthSummary
    rules: RulesOverviewSummary
    responses: ResponseOutcomesSummary


# ==============================================================================
# Purple-Team Simulation Contracts
# ==============================================================================

class SimulationRunRegisterRequest(BaseContract):
    """Payload for registering a purple-team simulation run prior to event submission."""
    run_id: str = Field(..., min_length=4, max_length=64, pattern=r"^[a-zA-Z0-9_\-]+$")
    trace_id: str = Field(..., min_length=4, max_length=64, pattern=r"^[a-zA-Z0-9_\-]+$")
    scenario_id: str = Field(..., min_length=2, max_length=64)
    scenario_name: str = Field(..., min_length=2, max_length=128)
    mitre_attack_ids: List[str] = Field(default_factory=list)
    target_rule_id: str = Field(..., min_length=2, max_length=64)
    is_negative_test: bool = Field(default=False)
    expected_detection: bool = Field(default=True)


class SimulationRunFinalizeRequest(BaseContract):
    """Payload for finalizing a simulation run with reported telemetry metrics."""
    events_submitted_count: int = Field(default=0, ge=0)
    events_accepted_count: int = Field(default=0, ge=0)
    client_status: Optional[str] = Field(default=None, max_length=32)
    error_detail: Optional[str] = Field(default=None, max_length=4096)


class SimulationRunResponse(BaseContract):
    """Full detail of a durable simulation execution record."""
    run_id: str
    trace_id: str
    scenario_id: str
    scenario_name: str
    mitre_attack_ids: List[str]
    target_rule_id: str
    is_negative_test: bool
    status: str
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    events_submitted_count: int
    events_accepted_count: int
    expected_detection: bool
    observed_detection: bool
    matching_finding_ids: List[str] = Field(default_factory=list)
    matching_incident_ids: List[str] = Field(default_factory=list)
    latency_seconds: Optional[float] = None
    latency_notes: Optional[str] = None
    summary: Optional[str] = None
    error_detail: Optional[str] = None
    is_simulation: bool = True
    created_at: datetime
    updated_at: datetime
    is_simulation: bool = False
    simulation_run_id: Optional[str] = None


class SimulationScenarioCoverageItem(BaseContract):
    """Coverage and validation state for an individual purple-team scenario."""
    scenario_id: str
    scenario_name: str
    mitre_attack_id: str
    target_rule_id: str
    positive_status: Literal["VALIDATED", "FAILED", "INCONCLUSIVE", "NOT_TESTED"]
    negative_status: Literal["VALIDATED", "FAILED", "INCONCLUSIVE", "NOT_TESTED"]
    last_tested_at: Optional[datetime] = None
    last_run_id: Optional[str] = None
    last_status: Optional[str] = None


class SimulationCoverageResponse(BaseContract):
    """Aggregate platform validation metrics and scenario coverage matrix."""
    total_runs: int = Field(default=0, ge=0)
    passed_runs: int = Field(default=0, ge=0)
    failed_runs: int = Field(default=0, ge=0)
    inconclusive_runs: int = Field(default=0, ge=0)
    distinct_scenarios_tested: int = Field(default=0, ge=0)
    validated_rules_count: int = Field(default=0, ge=0)
    total_rules_count: int = Field(default=0, ge=0)
    most_recent_run_id: Optional[str] = None
    most_recent_run_at: Optional[datetime] = None
    scenarios: List[SimulationScenarioCoverageItem] = Field(default_factory=list)


class NotificationDestinationCreate(BaseContract):
    """Payload for configuring a new external notification destination."""
    name: str = Field(..., min_length=1, max_length=128)
    destination_url: str = Field(..., min_length=1, max_length=512)
    is_enabled: bool = Field(default=True)
    subscribed_events: List[str] = Field(default_factory=list)
    signing_secret: Optional[str] = Field(default=None, min_length=8, max_length=256)


class NotificationDestinationUpdate(BaseContract):
    """Payload for updating an existing external notification destination."""
    name: Optional[str] = Field(default=None, min_length=1, max_length=128)
    destination_url: Optional[str] = Field(default=None, min_length=1, max_length=512)
    is_enabled: Optional[bool] = None
    subscribed_events: Optional[List[str]] = None
    signing_secret: Optional[str] = Field(default=None, min_length=8, max_length=256)


class NotificationDestinationResponse(BaseContract):
    """Safe external destination details with signing secret redacted."""
    id: UUID
    name: str
    destination_url: str
    is_enabled: bool
    subscribed_events: List[str]
    has_signing_secret: bool
    created_by: str
    created_at: datetime
    updated_at: datetime
    last_delivery_at: Optional[datetime] = None
    last_delivery_status: Optional[str] = None
    last_delivery_error: Optional[str] = None


class NotificationDeliveryResponse(BaseContract):
    """Individual outbound notification delivery audit record."""
    id: UUID
    destination_id: UUID
    destination_name: Optional[str] = None
    delivery_id: UUID
    event_type: str
    event_id: str
    status: str
    attempt_count: int
    max_attempts: int
    next_attempt_at: Optional[datetime] = None
    payload: Dict[str, Any]
    response_status_code: Optional[int] = None
    response_time_ms: Optional[int] = None
    error_message: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    delivered_at: Optional[datetime] = None


class NotificationDeliveryListResponse(BaseContract):
    """Paginated collection of outbound notification deliveries."""
    total: int
    deliveries: List[NotificationDeliveryResponse]


# ---------------------------------------------------------------------------
# Inbound External Event Integration Contracts
# ---------------------------------------------------------------------------


class InboundSourceCreate(BaseContract):
    """Payload for registering a new authenticated inbound event source."""
    source_id: str = Field(..., min_length=2, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    name: str = Field(..., min_length=1, max_length=128)
    provider_type: str = Field(default="GENERIC", max_length=32)
    is_enabled: bool = Field(default=True)
    auth_type: str = Field(default="HMAC_SHA256", max_length=32)
    shared_secret: str = Field(..., min_length=16, max_length=256)
    permitted_event_types: Optional[List[str]] = Field(default_factory=list)


class InboundSourceUpdate(BaseContract):
    """Payload for modifying an existing inbound event source."""
    name: Optional[str] = Field(default=None, min_length=1, max_length=128)
    provider_type: Optional[str] = Field(default=None, max_length=32)
    is_enabled: Optional[bool] = None
    auth_type: Optional[str] = Field(default=None, max_length=32)
    shared_secret: Optional[str] = Field(default=None, min_length=16, max_length=256)
    permitted_event_types: Optional[List[str]] = None


class InboundSourceResponse(BaseContract):
    """Safe inbound source configuration response with signing secret redacted."""
    id: UUID
    source_id: str
    name: str
    provider_type: str
    is_enabled: bool
    auth_type: str
    has_shared_secret: bool
    permitted_event_types: List[str]
    total_events_received: int
    total_events_accepted: int
    total_events_rejected: int
    total_events_deduplicated: int
    last_received_at: Optional[datetime] = None
    last_error_message: Optional[str] = None
    created_by: str
    created_at: datetime
    updated_at: datetime


class ExternalSecurityEventPayload(BaseContract):
    """Generic or provider-normalized incoming security event payload."""
    schema_version: str = Field(default="1.0", max_length=16)
    external_event_id: str = Field(..., min_length=1, max_length=128)
    event_type: str = Field(default="EXTERNAL_ALERT", max_length=64)
    timestamp: Optional[datetime] = None
    severity: str = Field(default="MEDIUM", max_length=32)
    title: Optional[str] = Field(default=None, max_length=256)
    description: Optional[str] = Field(default=None, max_length=2048)
    attributes: Dict[str, Any] = Field(default_factory=dict)
    raw_metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)


class InboundEventIngestResponse(BaseContract):
    """Response returned upon submission of an external security event."""
    status: str  # "ACCEPTED", "DUPLICATE", "REJECTED"
    event_id: Optional[str] = None
    external_event_id: str
    source_id: str
    duplicate: bool = False
    received_at: datetime
    message: Optional[str] = None
