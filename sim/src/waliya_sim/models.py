"""Data contracts and validation models for Waliya-Sim."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class ScenarioOutcome(str, Enum):
    """Execution status and evaluation verdict of a simulation scenario."""
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"


class ExpectedOutcome(BaseModel):
    """Expected detection engine behavior for a scenario run."""
    should_detect: bool = Field(..., description="Whether a finding and incident should be generated")
    expected_rule_id: str = Field(..., description="Target detection rule ID")
    expected_mitre_id: str = Field(..., description="Target MITRE ATT&CK technique")
    expected_severity: str = Field(..., description="Expected finding severity")
    min_events_for_trigger: int = Field(default=1, description="Minimum events needed to trigger condition")
    description: str = Field(default="", description="Human-readable expectation summary")


class ScenarioMetadata(BaseModel):
    """Metadata describing a deterministic purple-team simulation scenario."""
    scenario_id: str
    name: str
    description: str
    mitre_attack_id: str
    target_rule_id: str
    event_type: str
    threshold_description: str
    boundary_description: str


class DetectionLatencyMetrics(BaseModel):
    """Timestamp-based measurement of detection pipeline latency."""
    first_event_timestamp: Optional[str] = None
    finding_timestamp: Optional[str] = None
    latency_seconds: Optional[float] = None
    measurement_established: bool = False
    measurement_notes: str = ""


class SimulationRunRecord(BaseModel):
    """Comprehensive, auditable record of a completed simulation execution."""
    run_id: str
    trace_id: str
    scenario_id: str
    scenario_name: str
    mitre_attack_id: str
    target_rule_id: str
    is_negative_test: bool
    start_time: str
    end_time: str
    duration_seconds: float
    events_generated_count: int
    events_submitted_count: int
    events_accepted_count: int
    events_processed_count: int
    expected_detection: bool
    observed_detection: bool
    status: ScenarioOutcome
    matching_finding_ids: List[str] = Field(default_factory=list)
    matching_incident_ids: List[str] = Field(default_factory=list)
    latency_metrics: DetectionLatencyMetrics = Field(default_factory=DetectionLatencyMetrics)
    summary: str
    error_detail: Optional[str] = None
