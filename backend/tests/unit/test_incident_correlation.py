"""Unit tests for the incident correlation service and grouping invariants."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4
import pytest
import networkx as nx

from waliya.contracts import EntityTypeEnum, IncidentStatusEnum, SeverityEnum
from waliya.correlation.graph_engine import EntityGraphManager
from waliya.db.models import EventModel, FindingModel, IncidentModel
from waliya.incidents.correlation_service import (
    DEFAULT_CORRELATION_WINDOW_SECONDS,
    IncidentCorrelationService,
    rebuild_graph_from_events,
)


def create_mock_incident(
    incident_id=None,
    affected_entities=None,
    status="OPEN",
    last_seen=None,
    severity="MEDIUM",
    composite_risk_score=50.0,
):
    inc_id = incident_id or uuid4()
    now_utc = last_seen or datetime.now(timezone.utc)
    return IncidentModel(
        id=inc_id,
        title="Test Incident",
        description="Test incident description",
        severity=severity,
        status=status,
        composite_risk_score=composite_risk_score,
        risk_explanation={"base_score": composite_risk_score},
        first_seen=now_utc - timedelta(minutes=5),
        last_seen=now_utc,
        affected_entities=affected_entities or [],
        mitre_attack_ids=["T1059"],
        entity_graph_snapshot={},
        update_history=[],
    )


def test_should_not_merge_merely_sharing_host():
    """Verify core invariant: two findings sharing ONLY a host entity MUST NOT merge."""
    service = IncidentCorrelationService()
    graph_manager = EntityGraphManager()

    agent_id = str(uuid4())
    # Candidate incident has host entity and User A
    candidate = create_mock_incident(
        affected_entities=[f"host:{agent_id}", "user:alice", "process:bash:1001"]
    )

    # New finding has same host, but completely unrelated User B and Process C
    finding_entities = {f"host:{agent_id}", "user:bob", "process:nginx:2002"}

    should_merge = service._should_merge(candidate, finding_entities, graph_manager)
    assert should_merge is False, "Findings sharing ONLY host entity must not be correlated!"


def test_should_merge_with_shared_non_host_entity():
    """Verify that findings sharing a non-host entity (user, IP, file, process) merge."""
    service = IncidentCorrelationService()
    graph_manager = EntityGraphManager()

    agent_id = str(uuid4())
    candidate = create_mock_incident(
        affected_entities=[f"host:{agent_id}", "user:attacker", "ip:198.51.100.44"]
    )

    # Finding shares IP 198.51.100.44
    finding_entities_shared_ip = {f"host:{agent_id}", "ip:198.51.100.44", "user:nobody"}
    assert service._should_merge(candidate, finding_entities_shared_ip, graph_manager) is True

    # Finding shares user:attacker on a different host
    different_host = str(uuid4())
    finding_entities_shared_user = {f"host:{different_host}", "user:attacker"}
    assert service._should_merge(candidate, finding_entities_shared_user, graph_manager) is True


@pytest.mark.asyncio
async def test_should_merge_via_graph_path_connectivity():
    """Verify that findings with entities connected within 2 hops in the graph merge."""
    service = IncidentCorrelationService()
    graph_manager = EntityGraphManager()
    agent_id = uuid4()

    # Ingest event 1: User spawns process
    await graph_manager.ingest_event({
        "event_id": str(uuid4()),
        "event_type": "PROCESS_EXECUTION",
        "agent_id": str(agent_id),
        "attributes": {
            "user": "developer",
            "process_name": "sudo",
            "pid": 5555,
        },
    })
    # Ingest event 2: Process creates network connection to external IP
    await graph_manager.ingest_event({
        "event_id": str(uuid4()),
        "event_type": "NETWORK_CONNECTION",
        "agent_id": str(agent_id),
        "attributes": {
            "pid": 5555,
            "process_name": "sudo",
            "dest_ip": "203.0.113.99",
            "dest_port": 4444,
            "protocol": "TCP",
        },
    })

    # Candidate incident has user:developer
    candidate = create_mock_incident(
        affected_entities=[f"host:{agent_id}", "user:developer"]
    )

    # Finding observes dest_ip 203.0.113.99 (connected via pid 5555: user -> host/proc -> ip)
    finding_entities = {"ip:203.0.113.99"}

    # Should merge because dest_ip is within 2 hops of user/process
    should_merge = service._should_merge(candidate, finding_entities, graph_manager)
    assert should_merge is True


@pytest.mark.asyncio
async def test_correlate_findings_creates_new_incident():
    """Verify that correlate_findings creates a new incident when no active candidates exist."""
    service = IncidentCorrelationService()
    graph_manager = EntityGraphManager()
    agent_id = uuid4()

    # Mock database session
    session = AsyncMock()
    session.add = MagicMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = []  # No candidate incidents
    session.execute.return_value = mock_result

    finding = FindingModel(
        id=uuid4(),
        event_id=uuid4(),
        agent_id=agent_id,
        rule_id=uuid4(),
        severity="HIGH",
        confidence=0.9,
        dedup_key="dedup-1",
        explanation={
            "rule_name": "SSH Brute Force",
            "rule_id": "rule-ssh-bf",
            "mitre_attack_ids": ["T1110.001"],
            "explanation": "Multiple failed SSH authentications detected",
        },
    )

    event_data = {
        "event_id": str(finding.event_id),
        "agent_id": str(agent_id),
        "event_type": "AUTHENTICATION",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "attributes": {
            "user": "root",
            "src_ip": "198.51.100.77",
            "status": "FAILURE",
        },
    }

    incidents = await service.correlate_findings(
        session=session,
        findings=[finding],
        event_data=event_data,
        graph_manager=graph_manager,
    )

    assert len(incidents) == 1
    new_inc = incidents[0]
    assert new_inc.status == "OPEN"
    assert new_inc.severity == "HIGH"
    assert finding.incident_id == new_inc.id
    assert "user:root" in new_inc.affected_entities
    assert "ip:198.51.100.77" in new_inc.affected_entities
    assert "T1110.001" in new_inc.mitre_attack_ids
    assert new_inc.composite_risk_score > 0
    assert "raw_findings_count" in new_inc.risk_explanation
    assert session.add.called
    assert session.flush.called


@pytest.mark.asyncio
async def test_correlate_findings_merges_into_existing_incident():
    """Verify that a second related finding merges into existing active incident and elevates risk."""
    service = IncidentCorrelationService()
    graph_manager = EntityGraphManager()
    agent_id = uuid4()

    now_utc = datetime.now(timezone.utc)
    existing_incident = create_mock_incident(
        affected_entities=[f"host:{agent_id}", "user:compromised_user"],
        status="OPEN",
        last_seen=now_utc - timedelta(minutes=10),
        severity="LOW",
        composite_risk_score=25.0,
    )

    # Mock session returning existing_incident for candidate query
    session = AsyncMock()
    session.add = MagicMock()
    mock_candidates_res = MagicMock()
    mock_candidates_res.scalars.return_value.all.return_value = [existing_incident]

    # Mock session returning attached findings for recalculating risk
    mock_findings_res = MagicMock()
    existing_finding = FindingModel(
        id=uuid4(),
        incident_id=existing_incident.id,
        severity="LOW",
        confidence=0.8,
        dedup_key="dedup-old",
        explanation={"rule_id": "rule-initial"},
    )
    mock_findings_res.scalars.return_value.all.return_value = [existing_finding]

    # session.execute called twice: 1 for active incidents, 2 for attached findings in _merge_into_incident
    session.execute.side_effect = [mock_candidates_res, mock_findings_res]

    new_finding = FindingModel(
        id=uuid4(),
        event_id=uuid4(),
        agent_id=agent_id,
        rule_id=uuid4(),
        severity="CRITICAL",
        confidence=0.95,
        dedup_key="dedup-new",
        explanation={
            "rule_name": "Privilege Escalation via Sudo",
            "rule_id": "rule-priv-esc",
            "mitre_attack_ids": ["T1548.003"],
            "explanation": "Unauthorized sudo execution",
        },
    )

    event_data = {
        "event_id": str(new_finding.event_id),
        "agent_id": str(agent_id),
        "event_type": "PROCESS_EXECUTION",
        "timestamp": now_utc.isoformat(),
        "attributes": {
            "user": "compromised_user",  # Same user!
            "pid": 5555,
            "process_name": "sudo",
            "command_line": "sudo su -",
        },
    }

    modified = await service.correlate_findings(
        session=session,
        findings=[new_finding],
        event_data=event_data,
        graph_manager=graph_manager,
    )

    assert len(modified) == 1
    merged = modified[0]
    assert merged.id == existing_incident.id
    assert new_finding.incident_id == existing_incident.id
    # Severity upgraded to CRITICAL
    assert merged.severity == "CRITICAL"
    # Mitre ID merged
    assert "T1548.003" in merged.mitre_attack_ids
    # Risk score increased
    assert merged.composite_risk_score > 25.0
    # Audit history updated
    assert len(merged.update_history) >= 1
    assert merged.update_history[-1]["action"] == "FINDING_ATTACHED"


@pytest.mark.asyncio
async def test_rebuild_graph_from_events():
    """Verify that rebuild_graph_from_events replays historical events into graph manager."""
    graph_manager = EntityGraphManager()
    session = AsyncMock()

    agent_id = uuid4()
    mock_event = EventModel(
        id=uuid4(),
        agent_id=agent_id,
        event_type="AUTHENTICATION",
        severity="INFO",
        timestamp=datetime.now(timezone.utc),
        source="auditd",
        raw_payload={},
        normalized_payload={
            "attributes": {
                "user": "secops",
                "src_ip": "10.0.1.15",
                "status": "SUCCESS",
            }
        },
    )

    mock_res = MagicMock()
    mock_res.scalars.return_value.all.return_value = [mock_event]
    session.execute.return_value = mock_res

    rebuilt = await rebuild_graph_from_events(session, graph_manager, hours=12)
    assert rebuilt == 1
    assert graph_manager.graph.has_node("user:secops")
    assert graph_manager.graph.has_node("ip:10.0.1.15")
    assert graph_manager.graph.has_node(f"host:{agent_id}")
