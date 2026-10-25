"""Unit tests for evidence-backed incident reconstruction and cross-layer consistency validation."""

import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4

from waliya.contracts import (
    EntityTypeEnum,
    GraphEdge,
    GraphNode,
    GraphSnapshot,
    IncidentAttackCoverageResponse,
    MitreMappingStateEnum,
    MitreTechniqueMapping,
    ReconstructionItemTypeEnum,
    RelationTypeEnum,
    SeverityEnum,
)
from waliya.db.models import AgentModel, EventModel, FindingModel, IncidentModel, RuleModel
from waliya.db.session import async_session_factory
from waliya.incidents.consistency_validator import IncidentConsistencyValidator
from waliya.incidents.reconstruction_service import (
    IncidentReconstructionService,
    RECONSTRUCTION_LIMITATIONS,
)


@pytest.mark.asyncio
async def test_reconstruction_chronology_and_deterministic_ordering():
    """Verify deterministic chronological ordering with stable secondary tie-breaking."""
    incident_id = uuid4()
    agent_id = uuid4()
    base_time = datetime(2026, 10, 24, 12, 0, 0, tzinfo=timezone.utc)

    rule_id = uuid4()
    ev1_id = uuid4()
    ev2_id = uuid4()

    async with async_session_factory() as session:
        # Agent
        agent = AgentModel(
            id=agent_id,
            hostname=f"host-recon-{uuid4().hex[:6]}",
            os_family="linux",
            os_version="Ubuntu 24.04 LTS",
            primary_ip="10.0.5.10",
            mac_address="52:54:00:12:34:56",
            agent_version="2.0.0",
            status="ONLINE",
            api_token_hash=f"hash-{uuid4().hex}",
            secret_key_enc="enc_secret",
            registered_at=base_time,
            last_heartbeat=base_time,
        )
        session.add(agent)

        rule = RuleModel(
            id=rule_id,
            rule_id=f"RULE-RECON-TEST-{uuid4().hex[:6]}",
            name="Suspicious Script Execution",
            description="Reconstruction test rule",
            severity="HIGH",
            event_type="PROCESS_EXECUTION",
            conditions=[{"field": "exe", "operator": "EQUALS", "value": "/bin/bash"}],
            mitre_attack_ids=["T1059.004"],
            is_active=False,
        )
        session.add(rule)

        # Event 1 at T+10s
        ev1 = EventModel(
            id=ev1_id,
            agent_id=agent_id,
            event_type="PROCESS_EXECUTION",
            severity="MEDIUM",
            timestamp=base_time + timedelta(seconds=10),
            source="auditd",
            raw_payload={},
            normalized_payload={"attributes": {"exe": "/bin/bash", "pid": 1001}},
        )
        # Event 2 at T+20s
        ev2 = EventModel(
            id=ev2_id,
            agent_id=agent_id,
            event_type="NETWORK_CONNECTION",
            severity="HIGH",
            timestamp=base_time + timedelta(seconds=20),
            source="suricata",
            raw_payload={},
            normalized_payload={"attributes": {"destination_ip": "198.51.100.22", "destination_port": 443}},
        )
        session.add_all([ev1, ev2])

        # Finding 1 at T+10s (Identical timestamp to ev1 to test secondary tie-breaker)
        f1 = FindingModel(
            id=uuid4(),
            incident_id=incident_id,
            event_id=ev1_id,
            rule_id=rule_id,
            severity="HIGH",
            confidence=0.9,
            timestamp=base_time + timedelta(seconds=10),
            explanation={"rule_id": rule.rule_id, "mitre_attack_ids": ["T1059.004"]},
            is_simulation=False,
        )
        session.add(f1)

        # Incident
        incident = IncidentModel(
            id=incident_id,
            title="Reconstruction Test Incident",
            description="Reconstruction test description",
            severity="HIGH",
            status="INVESTIGATING",
            composite_risk_score=75.0,
            first_seen=base_time,
            last_seen=base_time + timedelta(seconds=20),
            affected_entities=[f"host:{agent_id}"],
            is_simulation=False,
        )
        session.add(incident)
        await session.commit()

        # Execute reconstruction
        recon = await IncidentReconstructionService.reconstruct_incident(
            session=session,
            incident_id=incident_id,
        )

        assert recon.incident_id == incident_id
        assert recon.severity == SeverityEnum.HIGH
        assert len(recon.timeline) >= 2

        # Verify timestamps are strictly monotonically non-decreasing
        timestamps = [item.timestamp for item in recon.timeline if item.timestamp is not None]
        for i in range(1, len(timestamps)):
            assert timestamps[i] >= timestamps[i - 1]

        # Verify separation of raw events vs finding interpretations
        event_items = [it for it in recon.timeline if it.item_type == ReconstructionItemTypeEnum.EVENT]
        finding_items = [it for it in recon.timeline if it.item_type == ReconstructionItemTypeEnum.FINDING]
        assert len(event_items) >= 1
        assert len(finding_items) >= 1
        assert all(it.is_interpretation is False for it in event_items)
        assert all(it.is_interpretation is True for it in finding_items)

        # Verify non-interference: incident risk score was not modified
        assert recon.consistency_report.is_consistent is True
        assert incident.composite_risk_score == 75.0


@pytest.mark.asyncio
async def test_reconstruction_incomplete_evidence_handling():
    """Verify graceful and transparent disclosure of missing events and unmapped findings."""
    incident_id = uuid4()
    agent_id = uuid4()
    now_utc = datetime.now(timezone.utc)

    rule_unmapped_id = uuid4()
    ev_anom_id = uuid4()
    finding_id = uuid4()

    async with async_session_factory() as session:
        # Agent
        agent = AgentModel(
            id=agent_id,
            hostname=f"host-metric-{uuid4().hex[:6]}",
            os_family="linux",
            os_version="Ubuntu 24.04 LTS",
            primary_ip="10.0.9.15",
            mac_address="52:54:00:11:22:99",
            agent_version="2.0.0",
            status="ONLINE",
            api_token_hash=f"hash-{uuid4().hex}",
            secret_key_enc="enc_secret",
            registered_at=now_utc,
            last_heartbeat=now_utc,
        )
        session.add(agent)

        # Rule without MITRE technique
        rule_unmapped = RuleModel(
            id=rule_unmapped_id,
            rule_id=f"RULE-ANOMALY-{uuid4().hex[:6]}",
            name="High CPU Anomaly",
            description="Statistical anomaly",
            severity="LOW",
            event_type="SYSTEM_METRIC",
            conditions=[],
            mitre_attack_ids=[],
            is_active=False,
        )
        session.add(rule_unmapped)

        # Telemetry event without MITRE mapping
        ev_anom = EventModel(
            id=ev_anom_id,
            agent_id=agent_id,
            event_type="SYSTEM_METRIC",
            severity="LOW",
            timestamp=now_utc,
            source="node_exporter",
            raw_payload={},
            normalized_payload={"attributes": {"cpu_pct": 99.2}},
        )
        session.add(ev_anom)

        # Finding with event lacking MITRE mapping
        f_anom = FindingModel(
            id=finding_id,
            incident_id=incident_id,
            event_id=ev_anom_id,
            rule_id=rule_unmapped_id,
            severity="LOW",
            confidence=0.5,
            timestamp=now_utc,
            explanation={"rule_id": rule_unmapped.rule_id},
            is_simulation=False,
        )
        session.add(f_anom)

        incident = IncidentModel(
            id=incident_id,
            title="Incomplete Evidence Incident",
            description="Testing incomplete evidence reporting",
            severity="LOW",
            status="OPEN",
            composite_risk_score=20.0,
            first_seen=now_utc,
            last_seen=now_utc,
            affected_entities=[f"host:{agent_id}"],
            is_simulation=False,
        )
        session.add(incident)
        await session.commit()

        recon = await IncidentReconstructionService.reconstruct_incident(
            session=session,
            incident_id=incident_id,
        )

        # Unmapped findings and events without MITRE are tracked transparently
        assert recon.coverage_summary.unmapped_findings_count >= 1
        assert recon.incomplete_evidence.events_without_mitre >= 1
        assert len(recon.incomplete_evidence.uncertainties) >= 1


def test_cross_layer_consistency_validator_detects_violations():
    """Verify that IncidentConsistencyValidator detects simulation leakage and broken references."""
    incident_id = uuid4()
    incident = IncidentModel(
        id=incident_id,
        title="Validation Test",
        description="Testing validator constraints",
        severity="MEDIUM",
        status="OPEN",
        composite_risk_score=40.0,
        is_simulation=False,
    )

    # Broken finding referencing a non-existent event
    f_broken = FindingModel(
        id=uuid4(),
        incident_id=incident_id,
        event_id=uuid4(),  # Does not resolve in events list
        severity="HIGH",
        confidence=0.8,
        timestamp=datetime.now(timezone.utc),
        is_simulation=True,  # Boundary violation: incident is False, finding is True!
    )

    # Graph snapshot with edge referencing non-existent target node
    broken_graph = GraphSnapshot(
        incident_id=incident_id,
        nodes=[GraphNode(id="host:srv1", label="srv1", type=EntityTypeEnum.HOST)],
        edges=[
            GraphEdge(
                source="host:srv1",
                target="host:non_existent",  # Missing node!
                relation=RelationTypeEnum.CONNECTED_TO,
            )
        ],
    )

    report = IncidentConsistencyValidator.validate_incident_reconstruction(
        incident=incident,
        findings=[f_broken],
        events=[],
        graph_snapshot=broken_graph,
        mitre_coverage=None,
        reconstruction_items=[],
    )

    assert report.is_consistent is False
    assert report.checks_run == 12
    # Should catch missing node, missing event resolution, and simulation mismatch
    assert any("Check 1 Failed" in err for err in report.inconsistencies)
    assert any("Check 3 Failed" in err for err in report.inconsistencies)
    assert any("Check 10 Failed" in err for err in report.inconsistencies)
