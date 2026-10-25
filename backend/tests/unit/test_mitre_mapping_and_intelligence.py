"""Unit tests for evidence-backed MITRE ATT&CK catalog and mapping intelligence."""

import pytest
from datetime import datetime, timezone
from uuid import uuid4

from waliya.contracts import (
    MitreMappingStateEnum,
    MitreTechniqueMapping,
    UnmappedFindingSummary,
    IncidentAttackCoverageResponse,
)
from waliya.db.models import AgentModel, EventModel, FindingModel, IncidentModel, RuleModel
from waliya.db.session import async_session_factory
from waliya.detection.mitre_catalog import (
    MITRE_CATALOG,
    MITRE_CATALOG_VERSION,
    get_catalog_version,
    get_technique_info,
    is_known_technique,
    lookup_technique_or_fallback,
)
from waliya.incidents.mitre_service import EXPLICIT_LIMITATIONS, IncidentMitreService


def test_mitre_catalog_metadata_and_version():
    """Verify local MITRE catalog is versioned, offline, and covers essential Linux techniques."""
    assert get_catalog_version() == "v15.1"
    assert MITRE_CATALOG_VERSION == "v15.1"

    # Verify standard known techniques
    assert is_known_technique("T1059.004") is True
    assert is_known_technique("T1548.003") is True
    assert is_known_technique("T1110.001") is True
    assert is_known_technique("T1505.003") is True
    assert is_known_technique("T1046") is True
    assert is_known_technique("T1078.003") is True

    # Case insensitivity & whitespace stripping
    assert is_known_technique("  t1059.004  ") is True

    # Unknown technique lookup
    assert is_known_technique("T9999.999") is False
    fallback = lookup_technique_or_fallback("T9999.999")
    assert fallback.technique_id == "T9999.999"
    assert "Custom Technique" in fallback.name
    assert fallback.tactics == ["Uncategorized"]
    assert fallback.is_subtechnique is True

    # Tactic verification
    t1548 = get_technique_info("T1548.003")
    assert t1548 is not None
    assert "Privilege Escalation" in t1548.tactics
    assert "Defense Evasion" in t1548.tactics
    assert t1548.parent_technique_id == "T1548"


@pytest.mark.asyncio
async def test_mitre_service_three_state_classification():
    """Verify classification into MAPPED, UNMAPPED, and INSUFFICIENT_EVIDENCE."""
    incident_id = uuid4()
    agent_id = uuid4()
    now_utc = datetime.now(timezone.utc)

    rule_sudo_id = uuid4()
    rule_heuristic_id = uuid4()
    ev_mapped_id = uuid4()

    async with async_session_factory() as session:
        # Monitored host
        agent = AgentModel(
            id=agent_id,
            hostname=f"srv-prod-{uuid4().hex[:6]}",
            os_family="linux",
            os_version="Ubuntu 24.04 LTS",
            primary_ip="10.0.0.50",
            mac_address="52:54:00:11:22:33",
            agent_version="2.0.0",
            status="ONLINE",
            api_token_hash=f"hash-{uuid4().hex}",
            secret_key_enc="enc_secret",
            registered_at=now_utc,
            last_heartbeat=now_utc,
        )
        session.add(agent)

        # Rules
        rule_sudo = RuleModel(
            id=rule_sudo_id,
            rule_id=f"RULE-PROC-SUDO-ABUSE-{uuid4().hex[:6]}",
            name="Sudo Elevation Execution",
            description="Detects suspicious sudo abuse",
            severity="HIGH",
            event_type="PROCESS_EXECUTION",
            conditions=[],
            mitre_attack_ids=["T1548.003"],
            is_active=False,
        )
        rule_heuristic = RuleModel(
            id=rule_heuristic_id,
            rule_id=f"RULE-ANOMALY-EWMA-SPIKE-{uuid4().hex[:6]}",
            name="Unusual Process Spike (Heuristic)",
            description="Statistical baseline outlier",
            severity="MEDIUM",
            event_type="PROCESS_EXECUTION",
            conditions=[],
            mitre_attack_ids=[],  # Intentionally empty (UNMAPPED)
            is_active=False,
        )
        session.add_all([rule_sudo, rule_heuristic])

        # Backing event for mapped finding
        event_mapped = EventModel(
            id=ev_mapped_id,
            agent_id=agent_id,
            event_type="PROCESS_EXECUTION",
            severity="HIGH",
            timestamp=now_utc,
            source="auditd",
            raw_payload={},
            normalized_payload={"attributes": {"exe": "/usr/bin/sudo", "username": "guest"}},
        )
        session.add(event_mapped)

        # Incident with extra technique in metadata (INSUFFICIENT_EVIDENCE)
        incident = IncidentModel(
            id=incident_id,
            title="Investigate Privilege Escalation & Anomaly",
            description="Test incident for MITRE coverage verification",
            severity="HIGH",
            status="INVESTIGATING",
            composite_risk_score=75.0,
            affected_entities=[f"host:{agent_id}", "user:guest"],
            mitre_attack_ids=["T1548.003", "T1070.004"],  # T1070.004 not in any finding
        )
        session.add(incident)

        # Finding 1: MAPPED (Rule has T1548.003, has event evidence)
        f_mapped = FindingModel(
            id=uuid4(),
            rule_id=rule_sudo_id,
            event_id=ev_mapped_id,
            agent_id=agent_id,
            incident_id=incident_id,
            severity="HIGH",
            confidence=0.9,
            explanation={"name": "Sudo Abuse Alert", "mitre_attack_ids": ["T1548.003"]},
            timestamp=now_utc,
        )

        # Finding 2: UNMAPPED (Rule has no mitre_attack_ids, backed by event)
        f_unmapped = FindingModel(
            id=uuid4(),
            rule_id=rule_heuristic_id,
            event_id=ev_mapped_id,
            agent_id=agent_id,
            incident_id=incident_id,
            severity="MEDIUM",
            confidence=0.7,
            explanation={"name": "Process Volume Spike"},
            timestamp=now_utc,
        )

        # Finding 3: INSUFFICIENT_EVIDENCE (Rule has T1046, but non-existent event ID)
        fake_event_id = uuid4()
        f_insufficient = FindingModel(
            id=uuid4(),
            rule_id=None,
            event_id=fake_event_id,
            agent_id=agent_id,
            incident_id=incident_id,
            severity="MEDIUM",
            confidence=0.6,
            explanation={"name": "Port Scan Speculation", "mitre_attack_ids": ["T1046"]},
            timestamp=now_utc,
        )

        # Note: f_insufficient foreign key requires event in DB or will fail if enforced.
        # But wait! FindingModel has ForeignKey("events.id", ondelete="CASCADE"), nullable=False!
        # In SQLite or Postgres with FK enforcement, event must exist.
        # Let's create an event for f_insufficient or check how insufficient evidence happens:
        # A finding can reference an event that was pruned, or incident metadata lists T1070.004!
        # Let's test incident-level insufficient evidence (T1070.004) and mapped/unmapped findings.
        session.add_all([f_mapped, f_unmapped])
        await session.commit()

    # Now execute MITRE coverage analysis
    async with async_session_factory() as session:
        coverage = await IncidentMitreService.get_incident_mitre_coverage(
            session=session,
            incident_id=incident_id,
        )

        assert coverage.incident_id == incident_id
        assert coverage.catalog_version == "v15.1"
        assert coverage.mapped_findings_count == 1
        assert coverage.unmapped_findings_count == 1
        assert coverage.insufficient_evidence_count == 1  # T1070.004 from incident metadata

        # Check mapped technique
        mapped_t = next(t for t in coverage.techniques if t.technique_id == "T1548.003")
        assert mapped_t.mapping_state == MitreMappingStateEnum.MAPPED
        assert mapped_t.technique_name == "Abuse Elevation Control Mechanism: Sudo and Sudo Caching"
        assert mapped_t.confidence == 90
        assert f_mapped.id in mapped_t.finding_ids
        assert ev_mapped_id in mapped_t.evidence_event_ids
        assert "auditd" in mapped_t.rationale

        # Check insufficient evidence technique from metadata
        insufficient_t = next(t for t in coverage.techniques if t.technique_id == "T1070.004")
        assert insufficient_t.mapping_state == MitreMappingStateEnum.INSUFFICIENT_EVIDENCE
        assert insufficient_t.technique_name == "Indicator Removal: File Deletion"
        assert len(insufficient_t.evidence_event_ids) == 0
        assert "not supported by any finding" in insufficient_t.rationale

        # Check unmapped finding summary
        assert len(coverage.unmapped_findings) == 1
        unmapped = coverage.unmapped_findings[0]
        assert unmapped.finding_id == f_unmapped.id
        assert "RULE-ANOMALY-EWMA-SPIKE" in unmapped.rule_id
        assert "heuristic" in unmapped.reason.lower()

        # Check tactics grouping
        assert "Privilege Escalation" in coverage.tactics
        assert any(t.technique_id == "T1548.003" for t in coverage.tactics["Privilege Escalation"])
        assert "Defense Evasion" in coverage.tactics
        assert any(t.technique_id == "T1548.003" for t in coverage.tactics["Defense Evasion"])
        assert any(t.technique_id == "T1070.004" for t in coverage.tactics["Defense Evasion"])

        # Check explicit limitations
        assert len(coverage.limitations) >= 4
        assert any("causal attack sequence" in lim for lim in coverage.limitations)


@pytest.mark.asyncio
async def test_mitre_service_technique_deduplication():
    """Verify that multiple findings referencing the same technique ID are consolidated cleanly."""
    incident_id = uuid4()
    agent_id = uuid4()
    now_utc = datetime.now(timezone.utc)
    ev_1_id = uuid4()
    ev_2_id = uuid4()

    async with async_session_factory() as session:
        agent = AgentModel(
            id=agent_id,
            hostname=f"srv-dedup-{uuid4().hex[:6]}",
            os_family="linux",
            os_version="Debian 12",
            primary_ip="10.0.2.15",
            mac_address="52:54:00:22:33:44",
            agent_version="2.0.0",
            status="ONLINE",
            api_token_hash=f"hash-{uuid4().hex}",
            secret_key_enc="enc_secret",
            registered_at=now_utc,
            last_heartbeat=now_utc,
        )
        session.add(agent)

        ev1 = EventModel(
            id=ev_1_id,
            agent_id=agent_id,
            event_type="FILE_INTEGRITY",
            severity="HIGH",
            timestamp=now_utc,
            source="auditd",
            raw_payload={},
            normalized_payload={"attributes": {"file_path": "/var/www/shell.php"}},
        )
        ev2 = EventModel(
            id=ev_2_id,
            agent_id=agent_id,
            event_type="FILE_INTEGRITY",
            severity="HIGH",
            timestamp=now_utc,
            source="osquery",
            raw_payload={},
            normalized_payload={"attributes": {"file_path": "/var/www/backdoor.php"}},
        )
        session.add_all([ev1, ev2])

        incident = IncidentModel(
            id=incident_id,
            title="Web Shell Infection",
            description="Multiple web shell findings",
            severity="HIGH",
            status="OPEN",
            composite_risk_score=80.0,
            affected_entities=[f"host:{agent_id}"],
            mitre_attack_ids=["T1505.003"],
        )
        session.add(incident)

        # Finding 1 (confidence 0.85)
        f1_id = uuid4()
        f1 = FindingModel(
            id=f1_id,
            rule_id=None,
            event_id=ev_1_id,
            agent_id=agent_id,
            incident_id=incident_id,
            severity="HIGH",
            confidence=0.85,
            explanation={"name": "Web Shell Alpha", "mitre_attack_ids": ["T1505.003"]},
            timestamp=now_utc,
        )
        # Finding 2 (confidence 0.95)
        f2_id = uuid4()
        f2 = FindingModel(
            id=f2_id,
            rule_id=None,
            event_id=ev_2_id,
            agent_id=agent_id,
            incident_id=incident_id,
            severity="HIGH",
            confidence=0.95,
            explanation={"name": "Web Shell Beta", "mitre_attack_ids": ["T1505.003"]},
            timestamp=now_utc,
        )
        session.add_all([f1, f2])
        await session.commit()

    async with async_session_factory() as session:
        coverage = await IncidentMitreService.get_incident_mitre_coverage(
            session=session,
            incident_id=incident_id,
        )

        # Deduplication must result in exactly 1 distinct technique
        assert coverage.distinct_techniques_count == 1
        assert len(coverage.techniques) == 1
        t = coverage.techniques[0]
        assert t.technique_id == "T1505.003"
        assert t.confidence == 95  # Max confidence
        assert set(t.finding_ids) == {f1_id, f2_id}
        assert set(t.evidence_event_ids) == {ev_1_id, ev_2_id}
        assert t.mapping_state == MitreMappingStateEnum.MAPPED
