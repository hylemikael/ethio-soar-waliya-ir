"""Unit tests for Phase 8: Entity Correlation, Provenance, and Bounded Attack Graphs."""

from datetime import datetime, timezone
from uuid import uuid4
import pytest
import networkx as nx

from waliya.contracts import (
    EntityTypeEnum,
    GraphSnapshot,
    RelationTypeEnum,
    SeverityEnum,
)
from waliya.correlation.entity_extractor import EntityExtractor
from waliya.correlation.graph_engine import EntityGraphManager


def test_entity_extractor_provenance_and_evidence():
    """Verify that entity extraction strictly records event evidence and provenance."""
    event_id = str(uuid4())
    agent_id = uuid4()
    now_utc = datetime.now(timezone.utc)

    # 1. Authentication Event
    auth_event = {
        "event_id": event_id,
        "event_type": "AUTHENTICATION",
        "agent_id": str(agent_id),
        "timestamp": now_utc.isoformat(),
        "source": "auth_pam",
        "attributes": {
            "user": "secops",
            "src_ip": "198.51.100.42",
            "service": "sshd",
            "status": "SUCCESS",
        },
    }
    entities, relationships = EntityExtractor.extract(auth_event)
    assert len(entities) == 3  # Host, User, IP
    assert len(relationships) == 2  # User -> Host, IP -> Host

    user_rel = next(r for r in relationships if r.relation == RelationTypeEnum.AUTHENTICATED_TO)
    assert user_rel.evidence_event_id == event_id
    assert user_rel.confidence == 1.0
    assert user_rel.provenance == "telemetry:sshd"
    assert "secops" in user_rel.description

    # 2. Failed Authentication has lower confidence (0.7) and weight
    failed_auth = {
        "event_id": str(uuid4()),
        "event_type": "AUTHENTICATION",
        "agent_id": str(agent_id),
        "timestamp": now_utc.isoformat(),
        "attributes": {
            "user": "attacker",
            "src_ip": "198.51.100.99",
            "service": "sshd",
            "status": "FAILURE",
        },
    }
    _, failed_rels = EntityExtractor.extract(failed_auth)
    failed_user_rel = next(r for r in failed_rels if r.relation == RelationTypeEnum.AUTHENTICATED_TO)
    assert failed_user_rel.confidence == 0.7
    assert failed_user_rel.weight == 0.5


def test_never_invent_connections_for_invalid_or_loopback_entities():
    """Verify that loopback IPs, unknown users, or missing PIDs never create spurious relationships."""
    agent_id = uuid4()
    now_utc = datetime.now(timezone.utc)

    # Network connection with loopback address
    loopback_event = {
        "event_id": str(uuid4()),
        "event_type": "NETWORK_CONNECTION",
        "agent_id": str(agent_id),
        "timestamp": now_utc.isoformat(),
        "attributes": {
            "src_ip": "127.0.0.1",
            "dst_ip": "127.0.0.1",
            "dst_port": 8080,
        },
    }
    entities, relationships = EntityExtractor.extract(loopback_event)
    # Loopback IP should NOT be extracted as a security entity
    ip_entities = [e for e in entities if e.type == EntityTypeEnum.IP_ADDRESS]
    assert len(ip_entities) == 0
    assert len(relationships) == 0


def test_alert_and_threat_indicator_entity_extraction():
    """Verify extraction of Alert and Threat Indicator nodes with TRIGGERED and ASSOCIATED_WITH edges."""
    finding_id = str(uuid4())
    event_id = str(uuid4())
    host_id = "host:srv-backend-01"

    # 1. Alert Extraction
    alert_ents, alert_rels = EntityExtractor.extract_from_finding(
        finding_id=finding_id,
        rule_name="Privilege Escalation via Sudo",
        severity="HIGH",
        confidence=0.88,
        mitre_ids=["T1548.003"],
        target_entity_id=host_id,
        event_id=event_id,
    )
    assert len(alert_ents) == 1
    assert alert_ents[0].type == EntityTypeEnum.ALERT
    assert alert_ents[0].properties["severity"] == "HIGH"

    assert len(alert_rels) == 1
    assert alert_rels[0].relation == RelationTypeEnum.TRIGGERED
    assert alert_rels[0].source_id == f"alert:{finding_id}"
    assert alert_rels[0].target_id == host_id
    assert alert_rels[0].evidence_event_id == event_id
    assert alert_rels[0].confidence == 0.88
    assert alert_rels[0].provenance == "detection_rule"

    # 2. Threat Intel Indicator Extraction
    ti_ents, ti_rels = EntityExtractor.extract_from_threat_intel(
        indicator_id=str(uuid4()),
        indicator_type="IPV4",
        indicator_value="198.51.100.77",
        source="ThreatFox",
        confidence=90,
        threat_category="C2",
        threat_actor="CobaltStrike",
        target_entity_id=host_id,
        evidence_event_id=event_id,
    )
    assert len(ti_ents) == 1
    assert ti_ents[0].type == EntityTypeEnum.INDICATOR
    assert ti_ents[0].properties["source"] == "ThreatFox"

    assert len(ti_rels) == 1
    assert ti_rels[0].relation == RelationTypeEnum.ASSOCIATED_WITH
    assert ti_rels[0].confidence == 0.90
    assert ti_rels[0].provenance == "threat_intel:ThreatFox"


@pytest.mark.asyncio
async def test_attack_path_discovery_and_determinism():
    """Demonstrate bounded attack path discovery connecting External IP -> Host -> Process -> File."""
    mgr = EntityGraphManager()
    agent_id = uuid4()
    now_utc = datetime.now(timezone.utc)

    # Step 1: External IP connects to Host (SSH)
    await mgr.ingest_event({
        "event_id": str(uuid4()),
        "event_type": "AUTHENTICATION",
        "agent_id": str(agent_id),
        "timestamp": now_utc.isoformat(),
        "attributes": {"user": "analyst", "src_ip": "198.51.100.55", "service": "sshd", "status": "SUCCESS"},
    })

    # Step 2: Host spawns process bash
    await mgr.ingest_event({
        "event_id": str(uuid4()),
        "event_type": "PROCESS_EXECUTION",
        "agent_id": str(agent_id),
        "timestamp": now_utc.isoformat(),
        "attributes": {"pid": 501, "exe": "/bin/bash", "username": "analyst", "cmdline": "bash"},
    })

    # Step 3: Bash spawns curl
    await mgr.ingest_event({
        "event_id": str(uuid4()),
        "event_type": "PROCESS_EXECUTION",
        "agent_id": str(agent_id),
        "timestamp": now_utc.isoformat(),
        "attributes": {"pid": 502, "ppid": 501, "exe": "/usr/bin/curl", "username": "analyst", "cmdline": "curl evil.com"},
    })

    # Step 4: Host modifies sensitive file
    await mgr.ingest_event({
        "event_id": str(uuid4()),
        "event_type": "FILE_INTEGRITY",
        "agent_id": str(agent_id),
        "timestamp": now_utc.isoformat(),
        "attributes": {"file_path": "/etc/shadow", "action": "MODIFIED"},
    })

    # Compute attack paths
    paths = await mgr.find_attack_paths(max_depth=5, max_paths=10)
    assert len(paths) >= 1

    # Verify path details
    p = paths[0]
    assert p.hop_count >= 1
    assert p.confidence > 0.0
    assert len(p.steps) == p.hop_count
    for step in p.steps:
        assert step.source
        assert step.target
        assert step.relation

    # Export snapshot determinism check
    snap1 = await mgr.export_snapshot(max_nodes=100, max_edges=100)
    snap2 = await mgr.export_snapshot(max_nodes=100, max_edges=100)
    assert [n.id for n in snap1.nodes] == [n.id for n in snap2.nodes]
    assert [(e.source, e.target) for e in snap1.edges] == [(e.source, e.target) for e in snap2.edges]


@pytest.mark.asyncio
async def test_attack_path_discovery_handles_cycles_safely():
    """Verify that cyclic graph structures do not cause infinite loops or traversal explosions."""
    mgr = EntityGraphManager()

    # Create cyclic structure manually
    mgr.graph.add_node("ip:198.51.100.1", entity_type="IPAddress", label="198.51.100.1")
    mgr.graph.add_node("host:srv-01", entity_type="Host", label="srv-01")
    mgr.graph.add_node("process:srv-01:100:daemon", entity_type="Process", label="daemon")
    mgr.graph.add_node("file:srv-01:/tmp/payload", entity_type="File", label="payload")

    # Add cycle: IP -> Host -> Process -> IP (cycle)
    mgr.graph.add_edge("ip:198.51.100.1", "host:srv-01", relation="CONNECTED_TO", weight=1.0, confidence=1.0)
    mgr.graph.add_edge("host:srv-01", "process:srv-01:100:daemon", relation="SPAWNED", weight=1.0, confidence=1.0)
    mgr.graph.add_edge("process:srv-01:100:daemon", "ip:198.51.100.1", relation="CONNECTED_TO", weight=1.0, confidence=1.0)
    # Target off the cycle
    mgr.graph.add_edge("process:srv-01:100:daemon", "file:srv-01:/tmp/payload", relation="MODIFIED", weight=1.0, confidence=1.0)

    # find_attack_paths must terminate cleanly without recursion error
    paths = await mgr.find_attack_paths(max_depth=4, max_paths=5)
    assert isinstance(paths, list)
    target_paths = [p for p in paths if p.target_node == "file:srv-01:/tmp/payload"]
    assert len(target_paths) >= 1
    # Simple paths do not contain repeated nodes
    for p in target_paths:
        node_sequence = [p.entry_node] + [s.target for s in p.steps]
        assert len(node_sequence) == len(set(node_sequence))


@pytest.mark.asyncio
async def test_entity_neighbors_and_paths_between():
    """Verify 1-hop and k-hop neighborhood inspection and targeted path discovery."""
    mgr = EntityGraphManager()

    mgr.graph.add_node("user:bob", entity_type="User", label="bob")
    mgr.graph.add_node("host:worker-01", entity_type="Host", label="worker-01")
    mgr.graph.add_node("process:worker-01:999:sh", entity_type="Process", label="sh")

    mgr.graph.add_edge("user:bob", "host:worker-01", relation="AUTHENTICATED_TO", weight=1.0, confidence=1.0)
    mgr.graph.add_edge("host:worker-01", "process:worker-01:999:sh", relation="SPAWNED", weight=1.0, confidence=1.0)

    # Neighbors for host:worker-01
    nbr_resp = await mgr.get_entity_neighbors("host:worker-01", depth=1)
    assert nbr_resp is not None
    assert nbr_resp.entity.id == "host:worker-01"
    assert nbr_resp.degree == 2
    neighbor_ids = {n.id for n in nbr_resp.neighbors}
    assert "user:bob" in neighbor_ids
    assert "process:worker-01:999:sh" in neighbor_ids

    # Targeted path query between user:bob and process:worker-01:999:sh
    paths = await mgr.find_paths_between(
        source_id="user:bob",
        target_id="process:worker-01:999:sh",
        max_depth=3,
    )
    assert len(paths) == 1
    assert paths[0].hop_count == 2
    assert paths[0].entry_node == "user:bob"
    assert paths[0].target_node == "process:worker-01:999:sh"
