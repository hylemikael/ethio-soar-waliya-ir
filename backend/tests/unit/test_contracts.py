"""Unit tests for Pydantic v2 data contracts in waliya.contracts."""

import uuid
from datetime import datetime, timedelta, timezone
import pytest
from pydantic import ValidationError

from waliya.contracts import (
    CommandEnvelope,
    DetectionRuleSchema,
    EventTypeEnum,
    GraphEdge,
    GraphNode,
    EntityTypeEnum,
    RelationTypeEnum,
    ResponseActionEnum,
    ResponseStateEnum,
    RuleCondition,
    SecurityEventEnvelope,
    SeverityEnum,
    AuditLedgerRecord,
)


def test_valid_security_event_envelope():
    """Verify that a compliant security event envelope passes validation."""
    now = datetime.now(timezone.utc)
    envelope = SecurityEventEnvelope(
        event_type=EventTypeEnum.FILE_INTEGRITY,
        severity=SeverityEnum.HIGH,
        timestamp=now,
        source="waliya-agent-fim",
        payload={
            "file_path": "/var/www/html/shell.php",
            "action": "CREATED",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        },
    )
    assert envelope.event_type == EventTypeEnum.FILE_INTEGRITY
    assert envelope.severity == SeverityEnum.HIGH
    assert envelope.payload["file_path"] == "/var/www/html/shell.php"
    assert envelope.timestamp.tzinfo is not None


def test_event_envelope_rejects_extra_fields():
    """Verify that unknown/unauthorized fields are rejected (extra='forbid')."""
    now = datetime.now(timezone.utc)
    with pytest.raises(ValidationError) as exc_info:
        SecurityEventEnvelope(
            event_type=EventTypeEnum.FILE_INTEGRITY,
            timestamp=now,
            source="waliya-agent-fim",
            payload={},
            unexpected_malicious_field="injection_attempt",
        )
    assert "extra_forbidden" in str(exc_info.value)


def test_detection_rule_validation():
    """Verify detection rule schema validation and regex pattern enforcement."""
    rule = DetectionRuleSchema(
        rule_id="RULE-FIM-004-WEBSHELL",
        version=1,
        name="Suspicious Web Shell Created in Webroot",
        description="Detects executable scripts created within web document root directories.",
        severity=SeverityEnum.HIGH,
        event_type=EventTypeEnum.FILE_INTEGRITY,
        conditions=[
            RuleCondition(
                field="file_path",
                operator="STARTS_WITH",
                value="/var/www/html",
            )
        ],
        mitre_attack_ids=["T1505.003"],
        dedup_window_seconds=300,
    )
    assert rule.rule_id == "RULE-FIM-004-WEBSHELL"
    assert rule.version == 1

    # Invalid rule_id pattern must fail
    with pytest.raises(ValidationError):
        DetectionRuleSchema(
            rule_id="invalid rule format with spaces",
            version=1,
            name="Invalid Rule",
            description="Short desc",
            severity=SeverityEnum.LOW,
            event_type=EventTypeEnum.FILE_INTEGRITY,
            conditions=[
                RuleCondition(field="path", operator="EQUALS", value="/tmp")
            ],
        )


def test_command_envelope_allowlisted_actions():
    """Verify that only strictly allowlisted response actions are accepted."""
    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=60)
    agent_id = uuid.uuid4()

    cmd = CommandEnvelope(
        agent_id=agent_id,
        action=ResponseActionEnum.BLOCK_IP,
        parameters={"ip_address": "198.51.100.42", "direction": "BOTH"},
        sequence=1,
        issued_at=now,
        expires_at=expires,
        signature="a" * 64,
    )
    assert cmd.action == ResponseActionEnum.BLOCK_IP

    # Reject arbitrary or unknown shell action
    with pytest.raises(ValidationError):
        CommandEnvelope(
            agent_id=agent_id,
            action="EXECUTE_RAW_BASH",  # Not in allowlist
            parameters={"cmd": "rm -rf /"},
            sequence=2,
            issued_at=now,
            expires_at=expires,
            signature="a" * 64,
        )


def test_command_envelope_rejects_expired_or_inverted_ttl():
    """Verify that command expires_at must be strictly greater than issued_at."""
    now = datetime.now(timezone.utc)
    agent_id = uuid.uuid4()

    with pytest.raises(ValidationError) as exc_info:
        CommandEnvelope(
            agent_id=agent_id,
            action=ResponseActionEnum.RESTORE_HOST,
            parameters={"flush_rules": True},
            sequence=1,
            issued_at=now,
            expires_at=now - timedelta(seconds=10),  # Inverted!
            signature="a" * 64,
        )
    assert "expires_at must be strictly greater than issued_at" in str(exc_info.value)


def test_graph_node_and_edge_validation():
    """Verify validation of entities and relationships for NetworkX correlation."""
    node = GraphNode(
        id="host:srv-linux-01",
        type=EntityTypeEnum.HOST,
        label="srv-linux-01",
        properties={"os": "ubuntu"},
    )
    assert node.type == EntityTypeEnum.HOST

    edge = GraphEdge(
        source="user:root",
        target="host:srv-linux-01",
        relation=RelationTypeEnum.AUTHENTICATED_TO,
        weight=2.5,
    )
    assert edge.relation == RelationTypeEnum.AUTHENTICATED_TO
    assert edge.weight == 2.5


def test_response_state_enum_invariants():
    """Verify permitted response states for closed-loop containment."""
    permitted_states = {s.value for s in ResponseStateEnum}
    assert "REQUESTED" in permitted_states
    assert "QUEUED" in permitted_states
    assert "EXECUTED" in permitted_states
    assert "VERIFYING" in permitted_states
    assert "VERIFIED_CONTAINED" in permitted_states
    assert "VERIFICATION_INCONCLUSIVE" in permitted_states


def test_audit_ledger_record_validation():
    """Verify schema and hash pattern for audit ledger records."""
    now = datetime.now(timezone.utc)
    rec = AuditLedgerRecord(
        sequence_number=1,
        record_id=uuid.uuid4(),
        timestamp=now,
        actor_id="analyst_alice",
        actor_role="ANALYST",
        action="APPROVE_RESPONSE_ACTION",
        target_entity="Incident:42",
        canonical_payload='{"action":"BLOCK_IP","target":"198.51.100.42"}',
        previous_hash="0" * 64,
        current_hash="f" * 64,
    )
    assert rec.sequence_number == 1
    assert rec.previous_hash == "0" * 64

    # Invalid hash format must fail regex check
    with pytest.raises(ValidationError):
        AuditLedgerRecord(
            sequence_number=2,
            record_id=uuid.uuid4(),
            timestamp=now,
            actor_id="analyst_alice",
            action="APPROVE",
            target_entity="Incident:42",
            canonical_payload="{}",
            previous_hash="not-a-valid-sha256",
            current_hash="f" * 64,
        )
