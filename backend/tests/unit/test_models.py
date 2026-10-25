"""Unit tests for SQLAlchemy ORM models."""

import uuid
from datetime import datetime, timezone
from waliya.db.models import (
    AgentModel,
    EventModel,
    RuleModel,
    IncidentModel,
    FindingModel,
    ThreatIndicatorModel,
    PlaybookModel,
    PlaybookRunModel,
    ResponseActionModel,
    AuditLedgerModel,
)
from waliya.db.session import Base


def test_table_registry():
    """Verify all 10 core tables are mapped in metadata."""
    tables = Base.metadata.tables.keys()
    expected_tables = {
        "agents",
        "events",
        "rules",
        "findings",
        "incidents",
        "threat_indicators",
        "playbooks",
        "playbook_runs",
        "response_actions",
        "audit_ledger",
    }
    assert expected_tables.issubset(tables)


def test_instantiate_agent_model():
    """Verify AgentModel column instantiation."""
    agent = AgentModel(
        id=uuid.uuid4(),
        hostname="linux-sensor-01",
        os_family="linux",
        os_version="Ubuntu 26.04",
        primary_ip="192.168.1.10",
        mac_address="00:11:22:33:44:55",
        agent_version="2.0.0",
        status="ONLINE",
        api_token_hash="hash_value_123",
        secret_key_enc="encrypted_secret_data",
    )
    assert agent.hostname == "linux-sensor-01"
    assert agent.status == "ONLINE"


def test_instantiate_audit_ledger_model():
    """Verify AuditLedgerModel column instantiation."""
    now = datetime.now(timezone.utc)
    entry = AuditLedgerModel(
        sequence_number=1,
        id=uuid.uuid4(),
        timestamp=now,
        actor_id="analyst_1",
        actor_role="ANALYST",
        action="UPDATE_RULE",
        target_entity="Rule:RULE-FIM-004",
        canonical_payload="{}",
        previous_hash="0" * 64,
        current_hash="1" * 64,
    )
    assert entry.sequence_number == 1
    assert entry.action == "UPDATE_RULE"
