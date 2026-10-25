"""0001_initial_schema

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-10-22 14:55:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. agents table
    op.create_table(
        "agents",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("os_family", sa.String(length=64), nullable=False),
        sa.Column("os_version", sa.String(length=128), nullable=False),
        sa.Column("primary_ip", sa.String(length=45), nullable=False),
        sa.Column("mac_address", sa.String(length=32), nullable=False),
        sa.Column("agent_version", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("api_token_hash", sa.String(length=128), nullable=False),
        sa.Column("secret_key_enc", sa.Text(), nullable=False),
        sa.Column("last_heartbeat", sa.DateTime(timezone=True), nullable=False),
        sa.Column("registered_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("api_token_hash"),
    )
    op.create_index(op.f("ix_agents_hostname"), "agents", ["hostname"], unique=False)
    op.create_index(op.f("ix_agents_status"), "agents", ["status"], unique=False)
    op.create_index(op.f("ix_agents_last_heartbeat"), "agents", ["last_heartbeat"], unique=False)

    # 2. events table
    op.create_table(
        "events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("agent_id", sa.Uuid(), nullable=True),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", sa.String(length=128), nullable=False),
        sa.Column("raw_payload", sa.JSON(), nullable=False),
        sa.Column("normalized_payload", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_events_agent_id"), "events", ["agent_id"], unique=False)
    op.create_index(op.f("ix_events_event_type"), "events", ["event_type"], unique=False)
    op.create_index(op.f("ix_events_severity"), "events", ["severity"], unique=False)
    op.create_index(op.f("ix_events_timestamp"), "events", ["timestamp"], unique=False)

    # 3. rules table
    op.create_table(
        "rules",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("conditions", sa.JSON(), nullable=False),
        sa.Column("mitre_attack_ids", sa.JSON(), nullable=False),
        sa.Column("dedup_window_seconds", sa.Integer(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("rule_id"),
    )
    op.create_index(op.f("ix_rules_rule_id"), "rules", ["rule_id"], unique=True)
    op.create_index(op.f("ix_rules_event_type"), "rules", ["event_type"], unique=False)
    op.create_index(op.f("ix_rules_is_active"), "rules", ["is_active"], unique=False)

    # 4. incidents table
    op.create_table(
        "incidents",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("incident_number", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("composite_risk_score", sa.Float(), nullable=False),
        sa.Column("assigned_to", sa.String(length=128), nullable=True),
        sa.Column("entity_graph_snapshot", sa.JSON(), nullable=True),
        sa.Column("evidence_manifest_hash", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("incident_number"),
    )
    op.create_index(op.f("ix_incidents_incident_number"), "incidents", ["incident_number"], unique=True)
    op.create_index(op.f("ix_incidents_severity"), "incidents", ["severity"], unique=False)
    op.create_index(op.f("ix_incidents_status"), "incidents", ["status"], unique=False)
    op.create_index(op.f("ix_incidents_created_at"), "incidents", ["created_at"], unique=False)

    # 5. findings table
    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("rule_id", sa.Uuid(), nullable=True),
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column("agent_id", sa.Uuid(), nullable=True),
        sa.Column("incident_id", sa.Uuid(), nullable=True),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("explanation", sa.JSON(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["event_id"], ["events.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["rule_id"], ["rules.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_findings_incident_id"), "findings", ["incident_id"], unique=False)
    op.create_index(op.f("ix_findings_severity"), "findings", ["severity"], unique=False)
    op.create_index(op.f("ix_findings_timestamp"), "findings", ["timestamp"], unique=False)

    # 6. threat_indicators table
    op.create_table(
        "threat_indicators",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("indicator_type", sa.String(length=32), nullable=False),
        sa.Column("value", sa.String(length=512), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("source", sa.String(length=128), nullable=False),
        sa.Column("threat_actor", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("value"),
    )
    op.create_index(op.f("ix_threat_indicators_indicator_type"), "threat_indicators", ["indicator_type"], unique=False)
    op.create_index(op.f("ix_threat_indicators_value"), "threat_indicators", ["value"], unique=True)

    # 7. playbooks table
    op.create_table(
        "playbooks",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("trigger_conditions", sa.JSON(), nullable=False),
        sa.Column("action_steps", sa.JSON(), nullable=False),
        sa.Column("requires_approval", sa.Boolean(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_index(op.f("ix_playbooks_is_active"), "playbooks", ["is_active"], unique=False)

    # 8. playbook_runs table
    op.create_table(
        "playbook_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("playbook_id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("dry_run", sa.Boolean(), nullable=False),
        sa.Column("executed_by", sa.String(length=128), nullable=False),
        sa.Column("start_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("end_time", sa.DateTime(timezone=True), nullable=True),
        sa.Column("output_summary", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["playbook_id"], ["playbooks.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_playbook_runs_status"), "playbook_runs", ["status"], unique=False)

    # 9. response_actions table
    op.create_table(
        "response_actions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("command_id", sa.Uuid(), nullable=False),
        sa.Column("playbook_run_id", sa.Uuid(), nullable=True),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("agent_id", sa.Uuid(), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("parameters", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("nonce", sa.Uuid(), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("signature", sa.String(length=64), nullable=False),
        sa.Column("execution_receipt", sa.JSON(), nullable=True),
        sa.Column("verification_result", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["playbook_run_id"], ["playbook_runs.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("command_id"),
        sa.UniqueConstraint("nonce"),
    )
    op.create_index(op.f("ix_response_actions_command_id"), "response_actions", ["command_id"], unique=True)
    op.create_index(op.f("ix_response_actions_incident_id"), "response_actions", ["incident_id"], unique=False)
    op.create_index(op.f("ix_response_actions_agent_id"), "response_actions", ["agent_id"], unique=False)
    op.create_index(op.f("ix_response_actions_status"), "response_actions", ["status"], unique=False)

    # 10. audit_ledger table
    op.create_table(
        "audit_ledger",
        sa.Column("sequence_number", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_id", sa.String(length=128), nullable=False),
        sa.Column("actor_role", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("target_entity", sa.String(length=128), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("previous_hash", sa.String(length=64), nullable=False),
        sa.Column("current_hash", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("sequence_number"),
        sa.UniqueConstraint("id"),
        sa.UniqueConstraint("current_hash"),
    )
    op.create_index(op.f("ix_audit_ledger_id"), "audit_ledger", ["id"], unique=True)
    op.create_index(op.f("ix_audit_ledger_timestamp"), "audit_ledger", ["timestamp"], unique=False)
    op.create_index(op.f("ix_audit_ledger_actor_id"), "audit_ledger", ["actor_id"], unique=False)
    op.create_index(op.f("ix_audit_ledger_action"), "audit_ledger", ["action"], unique=False)
    op.create_index(op.f("ix_audit_ledger_previous_hash"), "audit_ledger", ["previous_hash"], unique=False)
    op.create_index(op.f("ix_audit_ledger_current_hash"), "audit_ledger", ["current_hash"], unique=True)


def downgrade() -> None:
    op.drop_table("audit_ledger")
    op.drop_table("response_actions")
    op.drop_table("playbook_runs")
    op.drop_table("playbooks")
    op.drop_table("threat_indicators")
    op.drop_table("findings")
    op.drop_table("incidents")
    op.drop_table("rules")
    op.drop_table("events")
    op.drop_table("agents")
