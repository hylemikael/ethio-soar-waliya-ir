"""0007_simulation_runs

Revision ID: 0007_simulation_runs
Revises: 0006_soar_approvals
Create Date: 2026-10-23 07:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0007_simulation_runs"
down_revision: Union[str, None] = "0006_soar_approvals"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    json_col_type = postgresql.JSONB(astext_type=sa.Text()).with_variant(sa.JSON(), "sqlite")

    op.create_table(
        "simulation_runs",
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("trace_id", sa.String(length=64), nullable=False),
        sa.Column("scenario_id", sa.String(length=64), nullable=False),
        sa.Column("scenario_name", sa.String(length=128), nullable=False),
        sa.Column("mitre_attack_ids", json_col_type, nullable=False, server_default="[]"),
        sa.Column("target_rule_id", sa.String(length=64), nullable=False),
        sa.Column("is_negative_test", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="REGISTERED"),
        sa.Column("start_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("end_time", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_seconds", sa.Float(), nullable=True),
        sa.Column("events_submitted_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("events_accepted_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("expected_detection", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("observed_detection", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("matching_finding_ids", json_col_type, nullable=False, server_default="[]"),
        sa.Column("matching_incident_ids", json_col_type, nullable=False, server_default="[]"),
        sa.Column("latency_seconds", sa.Float(), nullable=True),
        sa.Column("latency_notes", sa.String(length=255), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("error_detail", sa.Text(), nullable=True),
        sa.Column("is_simulation", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("run_id"),
    )
    op.create_index(op.f("ix_simulation_runs_trace_id"), "simulation_runs", ["trace_id"], unique=False)
    op.create_index(op.f("ix_simulation_runs_scenario_id"), "simulation_runs", ["scenario_id"], unique=False)
    op.create_index(op.f("ix_simulation_runs_target_rule_id"), "simulation_runs", ["target_rule_id"], unique=False)
    op.create_index(op.f("ix_simulation_runs_status"), "simulation_runs", ["status"], unique=False)
    op.create_index(op.f("ix_simulation_runs_created_at"), "simulation_runs", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_simulation_runs_created_at"), table_name="simulation_runs")
    op.drop_index(op.f("ix_simulation_runs_status"), table_name="simulation_runs")
    op.drop_index(op.f("ix_simulation_runs_target_rule_id"), table_name="simulation_runs")
    op.drop_index(op.f("ix_simulation_runs_scenario_id"), table_name="simulation_runs")
    op.drop_index(op.f("ix_simulation_runs_trace_id"), table_name="simulation_runs")
    op.drop_table("simulation_runs")
