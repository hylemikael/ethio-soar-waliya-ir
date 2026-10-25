"""0012_response_plan_governance

Revision ID: 0012_response_plan_governance
Revises: 0011_ti_lifecycle_decay
Create Date: 2026-10-24 21:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "0012_response_plan_governance"
down_revision: Union[str, None] = "0011_ti_lifecycle_decay"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    tables = inspector.get_table_names()

    # 1. Create response_plans table
    op.execute(sa.text("CREATE SEQUENCE IF NOT EXISTS response_plans_plan_number_seq"))
    if "response_plans" not in tables:
        op.create_table(
            "response_plans",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column("plan_number", sa.BigInteger(), server_default=sa.text("nextval('response_plans_plan_number_seq')"), nullable=False),
            sa.Column("title", sa.String(255), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("incident_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("incidents.id", ondelete="CASCADE"), index=True, nullable=False),
            sa.Column("status", sa.String(32), default="DRAFT", index=True, nullable=False),
            sa.Column("risk_level", sa.String(32), default="CONTAINMENT", nullable=False),
            sa.Column("requires_approval", sa.Boolean(), default=True, nullable=False),
            sa.Column("actions", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column("approval_hash", sa.String(64), nullable=True),
            sa.Column("dry_run", sa.Boolean(), default=True, nullable=False),
            sa.Column("is_simulation", sa.Boolean(), default=False, index=True, nullable=False),
            sa.Column("simulation_run_id", sa.String(64), index=True, nullable=True),
            sa.Column("created_by", sa.String(128), nullable=False),
            sa.Column("approved_by", sa.String(128), nullable=True),
            sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("approval_reason", sa.Text(), nullable=True),
            sa.Column("rejected_by", sa.String(128), nullable=True),
            sa.Column("rejection_reason", sa.Text(), nullable=True),
            sa.Column("cancelled_by", sa.String(128), nullable=True),
            sa.Column("cancellation_reason", sa.Text(), nullable=True),
            sa.Column("idempotency_key", sa.String(64), index=True, nullable=True),
            sa.Column("execution_summary", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        )
        op.create_index("ix_response_plans_incident_status", "response_plans", ["incident_id", "status"])

    # 2. Add response_plan_id to response_actions
    act_cols = [c["name"] for c in inspector.get_columns("response_actions")]
    if "response_plan_id" not in act_cols:
        op.add_column(
            "response_actions",
            sa.Column("response_plan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("response_plans.id", ondelete="SET NULL"), index=True, nullable=True),
        )


def downgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    tables = inspector.get_table_names()

    act_cols = [c["name"] for c in inspector.get_columns("response_actions")]
    if "response_plan_id" in act_cols:
        op.drop_column("response_actions", "response_plan_id")

    if "response_plans" in tables:
        op.drop_index("ix_response_plans_incident_status", table_name="response_plans")
        op.drop_table("response_plans")
