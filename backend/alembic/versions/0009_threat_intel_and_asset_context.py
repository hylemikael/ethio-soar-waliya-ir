"""0009_threat_intel_and_asset_context

Revision ID: 0009_threat_intel_and_asset_context
Revises: 0008_simulation_isolation
Create Date: 2026-10-23 08:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0009_threat_intel_asset_ctx"
down_revision: Union[str, None] = "0008_simulation_isolation"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Update threat_indicators table
    # Drop previous single-value unique constraint and unique index
    try:
        op.drop_constraint("threat_indicators_value_key", "threat_indicators", type_="unique")
    except Exception:
        pass

    try:
        op.drop_index("ix_threat_indicators_value", table_name="threat_indicators")
    except Exception:
        pass

    # Add new columns to threat_indicators
    op.add_column("threat_indicators", sa.Column("source_id", sa.String(length=128), nullable=True))
    op.add_column("threat_indicators", sa.Column("severity", sa.String(length=32), nullable=False, server_default="MEDIUM"))
    op.add_column("threat_indicators", sa.Column("threat_category", sa.String(length=64), nullable=True))
    op.add_column("threat_indicators", sa.Column("tags", sa.JSON(), nullable=False, server_default="[]"))
    op.add_column("threat_indicators", sa.Column("description", sa.Text(), nullable=True))
    op.add_column("threat_indicators", sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True))
    op.add_column("threat_indicators", sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True))
    op.add_column("threat_indicators", sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")))
    op.add_column("threat_indicators", sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")))

    # Create composite unique constraint and search indexes
    op.create_unique_constraint(
        "uq_threat_indicators_type_value_source",
        "threat_indicators",
        ["indicator_type", "value", "source"],
    )
    op.create_index("ix_threat_indicators_value", "threat_indicators", ["value"], unique=False)
    op.create_index("ix_threat_indicators_source", "threat_indicators", ["source"], unique=False)
    op.create_index("ix_threat_indicators_confidence", "threat_indicators", ["confidence"], unique=False)
    op.create_index("ix_threat_indicators_threat_category", "threat_indicators", ["threat_category"], unique=False)
    op.create_index("ix_threat_indicators_expires_at", "threat_indicators", ["expires_at"], unique=False)
    op.create_index("ix_threat_indicators_is_active", "threat_indicators", ["is_active"], unique=False)

    # 2. Create asset_contexts table
    op.create_table(
        "asset_contexts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("agent_id", sa.Uuid(), nullable=False),
        sa.Column("criticality", sa.String(length=32), nullable=False, server_default="LOW"),
        sa.Column("environment", sa.String(length=64), nullable=True),
        sa.Column("asset_group", sa.String(length=128), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("owner", sa.String(length=128), nullable=True),
        sa.Column("business_unit", sa.String(length=128), nullable=True),
        sa.Column("network_zone", sa.String(length=128), nullable=True),
        sa.Column("tags", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_by", sa.String(length=128), nullable=True),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("agent_id"),
    )
    op.create_index("ix_asset_contexts_agent_id", "asset_contexts", ["agent_id"], unique=True)
    op.create_index("ix_asset_contexts_criticality", "asset_contexts", ["criticality"], unique=False)
    op.create_index("ix_asset_contexts_environment", "asset_contexts", ["environment"], unique=False)


def downgrade() -> None:
    # 1. Drop asset_contexts table
    op.drop_index("ix_asset_contexts_environment", table_name="asset_contexts")
    op.drop_index("ix_asset_contexts_criticality", table_name="asset_contexts")
    op.drop_index("ix_asset_contexts_agent_id", table_name="asset_contexts")
    op.drop_table("asset_contexts")

    # 2. Revert threat_indicators table
    op.drop_index("ix_threat_indicators_is_active", table_name="threat_indicators")
    op.drop_index("ix_threat_indicators_expires_at", table_name="threat_indicators")
    op.drop_index("ix_threat_indicators_threat_category", table_name="threat_indicators")
    op.drop_index("ix_threat_indicators_confidence", table_name="threat_indicators")
    op.drop_index("ix_threat_indicators_source", table_name="threat_indicators")
    op.drop_index("ix_threat_indicators_value", table_name="threat_indicators")
    op.drop_constraint("uq_threat_indicators_type_value_source", "threat_indicators", type_="unique")

    op.drop_column("threat_indicators", "updated_at")
    op.drop_column("threat_indicators", "is_active")
    op.drop_column("threat_indicators", "last_seen")
    op.drop_column("threat_indicators", "first_seen")
    op.drop_column("threat_indicators", "description")
    op.drop_column("threat_indicators", "tags")
    op.drop_column("threat_indicators", "threat_category")
    op.drop_column("threat_indicators", "severity")
    op.drop_column("threat_indicators", "source_id")

    op.create_unique_constraint("threat_indicators_value_key", "threat_indicators", ["value"])
    op.create_index("ix_threat_indicators_value", "threat_indicators", ["value"], unique=True)
