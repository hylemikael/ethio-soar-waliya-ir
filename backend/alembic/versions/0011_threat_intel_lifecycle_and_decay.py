"""0011_threat_intel_lifecycle_and_decay

Revision ID: 0011_ti_lifecycle_decay
Revises: 0010_ti_feeds_sync_runs
Create Date: 2026-10-24 16:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0011_ti_lifecycle_decay"
down_revision: Union[str, None] = "0010_ti_feeds_sync_runs"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Safely add last_decayed_at column to threat_indicators if not present
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    columns = [c["name"] for c in inspector.get_columns("threat_indicators")]

    if "last_decayed_at" not in columns:
        op.add_column(
            "threat_indicators",
            sa.Column("last_decayed_at", sa.DateTime(timezone=True), nullable=True),
        )

    # Add index on (is_active, last_decayed_at)
    existing_indexes = [idx["name"] for idx in inspector.get_indexes("threat_indicators")]
    if "ix_threat_indicators_active_decayed" not in existing_indexes:
        op.create_index(
            "ix_threat_indicators_active_decayed",
            "threat_indicators",
            ["is_active", "last_decayed_at"],
        )


def downgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_indexes = [idx["name"] for idx in inspector.get_indexes("threat_indicators")]
    if "ix_threat_indicators_active_decayed" in existing_indexes:
        op.drop_index("ix_threat_indicators_active_decayed", table_name="threat_indicators")

    columns = [c["name"] for c in inspector.get_columns("threat_indicators")]
    if "last_decayed_at" in columns:
        op.drop_column("threat_indicators", "last_decayed_at")
