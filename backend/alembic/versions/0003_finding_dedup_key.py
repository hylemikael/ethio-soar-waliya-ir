"""0003_finding_dedup_key

Revision ID: 0003_finding_dedup_key
Revises: 0002_event_outbox
Create Date: 2026-10-22 17:35:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0003_finding_dedup_key"
down_revision: Union[str, None] = "0002_event_outbox"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("dedup_key", sa.String(length=255), nullable=True))
    op.create_index(op.f("ix_findings_dedup_key"), "findings", ["dedup_key"], unique=False)
    op.create_unique_constraint("uq_findings_event_dedup", "findings", ["event_id", "dedup_key"])


def downgrade() -> None:
    op.drop_constraint("uq_findings_event_dedup", "findings", type_="unique")
    op.drop_index(op.f("ix_findings_dedup_key"), table_name="findings")
    op.drop_column("findings", "dedup_key")
