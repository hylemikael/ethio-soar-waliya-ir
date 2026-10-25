"""0004_incident_enrichment

Revision ID: 0004_incident_enrichment
Revises: 0003_finding_dedup_key
Create Date: 2026-10-22 18:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0004_incident_enrichment"
down_revision: Union[str, None] = "0003_finding_dedup_key"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("incidents", sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True))
    op.add_column("incidents", sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True))
    op.add_column("incidents", sa.Column("affected_entities", sa.JSON(), server_default='[]', nullable=False))
    op.add_column("incidents", sa.Column("mitre_attack_ids", sa.JSON(), server_default='[]', nullable=False))
    op.add_column("incidents", sa.Column("risk_explanation", sa.JSON(), nullable=True))
    op.add_column("incidents", sa.Column("update_history", sa.JSON(), server_default='[]', nullable=False))

    op.create_index(op.f("ix_incidents_first_seen"), "incidents", ["first_seen"], unique=False)
    op.create_index(op.f("ix_incidents_last_seen"), "incidents", ["last_seen"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_incidents_last_seen"), table_name="incidents")
    op.drop_index(op.f("ix_incidents_first_seen"), table_name="incidents")
    op.drop_column("incidents", "update_history")
    op.drop_column("incidents", "risk_explanation")
    op.drop_column("incidents", "mitre_attack_ids")
    op.drop_column("incidents", "affected_entities")
    op.drop_column("incidents", "last_seen")
    op.drop_column("incidents", "first_seen")
