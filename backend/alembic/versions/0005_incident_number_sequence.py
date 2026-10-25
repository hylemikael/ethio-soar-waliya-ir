"""0005_incident_number_sequence

Revision ID: 0005_incident_number_sequence
Revises: 0004_incident_enrichment
Create Date: 2026-10-22 18:28:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0005_incident_number_sequence"
down_revision: Union[str, None] = "0004_incident_enrichment"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create the sequence for incident_number
    op.execute(sa.schema.CreateSequence(sa.Sequence("incidents_incident_number_seq")))
    # Set the server default of incident_number to nextval of the sequence
    op.alter_column(
        "incidents",
        "incident_number",
        server_default=sa.text("nextval('incidents_incident_number_seq')"),
    )


def downgrade() -> None:
    op.alter_column(
        "incidents",
        "incident_number",
        server_default=None,
    )
    op.execute(sa.schema.DropSequence(sa.Sequence("incidents_incident_number_seq")))
