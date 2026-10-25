"""0006_soar_approvals

Revision ID: 0006_soar_approvals
Revises: 0005_incident_number_sequence
Create Date: 2026-10-22 18:42:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0006_soar_approvals"
down_revision: Union[str, None] = "0005_incident_number_sequence"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("response_actions", sa.Column("requested_by", sa.String(128), nullable=True))
    op.add_column("response_actions", sa.Column("approved_by", sa.String(128), nullable=True))
    op.add_column("response_actions", sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("response_actions", sa.Column("approval_reason", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("response_actions", "approval_reason")
    op.drop_column("response_actions", "approved_at")
    op.drop_column("response_actions", "approved_by")
    op.drop_column("response_actions", "requested_by")
