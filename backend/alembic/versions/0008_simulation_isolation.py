"""0008_simulation_isolation

Revision ID: 0008_simulation_isolation
Revises: 0007_simulation_runs
Create Date: 2026-10-23 07:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0008_simulation_isolation"
down_revision: Union[str, None] = "0007_simulation_runs"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add columns to findings
    op.add_column(
        "findings",
        sa.Column("is_simulation", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.add_column(
        "findings",
        sa.Column("simulation_run_id", sa.String(length=64), nullable=True),
    )
    op.create_index("ix_findings_is_simulation", "findings", ["is_simulation"])
    op.create_index("ix_findings_simulation_run_id", "findings", ["simulation_run_id"])

    # 2. Add columns to incidents
    op.add_column(
        "incidents",
        sa.Column("is_simulation", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.add_column(
        "incidents",
        sa.Column("simulation_run_id", sa.String(length=64), nullable=True),
    )
    op.create_index("ix_incidents_is_simulation", "incidents", ["is_simulation"])
    op.create_index("ix_incidents_simulation_run_id", "incidents", ["simulation_run_id"])

    # 3. Backfill simulation flag for existing incidents
    op.execute(
        sa.text("UPDATE incidents SET is_simulation = true WHERE title LIKE '[SIMULATION]%'")
    )


def downgrade() -> None:
    op.drop_index("ix_incidents_simulation_run_id", table_name="incidents")
    op.drop_index("ix_incidents_is_simulation", table_name="incidents")
    op.drop_column("incidents", "simulation_run_id")
    op.drop_column("incidents", "is_simulation")

    op.drop_index("ix_findings_simulation_run_id", table_name="findings")
    op.drop_index("ix_findings_is_simulation", table_name="findings")
    op.drop_column("findings", "simulation_run_id")
    op.drop_column("findings", "is_simulation")
