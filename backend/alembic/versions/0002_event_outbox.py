"""0002_event_outbox

Revision ID: 0002_event_outbox
Revises: 0001_initial_schema
Create Date: 2026-10-22 17:15:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0002_event_outbox"
down_revision: Union[str, None] = "0001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "event_outbox",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column("stream_name", sa.String(length=128), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("retry_count", sa.Integer(), nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("stream_message_id", sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(["event_id"], ["events.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_event_outbox_event_id"), "event_outbox", ["event_id"], unique=False)
    op.create_index(op.f("ix_event_outbox_stream_name"), "event_outbox", ["stream_name"], unique=False)
    op.create_index(op.f("ix_event_outbox_status"), "event_outbox", ["status"], unique=False)
    op.create_index(op.f("ix_event_outbox_created_at"), "event_outbox", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_table("event_outbox")
