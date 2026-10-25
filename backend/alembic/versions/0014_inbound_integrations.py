"""0014_inbound_integrations

Revision ID: 0014_inbound_integrations
Revises: 0013_outbound_notifications
Create Date: 2026-10-25 15:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "0014_inbound_integrations"
down_revision: Union[str, None] = "0013_outbound_notifications"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    tables = inspector.get_table_names()

    # 1. Create inbound_sources table
    if "inbound_sources" not in tables:
        op.create_table(
            "inbound_sources",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column("source_id", sa.String(64), unique=True, index=True, nullable=False),
            sa.Column("name", sa.String(128), nullable=False),
            sa.Column("provider_type", sa.String(32), default="GENERIC", nullable=False),
            sa.Column("is_enabled", sa.Boolean(), default=True, index=True, nullable=False),
            sa.Column("auth_type", sa.String(32), default="HMAC_SHA256", nullable=False),
            sa.Column("shared_secret_enc", sa.String(512), nullable=False),
            sa.Column("permitted_event_types", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
            sa.Column("total_events_received", sa.Integer(), default=0, nullable=False),
            sa.Column("total_events_accepted", sa.Integer(), default=0, nullable=False),
            sa.Column("total_events_rejected", sa.Integer(), default=0, nullable=False),
            sa.Column("total_events_deduplicated", sa.Integer(), default=0, nullable=False),
            sa.Column("last_received_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_error_message", sa.Text(), nullable=True),
            sa.Column("created_by", sa.String(128), default="admin", nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        )

    # 2. Create inbound_event_dedup table
    if "inbound_event_dedup" not in tables:
        op.create_table(
            "inbound_event_dedup",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column(
                "source_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("inbound_sources.id", ondelete="CASCADE"),
                index=True,
                nullable=False,
            ),
            sa.Column("external_event_id", sa.String(128), index=True, nullable=False),
            sa.Column(
                "internal_event_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("events.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("status", sa.String(32), default="ACCEPTED", nullable=False),
            sa.Column("received_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.UniqueConstraint("source_id", "external_event_id", name="uq_inbound_source_external_event"),
        )


def downgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    tables = inspector.get_table_names()

    if "inbound_event_dedup" in tables:
        op.drop_table("inbound_event_dedup")
    if "inbound_sources" in tables:
        op.drop_table("inbound_sources")
