"""0013_outbound_notifications

Revision ID: 0013_outbound_notifications
Revises: 0012_response_plan_governance
Create Date: 2026-10-25 14:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "0013_outbound_notifications"
down_revision: Union[str, None] = "0012_response_plan_governance"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    tables = inspector.get_table_names()

    # 1. Create notification_destinations table
    if "notification_destinations" not in tables:
        op.create_table(
            "notification_destinations",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column("name", sa.String(128), nullable=False),
            sa.Column("destination_url", sa.String(512), nullable=False),
            sa.Column("is_enabled", sa.Boolean(), default=True, index=True, nullable=False),
            sa.Column("subscribed_events", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column("signing_secret_enc", sa.String(512), nullable=True),
            sa.Column("created_by", sa.String(128), default="admin", nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("last_delivery_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_delivery_status", sa.String(32), nullable=True),
            sa.Column("last_delivery_error", sa.Text(), nullable=True),
        )

    # 2. Create notification_deliveries table
    if "notification_deliveries" not in tables:
        op.create_table(
            "notification_deliveries",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column(
                "destination_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("notification_destinations.id", ondelete="CASCADE"),
                index=True,
                nullable=False,
            ),
            sa.Column("delivery_id", postgresql.UUID(as_uuid=True), unique=True, index=True, nullable=False),
            sa.Column("event_type", sa.String(64), index=True, nullable=False),
            sa.Column("event_id", sa.String(128), index=True, nullable=False),
            sa.Column("status", sa.String(32), default="PENDING", index=True, nullable=False),
            sa.Column("attempt_count", sa.Integer(), default=0, nullable=False),
            sa.Column("max_attempts", sa.Integer(), default=5, nullable=False),
            sa.Column("next_attempt_at", sa.DateTime(timezone=True), index=True, nullable=True),
            sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column("response_status_code", sa.Integer(), nullable=True),
            sa.Column("response_time_ms", sa.Integer(), nullable=True),
            sa.Column("error_message", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), index=True, nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        )


def downgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    tables = inspector.get_table_names()

    if "notification_deliveries" in tables:
        op.drop_table("notification_deliveries")
    if "notification_destinations" in tables:
        op.drop_table("notification_destinations")
