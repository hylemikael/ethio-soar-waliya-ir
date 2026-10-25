"""0010_threat_intel_feeds_and_sync_runs

Revision ID: 0010_ti_feeds_sync_runs
Revises: 0009_threat_intel_asset_ctx
Create Date: 2026-10-23 13:30:00.000000

"""
from typing import Sequence, Union
import uuid

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0010_ti_feeds_sync_runs"
down_revision: Union[str, None] = "0009_threat_intel_asset_ctx"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create threat_intel_feeds table
    op.create_table(
        "threat_intel_feeds",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column("feed_id", sa.String(length=64), unique=True, nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_enabled", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("refresh_interval_minutes", sa.Integer(), server_default="60", nullable=False),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_successful_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(length=32), server_default="NEVER_RUN", nullable=False),
        sa.Column("last_error_summary", sa.Text(), nullable=True),
        sa.Column("config_options", sa.JSON(), server_default="{}", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_threat_intel_feeds_feed_id", "threat_intel_feeds", ["feed_id"])
    op.create_index("ix_threat_intel_feeds_is_enabled", "threat_intel_feeds", ["is_enabled"])

    # 2. Create threat_intel_sync_runs table
    op.create_table(
        "threat_intel_sync_runs",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column("feed_id", sa.String(length=64), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(length=32), server_default="RUNNING", nullable=False),
        sa.Column("is_dry_run", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("fetched_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("normalized_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("inserted_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("updated_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("skipped_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("rejected_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("deactivated_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("error_summary", sa.Text(), nullable=True),
        sa.Column("diagnostics", sa.JSON(), server_default="{}", nullable=False),
        sa.Column("triggered_by", sa.String(length=128), server_default="cli:manual", nullable=False),
    )
    op.create_index("ix_threat_intel_sync_runs_feed_id", "threat_intel_sync_runs", ["feed_id"])
    op.create_index("ix_threat_intel_sync_runs_started_at", "threat_intel_sync_runs", ["started_at"])
    op.create_index("ix_threat_intel_sync_runs_status", "threat_intel_sync_runs", ["status"])

    # 3. Seed initial feed configurations
    feeds_table = sa.table(
        "threat_intel_feeds",
        sa.column("id", sa.UUID()),
        sa.column("feed_id", sa.String()),
        sa.column("provider", sa.String()),
        sa.column("name", sa.String()),
        sa.column("description", sa.Text()),
        sa.column("is_enabled", sa.Boolean()),
        sa.column("refresh_interval_minutes", sa.Integer()),
        sa.column("last_status", sa.String()),
        sa.column("config_options", sa.JSON()),
    )

    op.bulk_insert(
        feeds_table,
        [
            {
                "id": uuid.uuid4(),
                "feed_id": "threatfox",
                "provider": "ThreatFox",
                "name": "ThreatFox Community IOCs",
                "description": "abuse.ch ThreatFox community threat indicators and C2/malware family tracking",
                "is_enabled": False,
                "refresh_interval_minutes": 60,
                "last_status": "NEVER_RUN",
                "config_options": {"days": 1, "max_records": 1000},
            },
            {
                "id": uuid.uuid4(),
                "feed_id": "urlhaus",
                "provider": "URLhaus",
                "name": "URLhaus Recent Malware URLs",
                "description": "abuse.ch URLhaus recent malicious URLs and payload delivery tracking",
                "is_enabled": False,
                "refresh_interval_minutes": 60,
                "last_status": "NEVER_RUN",
                "config_options": {"max_records": 1000},
            },
        ],
    )


def downgrade() -> None:
    op.drop_index("ix_threat_intel_sync_runs_status", table_name="threat_intel_sync_runs")
    op.drop_index("ix_threat_intel_sync_runs_started_at", table_name="threat_intel_sync_runs")
    op.drop_index("ix_threat_intel_sync_runs_feed_id", table_name="threat_intel_sync_runs")
    op.drop_table("threat_intel_sync_runs")

    op.drop_index("ix_threat_intel_feeds_is_enabled", table_name="threat_intel_feeds")
    op.drop_index("ix_threat_intel_feeds_feed_id", table_name="threat_intel_feeds")
    op.drop_table("threat_intel_feeds")
