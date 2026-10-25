"""0015_performance_indexes

Revision ID: 0015_performance_indexes
Revises: 0014_inbound_integrations
Create Date: 2026-10-25 17:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0015_performance_indexes"
down_revision: Union[str, None] = "0014_inbound_integrations"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    # 1. Composite index for incident findings ordered by timestamp (Incident Reconstruction & Forensic Timeline)
    findings_indexes = {idx["name"] for idx in inspector.get_indexes("findings")}
    if "ix_findings_incident_timestamp" not in findings_indexes:
        op.create_index(
            "ix_findings_incident_timestamp",
            "findings",
            ["incident_id", "timestamp"],
            unique=False,
        )

    # 2. Composite index for alert suppression window lookups (RuleEngine.is_suppressed)
    if "ix_findings_dedup_key_timestamp" not in findings_indexes:
        op.create_index(
            "ix_findings_dedup_key_timestamp",
            "findings",
            ["dedup_key", "timestamp"],
            unique=False,
        )

    # 3. Composite index for active incident correlation window lookups (IncidentCorrelationService)
    incidents_indexes = {idx["name"] for idx in inspector.get_indexes("incidents")}
    if "ix_incidents_status_last_seen" not in incidents_indexes:
        op.create_index(
            "ix_incidents_status_last_seen",
            "incidents",
            ["status", "last_seen"],
            unique=False,
        )

    # 4. Composite index for transactional outbox polling (OutboxPublisher)
    outbox_indexes = {idx["name"] for idx in inspector.get_indexes("event_outbox")}
    if "ix_event_outbox_status_created_at" not in outbox_indexes:
        op.create_index(
            "ix_event_outbox_status_created_at",
            "event_outbox",
            ["status", "created_at"],
            unique=False,
        )

    # 5. Composite index for outbound webhook delivery polling & backoff (NotificationDeliveryService)
    delivery_indexes = {idx["name"] for idx in inspector.get_indexes("notification_deliveries")}
    if "ix_notification_deliveries_status_next_attempt" not in delivery_indexes:
        op.create_index(
            "ix_notification_deliveries_status_next_attempt",
            "notification_deliveries",
            ["status", "next_attempt_at"],
            unique=False,
        )

    # 6. Composite index for threat intel observable matching against active indicators (ThreatIntelMatcher)
    ti_indexes = {idx["name"] for idx in inspector.get_indexes("threat_indicators")}
    if "ix_threat_indicators_type_val_active" not in ti_indexes:
        op.create_index(
            "ix_threat_indicators_type_val_active",
            "threat_indicators",
            ["indicator_type", "value", "is_active"],
            unique=False,
        )


def downgrade() -> None:
    op.drop_index("ix_threat_indicators_type_val_active", table_name="threat_indicators")
    op.drop_index("ix_notification_deliveries_status_next_attempt", table_name="notification_deliveries")
    op.drop_index("ix_event_outbox_status_created_at", table_name="event_outbox")
    op.drop_index("ix_incidents_status_last_seen", table_name="incidents")
    op.drop_index("ix_findings_dedup_key_timestamp", table_name="findings")
    op.drop_index("ix_findings_incident_timestamp", table_name="findings")
