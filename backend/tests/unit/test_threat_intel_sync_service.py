"""Unit and integration tests for ThreatIntelSyncService."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch
from uuid import uuid4
import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from waliya.audit.ledger_service import AuditLedgerService
from waliya.db.models import FeedConfigurationModel, FeedSyncRunModel, ThreatIndicatorModel
from waliya.threat_intel.connectors.base import (
    BaseFeedConnector,
    FeedFetchError,
    FeedFetchResult,
    FeedRateLimitError,
    RawIndicatorRecord,
)
from waliya.threat_intel.sync_service import ThreatIntelSyncService


class MockConnector(BaseFeedConnector):
    feed_id = "threatfox"
    provider = "ThreatFox"
    allowed_hosts = {"threatfox-api.abuse.ch"}

    def __init__(self, records_to_return=None):
        super().__init__()
        self.records_to_return = records_to_return or []

    async def fetch_indicators(self, config_options, api_key=None):
        return FeedFetchResult(
            records=self.records_to_return,
            fetched_count=len(self.records_to_return),
            metadata={"query_status": "ok"},
            diagnostics={"provider": self.provider},
        )


@pytest.mark.asyncio
async def test_sync_disabled_feed_requires_force(db_session: AsyncSession):
    """Verify that disabled feeds reject sync unless --force is passed."""
    # Ensure threatfox is explicitly disabled with no last_sync_at for test
    query = select(FeedConfigurationModel).where(FeedConfigurationModel.feed_id == "threatfox")
    feed = (await db_session.execute(query)).scalar_one()
    feed.is_enabled = False
    feed.last_sync_at = None
    await db_session.commit()

    with pytest.raises(FeedFetchError, match="is disabled"):
        await ThreatIntelSyncService.sync_feed(
            session=db_session,
            feed_id="threatfox",
            is_dry_run=False,
            force=False,
            connector_override=MockConnector(),
        )


@pytest.mark.asyncio
async def test_sync_idempotency_and_no_duplicates(db_session: AsyncSession):
    """Verify that repeated synchronization updates existing records without duplicate collisions."""
    # Clean previous indicators for this test
    await db_session.execute(
        delete(ThreatIndicatorModel).where(
            ThreatIndicatorModel.source == "ThreatFox",
            ThreatIndicatorModel.value.in_(["198.51.100.77", "malicious-sample.example.com"]),
        )
    )

    # Enable threatfox for test
    query = select(FeedConfigurationModel).where(FeedConfigurationModel.feed_id == "threatfox")
    res = await db_session.execute(query)
    feed = res.scalar_one()
    feed.is_enabled = True
    feed.last_sync_at = None
    await db_session.commit()

    test_records = [
        RawIndicatorRecord(
            value="198.51.100.77",
            indicator_type="IPV4",
            source_id="mock-1",
            confidence=80,
            severity="HIGH",
            threat_category="botnet_cc",
            tags=["cobaltstrike"],
            description="First sync version",
        ),
        RawIndicatorRecord(
            value="malicious-sample.example.com",
            indicator_type="DOMAIN",
            source_id="mock-2",
            confidence=75,
            severity="MEDIUM",
            threat_category="payload_delivery",
            tags=["downloader"],
            description="Domain indicator",
        ),
    ]

    mock_conn = MockConnector(records_to_return=test_records)

    # 1. First sync -> Both should be INSERTED
    run1 = await ThreatIntelSyncService.sync_feed(
        session=db_session,
        feed_id="threatfox",
        is_dry_run=False,
        force=True,
        connector_override=mock_conn,
    )

    assert run1.status == "SUCCESS"
    assert run1.inserted_count == 2
    assert run1.updated_count == 0

    # 2. Update metadata in test records and sync again -> Both should be UPDATED
    test_records[0].confidence = 95
    test_records[0].description = "Updated confidence version"

    run2 = await ThreatIntelSyncService.sync_feed(
        session=db_session,
        feed_id="threatfox",
        is_dry_run=False,
        force=True,
        connector_override=mock_conn,
    )

    assert run2.status == "SUCCESS"
    assert run2.inserted_count == 0
    assert run2.updated_count == 2

    # Verify no duplicate rows in threat_indicators table
    count_q = select(func.count(ThreatIndicatorModel.id)).where(
        ThreatIndicatorModel.source == "ThreatFox",
        ThreatIndicatorModel.value == "198.51.100.77",
    )
    count_res = await db_session.execute(count_q)
    assert count_res.scalar() == 1

    # Verify updated fields
    ind_q = select(ThreatIndicatorModel).where(
        ThreatIndicatorModel.source == "ThreatFox",
        ThreatIndicatorModel.value == "198.51.100.77",
    )
    ind = (await db_session.execute(ind_q)).scalar_one()
    assert ind.confidence == 95
    assert ind.description == "Updated confidence version"


@pytest.mark.asyncio
async def test_multi_source_provenance_preservation(db_session: AsyncSession):
    """Verify that multiple sources (e.g. ThreatFox and URLhaus) can submit the same observable without collision."""
    shared_url = "https://shared-c2.example.org/download.bin"

    # 1. Ingest via ThreatFox
    tf_records = [
        RawIndicatorRecord(
            value=shared_url,
            indicator_type="URL",
            source_id="tf-999",
            confidence=85,
            severity="HIGH",
            threat_category="botnet_cc",
        )
    ]
    await ThreatIntelSyncService.sync_feed(
        session=db_session,
        feed_id="threatfox",
        is_dry_run=False,
        force=True,
        connector_override=MockConnector(records_to_return=tf_records),
    )

    # 2. Ingest via URLhaus
    class MockURLhausConnector(BaseFeedConnector):
        feed_id = "urlhaus"
        provider = "URLhaus"
        allowed_hosts = {"urlhaus-api.abuse.ch"}

        async def fetch_indicators(self, config_options, api_key=None):
            return FeedFetchResult(
                records=[
                    RawIndicatorRecord(
                        value=shared_url,
                        indicator_type="URL",
                        source_id="uh-888",
                        confidence=60,
                        confidence_is_policy_derived=True,
                        severity="MEDIUM",
                        threat_category="malware_download",
                    )
                ],
                fetched_count=1,
            )

    await ThreatIntelSyncService.sync_feed(
        session=db_session,
        feed_id="urlhaus",
        is_dry_run=False,
        force=True,
        connector_override=MockURLhausConnector(),
    )

    # Verify both records exist with distinct provenance and confidence
    q = select(ThreatIndicatorModel).where(ThreatIndicatorModel.value == shared_url)
    res = await db_session.execute(q)
    records = list(res.scalars().all())

    assert len(records) == 2
    sources = {r.source for r in records}
    assert sources == {"ThreatFox", "URLhaus"}


@pytest.mark.asyncio
async def test_dry_run_makes_no_database_changes(db_session: AsyncSession):
    """Verify that dry-run previews insert and update metrics without altering threat_indicators."""
    dry_test_ip = f"198.51.100.{(uuid4().int % 200) + 10}"
    await db_session.execute(delete(ThreatIndicatorModel).where(ThreatIndicatorModel.value == dry_test_ip))
    await db_session.flush()

    test_records = [
        RawIndicatorRecord(
            value=dry_test_ip,
            indicator_type="IPV4",
            source_id="dry-1",
            confidence=90,
        )
    ]

    run = await ThreatIntelSyncService.sync_feed(
        session=db_session,
        feed_id="threatfox",
        is_dry_run=True,
        force=True,
        connector_override=MockConnector(records_to_return=test_records),
    )

    assert run.status == "SUCCESS"
    assert run.is_dry_run is True
    assert run.inserted_count == 1

    # Verify observable was NOT actually committed to DB
    q = select(ThreatIndicatorModel).where(ThreatIndicatorModel.value == dry_test_ip)
    res = await db_session.execute(q)
    assert res.scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_all_invalid_records_reports_failed(db_session: AsyncSession):
    """Verify that if 100% of fetched records fail validation, sync reports FAILED, not SUCCESS."""
    malformed_records = [
        RawIndicatorRecord(value="not-an-ip-or-domain", indicator_type="IPV4"),
        RawIndicatorRecord(value="invalid://///bad", indicator_type="URL"),
    ]

    run = await ThreatIntelSyncService.sync_feed(
        session=db_session,
        feed_id="threatfox",
        is_dry_run=False,
        force=True,
        connector_override=MockConnector(records_to_return=malformed_records),
    )

    assert run.status == "FAILED"
    assert run.fetched_count == 2
    assert run.normalized_count == 0
    assert run.rejected_count == 2
    assert "rejected during normalization" in (run.error_summary or "")


@pytest.mark.asyncio
async def test_rate_limit_interval_guard(db_session: AsyncSession):
    """Verify that running sync twice within minimum interval raises FeedRateLimitError."""
    # Set last_sync_at to 2 minutes ago
    query = select(FeedConfigurationModel).where(FeedConfigurationModel.feed_id == "threatfox")
    feed = (await db_session.execute(query)).scalar_one()
    feed.is_enabled = True
    feed.last_sync_at = datetime.now(timezone.utc) - timedelta(minutes=2)
    await db_session.commit()

    with pytest.raises(FeedRateLimitError, match="Please wait|rate limits"):
        await ThreatIntelSyncService.sync_feed(
            session=db_session,
            feed_id="threatfox",
            is_dry_run=False,
            force=False,
            connector_override=MockConnector(),
        )
