"""Unit tests for threat intelligence indicator lifecycle management, decay, and caching."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4
import pytest
from sqlalchemy import delete, select

from waliya.db.models import ThreatIndicatorModel
from waliya.db.session import async_session_factory
from waliya.threat_intel.decay_service import ThreatIntelDecayService
from waliya.threat_intel.matcher import ThreatIntelMatcher


@pytest.mark.asyncio
async def test_deterministic_decay_calculation_and_idempotency():
    """Verify that decay is calculated deterministically across time intervals and is strictly idempotent."""
    now_ref = datetime(2026, 10, 24, 12, 0, 0, tzinfo=timezone.utc)
    ind_id = uuid4()
    feed_name = f"TestDecayFeed-{uuid4().hex[:6]}"

    # Create indicator that was last seen 28 days ago, initial confidence 90
    created_at = now_ref - timedelta(days=28)
    last_seen = now_ref - timedelta(days=28)

    async with async_session_factory() as session:
        ind = ThreatIndicatorModel(
            id=ind_id,
            indicator_type="IPV4",
            value=f"198.51.100.{uuid4().int % 200 + 10}",
            source=feed_name,
            confidence=90,
            severity="HIGH",
            last_seen=last_seen,
            created_at=created_at,
            is_active=True,
        )
        session.add(ind)
        await session.commit()

    async with async_session_factory() as session:
        # Run 1: stale_days=14, interval=7 days, decay_points=10
        # Elapsed since stale threshold (28 - 14 = 14 days) -> 2 full intervals -> 20 points decay
        res1 = await ThreatIntelDecayService.run_decay(
            session=session,
            actor_id="test_admin",
            stale_days=14,
            decay_points=10,
            decay_interval_days=7,
            min_confidence=10,
            dry_run=False,
            source=feed_name,
            reference_now=now_ref,
        )

        assert res1["decayed_count"] == 1
        decayed = res1["decayed_indicators"][0]
        assert decayed["indicator_id"] == str(ind_id)
        assert decayed["previous_confidence"] == 90
        assert decayed["new_confidence"] == 70  # 90 - (2 * 10) = 70
        assert decayed["intervals_decayed"] == 2

    # Verify database persistence
    async with async_session_factory() as session:
        db_ind = (await session.execute(select(ThreatIndicatorModel).where(ThreatIndicatorModel.id == ind_id))).scalar_one()
        assert db_ind.confidence == 70
        assert db_ind.last_decayed_at is not None

    # Run 2: Immediately re-run at the exact same reference time -> IDEMPOTENT (0 change)
    async with async_session_factory() as session:
        res2 = await ThreatIntelDecayService.run_decay(
            session=session,
            actor_id="test_admin",
            stale_days=14,
            decay_points=10,
            decay_interval_days=7,
            min_confidence=10,
            dry_run=False,
            source=feed_name,
            reference_now=now_ref,
        )
        assert res2["decayed_count"] == 0
        assert res2["unaffected_count"] >= 1

    # Run 3: Advance time by 3 days (less than 7-day interval) -> IDEMPOTENT (0 change)
    advance_3_days = now_ref + timedelta(days=3)
    async with async_session_factory() as session:
        res3 = await ThreatIntelDecayService.run_decay(
            session=session,
            actor_id="test_admin",
            stale_days=14,
            decay_points=10,
            decay_interval_days=7,
            min_confidence=10,
            dry_run=False,
            source=feed_name,
            reference_now=advance_3_days,
        )
        assert res3["decayed_count"] == 0

    # Run 4: Advance time by 7 full days -> Decays by 1 interval (10 points -> 60)
    advance_7_days = now_ref + timedelta(days=7)
    async with async_session_factory() as session:
        res4 = await ThreatIntelDecayService.run_decay(
            session=session,
            actor_id="test_admin",
            stale_days=14,
            decay_points=10,
            decay_interval_days=7,
            min_confidence=10,
            dry_run=False,
            source=feed_name,
            reference_now=advance_7_days,
        )
        assert res4["decayed_count"] == 1
        assert res4["decayed_indicators"][0]["new_confidence"] == 60


@pytest.mark.asyncio
async def test_decay_dry_run_and_confidence_floor():
    """Verify that dry_run does not mutate the DB and confidence respects the lower bound."""
    now_ref = datetime(2026, 10, 24, 12, 0, 0, tzinfo=timezone.utc)
    ind_id = uuid4()
    feed_name = f"FloorFeed-{uuid4().hex[:6]}"

    # Indicator with low confidence (25) and very old (60 days)
    last_seen = now_ref - timedelta(days=60)

    async with async_session_factory() as session:
        ind = ThreatIndicatorModel(
            id=ind_id,
            indicator_type="DOMAIN",
            value=f"decay-floor-{uuid4().hex[:6]}.example.com",
            source=feed_name,
            confidence=25,
            severity="MEDIUM",
            last_seen=last_seen,
            is_active=True,
        )
        session.add(ind)
        await session.commit()

    # 1. Test Dry Run: projects decay down to floor (10), but DB unchanged
    async with async_session_factory() as session:
        dry_res = await ThreatIntelDecayService.run_decay(
            session=session,
            actor_id="test_admin",
            stale_days=14,
            decay_points=10,
            decay_interval_days=7,
            min_confidence=10,
            dry_run=True,
            source=feed_name,
            reference_now=now_ref,
        )
        assert dry_res["is_dry_run"] is True
        assert dry_res["decayed_count"] == 1
        assert dry_res["decayed_indicators"][0]["new_confidence"] == 10  # Clamped to min_confidence

    # Verify DB still has 25
    async with async_session_factory() as session:
        db_ind = (await session.execute(select(ThreatIndicatorModel).where(ThreatIndicatorModel.id == ind_id))).scalar_one()
        assert db_ind.confidence == 25
        assert db_ind.last_decayed_at is None

    # 2. Test Real Execution: Confidence clamps to 10 and does not drop below
    async with async_session_factory() as session:
        real_res = await ThreatIntelDecayService.run_decay(
            session=session,
            actor_id="test_admin",
            stale_days=14,
            decay_points=10,
            decay_interval_days=7,
            min_confidence=10,
            dry_run=False,
            source=feed_name,
            reference_now=now_ref,
        )
        assert real_res["decayed_count"] == 1
        assert real_res["decayed_indicators"][0]["new_confidence"] == 10

    # 3. Subsequent decay run on floor indicator applies 0 change
    advance_time = now_ref + timedelta(days=14)
    async with async_session_factory() as session:
        floor_res = await ThreatIntelDecayService.run_decay(
            session=session,
            actor_id="test_admin",
            stale_days=14,
            decay_points=10,
            decay_interval_days=7,
            min_confidence=10,
            dry_run=False,
            source=feed_name,
            reference_now=advance_time,
        )
        assert floor_res["decayed_count"] == 0


@pytest.mark.asyncio
async def test_fresh_and_expired_indicators_are_not_decayed():
    """Verify that fresh indicators (< stale_days) and expired indicators are ignored during decay."""
    now_ref = datetime(2026, 10, 24, 12, 0, 0, tzinfo=timezone.utc)

    fresh_id = uuid4()
    expired_id = uuid4()
    feed_name = f"FreshFeed-{uuid4().hex[:6]}"
    fresh_ip = f"198.51.100.{(uuid4().int % 100) + 10}"
    expired_ip = f"198.51.100.{(uuid4().int % 100) + 120}"

    async with async_session_factory() as session:
        fresh_ind = ThreatIndicatorModel(
            id=fresh_id,
            indicator_type="IPV4",
            value=fresh_ip,
            source=feed_name,
            confidence=80,
            last_seen=now_ref - timedelta(days=3),  # Only 3 days old (fresh)
            is_active=True,
        )
        expired_ind = ThreatIndicatorModel(
            id=expired_id,
            indicator_type="IPV4",
            value=expired_ip,
            source=feed_name,
            confidence=80,
            last_seen=now_ref - timedelta(days=30),
            expires_at=now_ref - timedelta(days=1),  # Expired
            is_active=True,
        )
        session.add_all([fresh_ind, expired_ind])
        await session.commit()

    async with async_session_factory() as session:
        res = await ThreatIntelDecayService.run_decay(
            session=session,
            actor_id="test_admin",
            stale_days=14,
            source=feed_name,
            reference_now=now_ref,
        )
        # Neither fresh nor expired should be decayed
        assert res["decayed_count"] == 0


@pytest.mark.asyncio
async def test_matcher_bounded_cache_and_ignorable_observables():
    """Verify in-memory caching, cache invalidation, and filtering of loopback observables."""
    ThreatIntelMatcher.clear_cache()

    async with async_session_factory() as session:
        # Loopback/local addresses must return immediately without querying DB
        assert await ThreatIntelMatcher.match_observable(session, "127.0.0.1") == []
        assert await ThreatIntelMatcher.match_observable(session, "::1") == []
        assert await ThreatIntelMatcher.match_observable(session, "localhost") == []

        # Seed an indicator
        target_ip = f"203.0.113.{uuid4().int % 200 + 20}"
        await session.execute(delete(ThreatIndicatorModel).where(ThreatIndicatorModel.value == target_ip))
        await session.commit()

        ind = ThreatIndicatorModel(
            id=uuid4(),
            indicator_type="IPV4",
            value=target_ip,
            source="CacheTestFeed",
            confidence=95,
            is_active=True,
        )
        session.add(ind)
        await session.commit()

        try:
            # Query 1: Hits DB and populates cache
            matches1 = await ThreatIntelMatcher.match_observable(session, target_ip, "IPV4")
            assert len(matches1) == 1
            assert matches1[0].value == target_ip

            # Cache key should now exist
            cache_key = ("IPV4", target_ip)
            assert cache_key in ThreatIntelMatcher._cache

            # Query 2: Serviced from in-memory cache
            matches2 = await ThreatIntelMatcher.match_observable(session, target_ip, "IPV4")
            assert len(matches2) == 1
            assert matches2[0].value == target_ip

            # Clear cache: verify cache key is removed
            ThreatIntelMatcher.clear_cache()
            assert len(ThreatIntelMatcher._cache) == 0
        finally:
            await session.execute(delete(ThreatIndicatorModel).where(ThreatIndicatorModel.id == ind.id))
            await session.commit()
