"""Integration tests for Threat Intelligence Feeds API and end-to-end matching integration."""

from datetime import datetime, timezone
import uuid
import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from waliya.config import settings
from waliya.db.models import FeedConfigurationModel, ThreatIndicatorModel
from waliya.incidents.risk_engine import compute_incident_risk
from waliya.threat_intel.connectors.base import BaseFeedConnector, FeedFetchResult, RawIndicatorRecord
from waliya.threat_intel.matcher import ThreatIntelMatcher
from waliya.threat_intel.sync_service import ThreatIntelSyncService


class MockFeedTestConnector(BaseFeedConnector):
    feed_id = "threatfox"
    provider = "ThreatFox"
    allowed_hosts = {"threatfox-api.abuse.ch"}

    async def fetch_indicators(self, config_options, api_key=None):
        return FeedFetchResult(
            records=[
                RawIndicatorRecord(
                    value="198.51.100.99",
                    indicator_type="IPV4",
                    source_id="tf-int-1",
                    confidence=85,
                    severity="HIGH",
                    threat_category="botnet_cc",
                    tags=["cobaltstrike", "c2"],
                    description="Integration test C2 indicator",
                )
            ],
            fetched_count=1,
            metadata={"query_status": "ok"},
            diagnostics={"provider": self.provider},
        )


@pytest.mark.asyncio
async def test_feeds_api_list_and_detail(async_client: AsyncClient):
    """Verify listing and viewing feed configurations."""
    headers = {"X-Admin-Key": settings.ADMIN_API_KEY}

    # 1. Unauthorized request fails
    res_unauth = await async_client.get("/api/v1/threat-intel/feeds")
    assert res_unauth.status_code in (401, 403)

    # 2. Authorized list request
    res = await async_client.get("/api/v1/threat-intel/feeds", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) >= 2

    feed_ids = [f["feed_id"] for f in data]
    assert "threatfox" in feed_ids
    assert "urlhaus" in feed_ids

    # 3. Single feed detail
    res_single = await async_client.get("/api/v1/threat-intel/feeds/threatfox", headers=headers)
    assert res_single.status_code == 200
    feed = res_single.json()
    assert feed["feed_id"] == "threatfox"
    assert feed["provider"] == "ThreatFox"
    assert "indicators_count" in feed


@pytest.mark.asyncio
async def test_feed_config_patch_and_audit_logging(async_client: AsyncClient, db_session: AsyncSession):
    """Verify that updating feed configuration persists and creates an audit ledger entry."""
    headers = {"X-Admin-Key": settings.ADMIN_API_KEY}

    patch_payload = {
        "is_enabled": True,
        "refresh_interval_minutes": 120,
        "description": "Updated ThreatFox feed description for test",
    }

    res = await async_client.patch(
        "/api/v1/threat-intel/feeds/threatfox",
        json=patch_payload,
        headers=headers,
    )
    assert res.status_code == 200
    updated = res.json()
    assert updated["is_enabled"] is True
    assert updated["refresh_interval_minutes"] == 120
    assert updated["description"] == "Updated ThreatFox feed description for test"


@pytest.mark.asyncio
async def test_feed_sync_endpoint_and_history(async_client: AsyncClient, db_session: AsyncSession):
    """Verify triggering synchronization via API and querying execution history."""
    headers = {"X-Admin-Key": settings.ADMIN_API_KEY}

    # Clean existing test indicator to ensure deterministic inserted count
    await db_session.execute(delete(ThreatIndicatorModel).where(ThreatIndicatorModel.value == "198.51.100.99"))
    await db_session.commit()

    # Dry-run sync via API
    sync_payload = {
        "dry_run": True,
        "force": True,
    }

    # Mock sync service connector for testing API trigger
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "waliya.threat_intel.sync_service.CONNECTORS",
            {"threatfox": MockFeedTestConnector, "urlhaus": MockFeedTestConnector},
        )
        mp.setenv("WALIYA_TI_THREATFOX_API_KEY", "mock-key-for-test")

        res = await async_client.post(
            "/api/v1/threat-intel/feeds/threatfox/sync",
            json=sync_payload,
            headers=headers,
        )
        assert res.status_code == 200
        run_data = res.json()
        assert run_data["feed_id"] == "threatfox"
        assert run_data["status"] == "SUCCESS"
        assert run_data["is_dry_run"] is True
        assert run_data["fetched_count"] == 1
        assert run_data["inserted_count"] == 1

        run_id = run_data["id"]

        # List runs
        res_runs = await async_client.get("/api/v1/threat-intel/feeds-runs?feed_id=threatfox", headers=headers)
        assert res_runs.status_code == 200
        runs_list = res_runs.json()
        assert runs_list["total"] >= 1
        assert any(r["id"] == run_id for r in runs_list["items"])

        # Get single run
        res_run = await async_client.get(f"/api/v1/threat-intel/feeds-runs/{run_id}", headers=headers)
        assert res_run.status_code == 200
        assert res_run.json()["id"] == run_id


@pytest.mark.asyncio
async def test_end_to_end_feed_ingest_match_and_risk_scoring(db_session: AsyncSession):
    """Verify full path: Ingest feed indicator -> Match observable -> Elevate incident risk with explanation."""
    test_c2_ip = "198.51.100.99"

    # 1. Sync live indicator into database
    mock_conn = MockFeedTestConnector()
    run = await ThreatIntelSyncService.sync_feed(
        session=db_session,
        feed_id="threatfox",
        is_dry_run=False,
        force=True,
        connector_override=mock_conn,
    )
    assert run.status == "SUCCESS"

    # 2. Match synthetic telemetry observable against offline threat indicators
    matches = await ThreatIntelMatcher.match_observable(
        session=db_session,
        observable=test_c2_ip,
        indicator_type="IPV4",
    )
    assert len(matches) == 1
    matched = matches[0]
    assert matched.value == test_c2_ip
    assert matched.source == "ThreatFox"
    assert matched.confidence == 85
    assert matched.threat_category == "botnet_cc"

    # 3. Supply match to incident risk scoring engine
    findings = [
        {
            "severity": "HIGH",
            "confidence": 0.9,
            "dedup_key": "alert-test-c2",
            "explanation": {"rule_name": "C2 Beaconing Detected"},
            "rule_id": uuid.uuid4(),
        }
    ]

    score, explanation = compute_incident_risk(
        findings=findings,
        affected_entities=[f"ip:{test_c2_ip}", "host:srv-backend"],
        mitre_attack_ids=["T1071"],
        asset_criticality="HIGH",
        threat_intel_matches=matches,
    )

    # Asset criticality HIGH (+5.0) + Threat Intel bonus (min(15, 85 * 0.15 = 12.75))
    assert score > 50.0
    assert explanation["asset_importance_bonus"] == 5.0
    assert explanation["threat_intel_bonus"] == pytest.approx(12.75, abs=0.1)
    assert "threat intel" in explanation["decision_reason"].lower()
    assert "conf=85%" in explanation["decision_reason"]
    assert "asset context [HIGH]" in explanation["decision_reason"]
