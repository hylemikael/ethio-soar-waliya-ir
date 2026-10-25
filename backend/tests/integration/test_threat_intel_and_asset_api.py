"""Integration tests for Threat Intelligence indicators, Asset Context, and Risk Scoring integration."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from waliya.config import settings
from waliya.core.crypto import hash_agent_token
from waliya.db.models import AgentModel, AssetContextModel, AuditLedgerModel, EventModel, FindingModel, IncidentModel, ThreatIndicatorModel
from waliya.db.session import async_session_factory
from waliya.incidents.correlation_service import IncidentCorrelationService
from waliya.correlation.graph_engine import EntityGraphManager
from waliya.main import create_app


@pytest.fixture
def api_headers():
    return {"X-Admin-Key": settings.ADMIN_API_KEY}


@pytest.mark.asyncio
async def test_threat_intel_endpoints_authorization():
    """Verify that threat intelligence and asset endpoints require valid admin credentials."""
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Unauthenticated request -> 401
        res = await ac.get("/api/v1/threat-intel/indicators")
        assert res.status_code == 401

        res = await ac.get("/api/v1/assets")
        assert res.status_code == 401

        # 2. Invalid admin key -> 403
        res = await ac.get("/api/v1/threat-intel/indicators", headers={"X-Admin-Key": "wrong-key"})
        assert res.status_code == 403

        # 3. Valid admin key -> 200
        res = await ac.get("/api/v1/threat-intel/indicators", headers={"X-Admin-Key": settings.ADMIN_API_KEY})
        assert res.status_code == 200


@pytest.mark.asyncio
async def test_threat_indicator_lifecycle_and_duplicate_prevention(api_headers):
    """Verify indicator creation, normalization, duplicate prevention, and deactivation."""
    app = create_app()
    unique_ip = f"203.0.113.{(uuid4().int % 50) + 200}"
    source_name = f"MISP-Feed-{uuid4().hex[:6]}"

    async with async_session_factory() as db:
        await db.execute(delete(ThreatIndicatorModel).where(ThreatIndicatorModel.value == unique_ip))
        await db.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:

        # 1. Create valid indicator with leading/trailing spaces
        create_payload = {
            "indicator_type": "IPV4",
            "value": f"  {unique_ip}  ",
            "source": source_name,
            "source_id": "MISP-EVENT-9001",
            "confidence": 85,
            "severity": "HIGH",
            "threat_category": "C2",
            "threat_actor": "APT-Test",
            "tags": ["apt", "c2", "cobalt-strike"],
            "description": "Active C2 listener node",
        }
        res = await ac.post("/api/v1/threat-intel/indicators", json=create_payload, headers=api_headers)
        assert res.status_code == 201
        created = res.json()
        assert created["value"] == unique_ip
        assert created["indicator_type"] == "IPV4"
        assert created["confidence"] == 85
        assert created["is_active"] is True
        ind_id = created["id"]

        # 2. Duplicate indicator from the SAME provider -> 409 Conflict
        res_dup = await ac.post("/api/v1/threat-intel/indicators", json=create_payload, headers=api_headers)
        assert res_dup.status_code == 409
        assert "already exists" in res_dup.json()["detail"]

        # 3. Same indicator from a DIFFERENT provider -> Accepted (provenance preserved)
        diff_source_payload = dict(create_payload)
        diff_source_payload["source"] = f"AlienVault-OTX-{uuid4().hex[:6]}"
        res_diff = await ac.post("/api/v1/threat-intel/indicators", json=diff_source_payload, headers=api_headers)
        assert res_diff.status_code == 201

        # 4. Search and filter
        res_list = await ac.get(f"/api/v1/threat-intel/indicators?search={unique_ip}", headers=api_headers)
        assert res_list.status_code == 200
        items = res_list.json()["items"]
        exact_items = [i for i in items if i["value"] == unique_ip]
        assert len(exact_items) == 2  # Both MISP and AlienVault records

        # 5. Patch indicator
        res_patch = await ac.patch(
            f"/api/v1/threat-intel/indicators/{ind_id}",
            json={"confidence": 95, "severity": "CRITICAL"},
            headers=api_headers,
        )
        assert res_patch.status_code == 200
        assert res_patch.json()["confidence"] == 95
        assert res_patch.json()["severity"] == "CRITICAL"

        # 6. Deactivate indicator
        res_deact = await ac.post(f"/api/v1/threat-intel/indicators/{ind_id}/deactivate", headers=api_headers)
        assert res_deact.status_code == 200
        assert res_deact.json()["is_active"] is False

        # 7. Verify audit ledger record exists
        async with async_session_factory() as db:
            audit_res = await db.execute(
                select(AuditLedgerModel)
                .where(AuditLedgerModel.target_entity == f"indicator:{ind_id}")
            )
            audit_records = audit_res.scalars().all()
            assert len(audit_records) >= 2  # CREATE, UPDATE, DEACTIVATE
            await db.execute(delete(ThreatIndicatorModel).where(ThreatIndicatorModel.value == unique_ip))
            await db.commit()


@pytest.mark.asyncio
async def test_threat_indicator_batch_import(api_headers):
    """Verify bounded batch import of indicators with valid, invalid, and updated records."""
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        source_feed = f"CERT-ET-{uuid4().hex[:6]}"
        ip1 = f"198.51.100.{uuid4().int % 200 + 10}"
        domain1 = f"c2-{uuid4().hex[:8]}.example.com"
        hash1 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        batch_payload = {
            "indicators": [
                {
                    "indicator_type": "IPV4",
                    "value": ip1,
                    "source": source_feed,
                    "confidence": 80,
                    "severity": "HIGH",
                    "threat_category": "BOTNET",
                },
                {
                    "indicator_type": "DOMAIN",
                    "value": domain1,
                    "source": source_feed,
                    "confidence": 90,
                    "severity": "CRITICAL",
                    "threat_category": "C2",
                },
                {
                    "indicator_type": "SHA256",
                    "value": hash1,
                    "source": source_feed,
                    "confidence": 70,
                    "severity": "MEDIUM",
                    "threat_category": "RANSOMWARE",
                },
                {
                    # Invalid item
                    "indicator_type": "IPV4",
                    "value": "invalid-ip-format",
                    "source": source_feed,
                    "confidence": 50,
                },
            ]
        }

        res = await ac.post("/api/v1/threat-intel/indicators/import", json=batch_payload, headers=api_headers)
        assert res.status_code == 200
        summary = res.json()
        assert summary["total_received"] == 4
        assert summary["imported_count"] == 3
        assert summary["rejected_count"] == 1
        assert len(summary["errors"]) == 1

        # Re-import with updated confidence for ip1
        batch_payload_update = {
            "indicators": [
                {
                    "indicator_type": "IPV4",
                    "value": ip1,
                    "source": source_feed,
                    "confidence": 99,
                    "severity": "CRITICAL",
                }
            ]
        }
        res_up = await ac.post("/api/v1/threat-intel/indicators/import", json=batch_payload_update, headers=api_headers)
        assert res_up.status_code == 200
        summary_up = res_up.json()
        assert summary_up["imported_count"] == 0
        assert summary_up["updated_count"] == 1


@pytest.mark.asyncio
async def test_threat_indicator_matching_service_and_expiration(api_headers):
    """Verify that matching detects active indicators and strictly ignores expired/inactive indicators."""
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        now = datetime.now(timezone.utc)
        active_ip = f"198.51.{(uuid4().int % 200) + 1}.{(uuid4().int % 200) + 1}"
        expired_ip = f"203.0.{(uuid4().int % 200) + 1}.{(uuid4().int % 200) + 1}"
        inactive_domain = f"dead-{uuid4().hex[:8]}.example.com"

        # 1. Active indicator (future expiration)
        await ac.post(
            "/api/v1/threat-intel/indicators",
            json={
                "indicator_type": "IPV4",
                "value": active_ip,
                "source": "ActiveSource",
                "confidence": 90,
                "expires_at": (now + timedelta(days=30)).isoformat(),
            },
            headers=api_headers,
        )

        # 2. Expired indicator (past expiration)
        await ac.post(
            "/api/v1/threat-intel/indicators",
            json={
                "indicator_type": "IPV4",
                "value": expired_ip,
                "source": "ExpiredSource",
                "confidence": 90,
                "expires_at": (now - timedelta(days=1)).isoformat(),
            },
            headers=api_headers,
        )

        # 3. Inactive indicator
        resp_inact = await ac.post(
            "/api/v1/threat-intel/indicators",
            json={
                "indicator_type": "DOMAIN",
                "value": inactive_domain,
                "source": "DeactSource",
                "confidence": 80,
                "is_active": False,
            },
            headers=api_headers,
        )
        assert resp_inact.status_code == 201

        # Match active IP -> Matches
        match_res = await ac.post(
            "/api/v1/threat-intel/match",
            json={"observable": active_ip, "indicator_type": "IPV4"},
            headers=api_headers,
        )
        assert match_res.status_code == 200
        match_data = match_res.json()
        assert match_data["matched"] is True
        assert match_data["matches_count"] >= 1
        assert match_data["matches"][0]["value"] == active_ip

        # Match expired IP -> Must NOT match
        match_exp = await ac.post(
            "/api/v1/threat-intel/match",
            json={"observable": expired_ip, "indicator_type": "IPV4"},
            headers=api_headers,
        )
        assert match_exp.status_code == 200
        assert match_exp.json()["matched"] is False

        # Match inactive domain -> Must NOT match
        match_deact = await ac.post(
            "/api/v1/threat-intel/match",
            json={"observable": inactive_domain, "indicator_type": "DOMAIN"},
            headers=api_headers,
        )
        assert match_deact.status_code == 200
        assert match_deact.json()["matched"] is False

        # Malformed observable -> Returns matched=False gracefully
        match_bad = await ac.post(
            "/api/v1/threat-intel/match",
            json={"observable": "not an ip address !@#", "indicator_type": "IPV4"},
            headers=api_headers,
        )
        assert match_bad.status_code == 200
        assert match_bad.json()["matched"] is False


@pytest.mark.asyncio
async def test_asset_context_management_and_criticality_scale(api_headers):
    """Verify asset context creation, criticality scale, and audit ledger tracking."""
    agent_id = uuid4()
    now_utc = datetime.now(timezone.utc)

    # 1. Seed an agent in PostgreSQL
    async with async_session_factory() as db:
        agent = AgentModel(
            id=agent_id,
            hostname=f"core-db-{uuid4().hex[:6]}",
            os_family="linux",
            os_version="Ubuntu 24.04 LTS",
            primary_ip="10.50.0.15",
            mac_address="52:54:00:12:34:56",
            agent_version="2.0.0",
            status="ONLINE",
            api_token_hash=f"hash-{uuid4().hex}",
            secret_key_enc="enc_secret",
            last_heartbeat=now_utc,
            registered_at=now_utc,
        )
        db.add(agent)
        await db.commit()

    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 2. Inspect asset before context is assigned
        # Criticality must be UNASSIGNED (None), clearly distinguishing missing metadata from LOW
        res_get = await ac.get(f"/api/v1/assets/{agent_id}", headers=api_headers)
        assert res_get.status_code == 200
        detail = res_get.json()
        assert detail["context"] is None
        assert detail["is_critical"] is False

        # 3. Assign CRITICAL asset context
        ctx_payload = {
            "criticality": "CRITICAL",
            "environment": "PRODUCTION",
            "asset_group": "PCI-DATABASE-CLUSTER",
            "description": "Primary transactional payments database",
            "owner": "DataPlatformSecOps",
            "business_unit": "FinTech Core",
            "network_zone": "PCI-CDE",
            "tags": ["pci-dss", "sox", "mission-critical"],
        }
        res_put = await ac.put(f"/api/v1/assets/{agent_id}/context", json=ctx_payload, headers=api_headers)
        assert res_put.status_code == 200
        ctx_resp = res_put.json()
        assert ctx_resp["criticality"] == "CRITICAL"
        assert ctx_resp["environment"] == "PRODUCTION"

        # 4. Re-inspect asset detail
        res_detail2 = await ac.get(f"/api/v1/assets/{agent_id}", headers=api_headers)
        assert res_detail2.status_code == 200
        detail2 = res_detail2.json()
        assert detail2["context"] is not None
        assert detail2["context"]["criticality"] == "CRITICAL"
        assert detail2["is_critical"] is True

        # 5. Filter assets list by criticality
        res_crit = await ac.get("/api/v1/assets?criticality=CRITICAL", headers=api_headers)
        assert res_crit.status_code == 200
        assert any(a["agent_id"] == str(agent_id) for a in res_crit.json()["items"])

        # 6. Reject invalid agent ID (404)
        res_404 = await ac.put(f"/api/v1/assets/{uuid4()}/context", json=ctx_payload, headers=api_headers)
        assert res_404.status_code == 404

        # 7. Reject invalid criticality scale value (422)
        bad_payload = dict(ctx_payload)
        bad_payload["criticality"] = "EXTREME_SUPER_CRITICAL"
        res_422 = await ac.put(f"/api/v1/assets/{agent_id}/context", json=bad_payload, headers=api_headers)
        assert res_422.status_code == 422

        # 8. Verify audit ledger record exists for asset update
        async with async_session_factory() as db:
            audit_res = await db.execute(
                select(AuditLedgerModel).where(AuditLedgerModel.target_entity == f"asset:{agent_id}")
            )
            audit_records = audit_res.scalars().all()
            assert len(audit_records) >= 1
            assert audit_records[0].action == "ASSET_CONTEXT_CREATED"


@pytest.mark.asyncio
async def test_incident_correlation_integrates_asset_and_threat_intel():
    """Verify that IncidentCorrelationService automatically factors in asset criticality

    and matched threat intelligence into composite risk scores and explanations.
    """
    agent_id = uuid4()
    now_utc = datetime.now(timezone.utc)
    malicious_c2_ip = f"198.51.100.{uuid4().int % 200 + 10}"

    async with async_session_factory() as db:
        # Pre-cleanup in case of IP reuse
        await db.execute(delete(ThreatIndicatorModel).where(ThreatIndicatorModel.value == malicious_c2_ip))
        await db.commit()

        # 1. Create monitored agent
        agent = AgentModel(
            id=agent_id,
            hostname=f"web-prod-{uuid4().hex[:6]}",
            os_family="linux",
            os_version="Ubuntu 24.04 LTS",
            primary_ip="10.0.1.20",
            mac_address="52:54:00:ab:cd:ef",
            agent_version="2.0.0",
            status="ONLINE",
            api_token_hash=f"hash-{uuid4().hex}",
            secret_key_enc="enc_secret",
            last_heartbeat=now_utc,
            registered_at=now_utc,
        )
        # 2. Assign CRITICAL asset context
        asset_ctx = AssetContextModel(
            id=uuid4(),
            agent_id=agent_id,
            criticality="CRITICAL",
            environment="PRODUCTION",
            owner="SecOps Team",
        )
        # 3. Store active threat intelligence indicator matching malicious_c2_ip
        feed_source = f"ThreatFeed-{uuid4().hex[:6]}"
        indicator = ThreatIndicatorModel(
            id=uuid4(),
            indicator_type="IPV4",
            value=malicious_c2_ip,
            source=feed_source,
            confidence=90,
            severity="HIGH",
            threat_category="C2",
            is_active=True,
        )
        db.add_all([agent, asset_ctx, indicator])
        await db.commit()

        # 4. Create security event and finding referencing the malicious IP on the critical agent
        ev_id = uuid4()
        event = EventModel(
            id=ev_id,
            agent_id=agent_id,
            event_type="NETWORK_CONNECTION",
            severity="HIGH",
            timestamp=now_utc,
            source="auditd",
            raw_payload={},
            normalized_payload={
                "attributes": {
                    "src_ip": "10.0.1.20",
                    "dst_ip": malicious_c2_ip,
                    "dst_port": 443,
                }
            },
        )
        finding = FindingModel(
            id=uuid4(),
            event_id=ev_id,
            agent_id=agent_id,
            severity="HIGH",
            confidence=1.0,
            explanation={
                "rule_id": "RULE-NET-001-C2",
                "rule_name": "Outbound Connection to Suspected C2",
                "mitre_attack_ids": ["T1071.001"],
            },
            dedup_key=f"c2:{malicious_c2_ip}",
        )
        db.add_all([event, finding])
        await db.commit()

        # 5. Correlate finding into incident
        service = IncidentCorrelationService()
        graph_manager = EntityGraphManager()
        event_data = {
            "event_id": str(ev_id),
            "agent_id": str(agent_id),
            "attributes": {
                "src_ip": "10.0.1.20",
                "dst_ip": malicious_c2_ip,
                "dst_port": 443,
            },
        }
        incidents = await service.correlate_findings(
            session=db,
            findings=[finding],
            event_data=event_data,
            graph_manager=graph_manager,
        )
        await db.commit()

        assert len(incidents) == 1
        inc = incidents[0]

        # 6. Verify risk explanation contains both asset criticality bonus and threat intel bonus
        risk_expl = inc.risk_explanation
        assert risk_expl["asset_criticality"] == "CRITICAL"
        assert risk_expl["asset_importance_bonus"] == 10.0
        assert risk_expl["threat_intel_confidence"] == 90
        assert risk_expl["threat_intel_bonus"] == 13.5  # 90 * 0.15 = 13.5
        assert len(risk_expl["threat_intel_matches"]) >= 1

        # Invariant: Score reflects both contextual bonuses
        assert inc.composite_risk_score >= 80.0

        # Post-cleanup to preserve test isolation
        await db.execute(delete(ThreatIndicatorModel).where(ThreatIndicatorModel.value == malicious_c2_ip))
        await db.commit()
