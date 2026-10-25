"""Integration tests for indicator lifecycle endpoints, decay API, incident threat intel context, and simulation isolation."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from waliya.main import create_app
from waliya.config import settings
from waliya.db.models import AuditLedgerModel, FindingModel, IncidentModel, ThreatIndicatorModel
from waliya.db.session import async_session_factory
from waliya.threat_intel.matcher import ThreatIntelMatcher


@pytest.fixture
def api_headers():
    return {
        "X-Admin-Key": settings.ADMIN_API_KEY,
        "Content-Type": "application/json",
    }


@pytest.mark.asyncio
async def test_indicator_lifecycle_endpoints_and_validation(api_headers):
    """Verify activate, deactivate, expire, extend-expiry endpoints, validation, and audit logging."""
    app = create_app()
    now_utc = datetime.now(timezone.utc)
    target_ip = f"203.0.113.{(uuid4().int % 200) + 10}"

    async with async_session_factory() as db:
        await db.execute(delete(ThreatIndicatorModel).where(ThreatIndicatorModel.value == target_ip))
        await db.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:

        # 1. Create active indicator
        resp_create = await ac.post(
            "/api/v1/threat-intel/indicators",
            json={
                "indicator_type": "IPV4",
                "value": target_ip,
                "source": "LifecycleSource",
                "confidence": 85,
                "severity": "HIGH",
                "expires_at": (now_utc + timedelta(days=10)).isoformat(),
            },
            headers=api_headers,
        )
        assert resp_create.status_code == 201
        ind_data = resp_create.json()
        ind_id = ind_data["id"]

        # Matches live query
        m1 = await ac.post("/api/v1/threat-intel/match", json={"observable": target_ip}, headers=api_headers)
        assert m1.json()["matched"] is True

        # 2. Deactivate indicator -> Must not match
        resp_deact = await ac.post(f"/api/v1/threat-intel/indicators/{ind_id}/deactivate", headers=api_headers)
        assert resp_deact.status_code == 200
        assert resp_deact.json()["is_active"] is False

        m2 = await ac.post("/api/v1/threat-intel/match", json={"observable": target_ip}, headers=api_headers)
        assert m2.json()["matched"] is False

        # 3. Reactivate indicator -> Matches again
        resp_act = await ac.post(f"/api/v1/threat-intel/indicators/{ind_id}/activate", headers=api_headers)
        assert resp_act.status_code == 200
        assert resp_act.json()["is_active"] is True

        m3 = await ac.post("/api/v1/threat-intel/match", json={"observable": target_ip}, headers=api_headers)
        assert m3.json()["matched"] is True

        # 4. Expire indicator immediately
        resp_exp = await ac.post(f"/api/v1/threat-intel/indicators/{ind_id}/expire", headers=api_headers)
        assert resp_exp.status_code == 200
        assert resp_exp.json()["expires_at"] is not None

        # Expired indicator must NOT match live telemetry
        m4 = await ac.post("/api/v1/threat-intel/match", json={"observable": target_ip}, headers=api_headers)
        assert m4.json()["matched"] is False

        # 5. Prevent silent reactivation of expired indicator without extending expiry
        resp_act_fail = await ac.post(f"/api/v1/threat-intel/indicators/{ind_id}/activate", headers=api_headers)
        assert resp_act_fail.status_code == 400
        assert "Cannot silently reactivate an expired indicator" in resp_act_fail.json()["detail"]

        # 6. Reject invalid extension (past timestamp)
        resp_ext_bad = await ac.post(
            f"/api/v1/threat-intel/indicators/{ind_id}/extend-expiry",
            json={"new_expires_at": (now_utc - timedelta(days=5)).isoformat()},
            headers=api_headers,
        )
        assert resp_ext_bad.status_code == 400
        assert "strictly in the future" in resp_ext_bad.json()["detail"]

        # 7. Valid extension (30 days)
        resp_ext_ok = await ac.post(
            f"/api/v1/threat-intel/indicators/{ind_id}/extend-expiry",
            json={"extension_days": 30},
            headers=api_headers,
        )
        assert resp_ext_ok.status_code == 200
        new_exp = datetime.fromisoformat(resp_ext_ok.json()["expires_at"])
        assert new_exp > now_utc

        # Matches live query again
        m5 = await ac.post("/api/v1/threat-intel/match", json={"observable": target_ip}, headers=api_headers)
        assert m5.json()["matched"] is True

        # 8. Verify Audit Ledger records for lifecycle mutations
        async with async_session_factory() as session:
            ledger_query = select(AuditLedgerModel).where(AuditLedgerModel.target_entity == f"indicator:{ind_id}")
            records = (await session.execute(ledger_query)).scalars().all()
            actions = [r.action for r in records]
            assert "THREAT_INDICATOR_CREATED" in actions
            assert "THREAT_INDICATOR_DEACTIVATED" in actions
            assert "THREAT_INDICATOR_ACTIVATED" in actions
            assert "THREAT_INDICATOR_EXPIRED" in actions
            assert "THREAT_INDICATOR_EXPIRY_EXTENDED" in actions


@pytest.mark.asyncio
async def test_decay_endpoint_and_authorization(api_headers):
    """Verify decay endpoint execution, dry-run, and unauthorized access rejection."""
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Unauthorized request without admin key -> 401/403
        unauth_res = await ac.post("/api/v1/threat-intel/indicators/decay", json={"stale_days": 14})
        assert unauth_res.status_code in (401, 403)

        # 2. Authorized dry-run
        dry_res = await ac.post(
            "/api/v1/threat-intel/indicators/decay",
            json={"stale_days": 14, "decay_points": 10, "dry_run": True},
            headers=api_headers,
        )
        assert dry_res.status_code == 200
        data = dry_res.json()
        assert data["is_dry_run"] is True
        assert "decayed_indicators" in data


@pytest.mark.asyncio
async def test_incident_threat_intel_context_and_risk_bonus_cap(api_headers):
    """Verify that GET /incidents/{id}/threat-intel returns complete context and caps risk score bonus."""
    app = create_app()
    now_utc = datetime.now(timezone.utc)
    incident_id = uuid4()
    c2_ip = f"198.51.{(uuid4().int % 250) + 1}.{(uuid4().int % 250) + 1}"

    # 1. Seed indicator in DB
    ind_id = uuid4()
    async with async_session_factory() as session:
        ind = ThreatIndicatorModel(
            id=ind_id,
            indicator_type="IPV4",
            value=c2_ip,
            source="ThreatFox",
            source_id="tf-10029",
            confidence=95,
            severity="CRITICAL",
            threat_category="C2",
            threat_actor="APT29",
            tags=["c2", "cobalt_strike"],
            description="High-fidelity C2 IP",
            first_seen=now_utc - timedelta(days=5),
            last_seen=now_utc,
            is_active=True,
        )
        session.add(ind)

        # 2. Seed incident with threat intelligence match
        inc = IncidentModel(
            id=incident_id,
            title=f"Command & Control Beaconing to {c2_ip}",
            description="Observed beaconing traffic matching external threat intelligence.",
            severity="HIGH",
            status="OPEN",
            composite_risk_score=78.5,
            first_seen=now_utc,
            last_seen=now_utc,
            affected_entities=[f"ip:{c2_ip}", "host:finance-srv-01"],
            mitre_attack_ids=["T1071.001"],
            risk_explanation={
                "base_severity": "HIGH",
                "base_weight": 70.0,
                "confidence_factor": 0.95,
                "threat_intel_confidence": 95,
                "threat_intel_bonus": 14.3,
                "decision_reason": f"Risk elevated by +14.3 pts due to match with ThreatFox C2 indicator ({c2_ip}).",
                "threat_intel_matches": [
                    {
                        "indicator_id": str(ind_id),
                        "indicator_type": "IPV4",
                        "value": c2_ip,
                        "observable": c2_ip,
                        "source": "ThreatFox",
                        "source_id": "tf-10029",
                        "confidence": 95,
                        "severity": "CRITICAL",
                        "threat_category": "C2",
                        "threat_actor": "APT29",
                        "tags": ["c2", "cobalt_strike"],
                        "description": "High-fidelity C2 IP",
                        "matched_at": now_utc.isoformat(),
                        "investigative_note": f"Observable '{c2_ip}' matched ThreatFox C2 indicator.",
                    }
                ],
            },
            is_simulation=False,
        )
        session.add(inc)
        await session.commit()

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            # Query threat intel context for incident
            resp = await ac.get(f"/api/v1/incidents/{incident_id}/threat-intel", headers=api_headers)
            assert resp.status_code == 200
            ti_data = resp.json()

            assert ti_data["has_threat_intel"] is True
            assert ti_data["total_matched_indicators"] == 1
            assert ti_data["max_confidence"] == 95
            # Threat intel bonus capped mathematically at 15.0
            assert ti_data["threat_intel_bonus"] <= 15.0
            assert ti_data["threat_intel_bonus"] == round(min(15.0, 95 * 0.15), 1)

            match = ti_data["matches"][0]
            assert match["indicator_id"] == str(ind_id)
            assert match["value"] == c2_ip
            assert match["source"] == "ThreatFox"
            assert match["provenance_label"] == "Feed: ThreatFox"
            assert match["is_active"] is True
            assert match["is_expired"] is False
            assert match["threat_category"] == "C2"
            assert match["threat_actor"] == "APT29"
            assert match["match_classification"] == "CONFIRMED_MATCH"
    finally:
        async with async_session_factory() as session:
            await session.execute(delete(ThreatIndicatorModel).where(ThreatIndicatorModel.id == ind_id))
            await session.execute(delete(IncidentModel).where(IncidentModel.id == incident_id))
            await session.commit()


@pytest.mark.asyncio
async def test_simulation_incident_isolation_and_containment_guard(api_headers):
    """Verify that simulation telemetry remains isolated and can never trigger real containment actions."""
    app = create_app()
    sim_inc_id = uuid4()
    now_utc = datetime.now(timezone.utc)

    async with async_session_factory() as session:
        sim_inc = IncidentModel(
            id=sim_inc_id,
            title="[SIMULATION] Simulated Web Shell Activity",
            description="Purple-team simulated event scenario.",
            severity="HIGH",
            status="OPEN",
            composite_risk_score=65.0,
            first_seen=now_utc,
            last_seen=now_utc,
            affected_entities=["host:sim-sensor-01"],
            mitre_attack_ids=["T1505.003"],
            is_simulation=True,
            simulation_run_id=f"run-{uuid4().hex[:8]}",
        )
        session.add(sim_inc)
        await session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Fetch simulation incident detail
        inc_res = await ac.get(f"/api/v1/incidents/{sim_inc_id}", headers=api_headers)
        assert inc_res.status_code == 200
        detail = inc_res.json()
        assert detail["is_simulation"] is True

        # Threat intel query for simulation incident returns gracefully with 0 matches
        ti_res = await ac.get(f"/api/v1/incidents/{sim_inc_id}/threat-intel", headers=api_headers)
        assert ti_res.status_code == 200
        assert ti_res.json()["total_matched_indicators"] == 0
