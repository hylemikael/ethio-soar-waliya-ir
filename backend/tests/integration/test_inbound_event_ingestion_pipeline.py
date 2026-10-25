"""Integration tests for inbound external security event ingestion, authentication, and pipeline routing."""

from datetime import datetime, timedelta, timezone
import json
from uuid import uuid4
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from waliya.config import settings
from waliya.db.models import (
    EventModel,
    EventOutboxModel,
    InboundEventDedupModel,
    InboundSourceModel,
    ResponsePlanModel,
    ResponseActionModel,
)
from waliya.db.session import async_session_factory
from waliya.integrations.signing import (
    compute_notification_signature,
    encrypt_destination_secret,
)
from waliya.main import create_app


@pytest_asyncio.fixture
async def async_client():
    app = create_app()
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        yield client


@pytest.fixture
def secret_plaintext():
    return "secret-hmac-key-for-test-32chars-long!"


@pytest_asyncio.fixture
async def test_inbound_source(secret_plaintext):
    """Seed an authorized inbound source."""
    slug = f"guardduty-{uuid4().hex[:6]}"
    secret_enc = encrypt_destination_secret(secret_plaintext)
    async with async_session_factory() as session:
        source = InboundSourceModel(
            id=uuid4(),
            source_id=slug,
            name="AWS GuardDuty Cloud Posture",
            provider_type="GENERIC",
            is_enabled=True,
            auth_type="HMAC_SHA256",
            shared_secret_enc=secret_enc,
            permitted_event_types=["EXTERNAL_ALERT", "NETWORK_CONNECTION"],
            created_by="test-admin",
        )
        session.add(source)
        await session.commit()
        await session.refresh(source)
        source_id = source.id
        source_slug = source.source_id

    yield {"id": source_id, "slug": source_slug, "secret": secret_plaintext}

    # Teardown
    async with async_session_factory() as session:
        s = await session.get(InboundSourceModel, source_id)
        if s:
            await session.delete(s)
            await session.commit()


def _build_signed_request(
    source_slug: str,
    secret: str,
    payload_dict: dict,
    timestamp_override: datetime = None,
):
    """Helper to compute valid timestamp, raw payload bytes, and HMAC signature."""
    raw_bytes = json.dumps(payload_dict).encode("utf-8")
    ts = timestamp_override or datetime.now(timezone.utc)
    ts_str = ts.strftime("%Y-%m-%dT%H:%M:%SZ")
    sig = compute_notification_signature(secret, raw_bytes)
    headers = {
        "Content-Type": "application/json",
        "X-Waliya-Source-Id": source_slug,
        "X-Waliya-Timestamp": ts_str,
        "X-Waliya-Signature": sig,
    }
    return raw_bytes, headers


@pytest.mark.asyncio
async def test_inbound_ingest_authentication_and_freshness_failures(
    async_client,
    test_inbound_source,
):
    """Verify inbound endpoint rejects invalid signatures, stale timestamps, and mismatched sources."""
    slug = test_inbound_source["slug"]
    secret = test_inbound_source["secret"]
    valid_payload = {
        "external_event_id": f"evt-{uuid4().hex[:8]}",
        "event_type": "EXTERNAL_ALERT",
        "severity": "HIGH",
        "title": "Crypto Mining Activity Detected",
    }

    # 1. Missing timestamp header -> 401
    raw_body, headers = _build_signed_request(slug, secret, valid_payload)
    del headers["X-Waliya-Timestamp"]
    resp = await async_client.post(
        f"/api/v1/integrations/inbound/{slug}/events",
        content=raw_body,
        headers=headers,
    )
    assert resp.status_code == 401
    assert "Missing required X-Waliya-Timestamp" in resp.json()["detail"]

    # 2. Missing signature header -> 401
    raw_body, headers = _build_signed_request(slug, secret, valid_payload)
    del headers["X-Waliya-Signature"]
    resp = await async_client.post(
        f"/api/v1/integrations/inbound/{slug}/events",
        content=raw_body,
        headers=headers,
    )
    assert resp.status_code == 401
    assert "Missing required X-Waliya-Signature" in resp.json()["detail"]

    # 3. Invalid signature -> 401
    raw_body, headers = _build_signed_request(slug, secret, valid_payload)
    headers["X-Waliya-Signature"] = "bad" * 16
    resp = await async_client.post(
        f"/api/v1/integrations/inbound/{slug}/events",
        content=raw_body,
        headers=headers,
    )
    assert resp.status_code == 401
    assert "Invalid HMAC-SHA256 signature" in resp.json()["detail"]

    # 4. Stale timestamp (10 minutes in past) -> 401
    stale_ts = datetime.now(timezone.utc) - timedelta(minutes=10)
    raw_body, headers = _build_signed_request(slug, secret, valid_payload, timestamp_override=stale_ts)
    resp = await async_client.post(
        f"/api/v1/integrations/inbound/{slug}/events",
        content=raw_body,
        headers=headers,
    )
    assert resp.status_code == 401
    assert "Timestamp freshness error" in resp.json()["detail"]

    # 5. Future timestamp (10 minutes in future) -> 401
    future_ts = datetime.now(timezone.utc) + timedelta(minutes=10)
    raw_body, headers = _build_signed_request(slug, secret, valid_payload, timestamp_override=future_ts)
    resp = await async_client.post(
        f"/api/v1/integrations/inbound/{slug}/events",
        content=raw_body,
        headers=headers,
    )
    assert resp.status_code == 401
    assert "Timestamp freshness error" in resp.json()["detail"]

    # 6. Mismatched X-Waliya-Source-Id -> 400
    raw_body, headers = _build_signed_request(slug, secret, valid_payload)
    headers["X-Waliya-Source-Id"] = "mismatched-other-slug"
    resp = await async_client.post(
        f"/api/v1/integrations/inbound/{slug}/events",
        content=raw_body,
        headers=headers,
    )
    assert resp.status_code == 400
    assert "does not match" in resp.json()["detail"]

    # 7. Unknown source in path -> 404
    raw_body, headers = _build_signed_request("nonexistent-slug", secret, valid_payload)
    resp = await async_client.post(
        "/api/v1/integrations/inbound/nonexistent-slug/events",
        content=raw_body,
        headers=headers,
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_inbound_ingest_success_provenance_and_deduplication(
    async_client,
    test_inbound_source,
):
    """Verify valid ingestion creates EventModel with agent_id=None and is_external=True,

    and repeated submission returns duplicate status without duplicate rows.
    """
    slug = test_inbound_source["slug"]
    secret = test_inbound_source["secret"]
    ext_event_id = f"ext-alert-{uuid4().hex[:8]}"

    payload = {
        "external_event_id": ext_event_id,
        "event_type": "EXTERNAL_ALERT",
        "severity": "CRITICAL",
        "title": "Unauthorized S3 Bucket Access",
        "description": "Suspicious IAM user assumed administrative role from external IP",
        "attributes": {
            "src_ip": "198.51.100.77",
            "dst_ip": "203.0.113.10",
            "user": "developer_alice",
        },
    }

    raw_body, headers = _build_signed_request(slug, secret, payload)

    # 1. First Ingestion -> 202 ACCEPTED
    resp1 = await async_client.post(
        f"/api/v1/integrations/inbound/{slug}/events",
        content=raw_body,
        headers=headers,
    )
    assert resp1.status_code == 202
    data1 = resp1.json()
    assert data1["status"] == "ACCEPTED"
    assert data1["duplicate"] is False
    assert data1["external_event_id"] == ext_event_id
    assert data1["event_id"] is not None
    internal_id = data1["event_id"]

    # 2. Check Database Records and Provenance
    async with async_session_factory() as session:
        # EventModel verification
        event_query = select(EventModel).where(EventModel.id == internal_id)
        ev_res = await session.execute(event_query)
        db_event = ev_res.scalars().first()
        assert db_event is not None
        # Strict security constraint: agent_id MUST be None (no agent impersonation)
        assert db_event.agent_id is None
        assert db_event.source == f"external:{slug}"
        assert db_event.event_type == "EXTERNAL_ALERT"
        assert db_event.severity == "CRITICAL"

        norm_payload = db_event.normalized_payload
        assert norm_payload["is_external"] is True
        assert norm_payload["is_simulation"] is False
        assert norm_payload["provenance"] == "EXTERNAL"
        assert norm_payload["external_source"] == slug

        # Outbox verification
        outbox_query = select(EventOutboxModel).where(EventOutboxModel.event_id == internal_id)
        outbox_res = await session.execute(outbox_query)
        db_outbox = outbox_res.scalars().first()
        assert db_outbox is not None
        assert db_outbox.stream_name == "stream:telemetry:raw"
        assert db_outbox.payload["agent_id"] is None

        # Deduplication tracking verification
        dedup_query = select(InboundEventDedupModel).where(
            InboundEventDedupModel.source_id == test_inbound_source["id"],
            InboundEventDedupModel.external_event_id == ext_event_id,
        )
        dedup_res = await session.execute(dedup_query)
        db_dedup = dedup_res.scalars().first()
        assert db_dedup is not None
        assert str(db_dedup.internal_event_id) == internal_id

    # 3. Duplicate Submission -> Idempotent Acknowledgment
    resp2 = await async_client.post(
        f"/api/v1/integrations/inbound/{slug}/events",
        content=raw_body,
        headers=headers,
    )
    assert resp2.status_code == 202
    data2 = resp2.json()
    assert data2["status"] == "DUPLICATE"
    assert data2["duplicate"] is True
    assert data2["event_id"] == internal_id

    # 4. Verify no second EventModel row exists
    async with async_session_factory() as session:
        count_query = select(EventModel).where(EventModel.source == f"external:{slug}")
        count_res = await session.execute(count_query)
        all_events = count_res.scalars().all()
        assert len(all_events) == 1

        # Verify source metrics
        src = await session.get(InboundSourceModel, test_inbound_source["id"])
        assert src.total_events_received == 2
        assert src.total_events_accepted == 1
        assert src.total_events_deduplicated == 1
        assert src.total_events_rejected == 0


@pytest.mark.asyncio
async def test_multi_source_deduplication_isolation(
    async_client,
    secret_plaintext,
):
    """Verify two distinct sources submitting identical external_event_id are properly isolated."""
    slug_a = f"source-a-{uuid4().hex[:6]}"
    slug_b = f"source-b-{uuid4().hex[:6]}"
    secret_enc = encrypt_destination_secret(secret_plaintext)

    async with async_session_factory() as session:
        s_a = InboundSourceModel(
            id=uuid4(),
            source_id=slug_a,
            name="Source A",
            provider_type="GENERIC",
            shared_secret_enc=secret_enc,
            created_by="admin",
        )
        s_b = InboundSourceModel(
            id=uuid4(),
            source_id=slug_b,
            name="Source B",
            provider_type="GENERIC",
            shared_secret_enc=secret_enc,
            created_by="admin",
        )
        session.add_all([s_a, s_b])
        await session.commit()

    shared_ext_id = "common-threat-alert-001"
    payload = {
        "external_event_id": shared_ext_id,
        "event_type": "EXTERNAL_ALERT",
        "severity": "HIGH",
        "title": "Common Threat Event",
    }

    # Submit to Source A
    body_a, headers_a = _build_signed_request(slug_a, secret_plaintext, payload)
    resp_a = await async_client.post(
        f"/api/v1/integrations/inbound/{slug_a}/events",
        content=body_a,
        headers=headers_a,
    )
    assert resp_a.status_code == 202
    assert resp_a.json()["duplicate"] is False
    id_a = resp_a.json()["event_id"]

    # Submit identical ID to Source B
    body_b, headers_b = _build_signed_request(slug_b, secret_plaintext, payload)
    resp_b = await async_client.post(
        f"/api/v1/integrations/inbound/{slug_b}/events",
        content=body_b,
        headers=headers_b,
    )
    assert resp_b.status_code == 202
    assert resp_b.json()["duplicate"] is False
    id_b = resp_b.json()["event_id"]

    # Both accepted with distinct internal IDs
    assert id_a != id_b


@pytest.mark.asyncio
async def test_response_safety_no_automatic_execution_or_containment(
    async_client,
    test_inbound_source,
):
    """Verify receiving high-severity external alerts does NOT execute response actions

    or bypass Phase 9 approval gates.
    """
    slug = test_inbound_source["slug"]
    secret = test_inbound_source["secret"]

    # Malicious attempt to instruct containment in external payload
    payload = {
        "external_event_id": f"crit-alert-{uuid4().hex[:8]}",
        "event_type": "EXTERNAL_ALERT",
        "severity": "CRITICAL",
        "title": "Ransomware Detected: Isolate Host Immediately",
        "attributes": {
            "recommended_action": "ISOLATE_HOST",
            "target_host": "production-db-01",
            "auto_execute": True,
        },
    }

    raw_body, headers = _build_signed_request(slug, secret, payload)
    resp = await async_client.post(
        f"/api/v1/integrations/inbound/{slug}/events",
        content=raw_body,
        headers=headers,
    )
    assert resp.status_code == 202

    # Verify no response plan or action was executed
    async with async_session_factory() as session:
        actions_res = await session.execute(select(ResponseActionModel))
        actions = actions_res.scalars().all()
        for a in actions:
            # No action should have been automatically executed by inbound event
            assert a.action != "ISOLATE_HOST" or a.status != "COMPLETED"
