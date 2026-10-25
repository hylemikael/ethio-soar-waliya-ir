"""Integration tests for detection rules, stream processing worker, and finding persistence."""

import json
import uuid
from datetime import datetime, timezone
import pytest
import pytest_asyncio
from httpx import AsyncClient
from redis.asyncio import Redis
from sqlalchemy import delete, select

from waliya.config import settings
from waliya.contracts import EventTypeEnum, SeverityEnum
from waliya.core.crypto import hash_agent_token
from waliya.db.models import AgentModel, EventModel, EventOutboxModel, FindingModel, RuleModel
from waliya.db.session import async_session_factory
from waliya.detection.builtin_rules import seed_builtin_rules
from waliya.detection.rule_engine import RuleEngine
from waliya.telemetry.consumer_worker import DLQ_STREAM, STREAM_NAME, TelemetryConsumerWorker


@pytest_asyncio.fixture
async def active_agent():
    """Create a verified test agent for telemetry submissions."""
    agent_id = uuid.uuid4()
    raw_token = f"detection-agent-token-{uuid.uuid4().hex}"
    token_hash = hash_agent_token(raw_token, pepper=settings.AGENT_TOKEN_PEPPER)

    agent = AgentModel(
        id=agent_id,
        hostname="waliya-sensor-detect-01",
        os_family="linux",
        os_version="Ubuntu 24.04 LTS",
        primary_ip="192.168.1.50",
        mac_address="00:1A:2B:3C:4D:EE",
        agent_version="2.0.0",
        status="ONLINE",
        api_token_hash=token_hash,
        secret_key_enc="enc_secret_placeholder",
    )

    async with async_session_factory() as session:
        session.add(agent)
        await session.commit()

    yield {"id": agent_id, "token": raw_token}

    # Cleanup
    async with async_session_factory() as session:
        await session.execute(delete(FindingModel).where(FindingModel.agent_id == agent_id))
        await session.execute(delete(EventOutboxModel).where(
            EventOutboxModel.event_id.in_(
                select(EventModel.id).where(EventModel.agent_id == agent_id)
            )
        ))
        await session.execute(delete(EventModel).where(EventModel.agent_id == agent_id))
        await session.execute(delete(AgentModel).where(AgentModel.id == agent_id))
        await session.commit()


@pytest.mark.asyncio
async def test_operational_and_rule_endpoint_authorization(async_client: AsyncClient):
    """Verify that operational and rule-management endpoints fail closed without admin key."""
    # 1. Outbox Flush
    resp_flush_no_auth = await async_client.post("/api/v1/telemetry/outbox/flush")
    assert resp_flush_no_auth.status_code == 401

    resp_flush_bad_auth = await async_client.post(
        "/api/v1/telemetry/outbox/flush",
        headers={"X-Admin-Key": "wrong-secret-key"},
    )
    assert resp_flush_bad_auth.status_code == 403

    resp_flush_ok = await async_client.post(
        "/api/v1/telemetry/outbox/flush",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert resp_flush_ok.status_code == 200

    # 2. Outbox Status
    resp_status_no_auth = await async_client.get("/api/v1/telemetry/outbox/status")
    assert resp_status_no_auth.status_code == 401

    resp_status_ok = await async_client.get(
        "/api/v1/telemetry/outbox/status",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert resp_status_ok.status_code == 200

    # 3. Rule Listing
    resp_rules_no_auth = await async_client.get("/api/v1/rules")
    assert resp_rules_no_auth.status_code == 401

    resp_rules_ok = await async_client.get(
        "/api/v1/rules",
        headers={"Authorization": f"Bearer {settings.ADMIN_API_KEY}"},
    )
    assert resp_rules_ok.status_code == 200

    # 4. Rule Management (Create/Update Rule)
    test_rule_payload = {
        "rule_id": "RULE-TEST-CUSTOM-001",
        "version": 1,
        "name": "Custom Test Rule",
        "description": "Rule created via administrative API",
        "severity": "MEDIUM",
        "event_type": "FILE_INTEGRITY",
        "conditions": [
            {"field": "attributes.file_path", "operator": "CONTAINS", "value": "/tmp/"}
        ],
        "mitre_attack_ids": ["T1059"],
        "dedup_window_seconds": 60,
        "is_active": True,
    }
    resp_create_no_auth = await async_client.post("/api/v1/rules", json=test_rule_payload)
    assert resp_create_no_auth.status_code == 401

    resp_create_ok = await async_client.post(
        "/api/v1/rules",
        json=test_rule_payload,
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert resp_create_ok.status_code == 201
    assert resp_create_ok.json()["rule_id"] == "RULE-TEST-CUSTOM-001"

    # Cleanup test rule
    async with async_session_factory() as session:
        await session.execute(delete(RuleModel).where(RuleModel.rule_id == "RULE-TEST-CUSTOM-001"))
        await session.commit()


@pytest.mark.asyncio
async def test_rule_dry_run_testing_endpoint(async_client: AsyncClient):
    """Verify dry-run rule testing endpoint evaluates matches without persisting findings."""
    test_request = {
        "rule": {
            "rule_id": "RULE-DRY-RUN-001",
            "version": 1,
            "name": "Dry Run Test",
            "description": "Dry run test description",
            "severity": "HIGH",
            "event_type": "PROCESS_EXECUTION",
            "conditions": [
                {"field": "attributes.exe", "operator": "STARTS_WITH", "value": "/bin/"}
            ],
            "dedup_window_seconds": 300,
            "is_active": True,
        },
        "event": {
            "event_id": str(uuid.uuid4()),
            "event_type": "PROCESS_EXECUTION",
            "severity": "LOW",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "sensor",
            "payload": {"exe": "/bin/sh", "pid": 100},
        },
    }

    resp = await async_client.post(
        "/api/v1/rules/test",
        json=test_request,
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert resp.status_code == 200
    res_data = resp.json()
    assert res_data["matched"] is True
    assert res_data["rule_id"] == "RULE-DRY-RUN-001"
    assert len(res_data["matched_conditions"]) == 1


@pytest.mark.asyncio
async def test_stateful_window_rules_bruteforce_and_portscan():
    """Verify stateful sliding-window rules for brute force (>= 5 auth failures) and port scan (>= 10 ports)."""
    redis = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        # 1. Test RULE-AUTH-001-BRUTEFORCE
        attacker_ip = f"10.200.1.{uuid.uuid4().hex[:4]}"
        auth_rule = RuleModel(
            rule_id="RULE-AUTH-001-BRUTEFORCE",
            version=1,
            name="Auth Brute Force",
            description="desc",
            severity="HIGH",
            event_type="AUTHENTICATION",
            conditions=[{"field": "attributes.status", "operator": "EQUALS", "value": "FAILURE"}],
            dedup_window_seconds=300,
            is_active=True,
        )

        # 4 failures (below threshold of 5)
        for _ in range(4):
            event = {
                "event_id": str(uuid.uuid4()),
                "event_type": "AUTHENTICATION",
                "attributes": {"status": "FAILURE", "src_ip": attacker_ip},
            }
            res = await RuleEngine.evaluate_rule(auth_rule, event, redis_client=redis)
            assert res.matched is False

        # 5th failure: threshold reached!
        event5 = {
            "event_id": str(uuid.uuid4()),
            "event_type": "AUTHENTICATION",
            "attributes": {"status": "FAILURE", "src_ip": attacker_ip},
        }
        res5 = await RuleEngine.evaluate_rule(auth_rule, event5, redis_client=redis)
        assert res5.matched is True
        assert any("Authentication failure threshold exceeded" in c for c in res5.matched_conditions)

        # 2. Test RULE-NET-001-PORTSCAN
        scanner_ip = f"10.200.2.{uuid.uuid4().hex[:4]}"
        net_rule = RuleModel(
            rule_id="RULE-NET-001-PORTSCAN",
            version=1,
            name="Port Scan",
            description="desc",
            severity="MEDIUM",
            event_type="NETWORK_CONNECTION",
            conditions=[{"field": "attributes.dst_port", "operator": "GREATER_THAN", "value": 0}],
            dedup_window_seconds=300,
            is_active=True,
        )

        # Scan 9 distinct ports (below threshold of 10)
        for port in range(1, 10):
            event = {
                "event_id": str(uuid.uuid4()),
                "event_type": "NETWORK_CONNECTION",
                "attributes": {"src_ip": scanner_ip, "dst_port": port, "dst_ip": "192.168.1.1"},
            }
            res = await RuleEngine.evaluate_rule(net_rule, event, redis_client=redis)
            assert res.matched is False

        # 10th distinct port: threshold reached!
        event10 = {
            "event_id": str(uuid.uuid4()),
            "event_type": "NETWORK_CONNECTION",
            "attributes": {"src_ip": scanner_ip, "dst_port": 10, "dst_ip": "192.168.1.1"},
        }
        res10 = await RuleEngine.evaluate_rule(net_rule, event10, redis_client=redis)
        assert res10.matched is True
        assert any("Port scan threshold exceeded" in c for c in res10.matched_conditions)

    finally:
        await redis.aclose()


@pytest.mark.asyncio
async def test_end_to_end_telemetry_to_finding_pipeline(
    async_client: AsyncClient,
    active_agent: dict,
):
    """Demonstrate event moving from Ingestion API -> Redis Stream -> Consumer Worker -> PostgreSQL Finding."""
    agent_id = active_agent["id"]
    token = active_agent["token"]

    webshell_event_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc).isoformat()

    # 1. Initialize dedicated consumer group right before sending new event
    test_group = f"test_group_{uuid.uuid4().hex[:6]}"
    worker = TelemetryConsumerWorker(consumer_name=f"test_consumer_{uuid.uuid4().hex[:6]}", group_name=test_group)
    await worker.init_consumer_group(id="$")

    # 2. Ingest event that triggers RULE-FIM-004-WEBSHELL
    batch_payload = {
        "batch_id": str(uuid.uuid4()),
        "agent_id": str(agent_id),
        "events": [
            {
                "event_id": str(webshell_event_id),
                "event_type": EventTypeEnum.FILE_INTEGRITY.value,
                "severity": SeverityEnum.HIGH.value,
                "timestamp": now_utc,
                "source": "fim_ebpf",
                "agent_id": str(agent_id),
                "payload": {
                    "file_path": "/var/www/html/backdoor_shell.php",
                    "action": "CREATED",
                    "sha256": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
                    "size_bytes": 4096,
                    "is_executable": True,
                },
            }
        ],
    }

    ingest_resp = await async_client.post(
        "/api/v1/telemetry/ingest",
        json=batch_payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert ingest_resp.status_code == 200

    # 3. Run Consumer Worker batch iteration
    try:
        processed_count = await worker.process_batch(count=10, block_ms=1000)
        assert processed_count >= 1

        # 4. Verify that a finding was created and committed to PostgreSQL
        async with async_session_factory() as session:
            findings_query = select(FindingModel).where(FindingModel.event_id == webshell_event_id)
            res = await session.execute(findings_query)
            findings = res.scalars().all()

            assert len(findings) >= 1
            webshell_finding = findings[0]
            assert webshell_finding.severity == "HIGH"
            assert "RULE-FIM-004-WEBSHELL" in webshell_finding.explanation["rule_id"]
            assert "/var/www/html/backdoor_shell.php" in webshell_finding.explanation["matched_conditions"][0]
            assert webshell_finding.dedup_key is not None

        # 5. Verify via Findings API endpoint
        api_findings_resp = await async_client.get(
            "/api/v1/rules/findings",
            headers={"X-Admin-Key": settings.ADMIN_API_KEY},
        )
        assert api_findings_resp.status_code == 200
        findings_list = api_findings_resp.json()
        assert any(f["event_id"] == str(webshell_event_id) for f in findings_list)

    finally:
        await worker.close()


@pytest.mark.asyncio
async def test_duplicate_delivery_idempotency(active_agent: dict):
    """Verify that duplicate message delivery does not create duplicate database findings."""
    worker = TelemetryConsumerWorker(consumer_name=f"test_idem_{uuid.uuid4().hex[:6]}")
    event_id = uuid.uuid4()
    agent_id = active_agent["id"]

    # Pre-populate EventModel so foreign key constraint is satisfied
    async with async_session_factory() as session:
        ev = EventModel(
            id=event_id,
            agent_id=agent_id,
            event_type="PROCESS_EXECUTION",
            severity="HIGH",
            timestamp=datetime.now(timezone.utc),
            source="auditd",
            raw_payload={"exe": "/usr/bin/sudo", "username": "attacker", "pid": 5555},
            normalized_payload={"attributes": {"exe": "/usr/bin/sudo", "username": "attacker", "pid": 5555}},
        )
        session.add(ev)
        await session.commit()

    event_payload = {
        "event_id": str(event_id),
        "agent_id": str(agent_id),
        "event_type": "PROCESS_EXECUTION",
        "severity": "HIGH",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "auditd",
        "attributes": {
            "exe": "/usr/bin/sudo",
            "username": "attacker",
            "pid": 5555,
        },
    }

    stream_msg = (
        f"{int(datetime.now().timestamp()*1000)}-0",
        {"data": json.dumps(event_payload)},
    )

    try:
        # First processing iteration
        await worker._process_messages([stream_msg])

        # Verify 1 finding created in PostgreSQL
        async with async_session_factory() as session:
            q = select(FindingModel).where(FindingModel.event_id == event_id)
            res = await session.execute(q)
            initial_count = len(res.scalars().all())
            assert initial_count == 1

        # Second delivery of identical message
        await worker._process_messages([stream_msg])

        # Count MUST remain exactly 1 (idempotent deduplication)
        async with async_session_factory() as session:
            q2 = select(FindingModel).where(FindingModel.event_id == event_id)
            res2 = await session.execute(q2)
            final_count = len(res2.scalars().all())
            assert final_count == 1

    finally:
        await worker.close()


@pytest.mark.asyncio
async def test_dead_letter_queue_handling_for_corrupt_message():
    """Verify corrupt/invalid messages are safely moved to the dead-letter stream without stalling workers."""
    test_group = f"dlq_grp_{uuid.uuid4().hex[:6]}"
    worker = TelemetryConsumerWorker(
        consumer_name=f"test_dlq_{uuid.uuid4().hex[:6]}",
        group_name=test_group,
    )
    redis = Redis.from_url(settings.REDIS_URL, decode_responses=True)

    try:
        await worker.init_consumer_group(id="$")

        # Publish corrupt non-JSON message directly to stream
        msg_id = await redis.xadd(STREAM_NAME, {"data": "NOT_VALID_JSON{{{[["})

        # Worker processes the corrupt entry
        processed = await worker.process_batch(count=5, block_ms=500)
        assert processed >= 1

        # Verify message was routed to DLQ stream
        dlq_entries = await redis.xrange(DLQ_STREAM, "-", "+")
        assert len(dlq_entries) >= 1
        last_dlq = dlq_entries[-1][1]
        assert "JSON_DECODE_ERROR" in last_dlq.get("error", "")

    finally:
        await redis.aclose()
        await worker.close()


@pytest.mark.asyncio
async def test_rule_toggle_status_and_ewma_baselines_api(async_client: AsyncClient):
    """Test enabling/disabling detection rules and querying streaming EWMA baselines."""
    # Ensure builtin rules exist
    async with async_session_factory() as session:
        await seed_builtin_rules(session)

    # 1. Query rules list
    res_rules = await async_client.get(
        "/api/v1/rules",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert res_rules.status_code == 200
    rules = res_rules.json()
    assert len(rules) >= 4
    rule = rules[0]
    rule_id = rule["rule_id"]

    # 2. Toggle status to False
    res_toggle_off = await async_client.patch(
        f"/api/v1/rules/{rule_id}/status",
        json={"is_active": False},
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert res_toggle_off.status_code == 200
    assert res_toggle_off.json()["is_active"] is False

    # 3. Toggle status back to True
    res_toggle_on = await async_client.patch(
        f"/api/v1/rules/{rule_id}/status",
        json={"is_active": True},
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert res_toggle_on.status_code == 200
    assert res_toggle_on.json()["is_active"] is True

    # 4. Query EWMA baselines endpoint
    res_baselines = await async_client.get(
        "/api/v1/rules/analytics/baselines",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert res_baselines.status_code == 200
    data = res_baselines.json()
    assert "baselines" in data
    assert "anomalies" in data
    assert "ewma_configuration" in data
    assert data["ewma_configuration"]["z_threshold"] == 3.0
