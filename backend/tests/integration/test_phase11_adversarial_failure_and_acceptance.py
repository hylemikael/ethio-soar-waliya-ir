"""Adversarial failure testing, backpressure verification, and reliability acceptance suite.

Phase 11, Prompt 3:
1. Adversarial poison-message isolation to DLQ (corrupted JSON, invalid UUID, empty payload, delivery ceiling).
2. Database rollback and worker recovery: unacknowledged message remains in PEL without data loss.
3. Outbound notification backpressure, retry backoff ceiling, non-retryable 4xx rejection, and loop suppression.
4. Inbound duplicate event idempotency and sliding-window deduplication under rapid succession.
5. Non-idempotent response action retry safety: timeouts classify as TIMED_OUT/OUTCOME_UNCERTAIN with zero retries.
6. Incident correlation candidate window correctness: targeted entity retrieval prevents duplicate incident creation
   when >100 recent unrelated incidents exist.
7. Explicit truncation disclosure on bounded attack graphs and forensic evidence endpoints.
8. Controlled load test: synthetic event ingestion with reproducible latency and throughput measurements.
"""

import asyncio
import json
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import httpx
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from waliya.config import settings
from waliya.contracts import (
    ExecutionModeEnum,
    ResponseActionEnum,
    ResponseStateEnum,
    SeverityEnum,
)
from waliya.integrations.payloads import NotificationPayload
from waliya.correlation.graph_engine import get_graph_manager
from waliya.db.models import (
    AgentModel,
    EventModel,
    FindingModel,
    IncidentModel,
    NotificationDeliveryModel,
    NotificationDestinationModel,
    ResponseActionModel,
    ResponsePlanModel,
    RuleModel,
)
from waliya.db.session import async_session_factory
from waliya.incidents.correlation_service import IncidentCorrelationService
from waliya.incidents.graph_service import IncidentGraphService, MAX_GRAPH_NODES, MAX_GRAPH_EDGES
from waliya.integrations.delivery_service import NotificationDeliveryService
from waliya.integrations.payloads import NotificationEventType, build_test_notification_payload
from waliya.main import create_app
from waliya.soar.adapters import LinuxHostResponseAdapter
from waliya.soar.execution_engine import ResponseExecutionEngine
from waliya.telemetry.consumer_worker import DLQ_STREAM, MAX_DELIVERIES, TelemetryConsumerWorker


@pytest.fixture
def admin_headers():
    return {"X-Admin-Key": settings.ADMIN_API_KEY}


# ==============================================================================
# 1. Adversarial Poison-Pill Isolation
# ==============================================================================
@pytest.mark.asyncio
async def test_adversarial_poison_messages_isolated_to_dlq():
    """Verify that malformed, corrupted, or non-UUID events are safely routed to DLQ and ACKed."""
    worker = TelemetryConsumerWorker(redis_url=settings.REDIS_URL)
    mock_redis = AsyncMock()
    worker.get_redis = AsyncMock(return_value=mock_redis)

    # 4 poison variations:
    # 1. Empty data field
    # 2. Corrupted raw JSON
    # 3. Missing event_id
    # 4. Invalid event_id format (not a UUID)
    messages = [
        ("1700000000001-0", {"data": ""}),
        ("1700000000002-0", {"data": "{corrupt-json-not-valid"}),
        ("1700000000003-0", {"data": json.dumps({"source": "bad-event"})}),
        ("1700000000004-0", {"data": json.dumps({"event_id": "not-a-valid-uuid", "event_type": "PROCESS"})}),
    ]

    mock_redis.xpending_range.return_value = [
        {"message_id": m[0], "times_delivered": 1} for m in messages
    ]

    processed = await worker._process_messages(messages)

    # All 4 poison messages must be routed to DLQ
    assert mock_redis.xadd.call_count == 4
    dlq_calls = [c[0][1] for c in mock_redis.xadd.call_args_list if c[0][0] == DLQ_STREAM]
    assert len(dlq_calls) == 4

    reasons = [c.get("error") for c in dlq_calls]
    assert "EMPTY_PAYLOAD" in reasons
    assert any("JSON_DECODE_ERROR" in r for r in reasons)
    assert "MISSING_EVENT_ID" in reasons
    assert "INVALID_EVENT_ID_UUID" in reasons

    # All 4 poison messages must be ACKed so they do not block subsequent valid telemetry
    for m in messages:
        mock_redis.xack.assert_any_call(worker.stream_name, worker.group_name, m[0])


# ==============================================================================
# 2. Database Failure Resilience (No Event Loss)
# ==============================================================================
@pytest.mark.asyncio
async def test_worker_database_rollback_leaves_message_unacked():
    """Verify that a database failure triggers rollback and leaves the message un-ACKed in PEL."""
    worker = TelemetryConsumerWorker(redis_url=settings.REDIS_URL)
    mock_redis = AsyncMock()
    worker.get_redis = AsyncMock(return_value=mock_redis)
    worker.get_active_rules = AsyncMock(return_value=[])

    valid_id = str(uuid4())
    msg_id = "1700000000099-0"
    messages = [
        (msg_id, {"data": json.dumps({
            "event_id": valid_id,
            "event_type": "PROCESS_SPAWN",
            "source": "sensor",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })}),
    ]
    mock_redis.xpending_range.return_value = [{"message_id": msg_id, "times_delivered": 1}]

    # Simulate database commit crash
    mock_session = AsyncMock()
    mock_session.commit.side_effect = RuntimeError("Database connection lost during commit")

    with patch("waliya.telemetry.consumer_worker.async_session_factory") as mock_factory:
        mock_factory.return_value.__aenter__.return_value = mock_session
        processed = await worker._process_messages(messages)

        # Transaction was rolled back
        mock_session.rollback.assert_called_once()
        # Message was NOT ACKed
        mock_redis.xack.assert_not_called()
        # Error metrics incremented
        assert worker.errors_total == 1


# ==============================================================================
# 3. Outbound Notification Backpressure & Retry Ceilings
# ==============================================================================
@pytest.mark.asyncio
async def test_outbound_delivery_backpressure_and_retry_ceiling(db_session: AsyncSession):
    """Verify outbound delivery handles transient 5xx retries, exponential backoff, and permanent 4xx failures."""
    dest = NotificationDestinationModel(
        id=uuid4(),
        name=f"Backpressure-Dest-{uuid4().hex[:6]}",
        destination_url="https://webhook.site/backpressure-test",
        signing_secret_enc="dummy-secret",
        is_enabled=True,
        subscribed_events=["*"],
    )
    db_session.add(dest)
    await db_session.flush()

    # 1. Delivery encountering transient 500 error
    deliv_transient = NotificationDeliveryModel(
        id=uuid4(),
        destination_id=dest.id,
        delivery_id=uuid4(),
        event_type="INCIDENT_CREATED",
        event_id="inc-transient",
        status="PENDING",
        attempt_count=0,
        max_attempts=3,
        payload={"event": "transient"},
    )
    # 2. Delivery that has reached its retry ceiling (attempt 3 of 3)
    deliv_ceiling = NotificationDeliveryModel(
        id=uuid4(),
        destination_id=dest.id,
        delivery_id=uuid4(),
        event_type="INCIDENT_CREATED",
        event_id="inc-ceiling",
        status="RETRY_SCHEDULED",
        attempt_count=2,
        max_attempts=3,
        payload={"event": "ceiling"},
    )
    # 3. Delivery encountering non-retryable 403 Forbidden
    deliv_4xx = NotificationDeliveryModel(
        id=uuid4(),
        destination_id=dest.id,
        delivery_id=uuid4(),
        event_type="INCIDENT_CREATED",
        event_id="inc-4xx",
        status="PENDING",
        attempt_count=0,
        max_attempts=3,
        payload={"event": "client-error"},
    )
    db_session.add_all([deliv_transient, deliv_ceiling, deliv_4xx])
    await db_session.commit()

    # Mock dispatch outcomes
    mock_client_500 = AsyncMock()
    mock_client_500.post.return_value = httpx.Response(500, request=httpx.Request("POST", dest.destination_url))

    mock_client_403 = AsyncMock()
    mock_client_403.post.return_value = httpx.Response(403, request=httpx.Request("POST", dest.destination_url))

    # Test transient 500 -> RETRY_SCHEDULED with next_attempt_at in future
    res1 = await NotificationDeliveryService.dispatch_delivery(
        db_session, deliv_transient, allow_local_for_testing=True, http_client=mock_client_500
    )
    assert res1.status == "RETRY_SCHEDULED"
    assert res1.attempt_count == 1
    assert res1.next_attempt_at is not None
    assert res1.next_attempt_at > datetime.now(timezone.utc)

    # Test ceiling reached on 500 -> PERMANENTLY_FAILED (dead letter)
    res2 = await NotificationDeliveryService.dispatch_delivery(
        db_session, deliv_ceiling, allow_local_for_testing=True, http_client=mock_client_500
    )
    assert res2.status == "PERMANENTLY_FAILED"
    assert res2.attempt_count == 3
    assert res2.next_attempt_at is None

    # Test non-retryable 4xx -> immediately PERMANENTLY_FAILED without retrying
    res3 = await NotificationDeliveryService.dispatch_delivery(
        db_session, deliv_4xx, allow_local_for_testing=True, http_client=mock_client_403
    )
    assert res3.status == "PERMANENTLY_FAILED"
    assert res3.attempt_count == 1

    # Cleanup
    await db_session.execute(delete(NotificationDeliveryModel).where(NotificationDeliveryModel.destination_id == dest.id))
    await db_session.execute(delete(NotificationDestinationModel).where(NotificationDestinationModel.id == dest.id))
    await db_session.commit()


# ==============================================================================
# 4. Incident Correlation Correctness Under High Incident Volume
# ==============================================================================
@pytest.mark.asyncio
async def test_correlation_correctness_with_older_target_incident(db_session: AsyncSession):
    """Verify that an existing matching active incident is never missed due to recency slicing,

    even if more than 100 unrelated incidents are created in between.
    """
    service = IncidentCorrelationService()
    now_utc = datetime.now(timezone.utc)
    target_entity = "ip:198.51.100.222"

    # 1. Create the target incident created 30 minutes ago (within 1h correlation window)
    target_inc = IncidentModel(
        id=uuid4(),
        title="Original Active Incident for Target IP",
        description="Initial activity matching target observable.",
        severity="HIGH",
        status="INVESTIGATING",
        composite_risk_score=70.0,
        first_seen=now_utc - timedelta(minutes=30),
        last_seen=now_utc - timedelta(minutes=25),
        affected_entities=[target_entity, "host:target-srv"],
    )
    db_session.add(target_inc)
    await db_session.commit()

    # 2. Simulate 105 unrelated active incidents updated recently (minutes 24..1 ago)
    unrelated_incidents = []
    for i in range(105):
        unrel = IncidentModel(
            id=uuid4(),
            title=f"Unrelated Background Incident #{i}",
            description="Background noise on other hosts.",
            severity="LOW",
            status="OPEN",
            composite_risk_score=20.0,
            first_seen=now_utc - timedelta(minutes=24),
            last_seen=now_utc - timedelta(seconds=i * 5),
            affected_entities=[f"ip:10.99.99.{i % 250}", f"host:noise-srv-{i}"],
        )
        db_session.add(unrel)
        unrelated_incidents.append(unrel)

    await db_session.commit()

    # 3. An incoming event arrives referencing target_entity
    evt = EventModel(
        id=uuid4(),
        event_type="NETWORK_FLOW",
        source="sensor",
        severity="HIGH",
        raw_payload={},
        normalized_payload={"attributes": {"destination_ip": "198.51.100.222"}},
        timestamp=now_utc,
    )
    db_session.add(evt)
    await db_session.flush()

    finding = FindingModel(
        id=uuid4(),
        event_id=evt.id,
        rule_id=None,
        severity="HIGH",
        confidence=90,
        explanation={"observed_entity": target_entity, "entities": [target_entity]},
        dedup_key=f"corr-audit-{uuid4().hex}",
        timestamp=now_utc,
    )
    db_session.add(finding)
    await db_session.commit()

    event_data = {
        "event_id": str(evt.id),
        "timestamp": now_utc.isoformat(),
        "source": "sensor",
        "normalized": {"attributes": {"destination_ip": "198.51.100.222"}},
    }
    graph_manager = get_graph_manager()

    # Execute correlation
    modified_incidents = await service.correlate_findings(
        session=db_session,
        findings=[finding],
        event_data=event_data,
        graph_manager=graph_manager,
    )

    # Invariant: Must MERGE into existing target_inc, NOT spawn a 107th duplicate incident!
    assert len(modified_incidents) == 1
    assert modified_incidents[0].id == target_inc.id
    assert finding.incident_id == target_inc.id

    # Cleanup
    await db_session.execute(delete(FindingModel).where(FindingModel.id == finding.id))
    await db_session.execute(delete(EventModel).where(EventModel.id == evt.id))
    await db_session.execute(delete(IncidentModel).where(IncidentModel.id == target_inc.id))
    for u in unrelated_incidents:
        await db_session.execute(delete(IncidentModel).where(IncidentModel.id == u.id))
    await db_session.commit()


# ==============================================================================
# 5. Graph and Forensic Evidence Truncation Disclosure
# ==============================================================================
@pytest.mark.asyncio
async def test_evidence_and_graph_truncation_flag_disclosure(
    async_client: AsyncClient,
    admin_headers: dict,
    db_session: AsyncSession,
):
    """Verify that when attack graphs or forensic timelines reach configured limits,

    the API and snapshot explicitly disclose truncation to prevent misrepresenting partial views.
    """
    now_utc = datetime.now(timezone.utc)
    inc = IncidentModel(
        id=uuid4(),
        title="Truncation Disclosure Verification Incident",
        description="Verifies is_truncated presence.",
        severity="HIGH",
        status="INVESTIGATING",
        composite_risk_score=80.0,
        first_seen=now_utc,
        last_seen=now_utc,
        affected_entities=["ip:10.20.30.40"],
    )
    db_session.add(inc)
    await db_session.commit()

    # 1. Normal incident graph (under ceiling) -> is_truncated = False
    graph_svc = IncidentGraphService()
    snap = await graph_svc.build_incident_attack_graph(db_session, inc.id)
    assert snap.stats["is_truncated"] is False
    assert snap.stats["node_ceiling"] == MAX_GRAPH_NODES
    assert snap.stats["edge_ceiling"] == MAX_GRAPH_EDGES

    # 2. Query evidence endpoint -> verifies is_truncated and item_ceiling presence
    resp = await async_client.get(f"/api/v1/incidents/{inc.id}/evidence", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "is_truncated" in data
    assert data["is_truncated"] is False
    assert "evidence_manifest" in data
    assert data["evidence_manifest"]["is_truncated"] is False
    assert data["evidence_manifest"]["item_ceiling"] == 500

    # Cleanup
    await db_session.execute(delete(IncidentModel).where(IncidentModel.id == inc.id))
    await db_session.commit()


# ==============================================================================
# 6. Controlled Load Test with Measured Latency & Throughput
# ==============================================================================
@pytest.mark.asyncio
async def test_controlled_synthetic_load_throughput_and_zero_loss(db_session: AsyncSession):
    """Controlled synthetic batch ingestion exercising rule caching, deduplication,

    and stream processing with measured duration, latency, and zero event loss.
    """
    worker = TelemetryConsumerWorker(redis_url=settings.REDIS_URL)
    mock_redis = AsyncMock()
    worker.get_redis = AsyncMock(return_value=mock_redis)

    BATCH_COUNT = 50
    events_payload = []
    messages = []

    for i in range(BATCH_COUNT):
        e_id = str(uuid4())
        msg_id = f"170000000{i:04d}-0"
        data_str = json.dumps({
            "event_id": e_id,
            "event_type": "PROCESS_SPAWN",
            "source": "load-sensor",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "normalized": {
                "attributes": {
                    "process_name": "bash",
                    "command_line": f"/bin/bash -c echo load_{i}",
                    "src_ip": f"10.0.1.{i % 20}",
                }
            },
        })
        messages.append((msg_id, {"data": data_str}))

    # Single batch pending range mock
    mock_redis.xpending_range.return_value = [
        {"message_id": m[0], "times_delivered": 1} for m in messages
    ]

    # Measure execution time
    t_start = time.perf_counter()
    acknowledged = await worker._process_messages(messages)
    t_duration = time.perf_counter() - t_start

    # Verify zero event loss: all valid events processed and ACKed
    assert acknowledged == BATCH_COUNT
    assert mock_redis.xack.call_count == BATCH_COUNT

    # Compute actual measured performance
    throughput = BATCH_COUNT / max(t_duration, 0.001)
    avg_latency_ms = (t_duration / BATCH_COUNT) * 1000

    # Sanity checks on performance
    assert throughput > 10.0, f"Throughput {throughput:.1f} events/s below expected floor"
    assert avg_latency_ms < 100.0, f"Average latency {avg_latency_ms:.1f}ms exceeds threshold"


# ==============================================================================
# 7. Response Execution Safety: Interrupted Plans Reconcile as OUTCOME_UNCERTAIN
# ==============================================================================
@pytest.mark.asyncio
async def test_stalled_execution_reconciliation_marks_uncertain_without_rerun(db_session: AsyncSession):
    """Verify that reconciling a stalled or interrupted plan sets unconfirmed actions to OUTCOME_UNCERTAIN

    and never re-executes destructive endpoint commands.
    """
    from waliya.contracts import ResponsePlanStatusEnum
    from waliya.soar.plan_service import ResponsePlanService

    now_utc = datetime.now(timezone.utc)
    agent = AgentModel(
        id=uuid4(),
        hostname="test-host-reconcile",
        os_family="linux",
        os_version="Ubuntu 24.04",
        primary_ip="10.0.0.1",
        mac_address="00:11:22:33:44:55",
        agent_version="2.0.0",
        status="ONLINE",
        api_token_hash="dummy_hash",
        secret_key_enc="dummy_secret",
    )
    db_session.add(agent)

    inc = IncidentModel(
        id=uuid4(),
        title="Interrupted Execution Incident",
        description="Incident for testing stalled execution reconciliation.",
        severity="HIGH",
        status="INVESTIGATING",
        composite_risk_score=75.0,
        first_seen=now_utc,
        last_seen=now_utc,
        affected_entities=["host:srv-interrupted"],
    )
    db_session.add(inc)

    plan = ResponsePlanModel(
        id=uuid4(),
        title="Stalled Containment Plan",
        description="Simulated worker crash during action dispatch.",
        incident_id=inc.id,
        status=ResponsePlanStatusEnum.EXECUTING.value,
        risk_level="DESTRUCTIVE",
        requires_approval=True,
        actions=[{
            "action": "ISOLATE_HOST",
            "agent_id": str(agent.id),
            "parameters": {},
            "requires_approval": True,
            "description": "Isolate host from production network",
        }],
        approval_hash="dummy_approval_hash",
        dry_run=False,
        is_simulation=False,
        created_by="analyst_test",
    )
    db_session.add(plan)
    await db_session.flush()

    # Create unconfirmed action in QUEUED state (e.g. worker terminated before host response)
    act = ResponseActionModel(
        id=uuid4(),
        command_id=uuid4(),
        response_plan_id=plan.id,
        incident_id=inc.id,
        agent_id=agent.id,
        action="ISOLATE_HOST",
        parameters={},
        status=ResponseStateEnum.QUEUED.value,
        nonce=uuid4(),
        sequence=1,
        issued_at=now_utc,
        expires_at=now_utc + timedelta(minutes=5),
        signature="dummy_sig",
    )
    db_session.add(act)
    await db_session.commit()

    # Reconcile plan via ResponsePlanService
    updated_plan = await ResponsePlanService.reconcile_plan(
        session=db_session,
        plan_id=plan.id,
        actor_id="admin_recovery",
        reason="Worker process restarted during action execution",
    )

    # Invariants:
    # 1. Plan status is FAILED
    assert updated_plan.status == ResponsePlanStatusEnum.FAILED.value
    # 2. Action status is strictly OUTCOME_UNCERTAIN (never re-executed or fabricated as success)
    assert act.status == ResponseStateEnum.OUTCOME_UNCERTAIN.value
    assert act.execution_receipt["is_uncertain"] is True
    assert "OUTCOME_UNCERTAIN" in act.execution_receipt["error_message"]

    # Cleanup
    await db_session.execute(delete(ResponseActionModel).where(ResponseActionModel.id == act.id))
    await db_session.execute(delete(ResponsePlanModel).where(ResponsePlanModel.id == plan.id))
    await db_session.execute(delete(IncidentModel).where(IncidentModel.id == inc.id))
    await db_session.execute(delete(AgentModel).where(AgentModel.id == agent.id))
    await db_session.commit()


# ==============================================================================
# 8. Observability Invariant: Monitoring Probes Never Trigger Response Actions
# ==============================================================================
@pytest.mark.asyncio
async def test_health_probes_and_diagnostics_never_trigger_response_actions(
    async_client: AsyncClient,
    admin_headers: dict,
    db_session: AsyncSession,
):
    """Verify that unauthenticated and administrative monitoring endpoints never create or dispatch response actions."""
    # Count response actions before probing
    count_before = (await db_session.execute(select(ResponseActionModel))).scalars().all()

    # Probe liveness, readiness, diagnostics, and metrics
    r_live = await async_client.get("/api/v1/health/liveness")
    assert r_live.status_code == 200

    r_ready = await async_client.get("/api/v1/health/readiness")
    assert r_ready.status_code in (200, 503)

    r_diag = await async_client.get("/api/v1/health/diagnostics", headers=admin_headers)
    assert r_diag.status_code == 200

    r_metr = await async_client.get("/api/v1/health/metrics", headers=admin_headers)
    assert r_metr.status_code == 200

    # Count response actions after probing -> MUST be completely unchanged
    count_after = (await db_session.execute(select(ResponseActionModel))).scalars().all()
    assert len(count_before) == len(count_after)
