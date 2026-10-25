"""Integration tests for performance hardening, backpressure, and failure resilience.

Phase 11, Prompt 2:
1. Active detection rule in-memory caching with TTL to eliminate per-batch SQL overhead.
2. Batched Redis Stream xpending_range queries and poison-pill DLQ routing.
3. Outbound notification HTTP client connection reuse across delivery batches.
4. Bounded active incident correlation candidates (.limit(100)).
5. Resource ceilings for attack graphs (MAX_GRAPH_NODES, MAX_GRAPH_EDGES) and evidence queries (.limit(500)).
6. Non-idempotent response action retry safety under timeouts/uncertain outcomes.
7. Verification of composite performance database indexes in PostgreSQL.
"""

import asyncio
import json
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from waliya.config import settings
from waliya.contracts import ExecutionModeEnum, ResponseActionEnum, ResponseStateEnum
from waliya.db.models import (
    EventModel,
    FindingModel,
    IncidentModel,
    NotificationDeliveryModel,
    NotificationDestinationModel,
)
from waliya.correlation.graph_engine import get_graph_manager
from waliya.incidents.correlation_service import IncidentCorrelationService
from waliya.incidents.graph_service import IncidentGraphService, MAX_GRAPH_NODES, MAX_GRAPH_EDGES
from waliya.integrations.delivery_service import NotificationDeliveryService
from waliya.soar.adapters import LinuxHostResponseAdapter
from waliya.soar.execution_engine import ResponseExecutionEngine
from waliya.telemetry.consumer_worker import DLQ_STREAM, MAX_DELIVERIES, TelemetryConsumerWorker


@pytest.fixture
def admin_headers():
    return {"X-Admin-Key": settings.ADMIN_API_KEY}


@pytest.mark.asyncio
async def test_database_performance_indexes_exist(db_session: AsyncSession):
    """Verify that all Phase 11 composite performance indexes exist in PostgreSQL."""
    res = await db_session.execute(
        text("SELECT indexname FROM pg_indexes WHERE schemaname = 'public'")
    )
    indexes = {row[0] for row in res.fetchall()}

    expected_indexes = [
        "ix_findings_incident_timestamp",
        "ix_findings_dedup_key_timestamp",
        "ix_incidents_status_last_seen",
        "ix_event_outbox_status_created_at",
        "ix_notification_deliveries_status_next_attempt",
        "ix_threat_indicators_type_val_active",
    ]

    for idx in expected_indexes:
        assert idx in indexes, f"Expected composite index '{idx}' not found in database schema"


@pytest.mark.asyncio
async def test_detection_rule_caching_and_ttl(db_session: AsyncSession):
    """Verify that TelemetryConsumerWorker caches active rules in memory and respects TTL."""
    worker = TelemetryConsumerWorker(redis_url=settings.REDIS_URL)

    # 1. Initial state: cache timestamp is 0.0
    assert worker._rules_cached_at == 0.0

    rules_1 = await worker.get_active_rules(db_session)
    assert len(rules_1) > 0
    assert worker._rules_cached_at > 0.0
    first_cached_at = worker._rules_cached_at

    # 2. Subsequent call within TTL returns cached rules without executing SQL query
    with patch.object(db_session, "execute", wraps=db_session.execute) as mock_exec:
        rules_2 = await worker.get_active_rules(db_session)
        assert len(rules_2) == len(rules_1)
        assert worker._rules_cached_at == first_cached_at
        mock_exec.assert_not_called()

    # 3. Simulate TTL expiry (> 60s) using time.monotonic()
    worker._rules_cached_at = time.monotonic() - 65.0
    with patch.object(db_session, "execute", wraps=db_session.execute) as mock_exec:
        rules_3 = await worker.get_active_rules(db_session)
        assert len(rules_3) == len(rules_1)
        assert mock_exec.called
        assert worker._rules_cached_at > first_cached_at


@pytest.mark.asyncio
async def test_batch_xpending_range_and_poison_pill_routing(db_session: AsyncSession):
    """Verify batch xpending_range lookup and poison-pill routing after MAX_DELIVERIES."""
    worker = TelemetryConsumerWorker(redis_url=settings.REDIS_URL)

    mock_redis = AsyncMock()
    worker.get_redis = AsyncMock(return_value=mock_redis)

    msg1_id = "1729000000001-0"
    msg2_id = "1729000000002-0"
    msg3_id = "1729000000003-0"

    messages = [
        (msg1_id, {"data": json.dumps({"event_id": str(uuid4()), "event_type": "PROCESS_SPAWN"})}),
        (msg2_id, {"data": json.dumps({"event_id": str(uuid4()), "event_type": "PROCESS_SPAWN"})}),
        (msg3_id, {"data": json.dumps({"event_id": str(uuid4()), "event_type": "PROCESS_SPAWN"})}),
    ]

    # Return batched pending range where msg2 has exceeded MAX_DELIVERIES (6 > 5)
    mock_redis.xpending_range.return_value = [
        {"message_id": msg1_id, "times_delivered": 1},
        {"message_id": msg2_id, "times_delivered": 6},
        {"message_id": msg3_id, "times_delivered": 2},
    ]

    await worker._process_messages(messages)

    # 1. Verify xpending_range was invoked ONCE as a batch (not once per message)
    assert mock_redis.xpending_range.call_count == 1
    call_kwargs = mock_redis.xpending_range.call_args[1]
    assert call_kwargs["min"] == msg1_id
    assert call_kwargs["max"] == msg3_id
    assert call_kwargs["count"] == 3

    # 2. Verify msg2 (delivery 6) was routed to DLQ with MAX_DELIVERIES_EXCEEDED error
    dlq_calls = [
        c for c in mock_redis.xadd.call_args_list
        if c[0][0] == DLQ_STREAM and c[0][1].get("error") == "MAX_DELIVERIES_EXCEEDED"
    ]
    assert len(dlq_calls) == 1
    assert dlq_calls[0][0][1]["original_id"] == msg2_id

    # 3. Verify msg2 was acknowledged so it stops blocking the consumer group
    mock_redis.xack.assert_any_call(worker.stream_name, worker.group_name, msg2_id)


@pytest.mark.asyncio
async def test_outbound_delivery_client_reuse_and_batch_processing(db_session: AsyncSession):
    """Verify that process_pending_deliveries reuses a single managed AsyncClient across a batch."""
    dest = NotificationDestinationModel(
        id=uuid4(),
        name=f"Perf-Test-Dest-{uuid4().hex[:6]}",
        destination_url="https://webhook.site/perf-test",
        signing_secret_enc="dummy-secret",
        is_enabled=True,
        subscribed_events=["INCIDENT_CREATED"],
    )
    db_session.add(dest)
    await db_session.flush()

    deliveries = []
    for i in range(3):
        deliv = NotificationDeliveryModel(
            id=uuid4(),
            destination_id=dest.id,
            delivery_id=uuid4(),
            event_type="INCIDENT_CREATED",
            event_id=f"inc-perf-{i}",
            status="PENDING",
            attempt_count=0,
            max_attempts=3,
            payload={"test": i},
        )
        db_session.add(deliv)
        deliveries.append(deliv)

    await db_session.commit()

    dispatched_clients = []

    async def mock_dispatch(session, delivery, allow_local_for_testing=False, http_client=None):
        dispatched_clients.append(http_client)
        delivery.status = "DELIVERED"
        delivery.delivered_at = datetime.now(timezone.utc)
        return delivery

    with patch.object(NotificationDeliveryService, "dispatch_delivery", side_effect=mock_dispatch):
        count = await NotificationDeliveryService.process_pending_deliveries(
            session=db_session,
            batch_size=10,
            allow_local_for_testing=True,
        )

        assert count >= 3
        assert len(dispatched_clients) >= 3

        # All dispatches in the batch must share the exact same AsyncClient instance
        first_client = dispatched_clients[0]
        assert first_client is not None
        assert isinstance(first_client, httpx.AsyncClient)
        for cl in dispatched_clients:
            assert cl is first_client

        # The client must be properly closed after batch execution
        assert first_client.is_closed

    # Cleanup
    await db_session.execute(
        delete(NotificationDeliveryModel).where(NotificationDeliveryModel.destination_id == dest.id)
    )
    await db_session.execute(
        delete(NotificationDestinationModel).where(NotificationDestinationModel.id == dest.id)
    )
    await db_session.commit()


@pytest.mark.asyncio
async def test_incident_correlation_window_bounding(db_session: AsyncSession):
    """Verify that IncidentCorrelationService.correlate_findings bounds candidate queries."""
    service = IncidentCorrelationService()

    now_utc = datetime.now(timezone.utc)
    incidents = []
    for i in range(3):
        inc = IncidentModel(
            id=uuid4(),
            title=f"Correlation Bound Test Incident {i}",
            description="Test description for bounded correlation",
            severity="MEDIUM",
            status="OPEN",
            composite_risk_score=50.0,
            first_seen=now_utc - timedelta(minutes=5),
            last_seen=now_utc - timedelta(minutes=1),
            affected_entities=["ip:10.0.0.99"],
        )
        db_session.add(inc)
        incidents.append(inc)

    await db_session.commit()

    # Create EventModel for finding
    evt = EventModel(
        id=uuid4(),
        event_type="PROCESS_SPAWN",
        source="endpoint",
        severity="MEDIUM",
        raw_payload={},
        normalized_payload={"attributes": {"process_name": "curl"}},
        timestamp=now_utc,
    )
    db_session.add(evt)
    await db_session.flush()

    finding = FindingModel(
        id=uuid4(),
        event_id=evt.id,
        rule_id=None,
        severity="MEDIUM",
        confidence=80,
        explanation={"entities": [{"type": "IP", "value": "10.0.0.99"}]},
        dedup_key=f"corr-bound-{uuid4().hex}",
        timestamp=now_utc,
    )
    db_session.add(finding)
    await db_session.commit()

    event_data = {
        "event_id": str(evt.id),
        "timestamp": now_utc.isoformat(),
        "source": "endpoint",
        "normalized": {"attributes": {"destination_ip": "10.0.0.99"}},
    }
    graph_manager = get_graph_manager()

    with patch.object(db_session, "execute", wraps=db_session.execute) as mock_exec:
        result = await service.correlate_findings(db_session, [finding], event_data, graph_manager)
        assert len(result) >= 1

        # Check that the execute call on active incidents applied limit(100)
        found_limited_query = False
        for call in mock_exec.call_args_list:
            stmt = call[0][0]
            if hasattr(stmt, "_limit") and stmt._limit == 100:
                found_limited_query = True
                break
        assert found_limited_query, "Active incident correlation query was not bounded with limit(100)"

    # Cleanup
    await db_session.execute(delete(FindingModel).where(FindingModel.id == finding.id))
    await db_session.execute(delete(EventModel).where(EventModel.id == evt.id))
    for inc in incidents:
        await db_session.execute(delete(IncidentModel).where(IncidentModel.id == inc.id))
    await db_session.commit()


@pytest.mark.asyncio
async def test_incident_graph_and_evidence_resource_ceilings(
    async_client: AsyncClient,
    admin_headers: dict,
    db_session: AsyncSession,
):
    """Verify attack graph and evidence endpoint limits prevent unbounded memory usage."""
    now_utc = datetime.now(timezone.utc)
    inc = IncidentModel(
        id=uuid4(),
        title="Ceiling Test Incident",
        description="Test incident for resource ceiling verification",
        severity="HIGH",
        status="INVESTIGATING",
        composite_risk_score=75.0,
        first_seen=now_utc,
        last_seen=now_utc,
        affected_entities=[{"type": "IP", "value": "10.10.10.10"}],
    )
    db_session.add(inc)
    await db_session.commit()

    # 1. Verify MAX_GRAPH_NODES and MAX_GRAPH_EDGES constants
    assert MAX_GRAPH_NODES == 500
    assert MAX_GRAPH_EDGES == 1000

    # 2. Test build_incident_attack_graph bounds
    graph_svc = IncidentGraphService()
    graph = await graph_svc.build_incident_attack_graph(db_session, inc.id)
    assert len(graph.nodes) <= MAX_GRAPH_NODES
    assert len(graph.edges) <= MAX_GRAPH_EDGES

    # 3. Test evidence API endpoint bounded query
    resp = await async_client.get(f"/api/v1/incidents/{inc.id}/evidence", headers=admin_headers)
    assert resp.status_code == 200
    ev_data = resp.json()
    assert "evidence_manifest" in ev_data
    assert "timeline" in ev_data
    assert len(ev_data["timeline"]) <= 500

    # Cleanup
    await db_session.execute(delete(IncidentModel).where(IncidentModel.id == inc.id))
    await db_session.commit()


@pytest.mark.asyncio
async def test_non_idempotent_retry_safety_on_timeout():
    """Verify that execution engine treats timeouts as OUTCOME_UNCERTAIN and aborts retries."""
    async def mock_timeout_execute(*args, **kwargs):
        raise asyncio.TimeoutError("Simulated remote adapter timeout")

    with patch.object(LinuxHostResponseAdapter, "execute", side_effect=mock_timeout_execute) as mock_exec:
        outcome = await ResponseExecutionEngine.execute_action_step(
            action_type=ResponseActionEnum.TERMINATE_PROCESS,
            parameters={"pid": 9999, "process_name": "malicious_miner"},
            execution_mode=ExecutionModeEnum.PRODUCTION,
            timeout_seconds=1,
        )

        assert outcome.status == ResponseStateEnum.TIMED_OUT
        assert outcome.is_uncertain is True
        assert outcome.attempt_count == 1  # Aborted retries after first attempt
        assert "Execution timed out" in outcome.error_message
        assert mock_exec.call_count == 1  # Destructive action was not retried
