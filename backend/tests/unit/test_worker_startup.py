import json
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from waliya.telemetry.consumer_worker import TelemetryConsumerWorker


def test_worker_entrypoint_imports():
    from waliya.worker import run_worker_daemon

    assert callable(run_worker_daemon)


@pytest.mark.asyncio
async def test_malformed_events_are_dead_lettered_without_blocking_valid_batch_items():
    worker = TelemetryConsumerWorker()
    redis = AsyncMock()
    worker.get_redis = AsyncMock(return_value=redis)
    worker.get_active_rules = AsyncMock(return_value=[])
    worker.graph_manager.ingest_event = AsyncMock()

    messages = [
        ("100-0", {"data": json.dumps(["not", "an", "event object"])}),
        (
            "101-0",
            {
                "data": json.dumps({
                    "event_id": str(uuid4()),
                    "agent_id": "not-a-uuid",
                    "event_type": "SYSTEM_LOG",
                    "attributes": {},
                })
            },
        ),
        (
            "102-0",
            {
                "data": json.dumps({
                    "event_id": str(uuid4()),
                    "agent_id": None,
                    "event_type": "SYSTEM_LOG",
                    "attributes": {},
                })
            },
        ),
    ]
    redis.xpending_range.return_value = [
        {"message_id": message_id, "times_delivered": 1}
        for message_id, _ in messages
    ]

    actions = []
    redis.xack.side_effect = lambda _stream, _group, message_id: actions.append(("ack", message_id))
    session = MagicMock()
    session.commit = AsyncMock(side_effect=lambda: actions.append(("commit", None)))

    with patch("waliya.telemetry.consumer_worker.async_session_factory") as session_factory:
        session_factory.return_value.__aenter__.return_value = session
        processed = await worker._process_messages(messages)

    assert processed == 3
    assert redis.xadd.await_count == 2
    assert {call.args[1]["error"] for call in redis.xadd.await_args_list} == {
        "INVALID_EVENT_OBJECT",
        "INVALID_AGENT_ID_UUID",
    }
    assert actions.index(("commit", None)) < actions.index(("ack", "102-0"))
    assert redis.xack.await_count == 3
    worker.graph_manager.ingest_event.assert_awaited_once()


@pytest.mark.asyncio
async def test_abandoned_message_recovery_processes_claimed_entries():
    worker = TelemetryConsumerWorker()
    redis = AsyncMock()
    worker.get_redis = AsyncMock(return_value=redis)
    redis.xautoclaim.return_value = (
        "0-0",
        [("200-0", {"data": "{}"})],
        [],
    )
    worker._process_messages = AsyncMock(return_value=1)

    recovered = await worker.recover_abandoned_messages(count=10)

    assert recovered == 1
    redis.xautoclaim.assert_awaited_once_with(
        worker.stream_name,
        worker.group_name,
        worker.consumer_name,
        min_idle_time=60000,
        start_id="0-0",
        count=10,
    )
    worker._process_messages.assert_awaited_once()
