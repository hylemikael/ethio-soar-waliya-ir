"""Tests for bounded durable local event buffer queue."""

from pathlib import Path
from uuid import uuid4

import pytest

from waliya_agent.buffer.queue import DurableEventQueue


def test_queue_put_get_acknowledge(temp_dir: Path):
    """Test basic enqueue, batch retrieval, and acknowledgment workflow."""
    db_file = temp_dir / "events.db"
    queue = DurableEventQueue(db_path=db_file, max_capacity=100)

    # 1. Initially empty
    assert queue.size() == 0

    # 2. Enqueue events
    event1 = {"event_id": str(uuid4()), "event_type": "FILE_INTEGRITY", "timestamp": "2026-10-22T20:00:00Z"}
    event2 = {"event_id": str(uuid4()), "event_type": "PROCESS_EXECUTION", "timestamp": "2026-10-22T20:01:00Z"}

    assert queue.put(event1) is True
    assert queue.put(event2) is True
    assert queue.size() == 2

    # 3. Retrieve batch
    batch = queue.get_batch(max_batch_size=10)
    assert len(batch) == 2
    assert batch[0]["event_id"] == event1["event_id"]
    assert batch[1]["event_id"] == event2["event_id"]

    # 4. Acknowledge first event
    acked = queue.acknowledge([event1["event_id"]])
    assert acked == 1
    assert queue.size() == 1

    remaining = queue.get_batch(max_batch_size=10)
    assert len(remaining) == 1
    assert remaining[0]["event_id"] == event2["event_id"]


def test_queue_capacity_limit_and_drop_oldest(temp_dir: Path):
    """Verify that buffer drops oldest items and updates drop counter when capacity is reached."""
    db_file = temp_dir / "bounded.db"
    # Small capacity of 10
    queue = DurableEventQueue(db_path=db_file, max_capacity=10)

    # Insert 10 events
    for i in range(10):
        queue.put({"event_id": f"event-{i}", "event_type": "AUTH", "timestamp": f"2026-10-22T20:{i:02d}:00Z"})

    assert queue.size() == 10
    assert queue.dropped_count() == 0

    # Insert 11th event -> triggers capacity drop
    queue.put({"event_id": "event-overflow", "event_type": "AUTH", "timestamp": "2026-10-22T21:00:00Z"})

    assert queue.dropped_count() > 0
    # Oldest events (event-0) were dropped
    batch = queue.get_batch(max_batch_size=20)
    assert not any(e["event_id"] == "event-0" for e in batch)
    assert any(e["event_id"] == "event-overflow" for e in batch)


def test_queue_persistence_across_restarts(temp_dir: Path):
    """Verify that unacknowledged queued events survive instance restarts."""
    db_file = temp_dir / "persistent.db"
    q1 = DurableEventQueue(db_path=db_file, max_capacity=100)

    event_id = str(uuid4())
    q1.put({"event_id": event_id, "event_type": "NETWORK", "timestamp": "2026-10-22T20:00:00Z"})
    assert q1.size() == 1

    # Simulate restart with new instance pointing to same file
    q2 = DurableEventQueue(db_path=db_file, max_capacity=100)
    assert q2.size() == 1
    batch = q2.get_batch(max_batch_size=10)
    assert batch[0]["event_id"] == event_id
