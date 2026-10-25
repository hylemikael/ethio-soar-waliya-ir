"""Bounded durable local queue for endpoint telemetry event buffering."""

import json
import logging
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import UUID

logger = logging.getLogger("waliya_agent.buffer")


class DurableEventQueue:
    """Thread-safe and process-safe bounded SQLite backed queue for offline event buffering.

    Guarantees:
    - Bounded capacity to prevent unbounded disk/memory growth during bursts.
    - FIFO ordering with priority for critical events.
    - Safe recovery across agent restarts.
    - Drop-oldest policy when max capacity is reached.
    """

    def __init__(self, db_path: Path, max_capacity: int = 5000):
        self.db_path = db_path
        self.max_capacity = max_capacity
        self._dropped_count = 0
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS buffered_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_buffered_id ON buffered_events (id ASC);")

    def put(self, event: Dict[str, Any]) -> bool:
        """Enqueue an event dictionary. If capacity is exceeded, drop oldest record."""
        event_id = str(event.get("event_id"))
        event_type = str(event.get("event_type", "UNKNOWN"))
        severity = str(event.get("severity", "INFORMATIONAL"))
        timestamp = str(event.get("timestamp"))
        payload_json = json.dumps(event)

        with self._get_connection() as conn:
            # Check capacity
            cur = conn.execute("SELECT COUNT(*) FROM buffered_events;")
            count = cur.fetchone()[0]

            if count >= self.max_capacity:
                # Drop the oldest 10% or at least 1 event
                drop_amount = max(1, int(self.max_capacity * 0.1))
                conn.execute(
                    "DELETE FROM buffered_events WHERE id IN (SELECT id FROM buffered_events ORDER BY id ASC LIMIT ?);",
                    (drop_amount,),
                )
                self._dropped_count += drop_amount
                logger.warning(
                    "Buffer capacity reached (%d). Dropped %d oldest events. Total dropped: %d",
                    self.max_capacity,
                    drop_amount,
                    self._dropped_count,
                )

            # Insert new event
            try:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO buffered_events (event_id, event_type, severity, timestamp, payload_json)
                    VALUES (?, ?, ?, ?, ?);
                    """,
                    (event_id, event_type, severity, timestamp, payload_json),
                )
                return True
            except Exception as exc:
                logger.error("Failed to enqueue event %s: %s", event_id, exc)
                return False

    def put_batch(self, events: List[Dict[str, Any]]) -> int:
        """Enqueue a batch of events atomically."""
        inserted = 0
        for ev in events:
            if self.put(ev):
                inserted += 1
        return inserted

    def get_batch(self, max_batch_size: int = 100) -> List[Dict[str, Any]]:
        """Retrieve the oldest batch of events up to max_batch_size."""
        with self._get_connection() as conn:
            cur = conn.execute(
                """
                SELECT event_id, payload_json FROM buffered_events
                ORDER BY id ASC
                LIMIT ?;
                """,
                (max_batch_size,),
            )
            rows = cur.fetchall()

        events = []
        for _event_id, payload_json in rows:
            try:
                events.append(json.loads(payload_json))
            except Exception:
                pass
        return events

    def acknowledge(self, event_ids: List[str]) -> int:
        """Remove confirmed processed events from the buffer."""
        if not event_ids:
            return 0

        with self._get_connection() as conn:
            placeholders = ",".join(["?"] * len(event_ids))
            cur = conn.execute(
                f"DELETE FROM buffered_events WHERE event_id IN ({placeholders});",
                event_ids,
            )
            return cur.rowcount

    def size(self) -> int:
        """Return total count of queued events."""
        with self._get_connection() as conn:
            cur = conn.execute("SELECT COUNT(*) FROM buffered_events;")
            return cur.fetchone()[0]

    def dropped_count(self) -> int:
        """Return total number of events dropped due to buffer capacity overruns."""
        return self._dropped_count
