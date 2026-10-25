"""Persistent replay defense, monotonic sequence tracker, and command idempotency store."""

import json
import logging
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from uuid import UUID

logger = logging.getLogger("waliya_agent.c2.replay")


class ReplayDefenseStore:
    """Durable state storage ensuring replay defense, monotonic sequencing, and idempotency across restarts."""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sequence_tracker (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    highest_sequence INTEGER NOT NULL DEFAULT 0,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            conn.execute(
                """
                INSERT OR IGNORE INTO sequence_tracker (id, highest_sequence)
                VALUES (1, 0);
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS seen_nonces (
                    nonce TEXT PRIMARY KEY,
                    command_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    expires_at TEXT NOT NULL,
                    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_nonces_expiry ON seen_nonces (expires_at);")

            # Command execution history for crash recovery and idempotency
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS command_history (
                    command_id TEXT PRIMARY KEY,
                    sequence INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    exit_code INTEGER NOT NULL DEFAULT 0,
                    output TEXT NOT NULL DEFAULT '',
                    observed_state_json TEXT,
                    receipt_acknowledged INTEGER NOT NULL DEFAULT 0,
                    verification_acknowledged INTEGER NOT NULL DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_history_seq ON command_history (sequence);")

    def get_highest_sequence(self) -> int:
        """Return the highest sequence number observed and accepted so far."""
        with self._lock, self._get_connection() as conn:
            cur = conn.execute("SELECT highest_sequence FROM sequence_tracker WHERE id = 1;")
            row = cur.fetchone()
            return int(row[0]) if row else 0

    @staticmethod
    def validate_timestamps(
        issued_at: datetime,
        expires_at: datetime,
        tolerance_seconds: float = 30.0,
    ) -> Tuple[bool, str]:
        """Validate command issuance and expiry times against current time with clock skew tolerance.

        Does NOT mutate any database or persistent state.
        """
        now_utc = datetime.now(timezone.utc)
        tol = timedelta(seconds=max(0.0, tolerance_seconds))

        if expires_at <= issued_at:
            return False, f"Invalid timestamps: expires_at ({expires_at.isoformat()}) must be after issued_at ({issued_at.isoformat()})"

        # Check if issued too far in the future (beyond clock skew tolerance)
        if issued_at > now_utc + tol:
            return False, f"Command issued in future: issued_at ({issued_at.isoformat()}) > now ({now_utc.isoformat()}) + {tolerance_seconds}s tolerance"

        # Check if already expired (allowing clock skew tolerance)
        if expires_at < now_utc - tol:
            return False, f"Command expired: expires_at ({expires_at.isoformat()}) < now ({now_utc.isoformat()}) - {tolerance_seconds}s tolerance"

        return True, ""

    def get_recorded_command(self, command_id: UUID) -> Optional[Dict[str, Any]]:
        """Retrieve existing command record for idempotency and duplicate delivery checking."""
        cmd_str = str(command_id)
        with self._lock, self._get_connection() as conn:
            cur = conn.execute(
                """
                SELECT command_id, sequence, action, status, exit_code, output,
                       observed_state_json, receipt_acknowledged, verification_acknowledged
                FROM command_history
                WHERE command_id = ?;
                """,
                (cmd_str,),
            )
            row = cur.fetchone()
            if not row:
                return None

            observed = None
            if row[6]:
                try:
                    observed = json.loads(row[6])
                except Exception:
                    pass

            return {
                "command_id": row[0],
                "sequence": row[1],
                "action": row[2],
                "status": row[3],
                "exit_code": row[4],
                "output": row[5],
                "observed_state": observed,
                "receipt_acknowledged": bool(row[7]),
                "verification_acknowledged": bool(row[8]),
            }

    def commit_authenticated_command(
        self,
        sequence: int,
        nonce: UUID,
        command_id: UUID,
        action: str,
        expires_at: datetime,
    ) -> Tuple[bool, str]:
        """Atomically validate sequence monotonicity, nonce uniqueness, and record command acceptance.

        CRITICAL SECURITY REQUIREMENT:
        This method must ONLY be called after cryptographic HMAC-SHA256 signature verification succeeds.
        Unauthenticated commands must NEVER call this method or advance replay state.

        Returns:
            (is_valid, rejection_reason)
        """
        now_utc = datetime.now(timezone.utc)
        nonce_str = str(nonce)
        cmd_str = str(command_id)
        exp_str = expires_at.astimezone(timezone.utc).isoformat()

        with self._lock, self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE;")

            # 1. Check if command_id was already recorded
            cur = conn.execute("SELECT status FROM command_history WHERE command_id = ?;", (cmd_str,))
            if cur.fetchone():
                conn.execute("ROLLBACK;")
                return False, f"Command {cmd_str} was already accepted (idempotency key conflict)"

            # 2. Check monotonic sequence
            cur = conn.execute("SELECT highest_sequence FROM sequence_tracker WHERE id = 1;")
            current_max = int(cur.fetchone()[0])
            if sequence <= current_max:
                conn.execute("ROLLBACK;")
                return (
                    False,
                    f"Command sequence {sequence} is not strictly greater than current sequence {current_max} (sequence replay detected)",
                )

            # 3. Check nonce uniqueness
            cur = conn.execute("SELECT command_id FROM seen_nonces WHERE nonce = ?;", (nonce_str,))
            if cur.fetchone():
                conn.execute("ROLLBACK;")
                return False, f"Command nonce {nonce_str} was already seen (nonce replay attack detected)"

            # Commit sequence tracker update
            conn.execute(
                "UPDATE sequence_tracker SET highest_sequence = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1;",
                (sequence,),
            )

            # Record seen nonce
            conn.execute(
                """
                INSERT INTO seen_nonces (nonce, command_id, sequence, expires_at)
                VALUES (?, ?, ?, ?);
                """,
                (nonce_str, cmd_str, sequence, exp_str),
            )

            # Insert initial command history row
            conn.execute(
                """
                INSERT INTO command_history (command_id, sequence, action, status, exit_code, output)
                VALUES (?, ?, ?, 'ACCEPTED', 0, 'Command authenticated and committed to replay defense');
                """,
                (cmd_str, sequence, action),
            )

            # Prune nonces that expired more than 1 hour ago
            cutoff_prune = (now_utc - timedelta(hours=1)).isoformat()
            conn.execute("DELETE FROM seen_nonces WHERE expires_at < ?;", (cutoff_prune,))

            conn.commit()
            return True, ""

    def validate_and_record_command(
        self,
        sequence: int,
        nonce: UUID,
        command_id: UUID,
        expires_at: datetime,
        action: str = "UNKNOWN",
        clock_skew_tolerance_seconds: float = 0.0,
    ) -> Tuple[bool, str]:
        """Convenience method combining timestamp validation and state commit.

        NOTE: In production runtime pipelines, callers must verify HMAC signatures
        BEFORE calling commit_authenticated_command.
        """
        now_utc = datetime.now(timezone.utc)
        if expires_at < now_utc - timedelta(seconds=max(0.0, clock_skew_tolerance_seconds)):
            return False, f"Command expired: expires_at ({expires_at.isoformat()}) < now ({now_utc.isoformat()})"

        return self.commit_authenticated_command(
            sequence=sequence,
            nonce=nonce,
            command_id=command_id,
            action=action,
            expires_at=expires_at,
        )

    def record_execution_outcome(
        self,
        command_id: UUID,
        status: str,
        exit_code: int,
        output: str,
        observed_state: Optional[Dict[str, Any]] = None,
        receipt_acknowledged: bool = False,
    ) -> None:
        """Persist command execution outcome and observed state for crash recovery."""
        cmd_str = str(command_id)
        observed_json = json.dumps(observed_state) if observed_state is not None else None

        with self._lock, self._get_connection() as conn:
            conn.execute(
                """
                UPDATE command_history
                SET status = ?,
                    exit_code = ?,
                    output = ?,
                    observed_state_json = COALESCE(?, observed_state_json),
                    receipt_acknowledged = CASE WHEN ? THEN 1 ELSE receipt_acknowledged END,
                    updated_at = CURRENT_TIMESTAMP
                WHERE command_id = ?;
                """,
                (status, exit_code, output, observed_json, 1 if receipt_acknowledged else 0, cmd_str),
            )

    def record_verification_outcome(
        self,
        command_id: UUID,
        status: str,
        explanation: str,
        verification_acknowledged: bool = True,
    ) -> None:
        """Persist containment verification outcome."""
        cmd_str = str(command_id)
        with self._lock, self._get_connection() as conn:
            conn.execute(
                """
                UPDATE command_history
                SET status = ?,
                    output = output || ' | Verification: ' || ?,
                    verification_acknowledged = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE command_id = ?;
                """,
                (status, explanation, 1 if verification_acknowledged else 0, cmd_str),
            )

    def reserve_command_for_execution(self, command_id: UUID) -> bool:
        """Atomically transition status from ACCEPTED to EXECUTING to prevent concurrent duplicate execution.

        Returns True if the reservation succeeded, or False if another task already reserved it.
        """
        cmd_str = str(command_id)
        with self._lock, self._get_connection() as conn:
            cur = conn.execute(
                """
                UPDATE command_history
                SET status = 'EXECUTING', updated_at = CURRENT_TIMESTAMP
                WHERE command_id = ? AND status = 'ACCEPTED';
                """,
                (cmd_str,),
            )
            conn.commit()
            return cur.rowcount > 0

    def recover_crashed_and_unacknowledged_commands(self) -> List[Dict[str, Any]]:
        """Recover from crashes: mark interrupted EXECUTING commands as UNCERTAIN, and return pending receipts."""
        with self._lock, self._get_connection() as conn:
            # 1. Any command left in EXECUTING state represents a crash during action execution
            conn.execute(
                """
                UPDATE command_history
                SET status = 'UNCERTAIN',
                    exit_code = 1,
                    output = 'Agent crashed or restarted during command execution. Destructive action not blindly rerun.',
                    updated_at = CURRENT_TIMESTAMP
                WHERE status = 'EXECUTING';
                """
            )
            conn.commit()

            # 2. Query any command where receipt_acknowledged = 0 and status in ('COMPLETED', 'FAILED', 'UNCERTAIN')
            cur = conn.execute(
                """
                SELECT command_id, sequence, action, status, exit_code, output, observed_state_json
                FROM command_history
                WHERE receipt_acknowledged = 0 AND status IN ('COMPLETED', 'FAILED', 'UNCERTAIN');
                """
            )
            rows = cur.fetchall()
            recovered = []
            for r in rows:
                observed = None
                if r[6]:
                    try:
                        observed = json.loads(r[6])
                    except Exception:
                        pass
                recovered.append({
                    "command_id": UUID(r[0]),
                    "sequence": r[1],
                    "action": r[2],
                    "status": "EXECUTED" if r[3] == "COMPLETED" else "FAILED",
                    "exit_code": r[4],
                    "output": r[5],
                    "observed_state": observed,
                })
            return recovered

    def mark_receipt_acknowledged(self, command_id: UUID) -> None:
        """Mark receipt as successfully acknowledged by the server."""
        cmd_str = str(command_id)
        with self._lock, self._get_connection() as conn:
            conn.execute(
                "UPDATE command_history SET receipt_acknowledged = 1, updated_at = CURRENT_TIMESTAMP WHERE command_id = ?;",
                (cmd_str,),
            )

    def mark_verification_acknowledged(self, command_id: UUID) -> None:
        """Mark verification telemetry as successfully acknowledged by the server."""
        cmd_str = str(command_id)
        with self._lock, self._get_connection() as conn:
            conn.execute(
                "UPDATE command_history SET verification_acknowledged = 1, updated_at = CURRENT_TIMESTAMP WHERE command_id = ?;",
                (cmd_str,),
            )
