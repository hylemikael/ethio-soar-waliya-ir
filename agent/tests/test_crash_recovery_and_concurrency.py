"""Tests for agent crash recovery, idempotency, and concurrency controls."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from waliya_agent.c2.replay import ReplayDefenseStore
from waliya_agent.config import AgentConfig
from waliya_agent.runtime import AgentRuntime


def test_crash_recovery_marks_executing_command_uncertain(tmp_path: Path):
    """Verify that if the agent crashes while an action is executing,
    it is marked UNCERTAIN upon restart and destructive actions are NEVER blindly rerun.
    """
    db_file = tmp_path / "replay.db"
    store1 = ReplayDefenseStore(db_path=db_file)

    cmd_id = uuid4()
    nonce = uuid4()
    future = datetime.now(timezone.utc) + timedelta(minutes=5)

    # 1. Authenticate and commit command
    ok, _ = store1.commit_authenticated_command(
        sequence=1,
        nonce=nonce,
        command_id=cmd_id,
        action="TERMINATE_PROCESS",
        expires_at=future,
    )
    assert ok is True

    # 2. Reserve for execution (moves status to EXECUTING)
    reserved = store1.reserve_command_for_execution(cmd_id)
    assert reserved is True

    # 3. Simulate process crash by dropping store1 without completing outcome
    del store1

    # 4. Agent restarts with new instance
    store2 = ReplayDefenseStore(db_path=db_file)
    recovered = store2.recover_crashed_and_unacknowledged_commands()

    assert len(recovered) == 1
    rec = recovered[0]
    assert rec["command_id"] == cmd_id
    assert rec["status"] == "FAILED"
    assert "Agent crashed" in rec["output"]
    assert "not blindly rerun" in rec["output"]

    # Verify state in DB
    rec_cmd = store2.get_recorded_command(cmd_id)
    assert rec_cmd is not None
    assert rec_cmd["status"] == "UNCERTAIN"


def test_concurrent_reservation_prevents_duplicate_execution(tmp_path: Path):
    """Verify atomic reservation prevents two concurrent tasks from executing the same command."""
    db_file = tmp_path / "replay.db"
    store = ReplayDefenseStore(db_path=db_file)

    cmd_id = uuid4()
    nonce = uuid4()
    future = datetime.now(timezone.utc) + timedelta(minutes=5)

    ok, _ = store.commit_authenticated_command(
        sequence=1,
        nonce=nonce,
        command_id=cmd_id,
        action="BLOCK_IP",
        expires_at=future,
    )
    assert ok is True

    # Task A reserves command
    assert store.reserve_command_for_execution(cmd_id) is True

    # Task B attempts to reserve same command concurrently -> MUST FAIL
    assert store.reserve_command_for_execution(cmd_id) is False


def test_unacknowledged_receipt_retried_on_restart(tmp_path: Path):
    """Verify that completed commands whose receipts were not acknowledged are retried on startup."""
    db_file = tmp_path / "replay.db"
    store1 = ReplayDefenseStore(db_path=db_file)

    cmd_id = uuid4()
    nonce = uuid4()
    future = datetime.now(timezone.utc) + timedelta(minutes=5)

    store1.commit_authenticated_command(
        sequence=1,
        nonce=nonce,
        command_id=cmd_id,
        action="COLLECT_FORENSIC_ARTIFACT",
        expires_at=future,
    )
    store1.reserve_command_for_execution(cmd_id)
    store1.record_execution_outcome(
        command_id=cmd_id,
        status="COMPLETED",
        exit_code=0,
        output="Artifact captured",
        observed_state={"artifact_size_bytes": 1024},
        receipt_acknowledged=False,  # Delivery failed / agent crashed before delivery
    )

    del store1

    # Restart
    store2 = ReplayDefenseStore(db_path=db_file)
    recovered = store2.recover_crashed_and_unacknowledged_commands()

    assert len(recovered) == 1
    assert recovered[0]["command_id"] == cmd_id
    assert recovered[0]["status"] == "EXECUTED"
    assert recovered[0]["observed_state"] == {"artifact_size_bytes": 1024}


@pytest.mark.asyncio
async def test_runtime_recovers_and_delivers_uncertain_receipt(sample_config: AgentConfig):
    """Test full runtime startup recovery of an interrupted command."""
    runtime = AgentRuntime(sample_config)

    cmd_id = uuid4()
    nonce = uuid4()
    future = datetime.now(timezone.utc) + timedelta(minutes=5)

    # Inject an EXECUTING command into the store as if crashed previously
    runtime.replay_store.commit_authenticated_command(
        sequence=1,
        nonce=nonce,
        command_id=cmd_id,
        action="TERMINATE_PROCESS",
        expires_at=future,
    )
    runtime.replay_store.reserve_command_for_execution(cmd_id)

    submitted_receipts = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/receipts"):
            submitted_receipts.append(request.read().decode("utf-8"))
            return httpx.Response(200, json={})
        return httpx.Response(200, json={})

    runtime.c2_client._client = httpx.AsyncClient(
        transport=httpx.MockTransport(mock_handler),
        base_url="http://mock-server:8000",
    )

    # Run recovery
    recovered = runtime.replay_store.recover_crashed_and_unacknowledged_commands()
    assert len(recovered) == 1

    for rec in recovered:
        sent = await runtime.c2_client.submit_receipt(
            command_id=rec["command_id"],
            status=rec["status"],
            exit_code=rec["exit_code"],
            output=rec["output"],
        )
        if sent:
            runtime.replay_store.mark_receipt_acknowledged(rec["command_id"])

    assert len(submitted_receipts) == 1
    receipt_data = submitted_receipts[0]
    assert "FAILED" in receipt_data
    assert "Agent crashed" in receipt_data

    # Verify acknowledged in DB
    rec_cmd = runtime.replay_store.get_recorded_command(cmd_id)
    assert rec_cmd["receipt_acknowledged"] is True

    await runtime.c2_client.aclose()
