"""Tests for agent runtime orchestrator, dry-run command verification, and lifecycle."""

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

import httpx
import pytest

from waliya_agent.c2.crypto import compute_command_signature
from waliya_agent.config import AgentConfig
from waliya_agent.runtime import AgentRuntime


@pytest.mark.asyncio
async def test_runtime_dry_run_command_execution(sample_config: AgentConfig):
    """Test full command lifecycle: poll -> verify signature -> replay check -> dry run receipt."""
    runtime = AgentRuntime(sample_config)

    command_id = uuid4()
    nonce = uuid4()
    now_utc = datetime.now(timezone.utc)
    expires_at = now_utc + timedelta(minutes=5)
    action = "TERMINATE_PROCESS"
    parameters = {"pid": 1337, "process_name": "malicious"}
    sequence = 1

    sig = compute_command_signature(
        command_id=command_id,
        agent_id=sample_config.agent.id,
        action=action,
        parameters=parameters,
        sequence=sequence,
        nonce=nonce,
        issued_at=now_utc,
        expires_at=expires_at,
        secret_key=sample_config.agent.signing_secret,
    )

    cmd_envelope = {
        "command_id": str(command_id),
        "agent_id": str(sample_config.agent.id),
        "action": action,
        "parameters": parameters,
        "sequence": sequence,
        "nonce": str(nonce),
        "issued_at": now_utc.isoformat(),
        "expires_at": expires_at.isoformat(),
        "signature": sig,
    }

    submitted_receipts = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/tasks/poll"):
            return httpx.Response(200, json=cmd_envelope)
        elif request.url.path.endswith("/receipts"):
            data = request.read().decode("utf-8")
            submitted_receipts.append(data)
            return httpx.Response(200, json={"status": "VERIFYING"})
        return httpx.Response(200, json={})

    runtime.c2_client._client = httpx.AsyncClient(
        transport=httpx.MockTransport(mock_handler),
        base_url="http://mock-server:8000",
    )

    # Process command
    await runtime._process_pending_commands()

    # Verify receipt was submitted with status EXECUTED and return code 0
    assert len(submitted_receipts) == 1
    receipt_str = submitted_receipts[0]
    assert "EXECUTED" in receipt_str
    assert str(command_id) in receipt_str
    assert "[DRY-RUN]" in receipt_str

    # Verify sequence was recorded in replay defense
    assert runtime.replay_store.get_highest_sequence() == 1
    await runtime.c2_client.aclose()


@pytest.mark.asyncio
async def test_runtime_tampered_command_rejection(sample_config: AgentConfig):
    """Verify that a command with tampered parameters is rejected and receives FAILED receipt."""
    runtime = AgentRuntime(sample_config)

    command_id = uuid4()
    nonce = uuid4()
    now_utc = datetime.now(timezone.utc)
    expires_at = now_utc + timedelta(minutes=5)
    action = "ISOLATE_HOST"
    parameters = {"direction": "ALL"}
    sequence = 1

    # Valid signature over legitimate params
    sig = compute_command_signature(
        command_id=command_id,
        agent_id=sample_config.agent.id,
        action=action,
        parameters=parameters,
        sequence=sequence,
        nonce=nonce,
        issued_at=now_utc,
        expires_at=expires_at,
        secret_key=sample_config.agent.signing_secret,
    )

    # Attacker alters parameter in transit
    tampered_envelope = {
        "command_id": str(command_id),
        "agent_id": str(sample_config.agent.id),
        "action": action,
        "parameters": {"direction": "NONE", "injected": True},
        "sequence": sequence,
        "nonce": str(nonce),
        "issued_at": now_utc.isoformat(),
        "expires_at": expires_at.isoformat(),
        "signature": sig,
    }

    submitted_receipts = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/tasks/poll"):
            return httpx.Response(200, json=tampered_envelope)
        elif request.url.path.endswith("/receipts"):
            submitted_receipts.append(request.read().decode("utf-8"))
            return httpx.Response(200, json={})
        return httpx.Response(200, json={})

    runtime.c2_client._client = httpx.AsyncClient(
        transport=httpx.MockTransport(mock_handler),
        base_url="http://mock-server:8000",
    )

    await runtime._process_pending_commands()

    # Rejection receipt submitted
    assert len(submitted_receipts) == 1
    assert "FAILED" in submitted_receipts[0]
    assert "signature verification failed" in submitted_receipts[0]

    await runtime.c2_client.aclose()


@pytest.mark.asyncio
async def test_runtime_graceful_shutdown(sample_config: AgentConfig):
    """Verify clean shutdown when request_shutdown is triggered."""
    runtime = AgentRuntime(sample_config)

    # Start run task
    run_task = asyncio.create_task(runtime.run())
    await asyncio.sleep(0.05)

    # Signal shutdown
    runtime.request_shutdown()
    await asyncio.wait_for(run_task, timeout=2.0)

    assert run_task.done()
