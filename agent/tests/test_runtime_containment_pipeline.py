"""End-to-end tests for verified command containment, cryptographic gating, and idempotency."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from waliya_agent.c2.crypto import compute_command_signature
from waliya_agent.config import AgentConfig
from waliya_agent.runtime import AgentRuntime


@pytest.mark.asyncio
async def test_unauthenticated_command_never_advances_sequence(sample_config: AgentConfig):
    """CRITICAL SECURITY INVARIANT:
    An unauthenticated or tampered command must NEVER advance sequence numbers or record nonces in replay defense.
    """
    runtime = AgentRuntime(sample_config)
    assert runtime.replay_store.get_highest_sequence() == 0

    command_id = uuid4()
    nonce = uuid4()
    now_utc = datetime.now(timezone.utc)
    expires_at = now_utc + timedelta(minutes=5)
    sequence = 999  # Attacker attempts to advance sequence to 999 to cause DoS

    # Attacker crafts envelope with an INVALID signature
    forged_envelope = {
        "command_id": str(command_id),
        "agent_id": str(sample_config.agent.id),
        "action": "BLOCK_IP",
        "parameters": {"ip_address": "198.51.100.200"},
        "sequence": sequence,
        "nonce": str(nonce),
        "issued_at": now_utc.isoformat(),
        "expires_at": expires_at.isoformat(),
        "signature": "forged_invalid_signature_hex_1234567890",
    }

    submitted_receipts = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/tasks/poll"):
            return httpx.Response(200, json=forged_envelope)
        elif request.url.path.endswith("/receipts"):
            submitted_receipts.append(request.read().decode("utf-8"))
            return httpx.Response(200, json={})
        return httpx.Response(200, json={})

    runtime.c2_client._client = httpx.AsyncClient(
        transport=httpx.MockTransport(mock_handler),
        base_url="http://mock-server:8000",
    )

    # Process command
    await runtime._process_pending_commands()

    # 1. Receipt must indicate failure due to signature mismatch
    assert len(submitted_receipts) == 1
    assert "FAILED" in submitted_receipts[0]
    assert "signature verification failed" in submitted_receipts[0]

    # 2. CRITICAL: Sequence in replay store must remain 0! Not 999!
    assert runtime.replay_store.get_highest_sequence() == 0

    # 3. Nonce must NOT be recorded
    with runtime.replay_store._lock, runtime.replay_store._get_connection() as conn:
        cur = conn.execute("SELECT COUNT(*) FROM seen_nonces WHERE nonce = ?;", (str(nonce),))
        count = cur.fetchone()[0]
        assert count == 0

    await runtime.c2_client.aclose()


@pytest.mark.asyncio
async def test_duplicate_command_delivery_idempotency(sample_config: AgentConfig):
    """CRITICAL SECURITY INVARIANT:
    Duplicate delivery of the same command_id must re-deliver cached receipts and NEVER re-execute actions.
    """
    runtime = AgentRuntime(sample_config)

    command_id = uuid4()
    nonce = uuid4()
    now_utc = datetime.now(timezone.utc)
    expires_at = now_utc + timedelta(minutes=5)
    action = "COLLECT_FORENSIC_ARTIFACT"
    parameters = {"artifact_type": "LOGS"}
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

    valid_envelope = {
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
    submitted_verifications = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/tasks/poll"):
            return httpx.Response(200, json=valid_envelope)
        elif path.endswith("/receipts"):
            submitted_receipts.append(request.read().decode("utf-8"))
            return httpx.Response(200, json={"status": "VERIFYING"})
        elif path.endswith("/verification"):
            submitted_verifications.append(request.read().decode("utf-8"))
            return httpx.Response(200, json={"status": "VERIFIED_CONTAINED", "explanation": "Artifact captured"})
        return httpx.Response(200, json={})

    runtime.c2_client._client = httpx.AsyncClient(
        transport=httpx.MockTransport(mock_handler),
        base_url="http://mock-server:8000",
    )

    # First pass: normal execution
    await runtime._process_pending_commands()
    assert len(submitted_receipts) == 1
    assert "EXECUTED" in submitted_receipts[0]
    assert len(submitted_verifications) == 1
    assert runtime.replay_store.get_highest_sequence() == 1

    # Second pass: duplicate delivery of the exact same command envelope
    await runtime._process_pending_commands()

    # Must re-send receipt with IDEMPOTENT tag and NOT increment sequence
    assert len(submitted_receipts) == 2
    assert "[IDEMPOTENT RE-DELIVERY]" in submitted_receipts[1]
    assert runtime.replay_store.get_highest_sequence() == 1

    await runtime.c2_client.aclose()


@pytest.mark.asyncio
async def test_verified_containment_two_phase_lifecycle(sample_config: AgentConfig):
    """Verify execution receipt and containment verification are sent to separate endpoints in proper order."""
    runtime = AgentRuntime(sample_config)

    command_id = uuid4()
    nonce = uuid4()
    now_utc = datetime.now(timezone.utc)
    expires_at = now_utc + timedelta(minutes=5)
    action = "BLOCK_IP"
    parameters = {"ip_address": "198.51.100.77", "direction": "BOTH"}
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

    envelope = {
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

    call_order = []
    receipt_data = []
    verification_data = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/tasks/poll"):
            return httpx.Response(200, json=envelope)
        elif path.endswith("/receipts"):
            call_order.append("receipts")
            receipt_data.append(request.read().decode("utf-8"))
            return httpx.Response(200, json={"status": "VERIFYING"})
        elif path.endswith("/verification"):
            call_order.append("verification")
            verification_data.append(request.read().decode("utf-8"))
            return httpx.Response(200, json={"status": "VERIFIED_CONTAINED", "explanation": "Rule verified"})
        return httpx.Response(200, json={})

    runtime.c2_client._client = httpx.AsyncClient(
        transport=httpx.MockTransport(mock_handler),
        base_url="http://mock-server:8000",
    )

    await runtime._process_pending_commands()

    # 1. Verify two-phase ordering: receipt first, then verification
    assert call_order == ["receipts", "verification"]

    # 2. Phase 1: Execution receipt indicates execution succeeded (dry-run)
    assert len(receipt_data) == 1
    assert "EXECUTED" in receipt_data[0]

    # 3. Phase 2: Verification payload contains independent OS evidence (firewall_rules)
    assert len(verification_data) == 1
    assert "firewall_rules" in verification_data[0]
    assert "198.51.100.77" in verification_data[0]
    assert "DROP" in verification_data[0]

    await runtime.c2_client.aclose()
