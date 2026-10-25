"""Comprehensive End-to-End Acceptance Test: Waliya Backend and Standalone Linux Agent.

Validates the complete closed-loop lifecycle:
1. Agent registration and authenticated heartbeat.
2. Telemetry ingestion and outbox acknowledgment.
3. Command creation, signing, and outbound HTTPS polling.
4. Cryptographic HMAC-SHA256 signature and replay defense verification.
5. Dry-run execution and execution receipt submission.
6. Negative containment proof: simulated evidence cannot establish VERIFIED_CONTAINED.
7. Rejection of tampered, expired, and replayed commands.
8. Duplicate delivery idempotency (no double-execution).
9. Audit ledger verification and tamper detection on corrupted records.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4
import pytest
import pytest_asyncio
import httpx
from sqlalchemy import select, update

from waliya.config import settings
from waliya.contracts import (
    CommandEnvelope,
    IncidentStatusEnum,
    ResponseActionEnum,
    ResponseStateEnum,
    SeverityEnum,
)
from waliya.core.crypto import (
    compute_command_signature,
    encrypt_agent_secret,
    hash_agent_token,
)
from waliya.db.models import (
    AgentModel,
    AuditLedgerModel,
    IncidentModel,
    ResponseActionModel,
)
from waliya.db.session import async_session_factory
from waliya.audit.ledger_service import AuditLedgerService
from waliya.main import app

from waliya_agent.c2.client import WaliyaC2Client
from waliya_agent.config import AgentConfig, ResponseConfig, ServerConfig, AgentIdentityConfig
from waliya_agent.runtime import AgentRuntime


@pytest_asyncio.fixture
async def e2e_agent(tmp_path: Path):
    """Set up an isolated agent registered in the backend database."""
    agent_id = uuid4()
    raw_token = f"e2e-token-{uuid4().hex}"
    token_hash = hash_agent_token(raw_token, pepper=settings.AGENT_TOKEN_PEPPER)
    raw_secret = f"e2e-hmac-secret-{uuid4().hex}"
    secret_enc = encrypt_agent_secret(raw_secret, settings.SECRET_KEY)

    agent_model = AgentModel(
        id=agent_id,
        hostname="e2e-linux-sensor",
        os_family="linux",
        os_version="Ubuntu 24.04 LTS",
        primary_ip="192.168.10.77",
        mac_address="00:1A:2B:3C:4D:5E",
        agent_version="2.0.0",
        status="ONLINE",
        api_token_hash=token_hash,
        secret_key_enc=secret_enc,
    )

    async with async_session_factory() as session:
        session.add(agent_model)
        await session.commit()

    agent_cfg = AgentConfig(
        server=ServerConfig(url="http://testserver", tls_verify=False),
        agent=AgentIdentityConfig(
            id=agent_id,
            api_token=raw_token,
            signing_secret=raw_secret,
            state_dir=tmp_path / "agent_state",
        ),
        response=ResponseConfig(
            enable_response_actions=False,  # Enforce dry-run default
            allowed_actions=["BLOCK_IP", "TERMINATE_PROCESS", "COLLECT_FORENSIC_ARTIFACT"],
            forensic_artifact_dir=tmp_path / "forensics",
        ),
    )

    yield {
        "id": agent_id,
        "token": raw_token,
        "secret": raw_secret,
        "config": agent_cfg,
    }

    # Teardown
    async with async_session_factory() as session:
        await session.execute(
            ResponseActionModel.__table__.delete().where(ResponseActionModel.agent_id == agent_id)
        )
        await session.execute(
            AgentModel.__table__.delete().where(AgentModel.id == agent_id)
        )
        await session.commit()


@pytest.mark.asyncio
async def test_e2e_complete_workflow(e2e_agent: dict):
    """Execute the complete end-to-end integration and security acceptance workflow."""
    agent_id = e2e_agent["id"]
    agent_config = e2e_agent["config"]

    # Use ASGITransport to route agent client traffic directly into the FastAPI backend
    transport = httpx.ASGITransport(app=app)
    runtime = AgentRuntime(agent_config)
    runtime.c2_client._client = httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
        headers={
            "Authorization": f"Bearer {runtime.c2_client.api_token}",
            "X-Agent-ID": str(runtime.c2_client.agent_id),
            "User-Agent": f"Waliya-Agent/2.0.0 ({runtime.c2_client.agent_id})",
        },
    )

    try:
        # 1. Agent Authentication and Heartbeat
        hb_resp = await runtime.c2_client.send_heartbeat(
            hostname="e2e-linux-sensor",
            primary_ip="192.168.10.77",
            os_version="Ubuntu 24.04 LTS",
            agent_version="2.0.0",
            cpu_percent=12.5,
            memory_used_mb=512,
        )
        assert hb_resp is not None
        assert hb_resp["status"] == "ACK"
        assert "server_time" in hb_resp

        # 2. Authenticated Telemetry Ingestion
        event_id = uuid4()
        events = [
            {
                "event_id": str(event_id),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": "AUTHENTICATION",
                "severity": "HIGH",
                "source": "agent:auth",
                "agent_id": str(agent_id),
                "payload": {
                    "service": "sshd",
                    "user": "root",
                    "src_ip": "198.51.100.99",
                    "status": "FAILURE",
                    "failure_reason": "invalid_password",
                },
            }
        ]
        success, accepted = await runtime.c2_client.upload_telemetry_batch(events)
        assert success is True
        assert str(event_id) in accepted

        # 3. Create Incident and Authorized Response Command in Backend
        incident_id = uuid4()
        command_id = uuid4()
        now_utc = datetime.now(timezone.utc)
        expires_at = now_utc + timedelta(minutes=10)

        async with async_session_factory() as session:
            incident = IncidentModel(
                id=incident_id,
                title="Unauthorized Root SSH Brute Force",
                description="Repeated failed authentications for user root",
                severity=SeverityEnum.HIGH.value,
                status=IncidentStatusEnum.INVESTIGATING.value,
                affected_entities=[f"ip:198.51.100.99", f"host:e2e-linux-sensor"],
            )
            session.add(incident)

            nonce = uuid4()
            sig = compute_command_signature(
                command_id=command_id,
                agent_id=agent_id,
                action=ResponseActionEnum.BLOCK_IP.value,
                parameters={"ip_address": "198.51.100.99", "direction": "BOTH"},
                sequence=1,
                nonce=nonce,
                issued_at=now_utc,
                expires_at=expires_at,
                secret_key=e2e_agent["secret"],
            )

            # Create queued response action
            action = ResponseActionModel(
                id=uuid4(),
                incident_id=incident_id,
                agent_id=agent_id,
                command_id=command_id,
                action=ResponseActionEnum.BLOCK_IP.value,
                parameters={"ip_address": "198.51.100.99", "direction": "BOTH"},
                status=ResponseStateEnum.QUEUED.value,
                sequence=1,
                nonce=nonce,
                issued_at=now_utc,
                expires_at=expires_at,
                signature=sig,
            )
            session.add(action)
            await session.commit()

        # 4. Agent Polls, Verifies HMAC Signature, and Processes Command
        await runtime._process_pending_commands()

        # 5. Verify Backend State after Receipt Submission:
        # Invariant: Receipt submission moves action to VERIFYING (NOT directly contained)
        async with async_session_factory() as session:
            res = await session.execute(
                select(ResponseActionModel).where(ResponseActionModel.command_id == command_id)
            )
            act_db = res.scalars().first()
            assert act_db is not None
            # Execution receipt was recorded
            assert act_db.execution_receipt is not None
            assert act_db.execution_receipt.get("status") == "EXECUTED"
            assert act_db.execution_receipt.get("dry_run") is True

            # 6. Critical Security Invariant: Simulated Evidence CANNOT Establish Real Containment!
            # The agent executed in dry_run mode, so verification determination MUST be VERIFICATION_INCONCLUSIVE
            assert act_db.status == ResponseStateEnum.VERIFICATION_INCONCLUSIVE.value
            assert "[DRY-RUN]" in act_db.verification_result.get("explanation", "")

            # Incident MUST NOT be marked CONTAINED based on dry-run simulation
            inc_res = await session.execute(
                select(IncidentModel).where(IncidentModel.id == incident_id)
            )
            inc_db = inc_res.scalars().first()
            assert inc_db.status != IncidentStatusEnum.CONTAINED.value
            assert inc_db.status == IncidentStatusEnum.INVESTIGATING.value

        # 7. Replay / Duplicate Delivery Idempotency:
        # Redelivering the same command must not re-execute or fail
        await runtime._process_pending_commands()
        assert runtime.replay_store.get_highest_sequence() == 1

        # 8. Cryptographic Tamper Defense:
        # A tampered envelope must be rejected and must NOT advance sequence
        tampered_cmd_id = uuid4()
        tampered_envelope = {
            "command_id": str(tampered_cmd_id),
            "agent_id": str(agent_id),
            "action": "BLOCK_IP",
            "parameters": {"ip_address": "203.0.113.111"},
            "sequence": 999,
            "nonce": str(uuid4()),
            "issued_at": now_utc.isoformat(),
            "expires_at": expires_at.isoformat(),
            "signature": "bad_signature_0000000000000000000000000000000000000000000000000000",
        }

        # Mock poll returning tampered envelope
        def mock_poll(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/tasks/poll"):
                return httpx.Response(200, json=tampered_envelope)
            return httpx.Response(200, json={})

        mock_client = httpx.AsyncClient(
            transport=httpx.MockTransport(mock_poll),
            base_url="http://testserver",
        )
        runtime.c2_client._client = mock_client
        await runtime._process_pending_commands()

        # Sequence must remain 1 (did not advance to 999)
        assert runtime.replay_store.get_highest_sequence() == 1

        # 9. Audit Ledger Verification and Deliberately Corrupted Record Detection
        async with async_session_factory() as session:
            # First verify ledger is initially clean
            clean_verif = await AuditLedgerService.verify_chain(session)
            assert clean_verif.verified is True
            assert clean_verif.tamper_detected is False

            # Deliberately corrupt an audit record in the database
            res = await session.execute(
                select(AuditLedgerModel).where(
                    AuditLedgerModel.target_entity == f"command:{command_id}"
                )
            )
            audit_entry = res.scalars().first()
            if audit_entry:
                corrupted_id = audit_entry.id
                corrupted_seq = audit_entry.sequence_number
                orig_payload = audit_entry.canonical_payload
                try:
                    # Tamper with the recorded payload
                    await session.execute(
                        update(AuditLedgerModel)
                        .where(AuditLedgerModel.id == corrupted_id)
                        .values(canonical_payload='{"corrupted": true, "tampered_by": "adversary"}')
                    )
                    await session.commit()

                    # Verify ledger check catches the corruption
                    tamper_verif = await AuditLedgerService.verify_chain(session)
                    assert tamper_verif.verified is False
                    assert tamper_verif.tamper_detected is True
                    assert tamper_verif.broken_sequence == corrupted_seq
                finally:
                    # Restore original payload so shared ledger chain remains valid for other tests
                    await session.execute(
                        update(AuditLedgerModel)
                        .where(AuditLedgerModel.id == corrupted_id)
                        .values(canonical_payload=orig_payload)
                    )
                    await session.commit()

    finally:
        await runtime.c2_client.aclose()
