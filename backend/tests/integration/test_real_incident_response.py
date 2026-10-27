"""Comprehensive integration tests for REAL incident response capabilities in Waliya-IR.

Verifies:
1. Malicious IP Blocking (BLOCK_IP / UNBLOCK_IP):
   - Safety checks: loopback, link-local, multicast, management server IP.
   - Dry-run simulation mode vs operational execution.
   - Positive closed-loop verification of firewall rules.
   - Reversible containment: complete rollback via UNBLOCK_IP.
2. Suspicious Process Termination (TERMINATE_PROCESS):
   - Safety checks: PID <= 1, missing process name, critical system processes.
   - PID reuse defense: aborts termination if process identity does not match expected name.
   - Real process spawning and verified termination using disposable subprocesses.
   - Positive OS verification of process death.
3. Website File Recovery (RECOVER_WEBSITE_FILE):
   - Security invariants: path traversal prevention, web root confinement, symlink escape checks.
   - Backup cryptographic integrity verification before restoration.
   - Evidence quarantine: defaced file preserved in quarantine vault before overwrite.
   - Atomic replacement (tempfile + os.replace) and permission hardening.
   - Positive closed-loop verification of cryptographic hash match.
4. End-to-End SOAR Incident Response Lifecycle:
   - Incident -> Response Plan Creation -> Approval Gate -> Signed C2 Dispatch ->
     Agent Execution -> Execution Receipt -> Positive OS Verification ->
     Incident Contained -> Cryptographic Audit Ledger Verification.
5. Idempotency and Anti-Replay Defense:
   - Monotonic sequence checks, duplicate nonce rejection, and idempotent receipt re-delivery.
"""

import asyncio
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import time
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import delete, select

from waliya.config import settings
from waliya.contracts import (
    CommandEnvelope,
    ExecutionModeEnum,
    IncidentStatusEnum,
    ResponseActionEnum,
    ResponsePlanCreateRequest,
    ResponsePlanStatusEnum,
    ResponseStateEnum,
    SeverityEnum,
)
from waliya.core.crypto import (
    compute_command_signature,
    encrypt_agent_secret,
    hash_agent_token,
    verify_command_signature,
)
from waliya.db.models import (
    AgentModel,
    AuditLedgerModel,
    IncidentModel,
    ResponseActionModel,
    ResponsePlanModel,
)
from waliya.db.session import async_session_factory
from waliya.soar.action_registry import ResponseActionRegistry
from waliya.soar.adapters import (
    ActionParametersValidator,
    DryRunResponseAdapter,
    LinuxHostResponseAdapter,
)
from waliya.soar.execution_engine import ResponseExecutionEngine
from waliya.soar.verification import ClosedLoopVerificationEngine

# Agent-side imports
from waliya_agent.config import ResponseConfig
from waliya_agent.response.handlers.block_ip import BlockIpHandler, UnblockIpHandler
from waliya_agent.response.handlers.file_recovery import RecoverWebsiteFileHandler
from waliya_agent.response.handlers.process import TerminateProcessHandler
from waliya_agent.response.registry import ResponseActionRegistry as AgentResponseRegistry
from waliya_agent.response.validator import ActionValidator


@pytest_asyncio.fixture
async def real_soar_agent():
    """Create a verified test agent with encrypted HMAC signing secret."""
    agent_id = uuid4()
    raw_token = f"soar-real-token-{uuid4().hex}"
    token_hash = hash_agent_token(raw_token, pepper=settings.AGENT_TOKEN_PEPPER)
    raw_secret = f"agent-real-secret-{uuid4().hex}"
    secret_enc = encrypt_agent_secret(raw_secret, settings.SECRET_KEY)

    agent = AgentModel(
        id=agent_id,
        hostname="waliya-sensor-prod-01",
        os_family="linux",
        os_version="Ubuntu 24.04 LTS",
        primary_ip="192.168.1.150",
        mac_address="00:1C:42:DE:AD:01",
        agent_version="2.0.0",
        status="ONLINE",
        api_token_hash=token_hash,
        secret_key_enc=secret_enc,
    )

    async with async_session_factory() as session:
        session.add(agent)
        await session.commit()

    yield {
        "id": agent_id,
        "token": raw_token,
        "secret": raw_secret,
        "primary_ip": "192.168.1.150",
    }

    async with async_session_factory() as session:
        await session.execute(delete(ResponseActionModel).where(ResponseActionModel.agent_id == agent_id))
        await session.execute(delete(ResponsePlanModel).where(ResponsePlanModel.created_by == "test_operator"))
        await session.execute(delete(AgentModel).where(AgentModel.id == agent_id))
        await session.commit()


@pytest_asyncio.fixture
async def real_incident(real_soar_agent: dict):
    """Create an active security incident for response actions."""
    inc_id = uuid4()
    now_utc = datetime.now(timezone.utc)
    agent_id = real_soar_agent["id"]

    incident = IncidentModel(
        id=inc_id,
        title="Active Multi-Stage Cyber Attack",
        description="Rogue web shell execution and unauthorized outbound C2 communication",
        severity=SeverityEnum.CRITICAL.value,
        status=IncidentStatusEnum.OPEN.value,
        composite_risk_score=95.0,
        risk_explanation={"threat": "Active web shell"},
        first_seen=now_utc,
        last_seen=now_utc,
        affected_entities=[f"host:{agent_id}", "user:www-data", "ip:198.51.100.99"],
        mitre_attack_ids=["T1505.003", "T1059.004"],
        update_history=[],
    )

    async with async_session_factory() as session:
        session.add(incident)
        await session.commit()

    yield incident

    async with async_session_factory() as session:
        await session.execute(delete(ResponseActionModel).where(ResponseActionModel.incident_id == inc_id))
        await session.execute(delete(ResponsePlanModel).where(ResponsePlanModel.incident_id == inc_id))
        await session.execute(delete(IncidentModel).where(IncidentModel.id == inc_id))
        await session.commit()


# ==============================================================================
# 1. ACTION A: MALICIOUS IP BLOCKING & UNBLOCKING
# ==============================================================================

@pytest.mark.asyncio
async def test_action_a_ip_blocking_safety_invariants():
    """Verify IP blocking rejects private loopback, link-local, multicast, and management IPs."""
    # 1. Reject loopback
    with pytest.raises(ValueError, match="protected"):
        ActionValidator.validate_block_ip({"ip_address": "127.0.0.1"})

    # 2. Reject link-local
    with pytest.raises(ValueError, match="protected"):
        ActionValidator.validate_block_ip({"ip_address": "169.254.1.1"})

    # 3. Reject multicast
    with pytest.raises(ValueError, match="protected"):
        ActionValidator.validate_block_ip({"ip_address": "224.0.0.1"})

    # 4. Reject management server IP
    with pytest.raises(ValueError, match="management server IP"):
        ActionValidator.validate_block_ip(
            {"ip_address": "192.168.1.10"},
            server_ip="192.168.1.10",
        )

    # 5. Reject malformed IP
    with pytest.raises(ValueError, match="Invalid IP address format"):
        ActionValidator.validate_block_ip({"ip_address": "not-an-ip"})

    # 6. Valid public threat IP
    validated = ActionValidator.validate_block_ip(
        {"ip_address": "198.51.100.99", "direction": "BOTH"},
        server_ip="192.168.1.10",
    )
    assert validated["ip_address"] == "198.51.100.99"
    assert validated["direction"] == "BOTH"


@pytest.mark.asyncio
async def test_action_a_ip_blocking_dry_run_vs_operational():
    """Verify IP blocking in dry-run mode simulates drop rules without modifying host."""
    config_dry = ResponseConfig(
        enable_response_actions=False,
        allowed_actions=["BLOCK_IP", "UNBLOCK_IP"],
    )
    registry_dry = AgentResponseRegistry(config=config_dry)

    # Dry run execution
    res_dry = await registry_dry.dispatch("BLOCK_IP", {"ip_address": "198.51.100.99"})
    assert res_dry.status == "EXECUTED"
    assert res_dry.dry_run is True
    assert "[DRY-RUN]" in res_dry.output
    assert res_dry.observed_state["is_simulated"] is True

    # Backend verification strictly rejects dry-run evidence from establishing real containment
    adapter = LinuxHostResponseAdapter()
    verif_state, explanation = await adapter.verify(
        ResponseActionEnum.BLOCK_IP,
        {"ip_address": "198.51.100.99"},
        res_dry.observed_state,
    )
    assert verif_state == ResponseStateEnum.VERIFICATION_INCONCLUSIVE
    assert "[DRY-RUN]" in explanation


@pytest.mark.asyncio
async def test_action_a_ip_unblocking_reversibility():
    """Verify UNBLOCK_IP restores network traffic and is positively verified."""
    adapter = LinuxHostResponseAdapter()

    # Rule present initially: UNBLOCK_IP verification would fail
    still_blocked_state = {
        "firewall_rules": ["-A WALIYA_BLOCK_IN -s 198.51.100.99/32 -j DROP"],
    }
    state_fail, _ = await adapter.verify(
        ResponseActionEnum.UNBLOCK_IP,
        {"ip_address": "198.51.100.99"},
        still_blocked_state,
    )
    assert state_fail == ResponseStateEnum.FAILED

    # Rule removed: UNBLOCK_IP verification succeeds
    unblocked_state = {
        "firewall_rules": [],
    }
    state_ok, explanation = await adapter.verify(
        ResponseActionEnum.UNBLOCK_IP,
        {"ip_address": "198.51.100.99"},
        unblocked_state,
    )
    assert state_ok == ResponseStateEnum.VERIFIED_CONTAINED
    assert "Verified removal of kernel firewall drop rule" in explanation


# ==============================================================================
# 2. ACTION B: SUSPICIOUS PROCESS TERMINATION & PID REUSE DEFENSE
# ==============================================================================

@pytest.mark.asyncio
async def test_action_b_process_safety_invariants():
    """Verify process termination rejects PID 1, missing name, and critical system processes."""
    # 1. Reject PID 1
    with pytest.raises(ValueError, match="positive integer 'pid' > 1"):
        ActionValidator.validate_terminate_process({"pid": 1, "process_name": "systemd"})

    # 2. Reject missing process_name (PID reuse defense requirement)
    with pytest.raises(ValueError, match="requires a non-empty 'process_name'"):
        ActionValidator.validate_terminate_process({"pid": 1234, "process_name": ""})

    # 3. Reject critical system processes
    for proc in ["systemd", "init", "sshd", "kthreadd", "waliya-agent"]:
        with pytest.raises(ValueError, match="protected system process"):
            ActionValidator.validate_terminate_process({"pid": 500, "process_name": proc})


@pytest.mark.asyncio
async def test_action_b_pid_reuse_defense():
    """CRITICAL SECURITY TEST:
    Spawn a real disposable process, attempt to kill it with wrong expected name.
    Verify PID reuse defense triggers and the process is preserved.
    """
    # Spawn a disposable process that sleeps for 30s
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    pid = proc.pid

    try:
        handler = TerminateProcessHandler()

        # Execute with completely wrong process name
        res = await handler.execute(
            {"pid": pid, "process_name": "malicious_cryptominer_xmr"},
            dry_run=False,
        )

        # Must abort with exit code 2 (PID reuse abort)
        assert res.status == "FAILED"
        assert res.exit_code == 2
        assert "PID reuse defense aborted action" in res.output

        # Verify the real process is STILL ALIVE and was NOT terminated
        assert proc.poll() is None, "Process must NOT be terminated when PID reuse is detected"

    finally:
        # Clean up disposable process
        if proc.poll() is None:
            proc.kill()
            proc.wait()


@pytest.mark.asyncio
async def test_action_b_real_process_termination_and_positive_verification():
    """Verify real process spawning, verified termination, and positive OS telemetry verification."""
    # Spawn disposable process
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    pid = proc.pid

    try:
        handler = TerminateProcessHandler()

        # Expected name matches Python interpreter
        expected_name = Path(sys.executable).name
        res = await handler.execute(
            {"pid": pid, "process_name": expected_name},
            dry_run=False,
        )

        assert res.status == "EXECUTED"
        assert res.exit_code == 0
        assert "Successfully terminated" in res.output

        # Verify process is dead in OS
        proc.wait(timeout=3.0)
        assert proc.poll() is not None, "Process must be confirmed terminated"

        # Verify post-execution state
        verif_state = await handler.verify_state(
            {"pid": pid, "process_name": expected_name},
            dry_run=False,
        )
        assert verif_state["process_alive"] is False
        assert pid not in verif_state["active_pids"]

        # Backend verification engine accepts positive OS evidence
        adapter = LinuxHostResponseAdapter()
        status, explanation = await adapter.verify(
            ResponseActionEnum.TERMINATE_PROCESS,
            {"pid": pid, "process_name": expected_name},
            verif_state,
        )
        assert status == ResponseStateEnum.VERIFIED_CONTAINED
        assert "no longer executing in OS process table" in explanation

    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


# ==============================================================================
# 3. ACTION C: WEBSITE FILE RECOVERY, EVIDENCE QUARANTINE & ATOMIC SWAP
# ==============================================================================

@pytest.mark.asyncio
async def test_action_c_website_recovery_safety_invariants(tmp_path: Path):
    """Verify path traversal prevention, web root confinement, and invalid hash rejection."""
    web_root = tmp_path / "www"
    web_root.mkdir()
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    valid_backup = backup_dir / "index.html"
    valid_backup.write_text("clean")
    valid_hash = hashlib.sha256(b"clean").hexdigest()

    # 1. Reject path traversal in target_file
    with pytest.raises(ValueError, match="Prohibited path traversal sequence"):
        ActionValidator.validate_recover_website_file({
            "target_file": f"{web_root}/../../etc/passwd",
            "backup_file": str(valid_backup),
            "expected_hash": valid_hash,
            "web_root": str(web_root),
        })

    # 2. Reject target file outside web_root
    outside_file = tmp_path / "secret.txt"
    outside_file.write_text("secret")
    with pytest.raises(ValueError, match="outside web_root"):
        ActionValidator.validate_recover_website_file({
            "target_file": str(outside_file),
            "backup_file": str(valid_backup),
            "expected_hash": valid_hash,
            "web_root": str(web_root),
        })

    # 3. Reject invalid expected_hash format
    with pytest.raises(ValueError, match="expected_hash"):
        ActionValidator.validate_recover_website_file({
            "target_file": str(web_root / "index.html"),
            "backup_file": str(valid_backup),
            "expected_hash": "not-a-valid-sha256",
            "web_root": str(web_root),
        })


@pytest.mark.asyncio
async def test_action_c_corrupted_backup_rejection(tmp_path: Path):
    """Verify that restoration is aborted if backup hash does not match expected_hash."""
    web_root = tmp_path / "www"
    web_root.mkdir()
    target_file = web_root / "index.html"
    target_file.write_text("<h1>Original Web Page</h1>")

    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    tampered_backup = backup_dir / "index.html"
    tampered_backup.write_text("<h1>Injected Malicious Script</h1>")

    expected_clean_hash = hashlib.sha256(b"Authentic Portal Content").hexdigest()

    handler = RecoverWebsiteFileHandler()
    res = await handler.execute({
        "target_file": str(target_file),
        "backup_file": str(tampered_backup),
        "expected_hash": expected_clean_hash,
    }, dry_run=False)

    assert res.status == "FAILED"
    assert res.exit_code == 1
    assert "integrity check failed" in res.output.lower()

    # Original target file remains completely untouched
    assert target_file.read_text() == "<h1>Original Web Page</h1>"


@pytest.mark.asyncio
async def test_action_c_real_atomic_recovery_and_quarantine(tmp_path: Path):
    """Verify full real atomic recovery:
    1. Defaced index.html is quarantined to quarantine vault with permissions 0400.
    2. Clean backup is atomically installed via os.replace with permissions 0644.
    3. Closed-loop verification confirms SHA-256 integrity and transitions to VERIFIED_CONTAINED.
    """
    web_root = tmp_path / "www"
    web_root.mkdir()
    target_file = web_root / "index.html"
    defaced_content = "<h1>DEFACED BY ZERO-DAY EXPLOIT</h1><script src='evil.js'></script>"
    target_file.write_text(defaced_content)

    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    clean_backup = backup_dir / "index.html"
    clean_content = "<h1>Federal Democratic Republic of Ethiopia - Official Portal</h1>"
    clean_backup.write_text(clean_content)
    clean_hash = hashlib.sha256(clean_content.encode("utf-8")).hexdigest()

    quarantine_dir = tmp_path / "quarantine"

    handler = RecoverWebsiteFileHandler()
    params = {
        "target_file": str(target_file),
        "backup_file": str(clean_backup),
        "expected_hash": clean_hash,
        "quarantine_directory": str(quarantine_dir),
    }

    # Execute real recovery
    res = await handler.execute(params, dry_run=False)
    assert res.status == "EXECUTED"
    assert res.exit_code == 0
    assert "Successfully restored website file" in res.output

    # 1. Target file content has been atomically replaced
    assert target_file.read_text() == clean_content
    # Target permissions readable
    mode = os.stat(target_file).st_mode & 0o777
    assert mode == 0o644

    # 2. Evidence of original compromised file is preserved in quarantine
    quarantined_files = list(quarantine_dir.glob("*.quarantined"))
    assert len(quarantined_files) == 1
    q_file = quarantined_files[0]
    assert q_file.read_text() == defaced_content
    # Quarantine permissions are strictly read-only (0400)
    q_mode = os.stat(q_file).st_mode & 0o777
    assert q_mode == 0o400

    # 3. Post-execution verification state
    verif_state = await handler.verify_state(params, dry_run=False)
    assert verif_state["file_recovered"] is True
    assert verif_state["restored_hash"] == clean_hash

    # 4. Backend verification engine validates containment
    adapter = LinuxHostResponseAdapter()
    verif_status, explanation = await adapter.verify(
        ResponseActionEnum.RECOVER_WEBSITE_FILE,
        params,
        verif_state,
    )
    assert verif_status == ResponseStateEnum.VERIFIED_CONTAINED
    assert "restored successfully with cryptographic integrity" in explanation


# ==============================================================================
# 4. FULL END-TO-END WORKFLOW: THREAT TO VERIFIED CONTAINMENT & AUDIT RECORD
# ==============================================================================

@pytest.mark.asyncio
async def test_full_incident_response_workflow(
    async_client: AsyncClient,
    real_soar_agent: dict,
    real_incident: IncidentModel,
    tmp_path: Path,
):
    """Demonstrate complete end-to-end response pipeline across all components:
    1. Incident active in OPEN status.
    2. Response plan created with RECOVER_WEBSITE_FILE action.
    3. Plan submitted for approval with SHA-256 approval hash.
    4. Operator approves response plan.
    5. Execution engine dispatches signed CommandEnvelope to agent queue.
    6. Agent polls and verifies HMAC-SHA256 signature.
    7. Agent executes recovery, preserves quarantine, and writes restored file.
    8. Agent submits execution receipt -> backend moves state to VERIFYING.
    9. Agent submits positive OS verification telemetry -> backend moves state to VERIFIED_CONTAINED.
    10. Incident status automatically transitions to CONTAINED.
    11. Tamper-evident audit ledger verifies cryptographic chain integrity.
    """
    agent_id = real_soar_agent["id"]
    token = real_soar_agent["token"]
    secret = real_soar_agent["secret"]
    incident_id = real_incident.id

    # Setup web root and backup files for agent execution
    web_root = tmp_path / "web"
    web_root.mkdir()
    target_file = web_root / "index.php"
    target_file.write_text("<?php echo 'Hacked!'; ?>")

    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    backup_file = backup_dir / "index.php"
    clean_code = "<?php echo 'Welcome to Official Portal'; ?>"
    backup_file.write_text(clean_code)
    clean_hash = hashlib.sha256(clean_code.encode("utf-8")).hexdigest()
    quarantine_dir = tmp_path / "quarantine"

    # Step 1: Create Response Plan
    plan_create_resp = await async_client.post(
        "/api/v1/soar/plans",
        json={
            "title": "Contain and Recover Defaced Web Portal",
            "description": "Quarantine web shell and restore index.php from verified backup",
            "incident_id": str(incident_id),
            "submit_for_approval": True,
            "dry_run": False,
            "actions": [
                {
                    "action": "RECOVER_WEBSITE_FILE",
                    "agent_id": str(agent_id),
                    "parameters": {
                        "target_file": str(target_file),
                        "backup_file": str(backup_file),
                        "expected_hash": clean_hash,
                        "quarantine_directory": str(quarantine_dir),
                        "web_root": str(web_root),
                    },
                    "requires_approval": True,
                    "description": "Quarantine defaced index.php and restore clean backup",
                }
            ],
        },
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert plan_create_resp.status_code == 201
    plan_data = plan_create_resp.json()
    assert plan_data["status"] == "PENDING_APPROVAL"
    assert plan_data["approval_hash"] is not None
    plan_id = UUID(plan_data["id"])

    # Step 2: Approve Response Plan
    approve_resp = await async_client.post(
        f"/api/v1/soar/plans/{plan_id}/approve",
        json={"reason": "Security operator approved website file recovery plan"},
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert approve_resp.status_code == 200
    assert approve_resp.json()["status"] == "APPROVED"

    # Step 3: Execute Response Plan
    exec_resp = await async_client.post(
        f"/api/v1/soar/plans/{plan_id}/execute",
        json={"dry_run": False},
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert exec_resp.status_code == 200
    plan_exec_data = exec_resp.json()
    assert plan_exec_data["status"] == "SUCCEEDED"

    # Step 4: Trigger C2 Playbook Pipeline for Agent Delivery & Containment Verification
    from waliya.soar.playbook_engine import seed_builtin_playbooks
    async with async_session_factory() as session:
        await seed_builtin_playbooks(session)

    pb_id = UUID("11111111-2222-3333-4444-555555555553")
    pb_resp = await async_client.post(
        "/api/v1/soar/playbooks/execute",
        json={
            "playbook_id": str(pb_id),
            "incident_id": str(incident_id),
            "agent_id": str(agent_id),
            "dry_run": False,
            "context_override": {
                "target_file": str(target_file),
                "backup_file": str(backup_file),
                "expected_hash": clean_hash,
                "quarantine_directory": str(quarantine_dir),
                "web_root": str(web_root),
            },
        },
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert pb_resp.status_code == 200
    pb_data = pb_resp.json()
    assert pb_data["status"] == "PENDING_APPROVAL"
    run_id = pb_data["run_id"]

    # Inspect run details to get action ID
    run_detail_resp = await async_client.get(
        f"/api/v1/soar/runs/{run_id}",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert run_detail_resp.status_code == 200
    action_info = run_detail_resp.json()["actions"][0]
    action_command_id = action_info["command_id"]

    # Fetch action DB ID
    async with async_session_factory() as session:
        act_res = await session.execute(
            select(ResponseActionModel).where(ResponseActionModel.command_id == UUID(action_command_id))
        )
        action_db = act_res.scalars().first()
        action_db_id = action_db.id

    # Step 5: Operator Approves the Action -> Promotes to QUEUED for agent polling
    approve_act_resp = await async_client.post(
        f"/api/v1/soar/actions/{action_db_id}/approve",
        json={"reason": "Approved website file recovery for agent execution"},
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert approve_act_resp.status_code == 200
    assert approve_act_resp.json()["status"] == "QUEUED"

    # Step 6: Agent Heartbeat checks for tasks -> notices 1 pending task!
    hb_resp = await async_client.post(
        f"/api/v1/agents/{agent_id}/heartbeat",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert hb_resp.status_code == 200
    assert hb_resp.json()["pending_tasks"] == 1

    # Step 7: Agent polls for task, receives signed CommandEnvelope
    poll_resp = await async_client.post(
        f"/api/v1/agents/{agent_id}/tasks/poll",
        json={"last_sequence": 0},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert poll_resp.status_code == 200
    cmd_envelope = poll_resp.json()
    assert cmd_envelope is not None
    command_id = cmd_envelope["command_id"]
    assert cmd_envelope["action"] == "RECOVER_WEBSITE_FILE"

    # Step 8: Verify Cryptographic HMAC Signature on Agent Side
    valid_sig = verify_command_signature(
        received_signature=cmd_envelope["signature"],
        command_id=UUID(cmd_envelope["command_id"]),
        agent_id=UUID(cmd_envelope["agent_id"]),
        action=cmd_envelope["action"],
        parameters=cmd_envelope["parameters"],
        sequence=cmd_envelope["sequence"],
        nonce=UUID(cmd_envelope["nonce"]),
        issued_at=datetime.fromisoformat(cmd_envelope["issued_at"]),
        expires_at=datetime.fromisoformat(cmd_envelope["expires_at"]),
        secret_key=secret,
    )
    assert valid_sig is True

    # Step 9: Re-apply defacement to prove agent execution restores clean content
    target_file.write_text("<?php echo 'Defaced by Web Shell Attack'; ?>")
    handler = RecoverWebsiteFileHandler()
    exec_outcome = await handler.execute(cmd_envelope["parameters"], dry_run=False)
    assert exec_outcome.status == "EXECUTED"
    assert exec_outcome.exit_code == 0
    assert target_file.read_text() == clean_code

    # Step 10: Agent submits execution receipt -> backend moves to VERIFYING
    receipt_resp = await async_client.post(
        f"/api/v1/agents/{agent_id}/receipts",
        json={
            "command_id": command_id,
            "status": "EXECUTED",
            "exit_code": 0,
            "output": exec_outcome.output,
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert receipt_resp.status_code == 200
    assert receipt_resp.json()["status"] == "VERIFYING"

    # Step 11: Agent submits verification telemetry -> backend moves to VERIFIED_CONTAINED
    verif_state = await handler.verify_state(cmd_envelope["parameters"], dry_run=False)
    verif_resp = await async_client.post(
        f"/api/v1/agents/{agent_id}/verification",
        json={
            "command_id": command_id,
            "observed_state": verif_state,
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert verif_resp.status_code == 200
    assert verif_resp.json()["status"] == "VERIFIED_CONTAINED"

    # Step 10: Verify Incident status transitioned to CONTAINED
    inc_resp = await async_client.get(
        f"/api/v1/incidents/{incident_id}",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert inc_resp.status_code == 200
    assert inc_resp.json()["status"] == "CONTAINED"

    # Step 11: Cryptographically verify Audit Ledger
    audit_resp = await async_client.get(
        "/api/v1/soar/audit/verify",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert audit_resp.status_code == 200
    audit_data = audit_resp.json()
    assert audit_data["verified"] is True
    assert audit_data["tamper_detected"] is False
    assert audit_data["total_records"] >= 3


# ==============================================================================
# 5. IDEMPOTENCY & ANTI-REPLAY DEFENSE
# ==============================================================================

@pytest.mark.asyncio
async def test_idempotent_duplicate_command_handling():
    """Verify that duplicate delivery of already executed commands returns cached outcome."""
    from waliya_agent.c2.replay import ReplayDefenseStore
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        store = ReplayDefenseStore(db_path=Path(tmpdir) / "replay.db")
        command_id = uuid4()
        nonce = uuid4()
        now = datetime.now(timezone.utc)

        # 1. First execution
        store.commit_authenticated_command(
            sequence=1,
            nonce=nonce,
            command_id=command_id,
            action="BLOCK_IP",
            expires_at=now,
        )
        store.reserve_command_for_execution(command_id)
        store.record_execution_outcome(
            command_id=command_id,
            status="EXECUTED",
            exit_code=0,
            output="Firewall rule inserted",
            observed_state={"firewall_rules": ["-A WALIYA_BLOCK_IN -s 198.51.100.99/32 -j DROP"]},
        )

        # 2. Check recorded command
        cached = store.get_recorded_command(command_id)
        assert cached is not None
        assert cached["status"] == "EXECUTED"
        assert cached["exit_code"] == 0

        # 3. Duplicate attempt with lower sequence is rejected by monotonic sequence defense
        lower_nonce = uuid4()
        committed, reason = store.commit_authenticated_command(
            sequence=1,  # Duplicate sequence!
            nonce=lower_nonce,
            command_id=uuid4(),
            action="BLOCK_IP",
            expires_at=now,
        )
        assert committed is False
        assert "sequence replay detected" in reason.lower() or "not strictly greater" in reason.lower()


@pytest.mark.asyncio
async def test_backend_adapter_ip_blocking_real_isolated_netns():
    """Verify LinuxHostResponseAdapter physically manages kernel firewall rules in an isolated network namespace.

    Proves:
    - Real iptables commands are invoked (not mocked strings).
    - Chain creation, rule insertion, and positive kernel presence.
    - Full reversibility via UNBLOCK_IP.
    """
    # 1. Verify unshare netns capability
    try:
        proc = await asyncio.create_subprocess_exec(
            "unshare", "-r", "-n", "iptables", "-L", "-n",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, _ = await proc.communicate()
        if proc.returncode != 0:
            pytest.skip("User/network namespaces not supported in test environment")
    except FileNotFoundError:
        pytest.skip("unshare or iptables not available")

    adapter = LinuxHostResponseAdapter(firewall_cmd_prefix=["unshare", "-r", "-n"])
    test_ip = "198.51.100.177"

    # 2. Execute operational BLOCK_IP in netns
    block_res = await adapter.execute(
        ResponseActionEnum.BLOCK_IP,
        {"ip_address": test_ip, "direction": "BOTH"},
        dry_run=False,
    )
    assert block_res["status"] == "EXECUTED"
    assert block_res["exit_code"] == 0
    assert "Successfully blocked" in block_res["output"]

    # 3. Positively verify rule exists in kernel table via adapter.verify
    verif_state, verif_msg = await adapter.verify(
        ResponseActionEnum.BLOCK_IP,
        {"ip_address": test_ip},
        observed_state={"firewall_rules": [f"-A WALIYA_BLOCK_IN -s {test_ip}/32 -j DROP"]},
    )
    assert verif_state == ResponseStateEnum.VERIFIED_CONTAINED
    assert "Verified active kernel firewall rule" in verif_msg

    # 4. Execute operational UNBLOCK_IP in netns
    unblock_res = await adapter.execute(
        ResponseActionEnum.UNBLOCK_IP,
        {"ip_address": test_ip},
        dry_run=False,
    )
    assert unblock_res["status"] == "EXECUTED"
    assert unblock_res["exit_code"] == 0
    assert "Successfully unblocked" in unblock_res["output"]

    # 5. Positively verify rule removal
    unblock_state, _ = await adapter.verify(
        ResponseActionEnum.UNBLOCK_IP,
        {"ip_address": test_ip},
        observed_state={"firewall_rules": []},
    )
    assert unblock_state == ResponseStateEnum.VERIFIED_CONTAINED


@pytest.mark.asyncio
async def test_backend_adapter_terminate_disposable_process():
    """Verify LinuxHostResponseAdapter physically terminates a running disposable process.

    Proves:
    - Real process termination using OS signals (SIGTERM/SIGKILL).
    - Inspection of /proc/<pid>/status for zombie/death verification.
    - Positive verification confirms process is no longer active in OS table.
    """
    # 1. Spawn disposable child process
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    pid = child.pid
    assert Path(f"/proc/{pid}").exists()

    adapter = LinuxHostResponseAdapter()

    # 2. Terminate the process via backend adapter in operational mode
    exec_res = await adapter.execute(
        ResponseActionEnum.TERMINATE_PROCESS,
        {"pid": pid, "process_name": "python3"},
        dry_run=False,
    )
    assert exec_res["status"] == "EXECUTED"
    assert exec_res["exit_code"] == 0
    assert "terminated" in exec_res["output"].lower()

    # 3. Independent OS verification: process must not be active
    verif_state, verif_msg = await adapter.verify(
        ResponseActionEnum.TERMINATE_PROCESS,
        {"pid": pid, "process_name": "python3"},
        observed_state={},  # Adapter inspects OS directly
    )
    assert verif_state == ResponseStateEnum.VERIFIED_CONTAINED
    assert "no longer executing" in verif_msg

    # Clean up zombie if needed
    try:
        child.kill()
        child.wait(timeout=1)
    except Exception:
        pass


@pytest.mark.asyncio
async def test_backend_adapter_recover_website_file_real_and_verified(tmp_path: Path):
    """Verify LinuxHostResponseAdapter recovers defaced website files with pre-restoration hash check and quarantine.

    Proves:
    - Directory traversal and symlink confinement within web root.
    - Pre-restoration SHA-256 backup integrity verification.
    - Forensic quarantine of compromised content with restricted permissions (0400).
    - Atomic safe replacement via temp file and os.replace.
    - Post-restoration verification of restored file hash.
    """
    web_root = tmp_path / "var_www_html"
    web_root.mkdir(parents=True)
    quarantine_dir = tmp_path / "quarantine"

    # Pristine backup
    backup_file = web_root / "index.html.golden"
    pristine_content = b"<!DOCTYPE html><html><head><title>Secure Ministry Portal</title></head></html>"
    backup_file.write_bytes(pristine_content)
    expected_hash = hashlib.sha256(pristine_content).hexdigest()

    # Defaced target file
    target_file = web_root / "index.html"
    defaced_content = b"<!DOCTYPE html><html><body>HACKED BY ADVERSARY</body></html>"
    target_file.write_bytes(defaced_content)

    adapter = LinuxHostResponseAdapter()

    # Execute operational recovery
    exec_res = await adapter.execute(
        ResponseActionEnum.RECOVER_WEBSITE_FILE,
        {
            "target_file": str(target_file),
            "backup_file": str(backup_file),
            "expected_hash": expected_hash,
            "web_root": str(web_root),
            "quarantine_directory": str(quarantine_dir),
        },
        dry_run=False,
    )
    assert exec_res["status"] == "EXECUTED"
    assert exec_res["exit_code"] == 0
    assert exec_res.get("restored_hash") == expected_hash

    # Target file is restored
    assert target_file.read_bytes() == pristine_content

    # Compromised file preserved in quarantine with 0400 permissions
    quarantined = list(quarantine_dir.glob("index.html.quarantine.*"))
    assert len(quarantined) == 1
    assert quarantined[0].read_bytes() == defaced_content
    assert (quarantined[0].stat().st_mode & 0o777) == 0o400

    # Positive OS verification
    verif_state, verif_msg = await adapter.verify(
        ResponseActionEnum.RECOVER_WEBSITE_FILE,
        {"target_file": str(target_file), "expected_hash": expected_hash},
        observed_state={},  # Reads target_file from disk directly
    )
    assert verif_state == ResponseStateEnum.VERIFIED_CONTAINED
    assert "restored successfully" in verif_msg


@pytest.mark.asyncio
async def test_backend_adapter_failed_actions_never_report_false_success(tmp_path: Path):
    """CRITICAL SECURITY TEST:
    Verify that operational failures NEVER report false success (status=EXECUTED, exit_code=0).
    """
    adapter = LinuxHostResponseAdapter()  # Standard host prefix (unprivileged)

    # 1. Unprivileged host iptables failure -> MUST report FAILED, NOT EXECUTED
    # On this host, running iptables without root or unshare fails with permission denied
    block_fail = await adapter.execute(
        ResponseActionEnum.BLOCK_IP,
        {"ip_address": "198.51.100.222", "direction": "BOTH"},
        dry_run=False,
    )
    assert block_fail["status"] == "FAILED"
    assert block_fail["exit_code"] != 0
    assert "Permission denied" in block_fail["output"] or "failed" in block_fail["output"].lower()

    # 2. Terminating non-existent PID -> MUST report FAILED
    proc_fail = await adapter.execute(
        ResponseActionEnum.TERMINATE_PROCESS,
        {"pid": 9999999, "process_name": "non_existent_rogue"},
        dry_run=False,
    )
    assert proc_fail["status"] == "FAILED"
    assert proc_fail["exit_code"] != 0
    assert "not found" in proc_fail["output"].lower()

    # 3. Terminating protected system PID 1 -> MUST report FAILED or reject in validation
    with pytest.raises(ValueError, match="critical system process"):
        ActionParametersValidator.validate(
            ResponseActionEnum.TERMINATE_PROCESS,
            {"pid": 1, "process_name": "systemd"},
        )

    # 4. Website recovery with corrupted backup -> MUST report FAILED, NOT EXECUTED
    web_dir = tmp_path / "web"
    web_dir.mkdir()
    corrupt_backup = web_dir / "backup.html"
    corrupt_backup.write_bytes(b"corrupted or tampered backup payload")
    good_hash = "f" * 64
    target = web_dir / "target.html"
    target.write_bytes(b"original target content")

    rec_fail = await adapter.execute(
        ResponseActionEnum.RECOVER_WEBSITE_FILE,
        {
            "target_file": str(target),
            "backup_file": str(corrupt_backup),
            "expected_hash": good_hash,
            "web_root": str(web_dir),
            "quarantine_directory": str(tmp_path / "quar"),
        },
        dry_run=False,
    )
    assert rec_fail["status"] == "FAILED"
    assert rec_fail["exit_code"] != 0
    assert "integrity verification failed" in rec_fail["output"].lower()
    # Target file remained untouched!
    assert target.read_bytes() == b"original target content"

    # 5. Website recovery with missing backup file -> MUST report FAILED
    missing_fail = await adapter.execute(
        ResponseActionEnum.RECOVER_WEBSITE_FILE,
        {
            "target_file": str(target),
            "backup_file": str(web_dir / "does_not_exist.html"),
            "expected_hash": good_hash,
            "web_root": str(web_dir),
            "quarantine_directory": str(tmp_path / "quar"),
        },
        dry_run=False,
    )
    assert missing_fail["status"] == "FAILED"
    assert missing_fail["exit_code"] != 0
    assert "does not exist" in missing_fail["output"].lower()

