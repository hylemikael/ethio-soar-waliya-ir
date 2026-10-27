"""Unit tests for allowlisted SOAR response adapters and parameter validation."""

import pytest

from waliya.contracts import ResponseActionEnum, ResponseStateEnum
from waliya.soar.adapters import (
    ActionParametersValidator,
    DryRunResponseAdapter,
    LinuxHostResponseAdapter,
)


def test_block_ip_parameter_validation():
    """Verify BLOCK_IP validates IP addresses and prevents blocking protected networks."""
    # Valid public / external IPs
    valid_params = {"ip_address": "198.51.100.45", "direction": "BOTH"}
    res = ActionParametersValidator.validate(ResponseActionEnum.BLOCK_IP, valid_params)
    assert res["ip_address"] == "198.51.100.45"
    assert res["direction"] == "BOTH"

    # Reject loopback IP (127.0.0.1)
    with pytest.raises(ValueError, match="protected management"):
        ActionParametersValidator.validate(ResponseActionEnum.BLOCK_IP, {"ip_address": "127.0.0.1"})

    # Reject link-local IP (169.254.10.20)
    with pytest.raises(ValueError, match="protected management"):
        ActionParametersValidator.validate(ResponseActionEnum.BLOCK_IP, {"ip_address": "169.254.10.20"})

    # Reject multicast (224.0.0.5)
    with pytest.raises(ValueError, match="protected management"):
        ActionParametersValidator.validate(ResponseActionEnum.BLOCK_IP, {"ip_address": "224.0.0.5"})

    # Reject invalid IP syntax
    with pytest.raises(ValueError, match="Invalid IP address"):
        ActionParametersValidator.validate(ResponseActionEnum.BLOCK_IP, {"ip_address": "999.999.999.999"})


def test_terminate_process_parameter_validation():
    """Verify TERMINATE_PROCESS prevents killing PID 1 and enforces process identity."""
    # Valid process
    valid_params = {"pid": 4512, "process_name": "nc", "kill_tree": False}
    res = ActionParametersValidator.validate(ResponseActionEnum.TERMINATE_PROCESS, valid_params)
    assert res["pid"] == 4512
    assert res["process_name"] == "nc"

    # Reject PID 1 (init/systemd)
    with pytest.raises(ValueError, match="critical system process"):
        ActionParametersValidator.validate(
            ResponseActionEnum.TERMINATE_PROCESS,
            {"pid": 1, "process_name": "systemd"},
        )

    # Reject missing or empty process name
    with pytest.raises(ValueError, match="process_name"):
        ActionParametersValidator.validate(
            ResponseActionEnum.TERMINATE_PROCESS,
            {"pid": 5000, "process_name": "   "},
        )


def test_collect_forensic_parameter_validation():
    """Verify COLLECT_FORENSIC_ARTIFACT rejects directory traversal attacks."""
    # Valid artifact collection
    valid_params = {"artifact_type": "LOGS", "destination_path": "/var/log/waliya/forensics.tar"}
    res = ActionParametersValidator.validate(ResponseActionEnum.COLLECT_FORENSIC_ARTIFACT, valid_params)
    assert res["artifact_type"] == "LOGS"

    # Reject directory traversal path
    with pytest.raises(ValueError, match="Prohibited forensic"):
        ActionParametersValidator.validate(
            ResponseActionEnum.COLLECT_FORENSIC_ARTIFACT,
            {"artifact_type": "LOGS", "destination_path": "/tmp/../../etc/shadow"},
        )


@pytest.mark.asyncio
async def test_dry_run_adapter_simulation():
    """Verify DryRunResponseAdapter simulates execution and containment without modifying host state."""
    adapter = DryRunResponseAdapter()
    exec_res = await adapter.execute(
        ResponseActionEnum.BLOCK_IP,
        {"ip_address": "203.0.113.10", "direction": "IN"},
        dry_run=True,
    )
    assert exec_res["status"] == "EXECUTED"
    assert exec_res["exit_code"] == 0
    assert exec_res["dry_run"] is True

    verify_res, explanation = await adapter.verify(
        ResponseActionEnum.BLOCK_IP,
        {"ip_address": "203.0.113.10"},
        {"simulated_containment": True},
    )
    # Under Prompt 3 invariant: simulated dry-run verification strictly cannot establish real containment
    assert verify_res == ResponseStateEnum.VERIFICATION_INCONCLUSIVE
    assert "[DRY-RUN]" in explanation


@pytest.mark.asyncio
async def test_linux_adapter_verification_firewall():
    """Verify LinuxHostResponseAdapter firewall rule verification."""
    adapter = LinuxHostResponseAdapter()
    params = {"ip_address": "198.51.100.99"}

    # Positive proof: rule present in observed firewall table
    positive_state = {
        "firewall_rules": [
            "-A WALIYA_BLOCK -s 198.51.100.99/32 -j DROP",
        ]
    }
    state, msg = await adapter.verify(ResponseActionEnum.BLOCK_IP, params, positive_state)
    assert state == ResponseStateEnum.VERIFIED_CONTAINED
    assert "Verified active kernel firewall rule" in msg

    # Missing evidence: inconclusive (cannot infer containment from absence)
    negative_state = {
        "firewall_rules": [
            "-A WALIYA_BLOCK -s 10.0.0.1/32 -j DROP",
        ]
    }
    state_inconc, msg_inconc = await adapter.verify(ResponseActionEnum.BLOCK_IP, params, negative_state)
    assert state_inconc == ResponseStateEnum.VERIFICATION_INCONCLUSIVE
    assert "Inconclusive" in msg_inconc


@pytest.mark.asyncio
async def test_linux_adapter_verification_process():
    """Verify LinuxHostResponseAdapter process termination verification."""
    adapter = LinuxHostResponseAdapter()
    params = {"pid": 8888, "process_name": "malware_miner"}

    # Positive proof: process confirmed dead
    dead_state = {"process_alive": False, "active_pids": [1, 2, 500, 600]}
    state, msg = await adapter.verify(ResponseActionEnum.TERMINATE_PROCESS, params, dead_state)
    assert state == ResponseStateEnum.VERIFIED_CONTAINED
    assert "no longer executing" in msg

    # Failure: PID still alive
    alive_state = {"process_alive": True, "active_pids": [1, 8888]}
    state_failed, msg_failed = await adapter.verify(ResponseActionEnum.TERMINATE_PROCESS, params, alive_state)
    assert state_failed == ResponseStateEnum.FAILED
    assert "still active" in msg_failed


@pytest.mark.asyncio
async def test_linux_adapter_simulated_evidence_cannot_establish_containment():
    """CRITICAL SECURITY TEST:
    Prove that simulated IP block and simulated process termination cannot establish real containment.
    """
    adapter = LinuxHostResponseAdapter()

    # 1. Simulated IP block with matching DROP rule format
    simulated_ip_state = {
        "firewall_rules": ["-A WALIYA_BLOCK -s 198.51.100.99/32 -j DROP"],
        "dry_run": True,
        "is_simulated": True,
    }
    state, msg = await adapter.verify(
        ResponseActionEnum.BLOCK_IP,
        {"ip_address": "198.51.100.99"},
        simulated_ip_state,
    )
    assert state == ResponseStateEnum.VERIFICATION_INCONCLUSIVE
    assert "[DRY-RUN]" in msg


    # 2. Simulated process termination with process_alive=False
    simulated_proc_state = {
        "process_alive": False,
        "active_pids": [],
        "dry_run": True,
        "is_simulated": True,
    }
    state, msg = await adapter.verify(
        ResponseActionEnum.TERMINATE_PROCESS,
        {"pid": 9999, "process_name": "simulated_malware"},
        simulated_proc_state,
    )
    assert state == ResponseStateEnum.VERIFICATION_INCONCLUSIVE
    assert "[DRY-RUN]" in msg


def test_recover_website_file_parameter_validation():
    """Verify RECOVER_WEBSITE_FILE validates parameters and prevents path traversal."""
    valid_hash = "a" * 64
    valid_params = {
        "target_file": "/var/www/html/index.html",
        "backup_file": "/var/backups/waliya/index.html",
        "expected_hash": valid_hash,
        "quarantine_directory": "/var/quarantine/waliya",
        "web_root": "/var/www/html",
    }
    res = ActionParametersValidator.validate(ResponseActionEnum.RECOVER_WEBSITE_FILE, valid_params)
    assert res["target_file"] == "/var/www/html/index.html"
    assert res["expected_hash"] == valid_hash

    # Reject path traversal in target_file
    with pytest.raises(ValueError, match="Prohibited path traversal"):
        ActionParametersValidator.validate(
            ResponseActionEnum.RECOVER_WEBSITE_FILE,
            {**valid_params, "target_file": "/var/www/html/../../etc/passwd"},
        )

    # Reject path traversal in backup_file
    with pytest.raises(ValueError, match="Prohibited path traversal"):
        ActionParametersValidator.validate(
            ResponseActionEnum.RECOVER_WEBSITE_FILE,
            {**valid_params, "backup_file": "/var/backups/../../etc/shadow"},
        )

    # Reject invalid hash format (too short)
    with pytest.raises(ValueError, match="expected_hash"):
        ActionParametersValidator.validate(
            ResponseActionEnum.RECOVER_WEBSITE_FILE,
            {**valid_params, "expected_hash": "short_hash"},
        )


@pytest.mark.asyncio
async def test_linux_adapter_verification_unblock_ip():
    """Verify LinuxHostResponseAdapter UNBLOCK_IP verification."""
    adapter = LinuxHostResponseAdapter()
    params = {"ip_address": "198.51.100.99"}

    # Positive proof of removal: rule no longer in table
    positive_state = {"firewall_rules": ["-A WALIYA_BLOCK -s 10.0.0.1/32 -j DROP"]}
    state, msg = await adapter.verify(ResponseActionEnum.UNBLOCK_IP, params, positive_state)
    assert state == ResponseStateEnum.VERIFIED_CONTAINED
    assert "Verified removal of kernel firewall drop rule" in msg

    # Failure: rule still present
    still_present_state = {"firewall_rules": ["-A WALIYA_BLOCK -s 198.51.100.99/32 -j DROP"]}
    state_fail, msg_fail = await adapter.verify(ResponseActionEnum.UNBLOCK_IP, params, still_present_state)
    assert state_fail == ResponseStateEnum.FAILED
    assert "still active" in msg_fail


@pytest.mark.asyncio
async def test_linux_adapter_verification_recover_website_file():
    """Verify LinuxHostResponseAdapter RECOVER_WEBSITE_FILE verification."""
    adapter = LinuxHostResponseAdapter()
    valid_hash = "b" * 64
    params = {"target_file": "/var/www/html/index.html", "expected_hash": valid_hash}

    # Positive proof: file recovered and hash matches
    positive_state = {
        "file_recovered": True,
        "restored_hash": valid_hash,
    }
    state, msg = await adapter.verify(ResponseActionEnum.RECOVER_WEBSITE_FILE, params, positive_state)
    assert state == ResponseStateEnum.VERIFIED_CONTAINED
    assert "restored successfully" in msg

    # Hash mismatch failure
    mismatch_state = {
        "file_recovered": True,
        "restored_hash": "c" * 64,
    }
    state_fail, msg_fail = await adapter.verify(ResponseActionEnum.RECOVER_WEBSITE_FILE, params, mismatch_state)
    assert state_fail == ResponseStateEnum.FAILED
    assert "Integrity check failed" in msg_fail

    # Simulated/dry-run telemetry cannot verify containment
    simulated_state = {
        "file_recovered": True,
        "restored_hash": valid_hash,
        "dry_run": True,
    }
    state_sim, msg_sim = await adapter.verify(ResponseActionEnum.RECOVER_WEBSITE_FILE, params, simulated_state)
    assert state_sim == ResponseStateEnum.VERIFICATION_INCONCLUSIVE
    assert "[DRY-RUN]" in msg_sim
