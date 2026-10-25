"""Unit tests for response action execution handlers."""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from waliya_agent.response.handlers.block_ip import BlockIpHandler, UnblockIpHandler
from waliya_agent.response.handlers.forensic import CollectForensicHandler
from waliya_agent.response.handlers.process import TerminateProcessHandler


@pytest.mark.asyncio
async def test_block_ip_dry_run():
    """Verify BlockIpHandler in dry-run mode returns positive verification evidence without touching iptables."""
    handler = BlockIpHandler()
    params = {"ip_address": "198.51.100.99", "direction": "BOTH"}

    result = await handler.execute(parameters=params, dry_run=True)
    assert result.status == "EXECUTED"
    assert result.exit_code == 0
    assert result.dry_run is True
    assert "[DRY-RUN]" in result.output
    assert "firewall_rules" in result.observed_state

    # Verify rules match backend positive containment proof requirements
    rules = result.observed_state["firewall_rules"]
    assert any("198.51.100.99" in r and "DROP" in r for r in rules)

    # State verification inspection
    state = await handler.verify_state(parameters=params, dry_run=True)
    assert any("198.51.100.99" in r and "DROP" in r for r in state["firewall_rules"])


@pytest.mark.asyncio
async def test_unblock_ip_dry_run():
    """Verify UnblockIpHandler in dry-run mode."""
    handler = UnblockIpHandler()
    params = {"ip_address": "198.51.100.99"}

    result = await handler.execute(parameters=params, dry_run=True)
    assert result.status == "EXECUTED"
    assert result.exit_code == 0
    assert result.dry_run is True


@pytest.mark.asyncio
async def test_terminate_process_pid_reuse_defense(tmp_path: Path):
    """Verify PID reuse defense rejects terminating a PID that now belongs to a different executable."""
    proc_root = tmp_path / "proc"
    pid_dir = proc_root / "4444"
    pid_dir.mkdir(parents=True)

    # In synthetic /proc/4444, the running process is "innocent_app"
    (pid_dir / "comm").write_text("innocent_app\n", encoding="utf-8")
    (pid_dir / "cmdline").write_bytes(b"/usr/bin/innocent_app\x00--worker\x00")

    handler = TerminateProcessHandler(proc_root=proc_root)

    # Attacker / SOAR requests to terminate PID 4444 expecting "crypto_miner"
    params = {"pid": 4444, "process_name": "crypto_miner"}
    result = await handler.execute(parameters=params, dry_run=False)

    # Must FAIL immediately with PID reuse alert
    assert result.status == "FAILED"
    assert result.exit_code == 2
    assert "PID reuse" in result.output
    assert "innocent_app" in result.output


@pytest.mark.asyncio
async def test_terminate_process_dry_run():
    """Verify TerminateProcessHandler in dry-run mode returns positive verification evidence."""
    handler = TerminateProcessHandler(proc_root=Path("/proc"))
    params = {"pid": 999999, "process_name": "simulated_malware"}

    result = await handler.execute(parameters=params, dry_run=True)
    assert result.status == "EXECUTED"
    assert result.dry_run is True
    assert result.observed_state.get("process_alive") is False

    state = await handler.verify_state(parameters=params, dry_run=True)
    assert state.get("process_alive") is False


@pytest.mark.asyncio
async def test_collect_forensic_dry_run(tmp_path: Path):
    """Verify CollectForensicHandler dry-run simulation."""
    handler = CollectForensicHandler(forensic_dir=tmp_path, max_size_mb=5.0)
    params = {"artifact_type": "LOGS"}

    result = await handler.execute(parameters=params, dry_run=True)
    assert result.status == "EXECUTED"
    assert result.dry_run is True
    assert result.observed_state["artifact_size_bytes"] > 0
    assert "sha256" in result.observed_state


@pytest.mark.asyncio
async def test_collect_forensic_real_execution(tmp_path: Path):
    """Verify CollectForensicHandler real diagnostic collection within directory boundaries."""
    forensic_dir = tmp_path / "forensics"
    handler = CollectForensicHandler(forensic_dir=forensic_dir, max_size_mb=2.0)
    params = {"artifact_type": "PROC_MAP"}

    result = await handler.execute(parameters=params, dry_run=False)
    assert result.status == "EXECUTED"
    assert result.dry_run is False
    assert result.observed_state["artifact_size_bytes"] > 0
    assert "sha256" in result.observed_state

    # Verify file was written inside destination dir
    artifact_path = Path(result.observed_state["artifact_path"])
    assert artifact_path.exists()
    assert artifact_path.parent == forensic_dir.resolve()

    # Verification inspection
    verif = await handler.verify_state(parameters={"artifact_type": "PROC_MAP", "destination_path": str(artifact_path)}, dry_run=False)
    assert verif["artifact_size_bytes"] == artifact_path.stat().st_size
    assert verif["sha256"] == result.observed_state["sha256"]


@pytest.mark.asyncio
async def test_collect_forensic_path_traversal_rejection(tmp_path: Path):
    """Verify refusal to write artifacts outside the configured forensic directory."""
    handler = CollectForensicHandler(forensic_dir=tmp_path / "forensics", max_size_mb=1.0)
    params = {"artifact_type": "LOGS", "destination_path": "/tmp/escaped_dump.json"}

    result = await handler.execute(parameters=params, dry_run=False)
    assert result.status == "FAILED"
    assert "escapes authorized forensic directory" in result.output
