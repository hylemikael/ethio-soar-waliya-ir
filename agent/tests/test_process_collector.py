"""Tests for Linux /proc process activity collector."""

import os
from pathlib import Path
from uuid import UUID

import pytest

from waliya_agent.collectors.process import ProcessCollector


@pytest.mark.asyncio
async def test_process_collector_synthetic_proc(temp_dir: Path, mock_agent_id: UUID):
    """Test process extraction logic using a synthetic /proc directory structure."""
    fake_proc = temp_dir / "proc"
    fake_proc.mkdir()

    # 1. Create fake initial process (PID 100)
    proc100 = fake_proc / "100"
    proc100.mkdir()
    (proc100 / "status").write_text("Name:\tsystemd\nPPid:\t0\nUid:\t0\t0\t0\t0\n", encoding="utf-8")
    (proc100 / "cmdline").write_bytes(b"/sbin/init\x00splash\x00")

    collector = ProcessCollector(agent_id=mock_agent_id, proc_root=fake_proc)

    # First run: seed baseline known PIDs
    initial_events = await collector.collect()
    assert len(initial_events) == 0

    # 2. Spawn a new synthetic process (PID 200)
    proc200 = fake_proc / "200"
    proc200.mkdir()
    (proc200 / "status").write_text("Name:\tmalicious\nPPid:\t100\nUid:\t1000\t1000\t1000\t1000\n", encoding="utf-8")
    (proc200 / "cmdline").write_bytes(b"/tmp/miner\x00--threads=4\x00")

    new_events = await collector.collect()
    assert len(new_events) == 1
    ev = new_events[0]
    assert ev["event_type"] == "PROCESS_EXECUTION"
    assert ev["payload"]["pid"] == 200
    assert ev["payload"]["ppid"] == 100
    assert "miner" in ev["payload"]["exe"]
    assert "--threads=4" in ev["payload"]["cmdline"]


@pytest.mark.asyncio
async def test_process_collector_handles_vanished_process(temp_dir: Path, mock_agent_id: UUID):
    """Verify that processes terminating during scan (FileNotFoundError) are handled cleanly."""
    fake_proc = temp_dir / "proc"
    fake_proc.mkdir()

    collector = ProcessCollector(agent_id=mock_agent_id, proc_root=fake_proc)
    await collector.collect()

    # Create PID directory then immediately leave it empty/unreadable
    vanished_proc = fake_proc / "999"
    vanished_proc.mkdir()

    events = await collector.collect()
    # Process had no status file -> safely skipped without exception
    assert isinstance(events, list)


@pytest.mark.asyncio
async def test_process_collector_real_proc_if_available(mock_agent_id: UUID):
    """Test collector against actual Linux /proc if running on Linux."""
    if not Path("/proc/1").exists():
        pytest.skip("Linux /proc not available in this environment")

    collector = ProcessCollector(agent_id=mock_agent_id, proc_root=Path("/proc"))
    # Run once to seed
    events = await collector.collect()
    assert isinstance(events, list)
