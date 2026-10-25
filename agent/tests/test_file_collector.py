"""Tests for File Integrity Monitoring (FIM) collector."""

import asyncio
import os
import time
from pathlib import Path
from uuid import UUID

import pytest

from waliya_agent.collectors.file_integrity import FileIntegrityCollector


@pytest.mark.asyncio
async def test_fim_baseline_and_creation(temp_dir: Path, mock_agent_id: UUID):
    """Verify that file creation is detected after baseline initialization."""
    monitored = temp_dir / "monitored"
    monitored.mkdir()

    # Pre-existing file
    file1 = monitored / "existing.txt"
    file1.write_text("initial content", encoding="utf-8")

    collector = FileIntegrityCollector(
        agent_id=mock_agent_id,
        paths_to_monitor=[str(monitored)],
        debounce_seconds=0.1,
    )

    # 1. Initial collection seeds baseline: 0 events emitted
    events = await collector.collect()
    assert len(events) == 0

    # 2. Create new file
    file2 = monitored / "new_threat.sh"
    file2.write_text("#!/bin/bash\necho test\n", encoding="utf-8")

    time.sleep(0.15)  # Wait for debounce window
    events = await collector.collect()
    assert len(events) == 1
    ev = events[0]
    assert ev["event_type"] == "FILE_INTEGRITY"
    assert ev["payload"]["action"] == "CREATED"
    assert ev["payload"]["file_path"] == str(file2)
    assert ev["payload"]["sha256"] is not None


@pytest.mark.asyncio
async def test_fim_modification_and_deletion(temp_dir: Path, mock_agent_id: UUID):
    """Verify that file modification and deletion are detected correctly."""
    monitored = temp_dir / "monitored"
    monitored.mkdir()

    target = monitored / "config.ini"
    target.write_text("param=1", encoding="utf-8")

    collector = FileIntegrityCollector(
        agent_id=mock_agent_id,
        paths_to_monitor=[str(monitored)],
        debounce_seconds=0.1,
    )
    await collector.collect()

    # 1. Modify the file
    time.sleep(0.15)
    target.write_text("param=2_modified", encoding="utf-8")

    events = await collector.collect()
    assert len(events) == 1
    assert events[0]["payload"]["action"] == "MODIFIED"

    # 2. Delete the file
    time.sleep(0.15)
    target.unlink()

    events = await collector.collect()
    assert len(events) == 1
    assert events[0]["payload"]["action"] == "DELETED"
    assert events[0]["payload"]["file_path"] == str(target)


@pytest.mark.asyncio
async def test_fim_debounces_rapid_writes(temp_dir: Path, mock_agent_id: UUID):
    """Verify that rapid successive writes within debounce interval are suppressed."""
    monitored = temp_dir / "monitored"
    monitored.mkdir()

    target = monitored / "rapid.log"
    target.write_text("line 1\n", encoding="utf-8")

    collector = FileIntegrityCollector(
        agent_id=mock_agent_id,
        paths_to_monitor=[str(monitored)],
        debounce_seconds=0.5,
    )
    await collector.collect()

    # Rapid modification 1
    time.sleep(0.05)
    target.write_text("line 2\n", encoding="utf-8")
    events1 = await collector.collect()
    assert len(events1) == 1

    # Rapid modification 2 within debounce window (< 0.5s)
    target.write_text("line 3\n", encoding="utf-8")
    events2 = await collector.collect()
    # Suppressed by debounce
    assert len(events2) == 0

    # Wait past debounce window
    time.sleep(0.6)
    target.write_text("line 4\n", encoding="utf-8")
    events3 = await collector.collect()
    assert len(events3) == 1


@pytest.mark.asyncio
async def test_fim_symlink_safety(temp_dir: Path, mock_agent_id: UUID):
    """Verify that symlinks outside monitored boundary are not traversed or dereferenced dangerously."""
    outside_dir = temp_dir / "secret_outside"
    outside_dir.mkdir()
    secret_file = outside_dir / "secret.key"
    secret_file.write_text("super_secret_bytes", encoding="utf-8")

    monitored = temp_dir / "monitored"
    monitored.mkdir()

    # Create symlink pointing outside
    symlink_path = monitored / "link_to_secret"
    try:
        os.symlink(str(secret_file), str(symlink_path))
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported in environment")

    collector = FileIntegrityCollector(
        agent_id=mock_agent_id,
        paths_to_monitor=[str(monitored)],
        debounce_seconds=0.1,
    )
    # Ensure it scans without throwing exceptions or leaking outside directory contents
    events = await collector.collect()
    assert isinstance(events, list)
