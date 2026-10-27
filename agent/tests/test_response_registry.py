"""Unit tests for response action registry and dispatch gating."""

from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from waliya_agent.config import ResponseConfig
from waliya_agent.response.handlers.base import ExecutionResult
from waliya_agent.response.registry import ResponseActionRegistry


@pytest.mark.asyncio
async def test_registry_dry_run_default_enforcement(tmp_path: Path):
    """Verify that when enable_response_actions is False (default), execution is forced to dry_run=True."""
    config = ResponseConfig(
        enable_response_actions=False,
        allowed_actions=["BLOCK_IP"],
        forensic_artifact_dir=tmp_path,
    )
    registry = ResponseActionRegistry(config=config, server_url="http://192.168.1.100:8000")

    result = await registry.dispatch("BLOCK_IP", {"ip_address": "198.51.100.42"})
    assert result.status == "EXECUTED"
    assert result.dry_run is True
    assert "[DRY-RUN]" in result.output


@pytest.mark.asyncio
async def test_registry_unallowed_action_rejected():
    """Verify that actions not in the allowed_actions list are rejected."""
    config = ResponseConfig(
        enable_response_actions=False,
        allowed_actions=["TERMINATE_PROCESS"],  # BLOCK_IP not allowed
    )
    registry = ResponseActionRegistry(config=config)

    result = await registry.dispatch("BLOCK_IP", {"ip_address": "198.51.100.42"})
    assert result.status == "FAILED"
    assert result.exit_code == 1
    assert "not in allowed_actions" in result.output


@pytest.mark.asyncio
async def test_registry_parameter_validation_failure():
    """Verify that invalid parameters return FAILED status cleanly."""
    config = ResponseConfig(
        enable_response_actions=False,
        allowed_actions=["TERMINATE_PROCESS"],
    )
    registry = ResponseActionRegistry(config=config)

    # Missing process_name
    result = await registry.dispatch("TERMINATE_PROCESS", {"pid": 555})
    assert result.status == "FAILED"
    assert result.exit_code == 1
    assert "Parameter validation failed" in result.output


@pytest.mark.asyncio
async def test_registry_dispatch_with_actions_enabled(tmp_path: Path):
    """Verify that when enable_response_actions=True, handler is called with dry_run=False."""
    config = ResponseConfig(
        enable_response_actions=True,
        allowed_actions=["COLLECT_FORENSIC_ARTIFACT"],
        forensic_artifact_dir=tmp_path,
    )
    registry = ResponseActionRegistry(config=config)

    result = await registry.dispatch("COLLECT_FORENSIC_ARTIFACT", {"artifact_type": "PROC_MAP"})
    assert result.status == "EXECUTED"
    assert result.dry_run is False
    assert result.observed_state["artifact_size_bytes"] > 0


@pytest.mark.asyncio
async def test_registry_dispatch_recover_website_file_dry_run(tmp_path: Path):
    """Verify that RECOVER_WEBSITE_FILE in dry-run mode simulates recovery without altering files."""
    web_root = tmp_path / "www"
    web_root.mkdir()
    target_file = web_root / "index.html"
    target_file.write_text("<h1>Hacked By Adversary</h1>")

    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    backup_file = backup_dir / "index.html"
    clean_content = "<h1>Official Ministry Portal</h1>"
    backup_file.write_text(clean_content)

    import hashlib
    clean_hash = hashlib.sha256(clean_content.encode("utf-8")).hexdigest()

    config = ResponseConfig(
        enable_response_actions=False,  # Dry run!
        allowed_actions=["RECOVER_WEBSITE_FILE"],
        website_root_dir=web_root,
        website_backup_dir=backup_dir,
        quarantine_dir=tmp_path / "quarantine",
    )
    registry = ResponseActionRegistry(config=config)

    result = await registry.dispatch("RECOVER_WEBSITE_FILE", {
        "target_file": str(target_file),
        "backup_file": str(backup_file),
        "expected_hash": clean_hash,
    })

    assert result.status == "EXECUTED"
    assert result.dry_run is True
    assert "[DRY-RUN]" in result.output
    # Target file is untouched in dry run
    assert target_file.read_text() == "<h1>Hacked By Adversary</h1>"


@pytest.mark.asyncio
async def test_registry_dispatch_recover_website_file_real_execution(tmp_path: Path):
    """Verify real atomic recovery: file is safely replaced, evidence quarantined, and state verified."""
    web_root = tmp_path / "www"
    web_root.mkdir()
    target_file = web_root / "index.html"
    defaced_content = "<h1>Defaced by Rogue Actor</h1>"
    target_file.write_text(defaced_content)

    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    backup_file = backup_dir / "index.html"
    clean_content = "<h1>Welcome to Official Portal</h1>"
    backup_file.write_text(clean_content)

    import hashlib
    clean_hash = hashlib.sha256(clean_content.encode("utf-8")).hexdigest()
    quarantine_dir = tmp_path / "quarantine"

    config = ResponseConfig(
        enable_response_actions=True,  # Real execution enabled!
        allowed_actions=["RECOVER_WEBSITE_FILE"],
        website_root_dir=web_root,
        website_backup_dir=backup_dir,
        quarantine_dir=quarantine_dir,
    )
    registry = ResponseActionRegistry(config=config)

    result = await registry.dispatch("RECOVER_WEBSITE_FILE", {
        "target_file": str(target_file),
        "backup_file": str(backup_file),
        "expected_hash": clean_hash,
        "quarantine_directory": str(quarantine_dir),
        "web_root": str(web_root),
    })

    assert result.status == "EXECUTED"
    assert result.dry_run is False
    assert result.exit_code == 0
    # Target file is restored
    assert target_file.read_text() == clean_content

    # Quarantine file exists and holds defaced content
    quarantine_files = list(quarantine_dir.glob("*.quarantined"))
    assert len(quarantine_files) == 1
    assert quarantine_files[0].read_text() == defaced_content

    # Verify state returns true
    verif = await registry.collect_verification_state("RECOVER_WEBSITE_FILE", {
        "target_file": str(target_file),
        "expected_hash": clean_hash,
    })
    assert verif["file_recovered"] is True
    assert verif["restored_hash"] == clean_hash


@pytest.mark.asyncio
async def test_registry_dispatch_recover_website_file_corrupted_backup_rejection(tmp_path: Path):
    """Verify that if backup file hash does not match expected_hash, restoration is aborted."""
    web_root = tmp_path / "www"
    web_root.mkdir()
    target_file = web_root / "index.html"
    target_file.write_text("<h1>Original Content</h1>")

    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    backup_file = backup_dir / "corrupted_backup.html"
    backup_file.write_text("<h1>Tampered Backup</h1>")

    import hashlib
    # Provide expected hash that does NOT match the corrupted backup
    legitimate_expected_hash = hashlib.sha256(b"Legitimate clean content").hexdigest()

    config = ResponseConfig(
        enable_response_actions=True,
        allowed_actions=["RECOVER_WEBSITE_FILE"],
        website_root_dir=web_root,
        website_backup_dir=backup_dir,
    )
    registry = ResponseActionRegistry(config=config)

    result = await registry.dispatch("RECOVER_WEBSITE_FILE", {
        "target_file": str(target_file),
        "backup_file": str(backup_file),
        "expected_hash": legitimate_expected_hash,
        "web_root": str(web_root),
    })

    assert result.status == "FAILED"
    assert result.exit_code == 1
    assert "integrity check failed" in result.output.lower()
    # Original file is preserved
    assert target_file.read_text() == "<h1>Original Content</h1>"


@pytest.mark.asyncio
async def test_registry_dispatch_recover_website_file_path_traversal_rejection(tmp_path: Path):
    """Verify that path traversal in target_file or escape from web_root is strictly blocked."""
    web_root = tmp_path / "www"
    web_root.mkdir()

    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    backup_file = backup_dir / "backup.html"
    backup_file.write_text("<h1>Backup</h1>")

    config = ResponseConfig(
        enable_response_actions=True,
        allowed_actions=["RECOVER_WEBSITE_FILE"],
        website_root_dir=web_root,
        website_backup_dir=backup_dir,
    )
    registry = ResponseActionRegistry(config=config)

    # Attempting to target /etc/passwd outside web_root
    result = await registry.dispatch("RECOVER_WEBSITE_FILE", {
        "target_file": "/etc/passwd",
        "backup_file": str(backup_file),
        "expected_hash": "d" * 64,
        "web_root": str(web_root),
    })

    assert result.status == "FAILED"
    assert "Parameter validation failed" in result.output
    assert "outside web_root" in result.output
