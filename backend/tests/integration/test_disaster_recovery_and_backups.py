"""Integration and resilience tests for Ethio-SOAR backup, restore, and disaster recovery tooling."""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import redis

from waliya.config import settings

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
BACKUP_SCRIPT = REPO_ROOT / "scripts" / "backup_db.sh"
RESTORE_SCRIPT = REPO_ROOT / "scripts" / "restore_db.sh"
MANAGE_SCRIPT = REPO_ROOT / "scripts" / "manage_backups.py"
REDIS_SCRIPT = REPO_ROOT / "scripts" / "redis_recovery.py"


def calculate_sha256(filepath: Path) -> str:
    """Helper to compute sha256 checksum."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


class TestDisasterRecoveryAndBackups:
    """Verifies operational resilience, backup generation, tamper resistance, and recovery workflows."""

    def test_backup_script_creates_valid_dump_and_manifest(self, tmp_path):
        """Verify backup_db.sh generates custom archive with correct permissions and SHA-256 manifest."""
        backup_dir = tmp_path / "backups"
        cmd = [
            str(BACKUP_SCRIPT),
            "--output-dir",
            str(backup_dir),
            "--keep",
            "5",
        ]

        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        assert res.returncode == 0, f"backup_db.sh failed: {res.stderr}"

        # Directory permissions should be 0700
        dir_stat = backup_dir.stat().st_mode & 0o777
        assert dir_stat == 0o700

        dumps = list(backup_dir.glob("*.dump"))
        metas = list(backup_dir.glob("*.meta.json"))

        assert len(dumps) == 1
        assert len(metas) == 1

        dump_path = dumps[0]
        meta_path = metas[0]

        # File permissions should be 0600
        assert (dump_path.stat().st_mode & 0o777) == 0o600
        assert (meta_path.stat().st_mode & 0o777) == 0o600

        # Validate manifest content
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        assert meta["backup_filename"] == dump_path.name
        assert meta["format"] == "custom (pg_dump -Fc)"
        assert meta["size_bytes"] == dump_path.stat().st_size
        assert meta["verification_status"] == "VERIFIED_VALID"
        assert meta["sha256_checksum"] == calculate_sha256(dump_path)
        assert "alembic_head_revision" in meta
        assert meta["alembic_head_revision"] != "unknown"

    def test_manage_backups_verification_and_tamper_detection(self, tmp_path):
        """Verify manage_backups.py detects valid backups and flags tampered files."""
        backup_dir = tmp_path / "backups"
        res = subprocess.run(
            [str(BACKUP_SCRIPT), "--output-dir", str(backup_dir), "--keep", "5"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert res.returncode == 0

        dump_path = list(backup_dir.glob("*.dump"))[0]

        # 1. Verify healthy backup
        verify_cmd = [sys.executable, str(MANAGE_SCRIPT), "verify", str(dump_path)]
        verify_res = subprocess.run(verify_cmd, capture_output=True, text=True, timeout=15)
        assert verify_res.returncode == 0
        assert "passed all integrity checks" in verify_res.stdout

        # 2. Tamper with the dump file by flipping bytes
        with open(dump_path, "r+b") as f:
            f.seek(50)
            original = f.read(4)
            f.seek(50)
            f.write(b"\x00\x00\x00\x00")

        # 3. Verify that tampered backup is rejected
        tampered_res = subprocess.run(verify_cmd, capture_output=True, text=True, timeout=15)
        assert tampered_res.returncode == 1
        assert "FAILED" in tampered_res.stderr or "Checksum mismatch" in tampered_res.stderr

    def test_restore_script_rejects_production_overwrite_without_flag(self, tmp_path):
        """Verify restore_db.sh halts with code 2 if targeted at production DB without confirmation."""
        backup_dir = tmp_path / "backups"
        subprocess.run(
            [str(BACKUP_SCRIPT), "--output-dir", str(backup_dir), "--keep", "5"],
            capture_output=True,
            check=True,
        )
        dump_path = list(backup_dir.glob("*.dump"))[0]

        restore_cmd = [
            str(RESTORE_SCRIPT),
            "--backup-file",
            str(dump_path),
            "--target-db",
            "waliya_ir",  # Primary DB without --confirm-production-overwrite
        ]

        res = subprocess.run(restore_cmd, capture_output=True, text=True, timeout=15)
        assert res.returncode == 2
        assert "PRIMARY PRODUCTION database" in res.stderr
        assert "--confirm-production-overwrite" in res.stderr

    def test_restore_script_rejects_tampered_backup(self, tmp_path):
        """Verify restore_db.sh detects checksum mismatch and halts before modifying database."""
        backup_dir = tmp_path / "backups"
        subprocess.run(
            [str(BACKUP_SCRIPT), "--output-dir", str(backup_dir), "--keep", "5"],
            capture_output=True,
            check=True,
        )
        dump_path = list(backup_dir.glob("*.dump"))[0]

        # Corrupt dump file
        with open(dump_path, "r+b") as f:
            f.seek(100)
            f.write(b"CORRUPTED_BYTES")

        restore_cmd = [
            str(RESTORE_SCRIPT),
            "--backup-file",
            str(dump_path),
            "--target-db",
            "waliya_recovery_tamper_test",
        ]

        res = subprocess.run(restore_cmd, capture_output=True, text=True, timeout=15)
        assert res.returncode == 3
        assert "Checksum mismatch" in res.stderr
        assert "Aborting restore" in res.stderr

    def test_safe_restore_into_isolated_target_db(self, tmp_path):
        """Verify restore_db.sh successfully restores schema and data into isolated sandbox DB."""
        backup_dir = tmp_path / "backups"
        subprocess.run(
            [str(BACKUP_SCRIPT), "--output-dir", str(backup_dir), "--keep", "5"],
            capture_output=True,
            check=True,
        )
        dump_path = list(backup_dir.glob("*.dump"))[0]
        test_recovery_db = "waliya_recovery_ci_test"

        restore_cmd = [
            str(RESTORE_SCRIPT),
            "--backup-file",
            str(dump_path),
            "--target-db",
            test_recovery_db,
        ]

        try:
            res = subprocess.run(restore_cmd, capture_output=True, text=True, timeout=180)
            assert res.returncode == 0, f"restore failed: {res.stderr}"
            assert f"Restoring schema and data into '{test_recovery_db}'" in res.stdout
            assert "Database restoration completed successfully" in res.stdout
        finally:
            # Ensure disposable test database is cleanly dropped to prevent artifact leakage
            subprocess.run(
                [
                    "docker",
                    "exec",
                    "-e",
                    "PGPASSWORD=waliya_dev_password",
                    "waliya_postgres",
                    "psql",
                    "-U",
                    "waliya_user",
                    "-d",
                    "postgres",
                    "-c",
                    f"DROP DATABASE IF EXISTS {test_recovery_db};",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )

    def test_retention_policy_pruning(self, tmp_path):
        """Verify backup retention prunes oldest archives when exceeding limit."""
        backup_dir = tmp_path / "backups"

        # Create 3 backups with keep=2
        for _ in range(3):
            subprocess.run(
                [str(BACKUP_SCRIPT), "--output-dir", str(backup_dir), "--keep", "2"],
                capture_output=True,
                check=True,
            )

        dumps = list(backup_dir.glob("*.dump"))
        metas = list(backup_dir.glob("*.meta.json"))

        assert len(dumps) == 2
        assert len(metas) == 2

    def test_redis_recovery_status_and_reinit(self):
        """Verify redis_recovery.py inspects stream health and re-initializes consumer groups."""
        # 1. Status command
        status_cmd = [sys.executable, str(REDIS_SCRIPT), "status"]
        status_res = subprocess.run(status_cmd, capture_output=True, text=True, timeout=15)
        assert status_res.returncode == 0
        assert "Redis Connectivity: ONLINE" in status_res.stdout
        assert "AOF Enabled" in status_res.stdout

        # 2. Re-init command
        reinit_cmd = [sys.executable, str(REDIS_SCRIPT), "reinit-groups"]
        reinit_res = subprocess.run(reinit_cmd, capture_output=True, text=True, timeout=15)
        assert reinit_res.returncode == 0
        assert "All required stream consumer groups are initialized" in reinit_res.stdout

        # 3. Verify consumer group exists via redis client
        r = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
        raw_groups = [g["name"] for g in r.xinfo_groups("stream:telemetry:raw")]
        assert "waliya_detection_group" in raw_groups
