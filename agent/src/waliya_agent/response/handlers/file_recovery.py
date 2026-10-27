"""Website file recovery response action handler with integrity verification, atomic swap, and quarantine."""

from datetime import datetime, timezone
import hashlib
import logging
import os
from pathlib import Path
import tempfile
from typing import Any, Dict, Optional

from waliya_agent.response.handlers.base import BaseActionHandler, ExecutionResult

logger = logging.getLogger("waliya_agent.response.file_recovery")


class RecoverWebsiteFileHandler(BaseActionHandler):
    """Safely recovers defaced or modified website files from cryptographic backups.

    Enforces:
    1. Cryptographic pre-restoration backup verification (SHA-256).
    2. Preservation of compromised file evidence in quarantine directory (read-only 0400).
    3. Atomic restoration using temporary file and atomic replace (os.replace) to prevent partial reads.
    4. Positive post-restoration verification of file hashes.
    """

    def __init__(self):
        super().__init__("RECOVER_WEBSITE_FILE")

    @staticmethod
    def _compute_sha256(path: Path) -> str:
        """Compute SHA-256 hex digest of a file in chunks."""
        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    async def execute(self, parameters: Dict[str, Any], dry_run: bool) -> ExecutionResult:
        target_path = Path(parameters["target_file"])
        backup_path = Path(parameters["backup_file"])
        expected_hash = parameters["expected_hash"].strip().lower()
        quarantine_dir = Path(parameters.get("quarantine_directory", "./data/quarantine"))

        # 1. Verify backup file exists and is a regular file
        if not backup_path.exists() or not backup_path.is_file():
            msg = f"Backup file not found or not a regular file: '{backup_path}'"
            logger.error(msg)
            return ExecutionResult(
                status="FAILED",
                exit_code=1,
                dry_run=dry_run,
                output=msg,
                observed_state={"file_recovered": False, "dry_run": dry_run},
            )

        # 2. Cryptographic verification of backup file integrity
        try:
            backup_hash = self._compute_sha256(backup_path).lower()
        except Exception as exc:
            msg = f"Failed to compute checksum of backup file '{backup_path}': {exc}"
            logger.error(msg)
            return ExecutionResult(
                status="FAILED",
                exit_code=1,
                dry_run=dry_run,
                output=msg,
                observed_state={"file_recovered": False, "dry_run": dry_run},
            )

        if backup_hash != expected_hash:
            msg = (
                f"Backup file integrity check failed: expected hash '{expected_hash}', "
                f"but backup has '{backup_hash}'. Aborting restoration to prevent deploying corrupt or untrusted content."
            )
            logger.critical("RESTORATION ABORTED: %s", msg)
            return ExecutionResult(
                status="FAILED",
                exit_code=1,
                dry_run=dry_run,
                output=msg,
                observed_state={
                    "file_recovered": False,
                    "expected_hash": expected_hash,
                    "actual_backup_hash": backup_hash,
                    "dry_run": dry_run,
                },
            )

        # 3. Check existing target file
        orig_hash: Optional[str] = None
        if target_path.exists() and target_path.is_file():
            try:
                orig_hash = self._compute_sha256(target_path).lower()
            except Exception as exc:
                logger.warning("Could not read original target file hash: %s", exc)

        # 4. Dry-run execution
        if dry_run:
            logger.info("[DRY-RUN] Simulating website file recovery for '%s' from '%s'", target_path, backup_path)
            sim_quarantine = (
                str(quarantine_dir / f"{target_path.name}_SIMULATED.quarantined")
                if orig_hash
                else None
            )
            return ExecutionResult(
                status="EXECUTED",
                exit_code=0,
                dry_run=True,
                output=(
                    f"[DRY-RUN] Verified backup integrity (SHA-256: {backup_hash[:16]}...). "
                    f"Simulated atomic restoration of '{target_path}' without modifying filesystem."
                ),
                observed_state={
                    "file_recovered": True,
                    "restored_hash": backup_hash,
                    "expected_hash": expected_hash,
                    "original_hash": orig_hash,
                    "quarantined_path": sim_quarantine,
                    "dry_run": True,
                    "is_simulated": True,
                },
            )

        # 5. Operational execution: Quarantine original file if present
        quarantined_path: Optional[Path] = None
        if target_path.exists() and target_path.is_file():
            try:
                quarantine_dir.mkdir(parents=True, exist_ok=True)
                timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                short_hash = orig_hash[:8] if orig_hash else "unknown"
                quarantined_path = quarantine_dir / f"{target_path.name}_{timestamp}_{short_hash}.quarantined"

                # Read and write to quarantine
                content = target_path.read_bytes()
                quarantined_path.write_bytes(content)
                # Restrict permissions: read-only, non-executable
                os.chmod(quarantined_path, 0o400)
                logger.info("Preserved compromised file evidence in quarantine: '%s'", quarantined_path)
            except Exception as exc:
                msg = f"Failed to quarantine original file '{target_path}' prior to restoration: {exc}"
                logger.error(msg)
                return ExecutionResult(
                    status="FAILED",
                    exit_code=1,
                    dry_run=False,
                    output=msg,
                    observed_state={"file_recovered": False, "dry_run": False},
                )

        # 6. Operational execution: Atomic file replacement
        try:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            backup_bytes = backup_path.read_bytes()

            # Create temp file in target's directory to ensure atomic os.replace across filesystem boundaries
            fd, tmp_file_path = tempfile.mkstemp(
                prefix=f".{target_path.name}.waliya_tmp_",
                dir=target_path.parent,
            )
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(backup_bytes)
                    f.flush()
                    os.fsync(f.fileno())

                # Set safe file permissions (0644 readable by web server)
                os.chmod(tmp_file_path, 0o644)

                # Atomic swap
                os.replace(tmp_file_path, target_path)
            except Exception:
                if os.path.exists(tmp_file_path):
                    try:
                        os.unlink(tmp_file_path)
                    except OSError:
                        pass
                raise

            # 7. Post-restoration verification check
            post_hash = self._compute_sha256(target_path).lower()
            if post_hash != expected_hash:
                msg = f"Post-restoration hash mismatch: expected {expected_hash}, observed {post_hash}"
                logger.critical(msg)
                return ExecutionResult(
                    status="FAILED",
                    exit_code=1,
                    dry_run=False,
                    output=msg,
                    observed_state={
                        "file_recovered": False,
                        "restored_hash": post_hash,
                        "expected_hash": expected_hash,
                        "dry_run": False,
                    },
                )

            logger.info("Successfully restored website file '%s' (hash: %s)", target_path, post_hash)
            return ExecutionResult(
                status="EXECUTED",
                exit_code=0,
                dry_run=False,
                output=(
                    f"Successfully restored website file '{target_path}' from verified backup. "
                    f"Quarantined previous file to '{quarantined_path}'"
                ),
                observed_state={
                    "file_recovered": True,
                    "restored_hash": post_hash,
                    "expected_hash": expected_hash,
                    "original_hash": orig_hash,
                    "quarantined_path": str(quarantined_path) if quarantined_path else None,
                    "dry_run": False,
                    "is_simulated": False,
                },
            )

        except Exception as exc:
            msg = f"Exception restoring website file '{target_path}': {exc}"
            logger.error(msg, exc_info=True)
            return ExecutionResult(
                status="FAILED",
                exit_code=1,
                dry_run=False,
                output=msg,
                observed_state={"file_recovered": False, "dry_run": False},
            )

    async def verify_state(self, parameters: Dict[str, Any], dry_run: bool) -> Dict[str, Any]:
        target_path = Path(parameters["target_file"])
        expected_hash = parameters["expected_hash"].strip().lower()

        if dry_run:
            return {
                "file_recovered": True,
                "restored_hash": expected_hash,
                "expected_hash": expected_hash,
                "dry_run": True,
                "is_simulated": True,
            }

        if not target_path.exists() or not target_path.is_file():
            return {
                "file_recovered": False,
                "restored_hash": None,
                "expected_hash": expected_hash,
                "dry_run": False,
                "is_simulated": False,
            }

        try:
            current_hash = self._compute_sha256(target_path).lower()
            return {
                "file_recovered": (current_hash == expected_hash),
                "restored_hash": current_hash,
                "expected_hash": expected_hash,
                "dry_run": False,
                "is_simulated": False,
            }
        except Exception as exc:
            logger.warning("Error verifying state for %s: %s", target_path, exc)
            return {
                "file_recovered": False,
                "error": str(exc),
                "expected_hash": expected_hash,
                "dry_run": False,
                "is_simulated": False,
            }
