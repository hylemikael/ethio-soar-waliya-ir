"""Forensic artifact collection response action handler with size limits and path containment."""

import asyncio
import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from waliya_agent.response.handlers.base import BaseActionHandler, ExecutionResult

logger = logging.getLogger("waliya_agent.response.forensic")


class CollectForensicHandler(BaseActionHandler):
    """Safely captures diagnostic forensic artifacts within strict size and path boundaries."""

    def __init__(self, forensic_dir: Path = Path("data/forensics"), max_size_mb: float = 10.0):
        super().__init__("COLLECT_FORENSIC_ARTIFACT")
        self.forensic_dir = forensic_dir
        self.max_bytes = int(max_size_mb * 1024 * 1024)

    def _resolve_safe_path(self, destination_path: str, artifact_type: str) -> Path:
        """Resolve and enforce that the artifact destination path remains inside the allowed forensic dir."""
        self.forensic_dir.mkdir(parents=True, exist_ok=True)
        resolved_base = self.forensic_dir.resolve()

        if destination_path:
            candidate = Path(destination_path)
            if not candidate.is_absolute():
                candidate = (resolved_base / candidate).resolve()
            else:
                candidate = candidate.resolve()
        else:
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filename = f"forensic_{artifact_type.lower()}_{ts}.json"
            candidate = (resolved_base / filename).resolve()

        # Enforce directory containment
        try:
            candidate.relative_to(resolved_base)
        except ValueError:
            raise ValueError(f"Destination path {candidate} escapes authorized forensic directory {resolved_base}")

        return candidate

    async def _collect_payload(self, artifact_type: str) -> bytes:
        """Collect bounded system diagnostic evidence without arbitrary shell commands."""
        collected: Dict[str, Any] = {
            "artifact_type": artifact_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if artifact_type == "LOGS":
            # Attempt bounded read of recent journalctl or /var/log/syslog
            log_lines = []
            try:
                proc = await asyncio.create_subprocess_exec(
                    "journalctl", "-n", "100", "--no-pager",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await proc.communicate()
                if proc.returncode == 0:
                    log_lines = stdout.decode("utf-8", errors="replace").splitlines()
            except Exception:
                pass

            if not log_lines:
                syslog_path = Path("/var/log/syslog")
                if syslog_path.exists():
                    try:
                        lines = syslog_path.read_text(encoding="utf-8", errors="replace").splitlines()
                        log_lines = lines[-100:]
                    except Exception:
                        pass

            collected["logs"] = log_lines or ["[No system logs accessible with current agent permissions]"]

        elif artifact_type == "PROC_MAP":
            # Collect current process snapshot
            procs = []
            try:
                proc = await asyncio.create_subprocess_exec(
                    "ps", "-eo", "pid,ppid,user,stat,comm",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await proc.communicate()
                if proc.returncode == 0:
                    lines = stdout.decode("utf-8", errors="replace").splitlines()
                    for line in lines[1:]:  # skip header
                        parts = line.split(None, 4)
                        if len(parts) >= 5:
                            procs.append({
                                "pid": parts[0],
                                "ppid": parts[1],
                                "user": parts[2],
                                "stat": parts[3],
                                "comm": parts[4],
                            })
            except Exception:
                pass
            collected["processes"] = procs

        elif artifact_type == "SOCKET_TABLE":
            # Collect active network listening sockets
            sockets = []
            try:
                proc = await asyncio.create_subprocess_exec(
                    "ss", "-tuln",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await proc.communicate()
                if proc.returncode == 0:
                    sockets = stdout.decode("utf-8", errors="replace").splitlines()
            except Exception:
                pass
            collected["sockets"] = sockets

        else:
            raise ValueError(f"Unsupported forensic artifact_type: '{artifact_type}'")

        payload_bytes = json.dumps(collected, indent=2).encode("utf-8")
        if len(payload_bytes) > self.max_bytes:
            raise ValueError(f"Collected forensic artifact exceeds maximum allowed size ({len(payload_bytes)} > {self.max_bytes} bytes)")

        return payload_bytes

    async def execute(self, parameters: Dict[str, Any], dry_run: bool) -> ExecutionResult:
        artifact_type = str(parameters.get("artifact_type", "LOGS")).upper()
        destination_path_param = parameters.get("destination_path", "")

        try:
            dest_file = self._resolve_safe_path(destination_path_param, artifact_type)
        except Exception as exc:
            return ExecutionResult(
                status="FAILED",
                exit_code=1,
                dry_run=dry_run,
                output=f"Forensic destination path validation failed: {exc}",
                observed_state={"artifact_size_bytes": 0, "error": str(exc)},
            )

        if dry_run:
            simulated_data = json.dumps({
                "artifact_type": artifact_type,
                "mode": "DRY_RUN_SIMULATION",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }).encode("utf-8")
            sha256 = hashlib.sha256(simulated_data).hexdigest()
            size = len(simulated_data)

            logger.info("[DRY-RUN] Simulating forensic collection of %s to %s", artifact_type, dest_file)
            return ExecutionResult(
                status="EXECUTED",
                exit_code=0,
                dry_run=True,
                output=f"[DRY-RUN] Simulated collection of {artifact_type} ({size} bytes, sha256: {sha256})",
                observed_state={
                    "artifact_size_bytes": size,
                    "artifact_path": str(dest_file),
                    "sha256": sha256,
                    "artifact_type": artifact_type,
                    "dry_run": True,
                    "is_simulated": True,
                },
            )

        # Real collection
        try:
            payload = await self._collect_payload(artifact_type)
            dest_file.parent.mkdir(parents=True, exist_ok=True)
            dest_file.write_bytes(payload)
            # Restrict artifact permissions to owner only (chmod 0600)
            dest_file.chmod(0o600)
            sha256 = hashlib.sha256(payload).hexdigest()
            size = len(payload)

            logger.info("Collected forensic artifact %s to %s (%d bytes)", artifact_type, dest_file, size)
            return ExecutionResult(
                status="EXECUTED",
                exit_code=0,
                dry_run=False,
                output=f"Collected {artifact_type} artifact: {dest_file.name} ({size} bytes, sha256: {sha256})",
                observed_state={
                    "artifact_size_bytes": size,
                    "artifact_path": str(dest_file),
                    "sha256": sha256,
                    "artifact_type": artifact_type,
                    "dry_run": False,
                    "is_simulated": False,
                },
            )
        except Exception as exc:
            logger.error("Failed to collect forensic artifact %s: %s", artifact_type, exc)
            return ExecutionResult(
                status="FAILED",
                exit_code=1,
                dry_run=False,
                output=f"Forensic collection failed: {exc}",
                observed_state={"artifact_size_bytes": 0, "error": str(exc)},
            )

    async def verify_state(self, parameters: Dict[str, Any], dry_run: bool) -> Dict[str, Any]:
        artifact_type = str(parameters.get("artifact_type", "LOGS")).upper()
        destination_path_param = parameters.get("destination_path", "")
        try:
            dest_file = self._resolve_safe_path(destination_path_param, artifact_type)
            if dest_file.exists() and dest_file.is_file():
                size = dest_file.stat().st_size
                content = dest_file.read_bytes()
                sha256 = hashlib.sha256(content).hexdigest()
                return {
                    "artifact_size_bytes": size,
                    "artifact_path": str(dest_file),
                    "sha256": sha256,
                    "artifact_type": artifact_type,
                }
        except Exception:
            pass

        if dry_run:
            return {
                "artifact_size_bytes": 256,
                "artifact_path": str(self.forensic_dir / f"simulated_{artifact_type.lower()}.json"),
                "sha256": hashlib.sha256(b"simulated").hexdigest(),
                "artifact_type": artifact_type,
                "dry_run": True,
                "is_simulated": True,
            }

        return {"artifact_size_bytes": 0, "artifact_type": artifact_type, "dry_run": False}
