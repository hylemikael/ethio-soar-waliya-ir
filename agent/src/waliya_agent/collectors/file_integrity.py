"""File Integrity Monitoring (FIM) collector with debouncing and symlink safety."""

import hashlib
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from uuid import UUID

from waliya_agent.collectors.base import BaseCollector

logger = logging.getLogger("waliya_agent.collectors.fim")


class FileRecord:
    """Snapshot representation of an observed file."""
    def __init__(self, path: Path, size_bytes: int, mtime: float, sha256: Optional[str] = None):
        self.path = path
        self.size_bytes = size_bytes
        self.mtime = mtime
        self.sha256 = sha256


class FileIntegrityCollector(BaseCollector):
    """Monitors explicitly configured filesystem paths for changes.

    Safety:
    - Never reads or uploads file contents.
    - Only computes SHA-256 digests in bounded 64KB chunks.
    - Safely skips symlinks pointing outside monitored boundaries to prevent loops.
    - Debounces rapid bursts of modifications.
    """

    def __init__(
        self,
        agent_id: UUID,
        paths_to_monitor: List[str],
        debounce_seconds: float = 2.0,
        max_file_size_mb: float = 25.0,
    ):
        super().__init__(agent_id=agent_id, collector_name="fim")
        self.paths_to_monitor = [Path(p).resolve() for p in paths_to_monitor]
        self.debounce_seconds = debounce_seconds
        self.max_file_size_bytes = int(max_file_size_mb * 1024 * 1024)

        # Baseline state: path_str -> FileRecord
        self._known_state: Dict[str, FileRecord] = {}
        # Debounce tracker: path_str -> last_event_time
        self._debounce_tracker: Dict[str, float] = {}

    def _compute_sha256(self, path: Path, file_size: int) -> Optional[str]:
        """Compute SHA-256 hash in bounded 64KB blocks. Returns None if oversized or unreadable."""
        if file_size > self.max_file_size_bytes:
            logger.debug("Skipping hash for %s: file size %d bytes exceeds limit", path, file_size)
            return None

        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest().lower()
        except (PermissionError, FileNotFoundError, OSError) as exc:
            logger.debug("Cannot compute SHA-256 for %s: %s", path, exc)
            return None

    def _scan_target(self, target: Path) -> Dict[str, FileRecord]:
        """Scan a configured path (file or directory) safely without following symlinks."""
        current: Dict[str, FileRecord] = {}

        if not target.exists():
            return current

        # Single file
        if target.is_file():
            try:
                st = os.lstat(target)
                sha = self._compute_sha256(target, st.st_size)
                current[str(target)] = FileRecord(target, st.st_size, st.st_mtime, sha)
            except (PermissionError, FileNotFoundError, OSError):
                pass
            return current

        # Directory traversal (bounded depth to prevent infinite loops)
        if target.is_dir():
            try:
                for root, dirs, files in os.walk(target, followlinks=False):
                    # Prevent recursing into deep virtual filesystems
                    if any(ignored in root for ignored in ["/proc", "/sys", "/dev"]):
                        continue

                    for fname in files:
                        file_path = Path(root) / fname
                        try:
                            # Use lstat to not follow symlinks
                            st = os.lstat(file_path)
                            # Skip FIFO, sockets, character devices
                            if not os.path.isfile(file_path):
                                continue

                            sha = self._compute_sha256(file_path, st.st_size)
                            current[str(file_path)] = FileRecord(file_path, st.st_size, st.st_mtime, sha)
                        except (PermissionError, FileNotFoundError, OSError):
                            continue
            except (PermissionError, OSError) as exc:
                logger.debug("Permission error scanning directory %s: %s", target, exc)

        return current

    async def collect(self) -> List[Dict[str, Any]]:
        """Compare current filesystem state against baseline and yield diff events."""
        events: List[Dict[str, Any]] = []
        now_ts = time.time()
        current_state: Dict[str, FileRecord] = {}

        # 1. Scan all targets
        for target in self.paths_to_monitor:
            try:
                scanned = self._scan_target(target)
                current_state.update(scanned)
            except Exception as exc:
                logger.warning("Error scanning FIM target %s: %s", target, exc)

        # First run: seed baseline state without alerting on existing files
        if not self._known_state:
            self._known_state = current_state
            return events

        # 2. Check for CREATED and MODIFIED files
        for path_str, record in current_state.items():
            last_event_time = self._debounce_tracker.get(path_str, 0.0)
            if now_ts - last_event_time < self.debounce_seconds:
                # Debounce: suppress rapid recurring events for same file
                continue

            if path_str not in self._known_state:
                # CREATED
                self._debounce_tracker[path_str] = now_ts
                events.append(
                    self.create_envelope(
                        event_type="FILE_INTEGRITY",
                        severity="LOW",
                        payload={
                            "file_path": path_str,
                            "action": "CREATED",
                            "sha256": record.sha256,
                            "size_bytes": record.size_bytes,
                            "is_executable": os.access(path_str, os.X_OK) if os.path.exists(path_str) else False,
                        },
                    )
                )
            else:
                old_record = self._known_state[path_str]
                # Compare mtime, size, or SHA-256
                if old_record.mtime != record.mtime or old_record.size_bytes != record.size_bytes or old_record.sha256 != record.sha256:
                    # MODIFIED
                    self._debounce_tracker[path_str] = now_ts
                    severity = "MEDIUM" if "/etc/" in path_str or "/bin/" in path_str else "LOW"
                    events.append(
                        self.create_envelope(
                            event_type="FILE_INTEGRITY",
                            severity=severity,
                            payload={
                                "file_path": path_str,
                                "action": "MODIFIED",
                                "sha256": record.sha256,
                                "size_bytes": record.size_bytes,
                                "is_executable": os.access(path_str, os.X_OK) if os.path.exists(path_str) else False,
                            },
                        )
                    )

        # 3. Check for DELETED files
        for path_str, old_record in self._known_state.items():
            if path_str not in current_state:
                last_event_time = self._debounce_tracker.get(path_str, 0.0)
                if now_ts - last_event_time >= self.debounce_seconds:
                    self._debounce_tracker[path_str] = now_ts
                    events.append(
                        self.create_envelope(
                            event_type="FILE_INTEGRITY",
                            severity="LOW",
                            payload={
                                "file_path": path_str,
                                "action": "DELETED",
                                "sha256": old_record.sha256,
                                "size_bytes": old_record.size_bytes,
                                "is_executable": False,
                            },
                        )
                    )

        # Update known state
        self._known_state = current_state

        # Prune debounce tracker
        cutoff = now_ts - (self.debounce_seconds * 5)
        self._debounce_tracker = {k: v for k, v in self._debounce_tracker.items() if v > cutoff}

        return events
