"""Process execution and state telemetry collector using Linux /proc filesystem."""

import logging
import os
import pwd
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from uuid import UUID

from waliya_agent.collectors.base import BaseCollector

logger = logging.getLogger("waliya_agent.collectors.process")


class ProcessCollector(BaseCollector):
    """Collects process activity observations by parsing Linux /proc directly.

    Visibility & Architecture Note:
    - This collector operates via periodic /proc snapshots.
    - It reliably detects running and newly spawned persistent processes.
    - Ephemeral processes that start and exit entirely between snapshot intervals
      will not be observed. True sub-second process execution visibility requires
      kernel eBPF or auditd event streaming.
    """

    def __init__(self, agent_id: UUID, proc_root: Path = Path("/proc")):
        super().__init__(agent_id=agent_id, collector_name="process")
        self.proc_root = proc_root
        self._known_pids: Set[int] = set()
        self._uid_cache: Dict[int, str] = {}

    def _resolve_username(self, uid: int) -> str:
        """Resolve numeric UID to username with caching."""
        if uid in self._uid_cache:
            return self._uid_cache[uid]
        try:
            name = pwd.getpwuid(uid).pw_name
            self._uid_cache[uid] = name
            return name
        except (KeyError, ValueError):
            return str(uid)

    def _read_process_info(self, pid: int) -> Optional[Dict[str, Any]]:
        """Read and parse /proc/[pid] attributes safely without raising exceptions."""
        proc_dir = self.proc_root / str(pid)
        if not proc_dir.is_dir():
            return None

        ppid: Optional[int] = None
        username: str = "unknown"
        exe_path: str = ""
        cmdline: str = ""

        # 1. Read PPID and UID from /proc/[pid]/status
        status_file = proc_dir / "status"
        try:
            with open(status_file, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.startswith("PPid:"):
                        parts = line.split(":", 1)
                        if len(parts) > 1:
                            ppid = int(parts[1].strip())
                    elif line.startswith("Uid:"):
                        parts = line.split()
                        if len(parts) > 1:
                            uid = int(parts[1])
                            username = self._resolve_username(uid)
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            return None
        except Exception:
            pass

        # 2. Read exe path via readlink on /proc/[pid]/exe
        exe_link = proc_dir / "exe"
        try:
            exe_path = os.readlink(exe_link)
        except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
            exe_path = ""

        # 3. Read cmdline arguments
        cmd_file = proc_dir / "cmdline"
        try:
            with open(cmd_file, "rb") as f:
                raw_bytes = f.read(2048)
                # Null-delimited arguments
                cmdline = " ".join([arg.decode("utf-8", errors="replace") for arg in raw_bytes.split(b"\x00") if arg])
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            pass

        if not exe_path and cmdline:
            # Fall back to first token of cmdline
            exe_path = cmdline.split()[0]
        if not exe_path:
            exe_path = f"[pid_{pid}]"

        return {
            "pid": pid,
            "ppid": ppid or 0,
            "exe": exe_path,
            "cmdline": cmdline[:1024],
            "username": username,
        }

    async def collect(self) -> List[Dict[str, Any]]:
        """Inspect running processes, identify newly spawned PIDs, and emit normalized events."""
        events: List[Dict[str, Any]] = []

        if not self.proc_root.exists():
            return events

        current_pids: Set[int] = set()

        try:
            for entry in os.scandir(self.proc_root):
                if entry.is_dir() and entry.name.isdigit():
                    current_pids.add(int(entry.name))
        except (PermissionError, OSError) as exc:
            logger.debug("Failed scanning /proc directory: %s", exc)
            return events

        # First run: seed baseline known PIDs without flooding events
        if not self._known_pids:
            self._known_pids = current_pids
            logger.debug("Process baseline initialized with %d active processes", len(current_pids))
            return events

        # Identify newly spawned processes
        new_pids = current_pids - self._known_pids

        for pid in new_pids:
            proc_info = self._read_process_info(pid)
            if proc_info:
                # Assess severity based on process characteristics
                exe = proc_info.get("exe", "")
                user = proc_info.get("username", "")
                severity = "INFORMATIONAL"
                if user == "root" and any(k in exe for k in ["nc", "ncat", "nmap", "tcpdump", "wireshark"]):
                    severity = "HIGH"
                elif any(susp in exe for susp in ["miner", "xmrig", "mimikatz", "hydra"]):
                    severity = "CRITICAL"

                events.append(
                    self.create_envelope(
                        event_type="PROCESS_EXECUTION",
                        severity=severity,
                        payload=proc_info,
                    )
                )

        # Update known PIDs
        self._known_pids = current_pids
        return events
