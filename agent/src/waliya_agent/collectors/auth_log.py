"""Linux authentication log monitor parsing SSH and PAM authentication events."""

import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import UUID

from waliya_agent.collectors.base import BaseCollector

logger = logging.getLogger("waliya_agent.collectors.auth")

# Regular expressions for SSH and PAM authentication logs
SSH_ACCEPTED_RE = re.compile(
    r"sshd\[\d+\]:\s+Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)
SSH_FAILED_RE = re.compile(
    r"sshd\[\d+\]:\s+Failed\s+(?P<method>\S+)\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)
PAM_FAILURE_RE = re.compile(
    r"(?P<service>\S+)\(pam_unix\)\[\d+\]:\s+authentication\s+failure;.*user=(?P<user>\S+)"
)
SUDO_AUTH_RE = re.compile(
    r"sudo:\s+(?P<user>\S+)\s+:\s+TTY=\S+\s+;\s+PWD=\S+\s+;\s+USER=(?P<target_user>\S+)\s+;\s+COMMAND=(?P<cmd>.*)"
)


class AuthLogCollector(BaseCollector):
    """Parses Linux authentication events from /var/log/auth.log or /var/log/secure.

    Handles:
    - Log file rotation (file truncation or inode changes).
    - Unprivileged permission denial gracefully (warns once).
    - Missing files gracefully.
    """

    def __init__(self, agent_id: UUID, log_path: Path = Path("/var/log/auth.log")):
        super().__init__(agent_id=agent_id, collector_name="auth")
        self.log_path = log_path
        self._last_offset = 0
        self._last_inode: Optional[int] = None
        self._permission_warned = False
        self._is_initialized = False

    def _open_log_file(self) -> Optional[Any]:
        """Open log file, detecting log rotation via inode or size shrinkage."""
        if not self.log_path.exists():
            return None

        try:
            st = os.stat(self.log_path)
            current_inode = st.st_ino
            current_size = st.st_size

            # If rotated or shrunk, reset offset to start of file
            if self._last_inode is not None and (self._last_inode != current_inode or current_size < self._last_offset):
                logger.info("Log rotation detected for %s. Resetting read position.", self.log_path)
                self._last_offset = 0

            self._last_inode = current_inode
            f = open(self.log_path, "r", encoding="utf-8", errors="replace")
            f.seek(self._last_offset)
            return f
        except PermissionError:
            if not self._permission_warned:
                logger.warning(
                    "Read permission denied on %s. Authentication monitoring requires read access or adm group membership.",
                    self.log_path,
                )
                self._permission_warned = True
            return None
        except Exception as exc:
            logger.debug("Failed opening auth log %s: %s", self.log_path, exc)
            return None

    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse an individual syslog line into an AUTHENTICATION event payload."""
        line = line.strip()
        if not line:
            return None

        # 1. SSH Accepted
        m = SSH_ACCEPTED_RE.search(line)
        if m:
            return {
                "service": "sshd",
                "user": m.group("user"),
                "src_ip": m.group("ip"),
                "status": "SUCCESS",
                "method": m.group("method"),
                "port": int(m.group("port")),
            }

        # 2. SSH Failed
        m = SSH_FAILED_RE.search(line)
        if m:
            return {
                "service": "sshd",
                "user": m.group("user"),
                "src_ip": m.group("ip"),
                "status": "FAILURE",
                "method": m.group("method"),
                "port": int(m.group("port")),
            }

        # 3. PAM generic failure
        m = PAM_FAILURE_RE.search(line)
        if m:
            return {
                "service": m.group("service"),
                "user": m.group("user"),
                "src_ip": None,
                "status": "FAILURE",
            }

        # 4. Sudo execution
        m = SUDO_AUTH_RE.search(line)
        if m:
            return {
                "service": "sudo",
                "user": m.group("user"),
                "src_ip": "127.0.0.1",
                "status": "SUCCESS",
                "target_user": m.group("target_user"),
            }

        return None

    async def collect(self) -> List[Dict[str, Any]]:
        """Tail auth log from previous offset and extract authentication events."""
        events: List[Dict[str, Any]] = []

        f = self._open_log_file()
        if not f:
            return events

        try:
            # First initialization: seek to end of existing file so we don't replay old history
            if not self._is_initialized:
                self._is_initialized = True
                if os.path.getsize(self.log_path) > 0:
                    f.seek(0, os.SEEK_END)
                    self._last_offset = f.tell()
                    return events

            for line in f:
                parsed = self.parse_line(line)
                if parsed:
                    severity = "INFORMATIONAL" if parsed["status"] == "SUCCESS" else "MEDIUM"
                    events.append(
                        self.create_envelope(
                            event_type="AUTHENTICATION",
                            severity=severity,
                            payload=parsed,
                        )
                    )

            self._last_offset = f.tell()
        except Exception as exc:
            logger.warning("Error reading auth log %s: %s", self.log_path, exc)
        finally:
            f.close()

        return events
