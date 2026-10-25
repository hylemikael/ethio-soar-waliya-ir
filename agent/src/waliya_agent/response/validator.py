"""Strict action-specific parameter validation and safety invariants."""

import ipaddress
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("waliya_agent.response.validator")

# Critical subnets that must never be blocked to prevent bricking endpoint or management channel
PROTECTED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),       # IPv4 Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-Local
    ipaddress.ip_network("224.0.0.0/4"),        # IPv4 Multicast
    ipaddress.ip_network("255.255.255.255/32"),  # Broadcast
    ipaddress.ip_network("::1/128"),           # IPv6 Loopback
    ipaddress.ip_network("fe80::/10"),          # IPv6 Link-Local
    ipaddress.ip_network("ff00::/8"),           # IPv6 Multicast
]

CRITICAL_SYSTEM_PROCESSES = {
    "systemd",
    "init",
    "kthreadd",
    "sshd",
    "login",
    "dbus-daemon",
    "systemd-journald",
    "udevd",
    "waliya-agent",
}


class ActionValidator:
    """Validates parameters for allowed defensive response actions."""

    @classmethod
    def validate_block_ip(cls, parameters: Dict[str, Any], server_ip: Optional[str] = None) -> Dict[str, Any]:
        """Validate IP address blocking parameters."""
        raw_ip = parameters.get("ip_address")
        if not raw_ip or not isinstance(raw_ip, str):
            raise ValueError("BLOCK_IP requires a non-empty string 'ip_address'")

        ip_str = raw_ip.strip()
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError as exc:
            raise ValueError(f"Invalid IP address format: '{raw_ip}'") from exc

        if ip_obj.is_unspecified:
            raise ValueError("Refusing to block unspecified address (0.0.0.0 or ::)")

        for net in PROTECTED_NETWORKS:
            if ip_obj in net:
                raise ValueError(
                    f"Refusing to block protected network address: '{ip_str}' is within {net}"
                )

        if server_ip and ip_str == server_ip.strip():
            raise ValueError(f"Refusing to block management server IP: '{ip_str}'")

        direction = str(parameters.get("direction", "BOTH")).upper()
        if direction not in ("IN", "OUT", "BOTH"):
            raise ValueError(f"Invalid direction '{direction}'; must be 'IN', 'OUT', or 'BOTH'")

        return {"ip_address": ip_str, "direction": direction}

    @classmethod
    def validate_unblock_ip(cls, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Validate IP address unblocking parameters."""
        raw_ip = parameters.get("ip_address")
        if not raw_ip or not isinstance(raw_ip, str):
            raise ValueError("UNBLOCK_IP requires a non-empty string 'ip_address'")

        ip_str = raw_ip.strip()
        try:
            ipaddress.ip_address(ip_str)
        except ValueError as exc:
            raise ValueError(f"Invalid IP address format: '{raw_ip}'") from exc

        return {"ip_address": ip_str}

    @classmethod
    def validate_terminate_process(cls, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Validate process termination parameters."""
        raw_pid = parameters.get("pid")
        if raw_pid is None or not isinstance(raw_pid, int) or raw_pid <= 1:
            raise ValueError("TERMINATE_PROCESS requires a positive integer 'pid' > 1")

        raw_name = parameters.get("process_name")
        if not raw_name or not isinstance(raw_name, str) or not raw_name.strip():
            raise ValueError("TERMINATE_PROCESS requires a non-empty 'process_name' to prevent PID reuse races")

        pname = raw_name.strip()
        if pname.lower() in CRITICAL_SYSTEM_PROCESSES:
            raise ValueError(f"Refusing to terminate protected system process: '{pname}' (PID {raw_pid})")

        return {
            "pid": raw_pid,
            "process_name": pname,
            "kill_tree": bool(parameters.get("kill_tree", False)),
        }

    @classmethod
    def validate_collect_forensic(cls, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Validate forensic artifact collection parameters."""
        atype = str(parameters.get("artifact_type", "")).upper()
        if atype == "MEMORY_DUMP":
            raise ValueError(
                "Unsupported forensic artifact_type 'MEMORY_DUMP'. Full physical memory capture requires dedicated kernel instrumentation (e.g. LiME) and is not supported in user-space."
            )

        allowed_types = {"LOGS", "PROC_MAP", "SOCKET_TABLE"}
        if atype not in allowed_types:
            raise ValueError(f"Unsupported forensic artifact_type '{atype}'. Allowed: {sorted(allowed_types)}")

        dest_path = parameters.get("destination_path")
        if dest_path:
            clean_path = str(dest_path).strip()
            if ".." in clean_path or clean_path.startswith(("/etc", "/root", "/boot", "/sys", "/proc")):
                raise ValueError(f"Prohibited forensic destination path traversal: '{dest_path}'")

        return {
            "artifact_type": atype,
            "destination_path": dest_path,
        }
