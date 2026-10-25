"""Network connection telemetry collector using Linux /proc/net interfaces."""

import logging
import socket
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import UUID

from waliya_agent.collectors.base import BaseCollector

logger = logging.getLogger("waliya_agent.collectors.network")

# TCP State mapping from Linux kernel include/net/tcp_states.h
TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}


def parse_ipv4_hex(hex_str: str) -> str:
    """Parse 8-character hex string from /proc/net/tcp into dot-decimal IPv4 string."""
    try:
        val = int(hex_str, 16)
        return socket.inet_ntoa(struct.pack("<L", val))
    except Exception:
        return "0.0.0.0"


def parse_ipv6_hex(hex_str: str) -> str:
    """Parse 32-character hex string from /proc/net/tcp6 into IPv6 address string."""
    try:
        raw_bytes = bytes.fromhex(hex_str)
        # Linux stores IPv6 words in 4x32-bit little-endian integers
        words = struct.unpack("<IIII", raw_bytes)
        packed = struct.pack(">IIII", *words)
        return socket.inet_ntop(socket.AF_INET6, packed)
    except Exception:
        return "::"


class NetworkCollector(BaseCollector):
    """Collects local network sockets and active TCP connections from /proc/net/tcp.

    Visibility & Architecture Note:
    - This collector inspects active socket tables via /proc/net/tcp and /proc/net/tcp6.
    - Captures established connections, outbound connections, and listening ports.
    - Extremely short-lived connections (like fast port scans completing within milliseconds)
      may finish between snapshot polls and require kernel packet capture or eBPF socket tracing.
    """

    def __init__(self, agent_id: UUID, proc_net_dir: Path = Path("/proc/net")):
        super().__init__(agent_id=agent_id, collector_name="network")
        self.proc_net_dir = proc_net_dir
        self._known_connections: Set[Tuple[str, str, int, str, int, str]] = set()

    def _parse_tcp_file(self, file_path: Path, is_ipv6: bool = False) -> List[Dict[str, Any]]:
        """Parse socket entries from /proc/net/tcp or /proc/net/tcp6."""
        results: List[Dict[str, Any]] = []
        if not file_path.exists():
            return results

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except (PermissionError, FileNotFoundError, OSError) as exc:
            logger.debug("Cannot read %s: %s", file_path, exc)
            return results

        for line in lines[1:]:  # Skip header
            parts = line.strip().split()
            if len(parts) < 4:
                continue

            local_raw = parts[1]
            remote_raw = parts[2]
            state_hex = parts[3]

            state = TCP_STATES.get(state_hex, f"STATE_{state_hex}")

            # Only track ESTABLISHED, SYN_SENT, and LISTEN connections
            if state not in ("ESTABLISHED", "SYN_SENT", "LISTEN"):
                continue

            # Parse local address and port
            if ":" not in local_raw or ":" not in remote_raw:
                continue

            loc_ip_hex, loc_port_hex = local_raw.split(":", 1)
            rem_ip_hex, rem_port_hex = remote_raw.split(":", 1)

            local_ip = parse_ipv6_hex(loc_ip_hex) if is_ipv6 else parse_ipv4_hex(loc_ip_hex)
            local_port = int(loc_port_hex, 16)

            remote_ip = parse_ipv6_hex(rem_ip_hex) if is_ipv6 else parse_ipv4_hex(rem_ip_hex)
            remote_port = int(rem_port_hex, 16)

            # Skip listening sockets or non-remote for connection event emission unless desired
            if state == "LISTEN" or remote_port == 0:
                direction = "INBOUND"
            elif remote_port < 1024 or remote_port in (80, 443, 8000, 8080, 8443, 22, 53):
                direction = "OUTBOUND"
            else:
                direction = "INBOUND"

            results.append({
                "src_ip": local_ip,
                "src_port": local_port,
                "dst_ip": remote_ip,
                "dst_port": remote_port,
                "protocol": "TCP",
                "direction": direction,
                "state": state,
            })

        return results

    async def collect(self) -> List[Dict[str, Any]]:
        """Collect current network socket table and emit events for newly observed connections."""
        events: List[Dict[str, Any]] = []

        tcp4_file = self.proc_net_dir / "tcp"
        tcp6_file = self.proc_net_dir / "tcp6"

        current_sockets = self._parse_tcp_file(tcp4_file, is_ipv6=False)
        current_sockets.extend(self._parse_tcp_file(tcp6_file, is_ipv6=True))

        current_set: Set[Tuple[str, str, int, str, int, str]] = set()
        for sock in current_sockets:
            # We don't flood on loopback connections
            if sock["src_ip"] in ("127.0.0.1", "::1") and sock["dst_ip"] in ("127.0.0.1", "::1", "0.0.0.0", "::"):
                continue

            entry_tuple = (
                sock["protocol"],
                sock["src_ip"],
                sock["src_port"],
                sock["dst_ip"],
                sock["dst_port"],
                sock["state"],
            )
            current_set.add(entry_tuple)

        # First run: seed baseline known connections
        if not self._known_connections:
            self._known_connections = current_set
            return events

        # Emit events for newly observed connections
        new_connections = current_set - self._known_connections
        for proto, src_ip, src_port, dst_ip, dst_port, state in new_connections:
            if dst_port == 0:  # Skip raw listen bindings without active peer
                continue

            direction = "OUTBOUND" if dst_port in (80, 443, 53, 22, 8000, 8080) else "INBOUND"
            severity = "HIGH" if dst_port in (4444, 1337, 31337, 6667) else "INFORMATIONAL"

            events.append(
                self.create_envelope(
                    event_type="NETWORK_CONNECTION",
                    severity=severity,
                    payload={
                        "src_ip": src_ip,
                        "src_port": src_port,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "protocol": proto,
                        "direction": direction,
                    },
                )
            )

        self._known_connections = current_set
        return events
