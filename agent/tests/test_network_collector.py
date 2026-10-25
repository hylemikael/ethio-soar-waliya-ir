"""Tests for Linux network connection collector."""

from pathlib import Path
from uuid import UUID

import pytest

from waliya_agent.collectors.network import (
    NetworkCollector,
    parse_ipv4_hex,
    parse_ipv6_hex,
)


def test_ip_hex_decoding():
    """Verify conversion of Linux kernel hex representations to standard IP strings."""
    # 127.0.0.1 -> 0100007F
    assert parse_ipv4_hex("0100007F") == "127.0.0.1"
    # 10.0.0.1 -> 0100000A
    assert parse_ipv4_hex("0100000A") == "10.0.0.1"


@pytest.mark.asyncio
async def test_network_collector_synthetic_proc(temp_dir: Path, mock_agent_id: UUID):
    """Test network socket table parsing using synthetic /proc/net files."""
    proc_net = temp_dir / "proc_net"
    proc_net.mkdir()

    tcp_file = proc_net / "tcp"
    # Initial table with one established socket (10.0.0.5:45000 -> 198.51.100.2:443)
    header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    line1 = "   0: 0500000A:AFC8 026433C6:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 11111 1 0 0 10 0\n"

    tcp_file.write_text(header + line1, encoding="utf-8")

    collector = NetworkCollector(agent_id=mock_agent_id, proc_net_dir=proc_net)

    # First run seeds baseline: 0 events emitted
    initial_events = await collector.collect()
    assert len(initial_events) == 0

    # Add a newly opened outbound connection (10.0.0.5:52000 -> 203.0.113.10:80)
    # 80 hex is 0050. 203.0.113.10 is CB.00.71.0A -> 0A7100CB
    line2 = "   1: 0500000A:CB20 0A7100CB:0050 01 00000000:00000000 00:00000000 00000000  1000        0 22222 1 0 0 10 0\n"
    tcp_file.write_text(header + line1 + line2, encoding="utf-8")

    events = await collector.collect()
    assert len(events) == 1
    ev = events[0]
    assert ev["event_type"] == "NETWORK_CONNECTION"
    assert ev["payload"]["src_ip"] == "10.0.0.5"
    assert ev["payload"]["dst_port"] == 80
    assert ev["payload"]["direction"] == "OUTBOUND"
    assert ev["payload"]["protocol"] == "TCP"


@pytest.mark.asyncio
async def test_network_collector_missing_proc_dir(temp_dir: Path, mock_agent_id: UUID):
    """Verify that unreadable or nonexistent /proc/net directories return empty lists safely."""
    missing = temp_dir / "nonexistent_proc_net"
    collector = NetworkCollector(agent_id=mock_agent_id, proc_net_dir=missing)
    events = await collector.collect()
    assert events == []
