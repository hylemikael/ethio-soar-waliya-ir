"""Tests for Linux authentication log monitoring collector."""

import os
from pathlib import Path
from uuid import UUID

import pytest

from waliya_agent.collectors.auth_log import AuthLogCollector


def test_auth_line_regex_parsing(mock_agent_id: UUID):
    """Verify parsing accuracy on standard Linux syslog authentication lines."""
    collector = AuthLogCollector(agent_id=mock_agent_id)

    # 1. SSH Accepted
    line_ssh_ok = "Oct 22 21:00:01 web-01 sshd[12345]: Accepted publickey for secadmin from 192.168.1.100 port 54321 ssh2"
    p1 = collector.parse_line(line_ssh_ok)
    assert p1 is not None
    assert p1["service"] == "sshd"
    assert p1["user"] == "secadmin"
    assert p1["src_ip"] == "192.168.1.100"
    assert p1["status"] == "SUCCESS"
    assert p1["port"] == 54321

    # 2. SSH Failed
    line_ssh_fail = "Oct 22 21:00:05 web-01 sshd[12346]: Failed password for invalid user root from 198.51.100.88 port 43210 ssh2"
    p2 = collector.parse_line(line_ssh_fail)
    assert p2 is not None
    assert p2["service"] == "sshd"
    assert p2["user"] == "root"
    assert p2["src_ip"] == "198.51.100.88"
    assert p2["status"] == "FAILURE"

    # 3. PAM Failure
    line_pam = "Oct 22 21:00:10 web-01 su(pam_unix)[12347]: authentication failure; logname= uid=1000 euid=0 tty=pts/1 ruser= rhost= user=root"
    p3 = collector.parse_line(line_pam)
    assert p3 is not None
    assert p3["service"] == "su"
    assert p3["user"] == "root"
    assert p3["status"] == "FAILURE"

    # 4. Sudo Execution
    line_sudo = "Oct 22 21:00:15 web-01 sudo:   analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/bin/cat /etc/shadow"
    p4 = collector.parse_line(line_sudo)
    assert p4 is not None
    assert p4["service"] == "sudo"
    assert p4["user"] == "analyst"
    assert p4["target_user"] == "root"
    assert p4["status"] == "SUCCESS"


@pytest.mark.asyncio
async def test_auth_collector_tailing_and_rotation(temp_dir: Path, mock_agent_id: UUID):
    """Test tailing new log lines and handling file rotation."""
    log_file = temp_dir / "auth.log"
    log_file.write_text("Oct 22 20:00:00 initial existing line\n", encoding="utf-8")

    collector = AuthLogCollector(agent_id=mock_agent_id, log_path=log_file)

    # Initial run seeks to end: 0 events emitted
    initial_events = await collector.collect()
    assert len(initial_events) == 0

    # Append new authentication event
    with open(log_file, "a", encoding="utf-8") as f:
        f.write("Oct 22 21:01:00 web-01 sshd[2222]: Failed password for attacker from 203.0.113.5 port 55555 ssh2\n")

    events = await collector.collect()
    assert len(events) == 1
    assert events[0]["event_type"] == "AUTHENTICATION"
    assert events[0]["payload"]["src_ip"] == "203.0.113.5"
    assert events[0]["payload"]["status"] == "FAILURE"

    # Simulate log rotation: file is truncated or replaced
    log_file.write_text("Oct 22 21:02:00 web-01 sshd[3333]: Accepted password for admin from 10.0.0.1 port 44444 ssh2\n", encoding="utf-8")

    rotated_events = await collector.collect()
    assert len(rotated_events) == 1
    assert rotated_events[0]["payload"]["src_ip"] == "10.0.0.1"
    assert rotated_events[0]["payload"]["status"] == "SUCCESS"


@pytest.mark.asyncio
async def test_auth_collector_missing_file_handled_safely(temp_dir: Path, mock_agent_id: UUID):
    """Verify that nonexistent auth logs do not crash the collector."""
    nonexistent = temp_dir / "does_not_exist.log"
    collector = AuthLogCollector(agent_id=mock_agent_id, log_path=nonexistent)
    events = await collector.collect()
    assert events == []
