#!/usr/bin/env python3
"""Operational tool for inspecting, diagnosing, and recovering Redis stream state in Ethio-SOAR."""

import argparse
import os
import sys
from typing import Any, Dict, List, Optional
import redis

# Defaults
DEFAULT_REDIS_URL = "redis://:waliya_redis_dev_secret@127.0.0.1:6380/0"
STREAM_RAW = "stream:telemetry:raw"
STREAM_DLQ = "stream:telemetry:dlq"
CONSUMER_GROUP = "waliya_detection_group"


def get_redis_client(redis_url: Optional[str] = None) -> redis.Redis:
    """Connect to Redis using URL from environment or parameter."""
    url = redis_url or os.getenv("WALIYA_REDIS_URL", DEFAULT_REDIS_URL)
    return redis.Redis.from_url(url, decode_responses=True)


def cmd_status(r: redis.Redis) -> int:
    """Inspect and report Redis persistence and stream consumer state."""
    print("=" * 80)
    print("Ethio-SOAR Redis Streaming & Persistence Diagnostics")
    print("=" * 80)

    try:
        r.ping()
        print("[+] Redis Connectivity: ONLINE (PONG)")
    except Exception as exc:
        print(f"[-] Redis Connectivity: OFFLINE ({exc})", file=sys.stderr)
        return 1

    info_persist = r.info("persistence")
    print(f"[*] Persistence Mode  : AOF Enabled = {info_persist.get('aof_enabled') == 1}")
    print(f"    AOF Rewrite Status: {info_persist.get('aof_last_bgrewrite_status', 'N/A')}")
    print(f"    AOF Current Size  : {info_persist.get('aof_current_size', 0)} bytes")

    # Inspect Streams
    for s_name in [STREAM_RAW, STREAM_DLQ]:
        print("-" * 80)
        print(f"Stream: '{s_name}'")
        try:
            s_len = r.xlen(s_name)
            print(f"    Total Messages    : {s_len}")
        except redis.ResponseError:
            print(f"    Status            : NOT INITIALIZED (Stream does not exist)")
            continue

        # Inspect Consumer Groups
        try:
            groups = r.xinfo_groups(s_name)
            if not groups:
                print("    Consumer Groups   : NONE")
            for g in groups:
                print(f"    Group '{g['name']}':")
                print(f"        Consumers      : {g.get('consumers', 0)}")
                print(f"        Pending (PEL)  : {g.get('pending', 0)}")
                print(f"        Last Delivered : {g.get('last-delivered-id', 'N/A')}")
        except Exception as exc:
            print(f"    Consumer Groups   : Error querying groups ({exc})")

    print("=" * 80)
    return 0


def cmd_reinit_groups(r: redis.Redis) -> int:
    """Safely ensure that required consumer groups exist on telemetry streams."""
    print("[*] Ensuring required consumer groups exist on Redis streams...")
    for s_name in [STREAM_RAW, STREAM_DLQ]:
        try:
            r.xgroup_create(s_name, CONSUMER_GROUP, id="$", mkstream=True)
            print(f"[+] Created consumer group '{CONSUMER_GROUP}' on stream '{s_name}'.")
        except redis.ResponseError as err:
            if "BUSYGROUP" in str(err):
                print(f"[+] Consumer group '{CONSUMER_GROUP}' already exists on stream '{s_name}'.")
            else:
                print(f"[-] ERROR creating group on '{s_name}': {err}", file=sys.stderr)
                return 1
    print("[SUCCESS] All required stream consumer groups are initialized.")
    return 0


def cmd_check_pel(r: redis.Redis) -> int:
    """Display pending entries list (PEL) to identify stuck in-flight messages."""
    print(f"[*] Checking Pending Entries List (PEL) for stream '{STREAM_RAW}'...")
    try:
        pending_summary = r.xpending(STREAM_RAW, CONSUMER_GROUP)
        total_pending = pending_summary["pending"]
        print(f"    Total Pending Entries : {total_pending}")
        print(f"    Smallest Pending ID   : {pending_summary['min']}")
        print(f"    Largest Pending ID    : {pending_summary['max']}")

        if total_pending > 0:
            print("\n[*] Detailed Pending Entries (up to 20):")
            entries = r.xpending_range(STREAM_RAW, CONSUMER_GROUP, min="-", max="+", count=20)
            for e in entries:
                idle_sec = e["idle"] / 1000.0
                print(f"    ID: {e['message_id']} | Consumer: {e['consumer']} | Idle: {idle_sec:.1f}s | Deliveries: {e['times_delivered']}")
    except redis.ResponseError as err:
        print(f"[-] Unable to query PEL: {err}", file=sys.stderr)
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Ethio-SOAR Redis Streaming & Recovery Tool")
    parser.add_argument("--redis-url", default=None, help="Redis connection URL")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("status", help="Inspect Redis stream lengths, consumer groups, and persistence")
    subparsers.add_parser("reinit-groups", help="Ensure required stream consumer groups exist")
    subparsers.add_parser("check-pel", help="List pending un-acknowledged messages in PEL")

    args = parser.parse_args()

    try:
        r = get_redis_client(args.redis_url)
    except Exception as exc:
        print(f"[-] Failed configuring Redis client: {exc}", file=sys.stderr)
        return 1

    if args.command == "status":
        return cmd_status(r)
    elif args.command == "reinit-groups":
        return cmd_reinit_groups(r)
    elif args.command == "check-pel":
        return cmd_check_pel(r)

    return 0


if __name__ == "__main__":
    sys.exit(main())
