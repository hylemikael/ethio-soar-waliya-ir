#!/usr/bin/env python3
"""Operational tool for listing, inspecting, and cryptographically verifying Ethio-SOAR database backups."""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


def calculate_sha256(filepath: Path) -> str:
    """Calculate SHA-256 hash of a file efficiently in 64KB chunks."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def verify_single_backup(backup_path: Path) -> Dict[str, Any]:
    """Verify backup file presence, SHA-256 integrity, manifest data, and pg_restore viability."""
    result: Dict[str, Any] = {
        "file": backup_path.name,
        "path": str(backup_path),
        "size_bytes": 0,
        "exists": False,
        "manifest_found": False,
        "checksum_verified": False,
        "archive_valid": False,
        "alembic_head": "unknown",
        "error": None,
    }

    if not backup_path.is_file():
        result["error"] = "Backup file not found."
        return result

    result["exists"] = True
    result["size_bytes"] = backup_path.stat().st_size

    # Check companion manifest
    meta_path = Path(str(backup_path) + ".meta.json")
    if meta_path.is_file():
        result["manifest_found"] = True
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            expected_sha = meta.get("sha256_checksum")
            actual_sha = calculate_sha256(backup_path)
            result["actual_sha256"] = actual_sha
            result["expected_sha256"] = expected_sha
            result["alembic_head"] = meta.get("alembic_head_revision", "unknown")

            if expected_sha and expected_sha.lower() == actual_sha.lower():
                result["checksum_verified"] = True
            else:
                result["error"] = f"Checksum mismatch: manifest {expected_sha} != actual {actual_sha}"
        except Exception as exc:
            result["error"] = f"Failed parsing metadata manifest: {exc}"
    else:
        # Calculate hash directly if no manifest
        actual_sha = calculate_sha256(backup_path)
        result["actual_sha256"] = actual_sha

    # Test pg_restore table of contents
    try:
        proc = subprocess.run(
            ["pg_restore", "--list", str(backup_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )
        if proc.returncode == 0:
            result["archive_valid"] = True
    except FileNotFoundError:
        # Fallback to docker container pg_restore
        try:
            docker_cmd = f"docker exec -i waliya_postgres pg_restore --list < '{backup_path}'"
            proc = subprocess.run(
                docker_cmd,
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
            )
            if proc.returncode == 0:
                result["archive_valid"] = True
        except Exception:
            pass
    except Exception as exc:
        result["error"] = f"pg_restore verification failed: {exc}"

    return result


def list_backups(backup_dir: Path) -> None:
    """Print an aligned tabular overview of all available backups and their status."""
    if not backup_dir.is_dir():
        print(f"[-] Backup directory '{backup_dir}' does not exist.")
        sys.exit(1)

    dumps = sorted(backup_dir.glob("*.dump"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not dumps:
        print(f"[*] No .dump files found in '{backup_dir}'.")
        return

    print("=" * 110)
    print(f"{'BACKUP FILE':<38} {'SIZE (MB)':<10} {'ALEMBIC REV':<24} {'CHECKSUM':<12} {'ARCHIVE':<10} {'STATUS'}")
    print("=" * 110)

    for dump in dumps:
        res = verify_single_backup(dump)
        size_mb = f"{res['size_bytes'] / (1024 * 1024):.2f}"
        chk_status = "PASS" if res["checksum_verified"] else ("NO_MANIFEST" if not res["manifest_found"] else "FAIL")
        arc_status = "VALID" if res["archive_valid"] else "INVALID"
        overall = "HEALTHY" if (res["checksum_verified"] and res["archive_valid"]) else "DEGRADED"

        print(
            f"{res['file']:<38} {size_mb:<10} {str(res['alembic_head']):<24} {chk_status:<12} {arc_status:<10} {overall}"
        )
    print("=" * 110)


def main() -> int:
    parser = argparse.ArgumentParser(description="Ethio-SOAR Database Backup Management & Verification Tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # list
    list_p = subparsers.add_parser("list", help="List all backups and their verification status")
    list_p.add_argument("--backup-dir", default="./backups", help="Directory containing backups")

    # verify
    verify_p = subparsers.add_parser("verify", help="Verify a specific backup file")
    verify_p.add_argument("backup_file", help="Path to the .dump file to verify")

    args = parser.parse_args()

    if args.command == "list":
        list_backups(Path(args.backup_dir).resolve())
        return 0
    elif args.command == "verify":
        target_path = Path(args.backup_file).resolve()
        print(f"[*] Verifying backup file: {target_path}")
        res = verify_single_backup(target_path)
        print(f"    File Size:          {res['size_bytes']} bytes")
        print(f"    Manifest Present:   {res['manifest_found']}")
        print(f"    Checksum Verified:  {res['checksum_verified']}")
        print(f"    Archive Valid:      {res['archive_valid']}")
        print(f"    Alembic Revision:   {res['alembic_head']}")

        if res["error"]:
            print(f"[-] Verification Error: {res['error']}", file=sys.stderr)
            return 1

        if res["checksum_verified"] and res["archive_valid"]:
            print("[SUCCESS] Backup file passed all integrity checks.")
            return 0
        else:
            print("[-] FAILED: Integrity checks did not pass.", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
