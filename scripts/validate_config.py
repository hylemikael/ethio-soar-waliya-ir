#!/usr/bin/env python3
"""Pre-flight configuration validator for Ethio-SOAR (Waliya-IR) deployments."""

import argparse
import os
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Ethio-SOAR deployment configuration.")
    parser.add_argument(
        "--env-file",
        default=".env",
        help="Path to .env configuration file (default: .env)",
    )
    args = parser.parse_args()

    env_path = Path(args.env_file)
    if not env_path.is_file():
        print(f"[FAIL] Configuration file '{args.env_file}' not found.")
        print("       Please copy .env.example to .env and configure mandatory variables.")
        return 1

    # Add backend/src to sys.path so waliya package can be imported
    repo_root = Path(__file__).resolve().parent.parent
    backend_src = repo_root / "backend" / "src"
    if str(backend_src) not in sys.path:
        sys.path.insert(0, str(backend_src))

    try:
        from waliya.config import Settings
    except ImportError as err:
        print(f"[FAIL] Failed importing Waliya configuration module: {err}")
        return 1

    print(f"[*] Validating deployment configuration from '{args.env_file}'...")

    try:
        # Load settings pointing to the designated env file
        settings = Settings(_env_file=str(env_path))
        is_prod = settings.ENV.lower() in ("production", "prod")

        print(f"[PASS] Environment: {settings.ENV}")
        print(f"[PASS] Log Level: {settings.LOG_LEVEL}")
        print(f"[PASS] Database URL scheme: {settings.DATABASE_URL.split('://')[0]}://...")
        print(f"[PASS] Redis URL scheme: {settings.REDIS_URL.split('://')[0]}://...")
        print(f"[PASS] CORS Origins: {settings.CORS_ORIGINS}")
        print(f"[PASS] Session Cookie Secure: {settings.SESSION_COOKIE_SECURE}")
        print(f"[PASS] Public API Docs Enabled: {settings.ENABLE_PUBLIC_DOCS if is_prod else True}")

        # Security posture advisories for production
        if is_prod:
            if not settings.SESSION_COOKIE_SECURE:
                print("       [WARN] WALIYA_SESSION_COOKIE_SECURE is False in production. Ensure HTTPS is enforced via upstream reverse proxy.")
            if settings.ENABLE_PUBLIC_DOCS:
                print("       [WARN] Public API Documentation is enabled in production. Recommend disabling unless explicitly required.")

        print("[SUCCESS] All configuration parameters validated successfully!")
        return 0
    except Exception as exc:
        print(f"[FAIL] Configuration validation error:\n{exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
