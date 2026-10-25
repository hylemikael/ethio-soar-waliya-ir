"""Command Line Interface (CLI) entry point for Waliya-IR Linux Endpoint Agent."""

import argparse
import asyncio
import json
import logging
import signal
import sys
from pathlib import Path
from typing import Optional

from waliya_agent.config import AgentConfig, load_config_from_file_or_env
from waliya_agent.runtime import AgentRuntime


class SensitiveDataFilter(logging.Filter):
    """Logging filter ensuring API tokens and HMAC secrets never appear in logs."""

    def __init__(self, masked_tokens: Optional[list[str]] = None):
        super().__init__()
        self.masked_tokens = [t for t in (masked_tokens or []) if t and len(t) >= 4]

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        for token in self.masked_tokens:
            if token in msg:
                record.msg = str(record.msg).replace(token, "***MASKED***")
        return True


def setup_logging(config: AgentConfig) -> None:
    """Configure structured or plain text logging with credential redaction."""
    log_level = getattr(logging, config.logging.level, logging.INFO)
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Clear existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)

    if config.logging.format == "json":
        formatter = logging.Formatter(
            '{"timestamp":"%(asctime)s","logger":"%(name)s","level":"%(levelname)s","message":"%(message)s"}',
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        )
    else:
        formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    console_handler.setFormatter(formatter)
    console_handler.addFilter(
        SensitiveDataFilter(
            masked_tokens=[
                config.agent.api_token,
                config.agent.signing_secret,
            ]
        )
    )
    root_logger.addHandler(console_handler)


def cmd_verify_config(args: argparse.Namespace) -> int:
    """Verify configuration validity and exit."""
    try:
        config = load_config_from_file_or_env(args.config)
        print("✓ Configuration is structurally valid.")
        print(json.dumps(config.sanitized_dict(), indent=2))
        return 0
    except Exception as exc:
        print(f"✗ Configuration validation error: {exc}", file=sys.stderr)
        return 1


def cmd_run(args: argparse.Namespace) -> int:
    """Start the endpoint agent in the foreground."""
    try:
        config = load_config_from_file_or_env(args.config)
    except Exception as exc:
        print(f"FATAL: Configuration error: {exc}", file=sys.stderr)
        return 1

    setup_logging(config)
    logger = logging.getLogger("waliya_agent.cli")
    logger.info("Starting Waliya-IR Agent v2.0.0 (Agent ID: %s)", config.agent.id)

    runtime = AgentRuntime(config)

    # Setup signal handlers for graceful termination
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def _signal_handler(sig, _frame):
        logger.info("Signal %s received", signal.Signals(sig).name)
        runtime.request_shutdown()

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    try:
        loop.run_until_complete(runtime.run())
        return 0
    except Exception as exc:
        logger.critical("Agent runtime exited with critical error: %s", exc, exc_info=True)
        return 1
    finally:
        loop.close()


def main() -> None:
    """Main CLI entrypoint parser."""
    config_parent = argparse.ArgumentParser(add_help=False)
    config_parent.add_argument(
        "-c", "--config",
        dest="config",
        type=str,
        default=None,
        help="Path to YAML configuration file (e.g., /etc/waliya/waliya-agent.yaml)",
    )

    parser = argparse.ArgumentParser(
        prog="waliya-agent",
        description="Waliya-IR Standalone Linux Endpoint Agent & Security Sensor",
        parents=[config_parent],
    )

    subparsers = parser.add_subparsers(dest="subcommand", help="Agent commands")

    # Command: run
    run_parser = subparsers.add_parser("run", help="Start agent in foreground mode", parents=[config_parent])
    run_parser.set_defaults(func=cmd_run)

    # Command: verify-config
    verify_parser = subparsers.add_parser("verify-config", help="Validate configuration file or env", parents=[config_parent])
    verify_parser.set_defaults(func=cmd_verify_config)
    verify_parser.set_defaults(func=cmd_verify_config)

    args = parser.parse_args()

    if not args.subcommand:
        # Default to 'run' if no subcommand provided
        args.func = cmd_run

    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
