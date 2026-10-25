"""Standalone Telemetry Consumer Worker entrypoint daemon with graceful signal handling."""

import asyncio
import logging
import signal
import sys
from typing import Optional

from waliya.config import settings
from waliya.observability.correlation import SensitiveDataFilter
from waliya.telemetry.consumer_worker import TelemetryConsumerWorker

logger = logging.getLogger("waliya.worker")


def setup_worker_logging() -> None:
    """Configure structured logging with sensitive data scrubbing."""
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    for handler in logging.root.handlers:
        handler.addFilter(SensitiveDataFilter())


async def run_worker_daemon() -> None:
    """Run the telemetry worker with graceful signal trapping and batch settling."""
    setup_worker_logging()
    logger.info("Initializing Ethio-SOAR Telemetry Consumer Worker daemon...")

    worker = TelemetryConsumerWorker()
    stop_event = asyncio.Event()

    def _signal_handler(sig_num: int) -> None:
        sig_name = signal.Signals(sig_num).name
        logger.info("Received termination signal %s, initiating graceful shutdown...", sig_name)
        worker._is_running = False
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, lambda s=sig: _signal_handler(s))
        except (NotImplementedError, RuntimeError):
            signal.signal(sig, lambda s, f: _signal_handler(s))

    worker_task = asyncio.create_task(worker.run_forever())
    stop_task = asyncio.create_task(stop_event.wait())

    done, pending = await asyncio.wait(
        [worker_task, stop_task],
        return_when=asyncio.FIRST_COMPLETED,
    )

    if stop_task.done() and not worker_task.done():
        logger.info("Waiting up to 10s for active telemetry batch to commit and acknowledge...")
        worker._is_running = False
        try:
            await asyncio.wait_for(worker_task, timeout=10.0)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            logger.warning("Worker shutdown timed out, cancelling remaining tasks...")
            worker_task.cancel()
    elif worker_task.done():
        # Worker exited on its own (or error)
        try:
            worker_task.result()
        except Exception as exc:
            logger.error("Worker terminated with unhandled exception: %s", exc)
            sys.exit(1)

    # Cancel pending stop task if worker stopped first
    if not stop_task.done():
        stop_task.cancel()

    logger.info("Ethio-SOAR Telemetry Consumer Worker daemon terminated cleanly.")


def main() -> None:
    """CLI entrypoint."""
    try:
        asyncio.run(run_worker_daemon())
    except (KeyboardInterrupt, SystemExit):
        pass


if __name__ == "__main__":
    main()
