"""Standalone Telemetry Consumer Worker entrypoint daemon with graceful signal handling."""

import asyncio
import logging
import signal
import sys
from typing import Optional

from waliya.config import settings
from waliya.integrations.delivery_service import NotificationDeliveryService
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
    """Run the telemetry worker and outbound notification delivery dispatcher daemon."""
    setup_worker_logging()
    logger.info("Initializing Ethio-SOAR background worker daemon (telemetry + notification dispatcher)...")

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
    delivery_task = asyncio.create_task(
        NotificationDeliveryService.run_delivery_worker(
            stop_event=stop_event,
            batch_size=50,
            poll_interval_seconds=3.0,
            allow_local_for_testing=settings.ENV in ("test", "testing"),
        )
    )
    stop_task = asyncio.create_task(stop_event.wait())

    done, pending = await asyncio.wait(
        [worker_task, delivery_task, stop_task],
        return_when=asyncio.FIRST_COMPLETED,
    )

    if stop_task.done():
        logger.info("Shutdown initiated, waiting up to 10s for active batches and deliveries to settle...")
        worker._is_running = False
        stop_event.set()
        try:
            await asyncio.wait_for(
                asyncio.gather(worker_task, delivery_task, return_exceptions=True),
                timeout=10.0,
            )
        except (asyncio.TimeoutError, asyncio.CancelledError):
            logger.warning("Worker shutdown timed out, cancelling remaining tasks...")
            worker_task.cancel()
            delivery_task.cancel()
    else:
        # A worker task terminated unexpectedly
        stop_event.set()
        worker._is_running = False
        for t, name in [(worker_task, "Telemetry worker"), (delivery_task, "Notification delivery worker")]:
            if t.done() and not t.cancelled():
                exc = t.exception()
                if exc:
                    logger.error("%s terminated with unhandled exception: %s", name, exc)
        await asyncio.gather(worker_task, delivery_task, return_exceptions=True)
        sys.exit(1)

    if not stop_task.done():
        stop_task.cancel()

    logger.info("Ethio-SOAR background worker daemon terminated cleanly.")


def main() -> None:
    """CLI entrypoint."""
    try:
        asyncio.run(run_worker_daemon())
    except (KeyboardInterrupt, SystemExit):
        pass


if __name__ == "__main__":
    main()
