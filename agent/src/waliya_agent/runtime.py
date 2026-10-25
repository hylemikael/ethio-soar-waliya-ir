"""Core agent runtime orchestrating collectors, durable queue, and C2 communication."""

import asyncio
import logging
import os
import platform
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import UUID

from waliya_agent.buffer.queue import DurableEventQueue
from waliya_agent.c2.client import WaliyaC2Client
from waliya_agent.c2.crypto import verify_command_signature
from waliya_agent.c2.replay import ReplayDefenseStore
from waliya_agent.collectors.auth_log import AuthLogCollector
from waliya_agent.collectors.base import BaseCollector
from waliya_agent.collectors.file_integrity import FileIntegrityCollector
from waliya_agent.collectors.network import NetworkCollector
from waliya_agent.collectors.process import ProcessCollector
from waliya_agent.config import AgentConfig
from waliya_agent.response.registry import ResponseActionRegistry

logger = logging.getLogger("waliya_agent.runtime")


def get_primary_ip() -> str:
    """Determine the primary outbound IP address of this host."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Does not send actual traffic, just resolves outbound route
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def read_system_metrics() -> tuple[float, int]:
    """Read CPU percentage and used memory in MB from Linux /proc filesystem."""
    cpu_pct = 0.0
    mem_used_mb = 0

    # 1. Memory from /proc/meminfo
    meminfo = Path("/proc/meminfo")
    if meminfo.exists():
        try:
            total_kb = 0
            avail_kb = 0
            with open(meminfo, "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        total_kb = int(line.split()[1])
                    elif line.startswith("MemAvailable:"):
                        avail_kb = int(line.split()[1])
            if total_kb > 0:
                mem_used_mb = max(0, (total_kb - avail_kb) // 1024)
        except Exception:
            pass

    # 2. CPU load from /proc/loadavg (1-minute normalized by core count)
    loadavg = Path("/proc/loadavg")
    if loadavg.exists():
        try:
            with open(loadavg, "r", encoding="utf-8") as f:
                load_1m = float(f.read().split()[0])
            cores = os.cpu_count() or 1
            cpu_pct = min(100.0, max(0.0, (load_1m / cores) * 100.0))
        except Exception:
            pass

    return cpu_pct, mem_used_mb


class AgentRuntime:
    """Manages the full asynchronous lifecycle of the standalone Waliya-IR Linux agent."""

    def __init__(self, config: AgentConfig):
        self.config = config
        self.agent_id = config.agent.id
        self.state_dir = config.agent.state_dir
        self.state_dir.mkdir(parents=True, exist_ok=True)
        try:
            self.state_dir.chmod(0o700)
        except OSError:
            pass

        # Host metadata
        self.hostname = socket.gethostname()
        self.primary_ip = get_primary_ip()
        self.os_version = platform.platform()
        self.agent_version = "2.0.0"

        # Initialize durable buffer and replay stores
        self.queue = DurableEventQueue(
            db_path=self.state_dir / "events.db",
            max_capacity=config.telemetry.buffer_capacity,
        )
        self.replay_store = ReplayDefenseStore(
            db_path=self.state_dir / "replay_defense.db"
        )

        # Initialize C2 Client
        self.c2_client = WaliyaC2Client(
            server_config=config.server,
            agent_id=self.agent_id,
            api_token=config.agent.api_token,
        )

        # Initialize response action registry
        self.response_registry = ResponseActionRegistry(
            config=config.response,
            server_url=config.server.url,
        )

        # Initialize collectors
        self.collectors: List[BaseCollector] = []
        if config.telemetry.fim_enabled:
            self.collectors.append(
                FileIntegrityCollector(
                    agent_id=self.agent_id,
                    paths_to_monitor=config.telemetry.fim_paths,
                    debounce_seconds=config.telemetry.fim_debounce_seconds,
                    max_file_size_mb=config.telemetry.fim_max_file_size_mb,
                )
            )
        if config.telemetry.process_enabled:
            self.collectors.append(ProcessCollector(agent_id=self.agent_id))
        if config.telemetry.auth_enabled:
            self.collectors.append(
                AuthLogCollector(
                    agent_id=self.agent_id,
                    log_path=Path(config.telemetry.auth_log_path),
                )
            )
        if config.telemetry.network_enabled:
            self.collectors.append(NetworkCollector(agent_id=self.agent_id))

        self._shutdown_event = asyncio.Event()
        self._tasks: List[asyncio.Task[None]] = []

    def request_shutdown(self) -> None:
        """Trigger graceful shutdown of all running loops."""
        logger.info("Shutdown signal received. Initiating graceful shutdown...")
        self._shutdown_event.set()

    async def _collection_loop(self) -> None:
        """Periodically run telemetry collectors and enqueue normalized events."""
        logger.info("Telemetry collection loop started (%d active collectors)", len(self.collectors))
        while not self._shutdown_event.is_set():
            for collector in self.collectors:
                try:
                    events = await collector.collect()
                    if events:
                        enqueued = self.queue.put_batch(events)
                        logger.debug(
                            "Collector %s generated %d events (%d enqueued, buffer size: %d)",
                            collector.collector_name,
                            len(events),
                            enqueued,
                            self.queue.size(),
                        )
                except Exception as exc:
                    logger.error("Error in collector %s: %s", collector.collector_name, exc)

            # Sleep between collection passes
            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=self.config.telemetry.upload_interval_seconds,
                )
            except asyncio.TimeoutError:
                pass

    async def _upload_loop(self) -> None:
        """Periodically drain the local queue and upload batches to server."""
        logger.info("Telemetry upload loop started")
        while not self._shutdown_event.is_set():
            batch = self.queue.get_batch(max_batch_size=self.config.telemetry.upload_batch_size)
            if batch:
                success, accepted_ids = await self.c2_client.upload_telemetry_batch(batch)
                if success and accepted_ids:
                    removed = self.queue.acknowledge(accepted_ids)
                    logger.debug("Uploaded and acknowledged %d events", removed)
                else:
                    logger.debug("Upload failed or queued. %d events retained in buffer", len(batch))

            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=self.config.telemetry.upload_interval_seconds,
                )
            except asyncio.TimeoutError:
                pass

    async def _heartbeat_loop(self) -> None:
        """Periodically transmit heartbeat to maintain online status and learn of pending tasks."""
        logger.info("C2 heartbeat loop started")
        while not self._shutdown_event.is_set():
            cpu_pct, mem_mb = read_system_metrics()
            hb_resp = await self.c2_client.send_heartbeat(
                hostname=self.hostname,
                primary_ip=self.primary_ip,
                os_version=self.os_version,
                agent_version=self.agent_version,
                cpu_percent=cpu_pct,
                memory_used_mb=mem_mb,
            )

            if hb_resp:
                pending = hb_resp.get("pending_tasks", 0)
                if pending > 0:
                    logger.info("Heartbeat notified of %d pending C2 tasks. Triggering task poll.", pending)
                    await self._process_pending_commands()

            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=self.config.c2.heartbeat_interval_seconds,
                )
            except asyncio.TimeoutError:
                pass

    async def _task_poll_loop(self) -> None:
        """Periodically poll for queued commands."""
        logger.info("C2 task polling loop started")
        while not self._shutdown_event.is_set():
            await self._process_pending_commands()
            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=self.config.c2.task_poll_interval_seconds,
                )
            except asyncio.TimeoutError:
                pass

    async def _process_pending_commands(self) -> None:
        """Poll, cryptographically verify, execute, and verify containment for queued commands."""
        last_seq = self.replay_store.get_highest_sequence()
        cmd_data = await self.c2_client.poll_tasks(last_sequence=last_seq)
        if not cmd_data:
            return

        command_id_str = cmd_data.get("command_id")
        action_name = cmd_data.get("action")
        signature = cmd_data.get("signature", "")
        parameters = cmd_data.get("parameters", {})
        sequence = int(cmd_data.get("sequence", 0))
        nonce_str = cmd_data.get("nonce")
        issued_at_str = cmd_data.get("issued_at")
        expires_at_str = cmd_data.get("expires_at")
        target_agent_id_str = cmd_data.get("agent_id")

        if not command_id_str or not nonce_str or not issued_at_str or not expires_at_str or not action_name:
            logger.error("Received malformed command envelope: missing required fields")
            return

        try:
            command_id = UUID(command_id_str)
            nonce = UUID(nonce_str)
            issued_at = datetime.fromisoformat(issued_at_str)
            expires_at = datetime.fromisoformat(expires_at_str)
        except (ValueError, TypeError) as exc:
            logger.error("Invalid field format in command envelope: %s", exc)
            return

        # 1. Target Agent Identity Verification
        if target_agent_id_str != str(self.agent_id):
            logger.critical(
                "SECURITY ALERT: Received command intended for agent %s, this agent is %s. Rejecting immediately.",
                target_agent_id_str,
                self.agent_id,
            )
            await self.c2_client.submit_receipt(
                command_id=command_id,
                status="FAILED",
                exit_code=1,
                output="Agent identity mismatch rejection",
            )
            return

        # 2. Pure Timestamp & Clock Skew Validation (Does NOT mutate replay state)
        is_time_valid, time_reason = self.replay_store.validate_timestamps(
            issued_at=issued_at,
            expires_at=expires_at,
            tolerance_seconds=self.config.response.clock_skew_tolerance_seconds,
        )
        if not is_time_valid:
            logger.warning("Command %s rejected by timestamp validation: %s", command_id, time_reason)
            await self.c2_client.submit_receipt(
                command_id=command_id,
                status="FAILED",
                exit_code=1,
                output=f"Timestamp validation rejection: {time_reason}",
            )
            return

        # 3. Cryptographic HMAC-SHA256 Signature Verification
        # CRITICAL SECURITY REQUIREMENT:
        # Signature MUST be verified BEFORE mutating any sequence or nonce in replay state.
        # Unauthenticated commands must NEVER advance replay defense state.
        is_sig_valid = verify_command_signature(
            received_signature=signature,
            command_id=command_id,
            agent_id=self.agent_id,
            action=action_name,
            parameters=parameters,
            sequence=sequence,
            nonce=nonce,
            issued_at=issued_at,
            expires_at=expires_at,
            secret_key=self.config.agent.signing_secret,
        )
        if not is_sig_valid:
            logger.critical(
                "SECURITY ALERT: Cryptographic signature mismatch on command %s! Payload tampering suspected. Rejecting without state mutation.",
                command_id,
            )
            await self.c2_client.submit_receipt(
                command_id=command_id,
                status="FAILED",
                exit_code=1,
                output="HMAC-SHA256 signature verification failed. Command rejected.",
            )
            return

        # 4. Idempotency Check: Was this command_id already accepted / executed?
        existing_record = self.replay_store.get_recorded_command(command_id)
        if existing_record:
            logger.info(
                "Command %s already recorded (status: %s). Re-sending cached execution receipt without re-executing.",
                command_id,
                existing_record["status"],
            )
            await self.c2_client.submit_receipt(
                command_id=command_id,
                status=existing_record["status"],
                exit_code=existing_record["exit_code"],
                output=f"[IDEMPOTENT RE-DELIVERY] {existing_record['output']}",
            )
            if existing_record.get("observed_state"):
                await self.c2_client.submit_verification(
                    command_id=command_id,
                    observed_state=existing_record["observed_state"],
                )
            return

        # 5. Commit Authenticated Command to Replay Defense (Monotonic Sequence + Nonce Uniqueness)
        is_committed, commit_reason = self.replay_store.commit_authenticated_command(
            sequence=sequence,
            nonce=nonce,
            command_id=command_id,
            action=action_name,
            expires_at=expires_at,
        )
        if not is_committed:
            logger.warning("Command %s rejected by replay defense: %s", command_id, commit_reason)
            await self.c2_client.submit_receipt(
                command_id=command_id,
                status="FAILED",
                exit_code=1,
                output=f"Replay defense rejection: {commit_reason}",
            )
            return

        # 6. Atomically Reserve Command to Prevent Concurrent Duplicate Execution
        reserved = self.replay_store.reserve_command_for_execution(command_id)
        if not reserved:
            logger.warning("Command %s was already reserved by another processing task; skipping concurrent execution", command_id)
            return

        # 7. Execute Response Action via ResponseActionRegistry
        logger.info(
            "Executing response action %s [Seq #%d] (command_id: %s)",
            action_name,
            sequence,
            command_id,
        )
        result = await self.response_registry.dispatch(action_name, parameters)

        # 8. Phase 1: Submit Execution Receipt (Moves backend status to VERIFYING or FAILED)
        exec_status = "COMPLETED" if result.status == "EXECUTED" else "FAILED"
        self.replay_store.record_execution_outcome(
            command_id=command_id,
            status=exec_status,
            exit_code=result.exit_code,
            output=result.output,
            observed_state=result.observed_state,
            receipt_acknowledged=False,
        )

        receipt_sent = await self.c2_client.submit_receipt(
            command_id=command_id,
            status=result.status,
            exit_code=result.exit_code,
            output=result.output,
            dry_run=result.dry_run,
        )
        if receipt_sent:
            self.replay_store.mark_receipt_acknowledged(command_id)

        # 9. Phase 2: Post-Action Containment Verification Telemetry
        # Execution success must never be confused with containment verification.
        # Submit positive OS evidence to /verification endpoint.
        if result.status == "EXECUTED":
            observed_state = result.observed_state
            if not observed_state:
                observed_state = await self.response_registry.collect_verification_state(action_name, parameters)

            verif_resp = await self.c2_client.submit_verification(
                command_id=command_id,
                observed_state=observed_state,
            )
            if verif_resp:
                new_state = verif_resp.get("status", "UNKNOWN")
                expl = verif_resp.get("explanation", "")
                logger.info(
                    "Containment verification result for command %s: %s (%s)",
                    command_id,
                    new_state,
                    expl,
                )
                self.replay_store.record_verification_outcome(
                    command_id=command_id,
                    status=new_state,
                    explanation=expl,
                    verification_acknowledged=True,
                )

    async def run(self) -> None:
        """Start all agent asynchronous services and run until shutdown is requested."""
        logger.info("Initializing Waliya-IR Linux Endpoint Agent [%s] on %s", self.agent_id, self.hostname)

        # 1. Crash Recovery: Detect interrupted commands and flush unacknowledged receipts
        recovered = self.replay_store.recover_crashed_and_unacknowledged_commands()
        if recovered:
            logger.warning("Crash recovery: detected %d interrupted or unacknowledged commands from previous session", len(recovered))
            for rec in recovered:
                try:
                    sent = await self.c2_client.submit_receipt(
                        command_id=rec["command_id"],
                        status=rec["status"],
                        exit_code=rec["exit_code"],
                        output=rec["output"],
                    )
                    if sent:
                        self.replay_store.mark_receipt_acknowledged(rec["command_id"])
                except Exception as exc:
                    logger.debug("Could not flush recovered receipt during startup: %s", exc)

        # Launch background loops
        self._tasks = [
            asyncio.create_task(self._collection_loop(), name="collection_loop"),
            asyncio.create_task(self._upload_loop(), name="upload_loop"),
            asyncio.create_task(self._heartbeat_loop(), name="heartbeat_loop"),
            asyncio.create_task(self._task_poll_loop(), name="task_poll_loop"),
        ]

        logger.info("All agent services operational. Running in foreground mode.")

        # Wait until shutdown event is triggered
        await self._shutdown_event.wait()

        # Cancel and cleanup loops
        for t in self._tasks:
            t.cancel()

        await asyncio.gather(*self._tasks, return_exceptions=True)
        await self.c2_client.aclose()
        logger.info("Waliya-IR Agent stopped cleanly.")
