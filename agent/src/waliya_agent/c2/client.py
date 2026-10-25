"""Asynchronous secure HTTP client for agent-to-server C2 and telemetry upload."""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

import httpx

from waliya_agent.config import ServerConfig

logger = logging.getLogger("waliya_agent.c2.client")


class WaliyaC2Client:
    """Outbound HTTPS client managing telemetry ingestion, heartbeats, and signed task polling."""

    def __init__(
        self,
        server_config: ServerConfig,
        agent_id: UUID,
        api_token: str,
    ):
        self.server_config = server_config
        self.agent_id = agent_id
        self.api_token = api_token

        # Configure TLS verification
        verify: Any = server_config.tls_verify
        if server_config.ca_cert_path:
            verify = server_config.ca_cert_path

        self._client = httpx.AsyncClient(
            base_url=server_config.url,
            verify=verify,
            timeout=httpx.Timeout(server_config.request_timeout_seconds),
            headers={
                "Authorization": f"Bearer {self.api_token}",
                "X-Agent-ID": str(self.agent_id),
                "User-Agent": f"Waliya-Agent/2.0.0 ({self.agent_id})",
            },
        )

    async def aclose(self) -> None:
        """Close underlying HTTP client connections."""
        await self._client.aclose()

    async def _execute_with_retry(
        self,
        method: str,
        endpoint: str,
        json_payload: Optional[Dict[str, Any]] = None,
    ) -> Optional[httpx.Response]:
        """Execute HTTP request with exponential backoff retries for transient network issues."""
        retries = self.server_config.max_retries
        backoff = 1.0

        for attempt in range(1, retries + 2):
            try:
                resp = await self._client.request(method, endpoint, json=json_payload)
                return resp
            except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as exc:
                if attempt > retries:
                    logger.warning("C2 request %s %s failed after %d retries: %s", method, endpoint, retries, exc)
                    return None
                wait_time = backoff * (self.server_config.retry_backoff_factor ** (attempt - 1))
                logger.debug("C2 connection error on %s, retry %d/%d in %.1fs: %s", endpoint, attempt, retries, exc)
                await asyncio.sleep(wait_time)
            except Exception as exc:
                logger.error("Unexpected C2 client error on %s: %s", endpoint, exc)
                return None
        return None

    async def send_heartbeat(
        self,
        hostname: str,
        primary_ip: str,
        os_version: str,
        agent_version: str,
        cpu_percent: float,
        memory_used_mb: int,
    ) -> Optional[Dict[str, Any]]:
        """Send periodic health heartbeat and retrieve server status / pending task count."""
        endpoint = f"/api/v1/agents/{self.agent_id}/heartbeat"
        payload = {
            "hostname": hostname,
            "primary_ip": primary_ip,
            "os_version": os_version,
            "agent_version": agent_version,
            "metrics": {
                "cpu_percent": round(cpu_percent, 2),
                "memory_used_mb": memory_used_mb,
            },
        }

        resp = await self._execute_with_retry("POST", endpoint, json_payload=payload)
        if resp is None:
            return None

        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 401:
            logger.error("Heartbeat rejected: Agent credentials unauthorized (401)")
        elif resp.status_code == 403:
            logger.error("Heartbeat rejected: Agent ID mismatch (403)")
        else:
            logger.warning("Heartbeat returned unexpected HTTP %d: %s", resp.status_code, resp.text)
        return None

    async def poll_tasks(
        self,
        last_sequence: int,
        supported_actions: Optional[List[str]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Poll for next queued signed command envelope."""
        endpoint = f"/api/v1/agents/{self.agent_id}/tasks/poll"
        payload = {
            "last_sequence": last_sequence,
            "supported_actions": supported_actions or [],
        }

        resp = await self._execute_with_retry("POST", endpoint, json_payload=payload)
        if resp is None:
            return None

        if resp.status_code == 200:
            data = resp.json()
            return data if data else None
        elif resp.status_code == 401:
            logger.error("Task poll rejected: Agent credentials unauthorized (401)")
        else:
            logger.warning("Task poll returned HTTP %d: %s", resp.status_code, resp.text)
        return None

    async def submit_receipt(
        self,
        command_id: UUID,
        status: str,
        exit_code: int,
        output: str,
        dry_run: bool = False,
        executed_at: Optional[datetime] = None,
    ) -> bool:
        """Submit execution receipt confirming command execution outcome."""
        endpoint = f"/api/v1/agents/{self.agent_id}/receipts"
        payload = {
            "command_id": str(command_id),
            "status": status,
            "exit_code": exit_code,
            "output": output[:4096],
            "dry_run": dry_run,
            "executed_at": (executed_at or datetime.now(timezone.utc)).isoformat(),
        }

        resp = await self._execute_with_retry("POST", endpoint, json_payload=payload)
        if resp is not None and resp.status_code == 200:
            logger.info("Command %s execution receipt acknowledged by server", command_id)
            return True

        status_code = resp.status_code if resp else "NO_RESPONSE"
        logger.error("Failed to submit execution receipt for command %s (HTTP %s)", command_id, status_code)
        return False

    async def submit_verification(
        self,
        command_id: UUID,
        observed_state: Dict[str, Any],
        verified_at: Optional[datetime] = None,
    ) -> Optional[Dict[str, Any]]:
        """Submit post-action observation telemetry to server for containment verification determination."""
        endpoint = f"/api/v1/agents/{self.agent_id}/verification"
        payload = {
            "command_id": str(command_id),
            "observed_state": observed_state,
            "verified_at": (verified_at or datetime.now(timezone.utc)).isoformat(),
        }

        resp = await self._execute_with_retry("POST", endpoint, json_payload=payload)
        if resp is not None and resp.status_code == 200:
            data = resp.json()
            logger.info(
                "Command %s verification telemetry submitted: Server determined status=%s",
                command_id,
                data.get("status"),
            )
            return data

        status_code = resp.status_code if resp else "NO_RESPONSE"
        logger.error("Failed to submit verification telemetry for command %s (HTTP %s)", command_id, status_code)
        return None

    async def upload_telemetry_batch(
        self,
        events: List[Dict[str, Any]],
    ) -> tuple[bool, List[str]]:
        """Upload a batch of normalized security events to the server ingestion endpoint.

        Returns:
            (success: bool, accepted_event_ids: List[str])
        """
        if not events:
            return True, []

        batch_id = str(uuid4())
        endpoint = "/api/v1/telemetry/ingest"
        payload = {
            "batch_id": batch_id,
            "agent_id": str(self.agent_id),
            "events": events,
        }

        resp = await self._execute_with_retry("POST", endpoint, json_payload=payload)
        if resp is None:
            return False, []

        if resp.status_code == 200:
            data = resp.json()
            processed_count = data.get("processed_count", len(events))
            accepted_ids = [str(e["event_id"]) for e in events[:processed_count]]
            logger.debug("Successfully ingested batch %s (%d events)", batch_id, processed_count)
            return True, accepted_ids
        elif resp.status_code == 401:
            logger.error("Telemetry upload rejected: Agent credentials unauthorized (401)")
            return False, []
        elif resp.status_code == 403:
            logger.error("Telemetry upload rejected: Agent ID mismatch (403)")
            return False, []
        elif resp.status_code == 422:
            logger.error("Telemetry batch validation failure (422): %s", resp.text)
            return False, []
        else:
            logger.warning("Telemetry upload failed with HTTP %d: %s", resp.status_code, resp.text)
            return False, []
