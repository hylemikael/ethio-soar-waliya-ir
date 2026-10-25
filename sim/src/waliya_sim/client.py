"""Authenticated HTTP client for Waliya-IR ingestion and verification endpoints."""

import logging
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

import httpx

logger = logging.getLogger("waliya_sim.client")


class SimClient:
    """Synchronous/asynchronous client interacting with Waliya-IR backend."""

    def __init__(
        self,
        base_url: str,
        agent_id: Optional[UUID] = None,
        agent_token: Optional[str] = None,
        admin_key: Optional[str] = None,
        transport: Optional[httpx.BaseTransport] = None,
        timeout: float = 10.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.agent_id = agent_id
        self.agent_token = agent_token
        self.admin_key = admin_key
        self.transport = transport
        self.timeout = timeout

    def _get_async_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self.base_url,
            transport=self.transport,
            timeout=self.timeout,
        )

    async def check_health(self) -> Tuple[bool, str]:
        """Check if target backend is reachable and responsive."""
        try:
            async with self._get_async_client() as client:
                resp = await client.get("/api/v1/health/liveness")
                if resp.status_code == 200:
                    return True, "Backend healthy and reachable"
                # Fallback to base health path
                resp2 = await client.get("/api/v1/health")
                if resp2.status_code == 200:
                    return True, "Backend healthy and reachable"
                return False, f"Backend returned HTTP {resp.status_code}: {resp.text[:100]}"
        except httpx.RequestError as exc:
            return False, f"Connection failed to {self.base_url}: {type(exc).__name__}"

    async def ingest_batch(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Submit a batch of synthetic security events through the authentic ingestion pipeline."""
        if not self.agent_id:
            raise ValueError("Simulation requires an authenticated 'agent_id' to submit telemetry")
        if not self.agent_token:
            raise ValueError("Simulation requires an authenticated 'agent_token' to submit telemetry")

        payload = {
            "batch_id": str(uuid4()),
            "agent_id": str(self.agent_id),
            "events": events,
        }

        headers = {
            "Authorization": f"Bearer {self.agent_token}",
            "X-Agent-ID": str(self.agent_id),
            "Content-Type": "application/json",
        }

        async with self._get_async_client() as client:
            resp = await client.post("/api/v1/telemetry/ingest", json=payload, headers=headers)
            if resp.status_code != 200:
                raise RuntimeError(f"Telemetry ingestion rejected with HTTP {resp.status_code}: {resp.text[:200]}")
            return resp.json()

    async def flush_outbox(self) -> int:
        """Trigger an immediate outbox publication flush to ensure events reach Redis Streams."""
        if not self.admin_key:
            logger.debug("No admin key configured; skipping explicit outbox flush")
            return 0

        headers = {
            "X-Admin-Key": self.admin_key,
        }

        try:
            async with self._get_async_client() as client:
                resp = await client.post("/api/v1/telemetry/outbox/flush", headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    return data.get("published_count", 0)
                logger.warning("Outbox flush returned HTTP %d", resp.status_code)
                return 0
        except Exception as exc:
            logger.warning("Outbox flush trigger failed: %s", exc)
            return 0

    async def fetch_findings(
        self,
        run_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        rule_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Retrieve persisted findings matching simulation metadata."""
        if not self.admin_key:
            raise ValueError("Admin key is required to query findings endpoint")

        headers = {
            "X-Admin-Key": self.admin_key,
        }

        params: Dict[str, Any] = {"limit": limit}
        if rule_id:
            params["rule_id"] = rule_id
        if trace_id:
            params["trace_id"] = trace_id
        if run_id:
            params["simulation_run_id"] = run_id

        async with self._get_async_client() as client:
            resp = await client.get("/api/v1/rules/findings", headers=headers, params=params)
            if resp.status_code != 200:
                raise RuntimeError(f"Querying findings failed with HTTP {resp.status_code}: {resp.text[:200]}")

            findings = resp.json()

            # Client-side filtering in case backend returns unfiltered list
            matched: List[Dict[str, Any]] = []
            for f in findings:
                expl = f.get("explanation") or {}
                if run_id and expl.get("simulation_run_id") != run_id:
                    continue
                if trace_id and expl.get("trace_id") != trace_id:
                    continue
                if rule_id:
                    rule_val = expl.get("rule_id") or f.get("rule_id")
                    if rule_val != rule_id and (expl.get("rule_id") != rule_id):
                        continue
                matched.append(f)

            return matched

    async def fetch_incidents(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent security incidents."""
        if not self.admin_key:
            raise ValueError("Admin key is required to query incidents endpoint")

        headers = {
            "X-Admin-Key": self.admin_key,
        }

        async with self._get_async_client() as client:
            resp = await client.get("/api/v1/incidents", headers=headers, params={"limit": limit})
            if resp.status_code != 200:
                raise RuntimeError(f"Querying incidents failed with HTTP {resp.status_code}: {resp.text[:200]}")
            return resp.json()

    async def register_simulation_run(
        self,
        run_id: str,
        trace_id: str,
        scenario_id: str,
        scenario_name: str,
        mitre_attack_ids: List[str],
        target_rule_id: str,
        is_negative_test: bool = False,
        expected_detection: bool = True,
    ) -> Dict[str, Any]:
        """Register a simulation run with the backend before submitting telemetry."""
        if not self.admin_key:
            raise ValueError("Admin key is required to register a simulation run with the backend")

        payload = {
            "run_id": run_id,
            "trace_id": trace_id,
            "scenario_id": scenario_id,
            "scenario_name": scenario_name,
            "mitre_attack_ids": mitre_attack_ids,
            "target_rule_id": target_rule_id,
            "is_negative_test": is_negative_test,
            "expected_detection": expected_detection,
        }
        headers = {
            "X-Admin-Key": self.admin_key,
            "Content-Type": "application/json",
        }

        async with self._get_async_client() as client:
            resp = await client.post("/api/v1/simulations/runs", json=payload, headers=headers)
            if resp.status_code not in [200, 201]:
                raise RuntimeError(f"Registering simulation run failed with HTTP {resp.status_code}: {resp.text[:200]}")
            return resp.json()

    async def finalize_simulation_run(
        self,
        run_id: str,
        events_submitted_count: int,
        events_accepted_count: int = 0,
        client_status: Optional[str] = None,
        error_detail: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Finalize simulation run in backend, triggering independent server-side verification."""
        if not self.admin_key:
            raise ValueError("Admin key is required to finalize a simulation run")

        payload = {
            "events_submitted_count": events_submitted_count,
            "events_accepted_count": events_accepted_count,
            "client_status": client_status,
            "error_detail": error_detail,
        }
        headers = {
            "X-Admin-Key": self.admin_key,
            "Content-Type": "application/json",
        }

        async with self._get_async_client() as client:
            resp = await client.post(f"/api/v1/simulations/runs/{run_id}/finalize", json=payload, headers=headers)
            if resp.status_code != 200:
                raise RuntimeError(f"Finalizing simulation run failed with HTTP {resp.status_code}: {resp.text[:200]}")
            return resp.json()

    async def fetch_simulation_runs(
        self,
        scenario_id: Optional[str] = None,
        status_filter: Optional[str] = None,
        is_negative: Optional[bool] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Retrieve paginated simulation run history from backend."""
        if not self.admin_key:
            raise ValueError("Admin key is required to list simulation runs")

        headers = {"X-Admin-Key": self.admin_key}
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if scenario_id:
            params["scenario_id"] = scenario_id
        if status_filter:
            params["status"] = status_filter
        if is_negative is not None:
            params["is_negative"] = is_negative

        async with self._get_async_client() as client:
            resp = await client.get("/api/v1/simulations/runs", headers=headers, params=params)
            if resp.status_code != 200:
                raise RuntimeError(f"Querying simulation runs failed with HTTP {resp.status_code}: {resp.text[:200]}")
            return resp.json()

    async def fetch_simulation_run(self, run_id: str) -> Dict[str, Any]:
        """Retrieve details of a single simulation run from backend."""
        if not self.admin_key:
            raise ValueError("Admin key is required to get simulation run details")

        headers = {"X-Admin-Key": self.admin_key}
        async with self._get_async_client() as client:
            resp = await client.get(f"/api/v1/simulations/runs/{run_id}", headers=headers)
            if resp.status_code != 200:
                raise RuntimeError(f"Querying simulation run '{run_id}' failed with HTTP {resp.status_code}: {resp.text[:200]}")
            return resp.json()

    async def fetch_simulation_coverage(self) -> Dict[str, Any]:
        """Retrieve aggregate simulation validation coverage metrics from backend."""
        if not self.admin_key:
            raise ValueError("Admin key is required to query simulation coverage")

        headers = {"X-Admin-Key": self.admin_key}
        async with self._get_async_client() as client:
            resp = await client.get("/api/v1/simulations/coverage", headers=headers)
            if resp.status_code != 200:
                raise RuntimeError(f"Querying simulation coverage failed with HTTP {resp.status_code}: {resp.text[:200]}")
            return resp.json()
