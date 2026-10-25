"""Deterministic purple-team simulation execution and closed-loop validation engine."""

import asyncio
from datetime import datetime, timezone
import logging
import time
from typing import Any, Callable, Dict, List, Optional
from uuid import UUID, uuid4

from waliya_sim.client import SimClient
from waliya_sim.config import SimConfig
from waliya_sim.models import (
    DetectionLatencyMetrics,
    ScenarioOutcome,
    SimulationRunRecord,
)
from waliya_sim.scenarios.base import BaseScenario
from waliya_sim.storage import ReportStorage

logger = logging.getLogger("waliya_sim.engine")


class SimulationEngine:
    """Executes scenarios and performs closed-loop detection validation against Waliya-IR backend."""

    def __init__(self, config: SimConfig, client: Optional[SimClient] = None):
        self.config = config
        self.client = client or SimClient(
            base_url=config.backend_url,
            agent_id=config.agent_id,
            agent_token=config.agent_token,
            admin_key=config.admin_key,
            timeout=config.timeout_seconds,
        )
        self.storage = ReportStorage(config.reports_dir)

    async def execute_scenario(
        self,
        scenario: BaseScenario,
        is_negative: bool = False,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> SimulationRunRecord:
        """Execute a controlled simulation and validate detection pipeline outcomes."""
        run_id = f"sim-{uuid4().hex[:12]}"
        trace_id = f"trace-{uuid4().hex[:12]}"
        start_mono = time.monotonic()
        start_utc = datetime.now(timezone.utc)

        def report_step(step_msg: str) -> None:
            if progress_callback:
                progress_callback(step_msg)
            logger.info("[%s] %s", run_id, step_msg)

        expected = scenario.expected_outcome(is_negative=is_negative)
        agent_id = self.config.agent_id or uuid4()

        # Step 1: Deterministic Event Generation
        report_step(f"Generating synthetic telemetry for scenario '{scenario.name}' (negative={is_negative})")
        events = scenario.generate_events(
            run_id=run_id,
            trace_id=trace_id,
            agent_id=agent_id,
            is_negative=is_negative,
        )
        events_generated_count = len(events)
        if events_generated_count == 0:
            duration = time.monotonic() - start_mono
            err_msg = f"Scenario '{scenario.name}' generated 0 events; aborting simulation"
            report_step(err_msg)
            record = SimulationRunRecord(
                run_id=run_id,
                trace_id=trace_id,
                scenario_id=scenario.scenario_id,
                scenario_name=scenario.name,
                mitre_attack_id=scenario.mitre_attack_id,
                target_rule_id=scenario.target_rule_id,
                is_negative_test=is_negative,
                start_time=start_utc.isoformat(),
                end_time=datetime.now(timezone.utc).isoformat(),
                duration_seconds=round(duration, 3),
                events_generated_count=0,
                events_submitted_count=0,
                events_accepted_count=0,
                events_processed_count=0,
                expected_detection=expected.should_detect,
                observed_detection=False,
                status=ScenarioOutcome.FAIL,
                summary=f"FAIL: No events generated for scenario '{scenario.name}'. Zero-event simulations cannot pass.",
                error_detail=err_msg,
            )
            self.storage.save_report(record)
            return record

        first_event_ts_str = events[0]["timestamp"] if events else None

        # Step 2: Validate Target Backend Connectivity
        report_step(f"Checking backend connectivity at {self.config.backend_url}")
        healthy, health_detail = await self.client.check_health()
        if not healthy:
            duration = time.monotonic() - start_mono
            record = SimulationRunRecord(
                run_id=run_id,
                trace_id=trace_id,
                scenario_id=scenario.scenario_id,
                scenario_name=scenario.name,
                mitre_attack_id=scenario.mitre_attack_id,
                target_rule_id=scenario.target_rule_id,
                is_negative_test=is_negative,
                start_time=start_utc.isoformat(),
                end_time=datetime.now(timezone.utc).isoformat(),
                duration_seconds=round(duration, 3),
                events_generated_count=events_generated_count,
                events_submitted_count=0,
                events_accepted_count=0,
                events_processed_count=0,
                expected_detection=expected.should_detect,
                observed_detection=False,
                status=ScenarioOutcome.INCONCLUSIVE,
                summary=f"Simulation inconclusive: backend unreachable ({health_detail})",
                error_detail=health_detail,
            )
            self.storage.save_report(record)
            return record

        # Step 2b: Register Simulation Run with Backend Before Submitting Telemetry
        report_step(f"Registering simulation run '{run_id}' with backend")
        try:
            await self.client.register_simulation_run(
                run_id=run_id,
                trace_id=trace_id,
                scenario_id=scenario.scenario_id,
                scenario_name=scenario.name,
                mitre_attack_ids=[scenario.mitre_attack_id],
                target_rule_id=scenario.target_rule_id,
                is_negative_test=is_negative,
                expected_detection=expected.should_detect,
            )
        except Exception as reg_exc:
            duration = time.monotonic() - start_mono
            err_msg = f"Run registration failed: {reg_exc}"
            report_step(f"Aborting simulation before telemetry submission: {err_msg}")
            record = SimulationRunRecord(
                run_id=run_id,
                trace_id=trace_id,
                scenario_id=scenario.scenario_id,
                scenario_name=scenario.name,
                mitre_attack_id=scenario.mitre_attack_id,
                target_rule_id=scenario.target_rule_id,
                is_negative_test=is_negative,
                start_time=start_utc.isoformat(),
                end_time=datetime.now(timezone.utc).isoformat(),
                duration_seconds=round(duration, 3),
                events_generated_count=events_generated_count,
                events_submitted_count=0,
                events_accepted_count=0,
                events_processed_count=0,
                expected_detection=expected.should_detect,
                observed_detection=False,
                status=ScenarioOutcome.INCONCLUSIVE,
                summary=f"Simulation inconclusive: registration rejected by backend ({reg_exc})",
                error_detail=err_msg,
            )
            self.storage.save_report(record)
            return record

        # Step 3: Authenticated Telemetry Batch Ingestion
        report_step(f"Submitting {events_generated_count} synthetic events to /api/v1/telemetry/ingest")
        try:
            ingest_result = await self.client.ingest_batch(events)
            events_submitted_count = events_generated_count
            events_accepted_count = ingest_result.get("processed_count", 0)
        except Exception as exc:
            duration = time.monotonic() - start_mono
            err_msg = str(exc)
            report_step(f"Telemetry submission failed: {err_msg}")
            record = SimulationRunRecord(
                run_id=run_id,
                trace_id=trace_id,
                scenario_id=scenario.scenario_id,
                scenario_name=scenario.name,
                mitre_attack_id=scenario.mitre_attack_id,
                target_rule_id=scenario.target_rule_id,
                is_negative_test=is_negative,
                start_time=start_utc.isoformat(),
                end_time=datetime.now(timezone.utc).isoformat(),
                duration_seconds=round(duration, 3),
                events_generated_count=events_generated_count,
                events_submitted_count=events_generated_count,
                events_accepted_count=0,
                events_processed_count=0,
                expected_detection=expected.should_detect,
                observed_detection=False,
                status=ScenarioOutcome.INCONCLUSIVE,
                summary=f"Simulation inconclusive: submission rejected ({err_msg})",
                error_detail=err_msg,
            )
            self.storage.save_report(record)
            return record

        # Step 4: Outbox Dispatch Trigger
        report_step("Flushing transactional outbox to dispatch events to Redis stream")
        await self.client.flush_outbox()

        # Step 5: Closed-Loop Polling for Findings and Incidents
        report_step("Polling backend detection pipeline for generated findings...")
        deadline = time.monotonic() + self.config.timeout_seconds
        observed_findings: List[Dict[str, Any]] = []
        matching_finding_ids: List[str] = []
        matching_incident_ids: List[str] = []
        latency_metrics = DetectionLatencyMetrics(
            first_event_timestamp=first_event_ts_str,
        )

        poll_attempts = 0
        while time.monotonic() < deadline:
            poll_attempts += 1
            try:
                findings = await self.client.fetch_findings(
                    run_id=run_id,
                    trace_id=trace_id,
                    rule_id=scenario.target_rule_id,
                )
                if findings:
                    observed_findings = findings
                    matching_finding_ids = [str(f.get("id")) for f in findings if f.get("id")]
                    # Stop early if we were expecting detection
                    if expected.should_detect:
                        break
            except Exception as poll_err:
                logger.debug("Finding query attempt %d failed: %s", poll_attempts, poll_err)

            # If this is a negative boundary test, wait at least a reasonable window (e.g. 2s) to prove silence
            if not expected.should_detect and poll_attempts >= 4 and (time.monotonic() - start_mono >= 2.0):
                break

            await asyncio.sleep(self.config.poll_interval_seconds)

        # Step 6: Query Correlated Incidents if findings were observed
        if observed_findings:
            report_step(f"Found {len(observed_findings)} matching finding(s); querying correlated incidents...")
            try:
                # Direct provenance: extract incident IDs attached directly to matching findings
                for f in observed_findings:
                    f_inc = f.get("incident_id")
                    if f_inc and str(f_inc) not in matching_incident_ids:
                        matching_incident_ids.append(str(f_inc))

                # Query incidents and match strictly by simulation_run_id or exact finding correlation
                incidents = await self.client.fetch_incidents()
                for inc in incidents:
                    inc_id_str = str(inc.get("incident_id") or inc.get("id"))
                    if inc.get("simulation_run_id") == run_id:
                        if inc_id_str not in matching_incident_ids:
                            matching_incident_ids.append(inc_id_str)
            except Exception as inc_err:
                logger.warning("Failed querying incidents: %s", inc_err)

        # Step 7: Calculate Real Detection Latency
        if observed_findings:
            finding_ts_str = observed_findings[0].get("timestamp")
            latency_metrics.finding_timestamp = finding_ts_str

            if first_event_ts_str and finding_ts_str:
                try:
                    t_event = datetime.fromisoformat(first_event_ts_str)
                    t_finding = datetime.fromisoformat(finding_ts_str)
                    diff_seconds = (t_finding - t_event).total_seconds()
                    # Floor at 0 if clock skew occurs in sub-second precision
                    latency_metrics.latency_seconds = max(0.0, round(diff_seconds, 4))
                    latency_metrics.measurement_established = True
                    latency_metrics.measurement_notes = (
                        f"Calculated from recorded event timestamp ({first_event_ts_str}) "
                        f"to recorded finding timestamp ({finding_ts_str})"
                    )
                except Exception as parse_err:
                    latency_metrics.measurement_established = False
                    latency_metrics.measurement_notes = f"Failed calculating latency: {parse_err}"
            else:
                latency_metrics.measurement_established = False
                latency_metrics.measurement_notes = "Recorded event or finding timestamp was unavailable"

        # Step 8: Compare Expected vs Observed Outcomes
        observed_detection = len(observed_findings) > 0
        duration = time.monotonic() - start_mono

        if is_negative:
            if not observed_detection:
                outcome = ScenarioOutcome.PASS
                summary = (
                    f"PASS (Boundary): Sub-threshold events correctly rejected by detection rule '{scenario.target_rule_id}'. "
                    f"Zero findings created across {poll_attempts} verification checks."
                )
            else:
                outcome = ScenarioOutcome.FAIL
                summary = (
                    f"FAIL (Boundary Violation): Rule '{scenario.target_rule_id}' triggered unexpectedly on sub-threshold "
                    f"events. Findings generated: {matching_finding_ids}"
                )
        else:
            if observed_detection:
                outcome = ScenarioOutcome.PASS
                summary = (
                    f"PASS: Detection rule '{scenario.target_rule_id}' triggered successfully ({scenario.mitre_attack_id}). "
                    f"Found {len(matching_finding_ids)} finding(s) and {len(matching_incident_ids)} correlated incident(s)."
                )
            else:
                outcome = ScenarioOutcome.FAIL
                summary = (
                    f"FAIL: Detection rule '{scenario.target_rule_id}' did NOT trigger within {self.config.timeout_seconds}s. "
                    f"Expected detection for MITRE technique {scenario.mitre_attack_id}."
                )

        report_step(f"Simulation completed with outcome: {outcome.value}")

        # Step 9: Finalize Server-Side Record
        report_step(f"Finalizing server-side simulation record for '{run_id}'")
        try:
            finalized_backend = await self.client.finalize_simulation_run(
                run_id=run_id,
                events_submitted_count=events_submitted_count,
                events_accepted_count=events_accepted_count,
                client_status=outcome.value,
                error_detail=None,
            )
            if finalized_backend.get("status") in ["PASS", "FAIL", "INCONCLUSIVE"]:
                outcome = ScenarioOutcome(finalized_backend["status"])
                if finalized_backend.get("summary"):
                    summary = finalized_backend["summary"]
        except Exception as finalize_exc:
            fin_err_msg = f"Failed publishing finalized run to backend: {finalize_exc}"
            report_step(fin_err_msg)
            summary = f"{summary} [Note: Local report preserved; server finalization error: {finalize_exc}]"

        record = SimulationRunRecord(
            run_id=run_id,
            trace_id=trace_id,
            scenario_id=scenario.scenario_id,
            scenario_name=scenario.name,
            mitre_attack_id=scenario.mitre_attack_id,
            target_rule_id=scenario.target_rule_id,
            is_negative_test=is_negative,
            start_time=start_utc.isoformat(),
            end_time=datetime.now(timezone.utc).isoformat(),
            duration_seconds=round(duration, 3),
            events_generated_count=events_generated_count,
            events_submitted_count=events_submitted_count,
            events_accepted_count=events_accepted_count,
            events_processed_count=len(observed_findings),
            expected_detection=expected.should_detect,
            observed_detection=observed_detection,
            status=outcome,
            matching_finding_ids=matching_finding_ids,
            matching_incident_ids=matching_incident_ids,
            latency_metrics=latency_metrics,
            summary=summary,
        )

        self.storage.save_report(record)
        return record
