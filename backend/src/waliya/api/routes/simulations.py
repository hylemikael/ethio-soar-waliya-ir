"""Authenticated API endpoints for Purple-Team Simulation Runs and MITRE Validation Coverage."""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from waliya.contracts import (
    SimulationCoverageResponse,
    SimulationRunFinalizeRequest,
    SimulationRunRegisterRequest,
    SimulationRunResponse,
    SimulationScenarioCoverageItem,
)
from waliya.core.auth import verify_admin_key
from waliya.db.models import EventModel, FindingModel, IncidentModel, RuleModel, SimulationRunModel
from waliya.db.session import get_db_session

logger = logging.getLogger("waliya.api.routes.simulations")

router = APIRouter(prefix="/simulations", tags=["purple-team-simulations"])

# Canonical Scenario Definitions for Coverage Matrix
REGISTERED_SCENARIOS = [
    {
        "scenario_id": "brute-force",
        "scenario_name": "Authentication Brute Force",
        "mitre_attack_id": "T1110.001",
        "target_rule_id": "RULE-AUTH-001-BRUTEFORCE",
    },
    {
        "scenario_id": "web-shell",
        "scenario_name": "Suspicious Web File",
        "mitre_attack_id": "T1505.003",
        "target_rule_id": "RULE-FIM-004-WEBSHELL",
    },
    {
        "scenario_id": "port-scan",
        "scenario_name": "Network Port-Scan Behavior",
        "mitre_attack_id": "T1046",
        "target_rule_id": "RULE-NET-001-PORTSCAN",
    },
    {
        "scenario_id": "priv-esc",
        "scenario_name": "Suspicious Privilege Escalation",
        "mitre_attack_id": "T1548.003",
        "target_rule_id": "RULE-PROC-001-PRIVILEGE-ESC",
    },
]


@router.post(
    "/runs",
    response_model=SimulationRunResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new purple-team simulation run",
)
async def register_simulation_run(
    req: SimulationRunRegisterRequest,
    _admin: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> SimulationRunResponse:
    """Register a simulation run prior to event submission.

    Ensures idempotency on identical retry and rejects duplicate run IDs with conflicting parameters.
    """
    query = select(SimulationRunModel).where(SimulationRunModel.run_id == req.run_id)
    res = await session.execute(query)
    existing = res.scalars().first()

    if existing:
        # Check parameter consistency for idempotent registration
        if (
            existing.scenario_id == req.scenario_id
            and existing.trace_id == req.trace_id
            and existing.target_rule_id == req.target_rule_id
            and existing.is_negative_test == req.is_negative_test
        ):
            return _to_response(existing)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Simulation run '{req.run_id}' already registered with different parameters",
        )

    now = datetime.now(timezone.utc)
    new_run = SimulationRunModel(
        run_id=req.run_id,
        trace_id=req.trace_id,
        scenario_id=req.scenario_id,
        scenario_name=req.scenario_name,
        mitre_attack_ids=req.mitre_attack_ids,
        target_rule_id=req.target_rule_id,
        is_negative_test=req.is_negative_test,
        expected_detection=req.expected_detection,
        status="RUNNING",
        start_time=now,
        is_simulation=True,
    )
    session.add(new_run)
    await session.commit()
    await session.refresh(new_run)

    logger.info("Registered simulation run '%s' for scenario '%s'", req.run_id, req.scenario_id)
    return _to_response(new_run)


@router.post(
    "/runs/{run_id}/finalize",
    response_model=SimulationRunResponse,
    status_code=status.HTTP_200_OK,
    summary="Finalize simulation run with independent backend verification",
)
async def finalize_simulation_run(
    run_id: str,
    req: SimulationRunFinalizeRequest,
    _admin: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> SimulationRunResponse:
    """Finalize a simulation run and independently verify detection outcomes against the database.

    Crucial invariant: Never trusts client-claimed detections blindly. Derives findings,
    incidents, and detection latency from actual persisted records in PostgreSQL.
    """
    query = select(SimulationRunModel).where(SimulationRunModel.run_id == run_id)
    res = await session.execute(query)
    run = res.scalars().first()

    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Simulation run '{run_id}' not found",
        )

    # Check for idempotent finalization
    if run.status in ["PASS", "FAIL", "INCONCLUSIVE"]:
        logger.debug("Simulation run '%s' already finalized with status '%s'", run_id, run.status)
        return _to_response(run)

    # 1. Independent Database Query for Persisted Findings
    findings_query = (
        select(FindingModel)
        .where(
            (FindingModel.simulation_run_id == run.run_id)
            | (FindingModel.explanation["simulation_run_id"].as_string() == run.run_id)
            | (FindingModel.explanation["trace_id"].as_string() == run.trace_id)
        )
        .order_by(FindingModel.timestamp.asc())
    )
    findings_res = await session.execute(findings_query)
    matching_findings = findings_res.scalars().all()

    # 2. Extract Matching Findings & Check Target Rule Match
    matching_finding_ids = [str(f.id) for f in matching_findings]
    target_rule_matched = False
    for f in matching_findings:
        expl = f.explanation or {}
        f_rule = expl.get("rule_id")
        if f_rule == run.target_rule_id:
            target_rule_matched = True

    # 3. Query Linked Incident Records (Direct provenance only, NO heuristic title matching)
    matching_incident_ids: List[str] = []
    for f in matching_findings:
        if f.incident_id and str(f.incident_id) not in matching_incident_ids:
            matching_incident_ids.append(str(f.incident_id))

    # Query incidents directly tagged with this simulation_run_id
    inc_query = select(IncidentModel).where(IncidentModel.simulation_run_id == run.run_id)
    inc_res = await session.execute(inc_query)
    for inc in inc_res.scalars().all():
        if str(inc.id) not in matching_incident_ids:
            matching_incident_ids.append(str(inc.id))

    # 4. Measure Detection Latency from Database Timestamps
    latency_seconds: Optional[float] = None
    latency_notes: Optional[str] = None

    if matching_findings:
        finding_ts = matching_findings[0].timestamp
        # Compare with run start time
        if finding_ts and run.start_time:
            diff = (finding_ts - run.start_time).total_seconds()
            latency_seconds = max(0.0, round(diff, 4))
            latency_notes = f"Measured from run start ({run.start_time.isoformat()}) to first finding ({finding_ts.isoformat()})"
        else:
            latency_notes = "Timestamp precision unavailable"
    else:
        latency_notes = "No findings generated; latency not applicable"

    # 5. Independent Outcome Verdict
    now = datetime.now(timezone.utc)
    duration = (now - run.start_time).total_seconds()

    if req.events_submitted_count == 0:
        status_verdict = "INCONCLUSIVE"
        summary = (
            f"INCONCLUSIVE: Zero telemetry events were submitted to validate rule '{run.target_rule_id}'. "
            f"Error reported: {req.error_detail or 'No events generated'}"
        )
    elif req.error_detail and req.events_accepted_count == 0:
        status_verdict = "INCONCLUSIVE"
        summary = f"INCONCLUSIVE: Telemetry submission rejected by backend: {req.error_detail}"
    elif run.is_negative_test:
        if len(matching_findings) == 0:
            status_verdict = "PASS"
            summary = (
                f"PASS (Boundary): Sub-threshold events correctly rejected by rule '{run.target_rule_id}'. "
                f"Zero findings created in backend."
            )
        else:
            status_verdict = "FAIL"
            summary = (
                f"FAIL (Boundary Violation): Rule '{run.target_rule_id}' triggered unexpectedly on sub-threshold events. "
                f"Observed finding IDs: {matching_finding_ids}"
            )
    else:
        # Positive scenario
        if target_rule_matched or len(matching_findings) > 0:
            status_verdict = "PASS"
            summary = (
                f"PASS: Detection rule '{run.target_rule_id}' validated successfully. "
                f"Persisted findings: {len(matching_finding_ids)}, Incidents: {len(matching_incident_ids)}."
            )
        else:
            status_verdict = "FAIL"
            summary = (
                f"FAIL: Target detection rule '{run.target_rule_id}' did not generate expected findings in database."
            )

    # 6. Persist Finalized State
    run.status = status_verdict
    run.end_time = now
    run.duration_seconds = max(0.0, round(duration, 3))
    run.events_submitted_count = req.events_submitted_count
    run.events_accepted_count = req.events_accepted_count
    run.observed_detection = len(matching_findings) > 0
    run.matching_finding_ids = matching_finding_ids
    run.matching_incident_ids = matching_incident_ids
    run.latency_seconds = latency_seconds
    run.latency_notes = latency_notes
    run.summary = summary
    run.error_detail = req.error_detail

    await session.commit()
    await session.refresh(run)

    logger.info("Finalized simulation run '%s' with backend-verified verdict '%s'", run_id, status_verdict)
    return _to_response(run)


@router.get(
    "/runs",
    response_model=List[SimulationRunResponse],
    status_code=status.HTTP_200_OK,
    summary="List paginated simulation run history",
)
async def list_simulation_runs(
    scenario_id: Optional[str] = Query(None, description="Filter by scenario ID"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by outcome status"),
    is_negative: Optional[bool] = Query(None, description="Filter by test boundary type"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    _admin: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> List[SimulationRunResponse]:
    """Retrieve history of purple-team simulation runs ordered by execution timestamp."""
    query = (
        select(SimulationRunModel)
        .order_by(SimulationRunModel.start_time.desc())
        .offset(offset)
        .limit(limit)
    )
    if scenario_id:
        query = query.where(SimulationRunModel.scenario_id == scenario_id)
    if status_filter:
        query = query.where(SimulationRunModel.status == status_filter.upper())
    if is_negative is not None:
        query = query.where(SimulationRunModel.is_negative_test == is_negative)

    res = await session.execute(query)
    runs = res.scalars().all()
    return [_to_response(r) for r in runs]


@router.get(
    "/runs/{run_id}",
    response_model=SimulationRunResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve details of a single simulation run",
)
async def get_simulation_run(
    run_id: str,
    _admin: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> SimulationRunResponse:
    """Retrieve full details, expected vs observed results, and linked evidence for a run."""
    query = select(SimulationRunModel).where(SimulationRunModel.run_id == run_id)
    res = await session.execute(query)
    run = res.scalars().first()

    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Simulation run '{run_id}' not found",
        )

    return _to_response(run)


@router.get(
    "/coverage",
    response_model=SimulationCoverageResponse,
    status_code=status.HTTP_200_OK,
    summary="Get purple-team simulation coverage and validation matrix",
)
async def get_simulation_coverage(
    _admin: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> SimulationCoverageResponse:
    """Calculate aggregate purple-team validation coverage across registered scenarios and rules."""
    # 1. Total counts query
    runs_query = select(SimulationRunModel)
    runs_res = await session.execute(runs_query)
    all_runs = runs_res.scalars().all()

    total_runs = len(all_runs)
    passed_runs = sum(1 for r in all_runs if r.status in ("PASS", "PASSED"))
    failed_runs = sum(1 for r in all_runs if r.status in ("FAIL", "FAILED"))
    inconclusive_runs = sum(1 for r in all_runs if r.status in ("INCONCLUSIVE", "ABORTED", "CANCELLED"))
    completed_statuses = {"PASS", "PASSED", "FAIL", "FAILED", "INCONCLUSIVE"}
    distinct_scenarios_tested = len({r.scenario_id for r in all_runs if r.status in completed_statuses})

    most_recent_run = max(all_runs, key=lambda r: r.start_time, default=None)

    # 2. Active rules count query
    rules_count_query = select(func.count(RuleModel.id)).where(RuleModel.is_active == True)
    rules_res = await session.execute(rules_count_query)
    total_rules = rules_res.scalar() or 0

    # 3. Scenario Coverage Matrix Construction
    scenario_items: List[SimulationScenarioCoverageItem] = []
    validated_rules_set = set()

    for s_def in REGISTERED_SCENARIOS:
        sc_id = s_def["scenario_id"]
        # Find runs for this scenario
        sc_runs = [r for r in all_runs if r.scenario_id == sc_id]

        # Positive runs (expected_detection = True, is_negative_test = False)
        pos_runs = [r for r in sc_runs if not r.is_negative_test]
        latest_pos = max(pos_runs, key=lambda r: r.start_time, default=None)

        if latest_pos:
            if latest_pos.status in ("PASS", "PASSED"):
                pos_status = "VALIDATED"
            elif latest_pos.status in ("FAIL", "FAILED"):
                pos_status = "FAILED"
            else:
                pos_status = "INCONCLUSIVE"
        else:
            pos_status = "NOT_TESTED"

        # Negative boundary runs (is_negative_test = True)
        neg_runs = [r for r in sc_runs if r.is_negative_test]
        latest_neg = max(neg_runs, key=lambda r: r.start_time, default=None)

        if latest_neg:
            if latest_neg.status in ("PASS", "PASSED"):
                neg_status = "VALIDATED"
            elif latest_neg.status in ("FAIL", "FAILED"):
                neg_status = "FAILED"
            else:
                neg_status = "INCONCLUSIVE"
        else:
            neg_status = "NOT_TESTED"

        # A detection rule is only certified as validated if:
        # 1. Its positive trigger passed (VALIDATED)
        # 2. Its negative boundary did NOT fail (prevents false-positive rules from claiming validation)
        if pos_status == "VALIDATED" and neg_status != "FAILED":
            validated_rules_set.add(s_def["target_rule_id"])

        # Overall latest run for this scenario
        latest_sc_run = max(sc_runs, key=lambda r: r.start_time, default=None)

        scenario_items.append(
            SimulationScenarioCoverageItem(
                scenario_id=sc_id,
                scenario_name=s_def["scenario_name"],
                mitre_attack_id=s_def["mitre_attack_id"],
                target_rule_id=s_def["target_rule_id"],
                positive_status=pos_status,
                negative_status=neg_status,
                last_tested_at=latest_sc_run.start_time if latest_sc_run else None,
                last_run_id=latest_sc_run.run_id if latest_sc_run else None,
                last_status=latest_sc_run.status if latest_sc_run else None,
            )
        )

    return SimulationCoverageResponse(
        total_runs=total_runs,
        passed_runs=passed_runs,
        failed_runs=failed_runs,
        inconclusive_runs=inconclusive_runs,
        distinct_scenarios_tested=distinct_scenarios_tested,
        validated_rules_count=len(validated_rules_set),
        total_rules_count=total_rules,
        most_recent_run_id=most_recent_run.run_id if most_recent_run else None,
        most_recent_run_at=most_recent_run.start_time if most_recent_run else None,
        scenarios=scenario_items,
    )


def _to_response(model: SimulationRunModel) -> SimulationRunResponse:
    return SimulationRunResponse(
        run_id=model.run_id,
        trace_id=model.trace_id,
        scenario_id=model.scenario_id,
        scenario_name=model.scenario_name,
        mitre_attack_ids=list(model.mitre_attack_ids or []),
        target_rule_id=model.target_rule_id,
        is_negative_test=model.is_negative_test,
        status=model.status,
        start_time=model.start_time,
        end_time=model.end_time,
        duration_seconds=model.duration_seconds,
        events_submitted_count=model.events_submitted_count,
        events_accepted_count=model.events_accepted_count,
        expected_detection=model.expected_detection,
        observed_detection=model.observed_detection,
        matching_finding_ids=list(model.matching_finding_ids or []),
        matching_incident_ids=list(model.matching_incident_ids or []),
        latency_seconds=model.latency_seconds,
        latency_notes=model.latency_notes,
        summary=model.summary,
        error_detail=model.error_detail,
        is_simulation=model.is_simulation,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )
