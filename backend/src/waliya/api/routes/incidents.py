"""Persistent security incident management and investigation API endpoints."""

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from waliya.contracts import (
    AttackPath,
    GraphSnapshot,
    IncidentAttackCoverageResponse,
    IncidentDetail,
    IncidentReconstructionResponse,
    IncidentStatusEnum,
    IncidentSummary,
    IncidentThreatIntelMatch,
    IncidentThreatIntelSummary,
    SeverityEnum,
)
from waliya.core.auth import (
    verify_analyst_or_above,
    verify_operator_or_admin,
    verify_viewer_or_above,
)
from waliya.db.models import FindingModel, IncidentModel, ThreatIndicatorModel
from waliya.db.session import get_db_session
from waliya.incidents.graph_service import IncidentGraphService
from waliya.incidents.mitre_service import IncidentMitreService
from waliya.incidents.reconstruction_service import IncidentReconstructionService

logger = logging.getLogger("waliya.api.routes.incidents")

router = APIRouter(prefix="/incidents", tags=["incidents"])


class IncidentStatusUpdateRequest(BaseModel):
    """Payload for updating incident lifecycle status."""
    status: IncidentStatusEnum
    note: Optional[str] = Field(default=None, max_length=1000, description="Analyst investigation note")


@router.get(
    "",
    response_model=List[IncidentSummary],
    status_code=status.HTTP_200_OK,
    summary="List and filter security incidents",
)
async def list_incidents(
    status_filter: Optional[IncidentStatusEnum] = Query(default=None, alias="status"),
    severity_filter: Optional[SeverityEnum] = Query(default=None, alias="severity"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _admin: str = Depends(verify_viewer_or_above),
    session: AsyncSession = Depends(get_db_session),
) -> List[IncidentSummary]:
    """Retrieve filtered security incidents ordered by last observation timestamp."""
    query = (
        select(
            IncidentModel,
            func.count(FindingModel.id).label("findings_count"),
        )
        .outerjoin(FindingModel, FindingModel.incident_id == IncidentModel.id)
        .group_by(IncidentModel.id)
        .order_by(IncidentModel.last_seen.desc().nullslast(), IncidentModel.created_at.desc())
        .offset(offset)
        .limit(limit)
    )

    if status_filter:
        query = query.where(IncidentModel.status == status_filter.value)
    if severity_filter:
        query = query.where(IncidentModel.severity == severity_filter.value)

    res = await session.execute(query)
    rows = res.all()

    summaries: List[IncidentSummary] = []
    for inc, f_count in rows:
        summaries.append(IncidentSummary(
            incident_id=inc.id,
            incident_number=inc.incident_number,
            title=inc.title,
            severity=SeverityEnum(inc.severity),
            status=IncidentStatusEnum(inc.status),
            composite_risk_score=inc.composite_risk_score,
            findings_count=f_count,
            first_seen=inc.first_seen,
            last_seen=inc.last_seen,
            created_at=inc.created_at,
            updated_at=inc.updated_at,
            is_simulation=getattr(inc, "is_simulation", False) or inc.title.startswith("[SIMULATION]"),
            simulation_run_id=getattr(inc, "simulation_run_id", None),
        ))

    return summaries


@router.get(
    "/{incident_id}",
    response_model=IncidentDetail,
    status_code=status.HTTP_200_OK,
    summary="Get incident details",
)
async def get_incident(
    incident_id: UUID,
    _admin: str = Depends(verify_viewer_or_above),
    session: AsyncSession = Depends(get_db_session),
) -> IncidentDetail:
    """Retrieve full incident details including risk factor breakdown and entities."""
    query = (
        select(
            IncidentModel,
            func.count(FindingModel.id).label("findings_count"),
        )
        .outerjoin(FindingModel, FindingModel.incident_id == IncidentModel.id)
        .where(IncidentModel.id == incident_id)
        .group_by(IncidentModel.id)
    )
    res = await session.execute(query)
    row = res.first()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    inc, f_count = row
    graph_snap = None
    if inc.entity_graph_snapshot:
        try:
            graph_snap = GraphSnapshot(**inc.entity_graph_snapshot)
        except Exception as e:
            logger.warning("Could not parse graph snapshot for incident %s: %s", incident_id, e)

    return IncidentDetail(
        incident_id=inc.id,
        incident_number=inc.incident_number,
        title=inc.title,
        description=inc.description,
        severity=SeverityEnum(inc.severity),
        status=IncidentStatusEnum(inc.status),
        composite_risk_score=inc.composite_risk_score,
        findings_count=f_count,
        first_seen=inc.first_seen,
        last_seen=inc.last_seen,
        created_at=inc.created_at,
        updated_at=inc.updated_at,
        assigned_to=inc.assigned_to,
        affected_entities=inc.affected_entities or [],
        mitre_attack_ids=inc.mitre_attack_ids or [],
        risk_explanation=inc.risk_explanation or {},
        update_history=inc.update_history or [],
        graph_snapshot=graph_snap,
        is_simulation=getattr(inc, "is_simulation", False) or inc.title.startswith("[SIMULATION]"),
        simulation_run_id=getattr(inc, "simulation_run_id", None),
    )


@router.get(
    "/{incident_id}/evidence",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Get incident evidence and timeline",
)
async def get_incident_evidence(
    incident_id: UUID,
    _admin: str = Depends(verify_viewer_or_above),
    session: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Retrieve all findings, timeline entries, affected entities, and cryptographic evidence manifest."""
    inc_query = select(IncidentModel).where(IncidentModel.id == incident_id)
    inc_res = await session.execute(inc_query)
    inc = inc_res.scalars().first()

    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    findings_query = (
        select(FindingModel)
        .options(
            selectinload(FindingModel.event),
            selectinload(FindingModel.rule),
        )
        .where(FindingModel.incident_id == incident_id)
        .order_by(FindingModel.timestamp.asc())
        .limit(500)
    )
    f_res = await session.execute(findings_query)
    findings = f_res.scalars().all()

    timeline = []
    evidence_items = []
    item_hashes = []

    for f in findings:
        payload_data = f.event.normalized_payload if f.event else f.explanation
        sha_hash = hashlib.sha256(
            json.dumps(payload_data, sort_keys=True).encode("utf-8")
        ).hexdigest()
        item_hashes.append(sha_hash)

        evidence_items.append({
            "evidence_id": str(f.event_id) if f.event_id else str(f.id),
            "evidence_type": f.event.event_type if f.event else "SECURITY_FINDING",
            "sha256_hash": sha_hash,
            "description": f"{f.severity} alert - {f.rule.name if f.rule else 'Behavioral observation'}",
            "collected_at": f.timestamp.isoformat() if f.timestamp else None,
        })

        timeline.append({
            "finding_id": str(f.id),
            "event_id": str(f.event_id) if f.event_id else None,
            "event_type": f.event.event_type if f.event else "SECURITY_FINDING",
            "source": f.event.source if f.event else "waliya-engine",
            "timestamp": f.timestamp.isoformat() if f.timestamp else None,
            "rule_id": str(f.rule_id) if f.rule_id else None,
            "rule_name": f.rule.name if f.rule else (f.explanation.get("rule_name") if isinstance(f.explanation, dict) else None),
            "mitre_attack_ids": f.rule.mitre_attack_ids if f.rule else [],
            "severity": f.severity,
            "confidence": f.confidence,
            "explanation": f.explanation,
            "dedup_key": f.dedup_key,
            "sha256_hash": sha_hash,
            "normalized_payload": f.event.normalized_payload if f.event else {},
        })

    computed_manifest_hash = None
    if item_hashes:
        computed_manifest_hash = hashlib.sha256(
            "".join(sorted(item_hashes)).encode("utf-8")
        ).hexdigest()

    is_verified = False
    if inc.evidence_manifest_hash and computed_manifest_hash:
        is_verified = (inc.evidence_manifest_hash == computed_manifest_hash)

    manifest_status = "VERIFIED" if is_verified else ("UNSEALED" if inc.evidence_manifest_hash is None else "TAMPER_DETECTED")

    is_evidence_truncated = (len(findings) >= 500)
    evidence_manifest = {
        "incident_id": str(inc.id),
        "manifest_hash": computed_manifest_hash,
        "stored_hash": inc.evidence_manifest_hash,
        "is_verified": is_verified,
        "status": manifest_status,
        "total_items": len(evidence_items),
        "is_truncated": is_evidence_truncated,
        "item_ceiling": 500,
        "items": evidence_items,
    }

    return {
        "incident_id": str(inc.id),
        "incident_number": inc.incident_number,
        "affected_entities": inc.affected_entities or [],
        "mitre_attack_ids": inc.mitre_attack_ids or [],
        "first_seen": inc.first_seen.isoformat() if inc.first_seen else None,
        "last_seen": inc.last_seen.isoformat() if inc.last_seen else None,
        "update_history": inc.update_history or [],
        "is_truncated": is_evidence_truncated,
        "timeline": timeline,
        "evidence_manifest": evidence_manifest,
    }


@router.get(
    "/{incident_id}/threat-intel",
    response_model=IncidentThreatIntelSummary,
    status_code=status.HTTP_200_OK,
    summary="Get threat intelligence indicators and enrichment for an incident",
)
async def get_incident_threat_intel(
    incident_id: UUID,
    _admin: str = Depends(verify_viewer_or_above),
    session: AsyncSession = Depends(get_db_session),
) -> IncidentThreatIntelSummary:
    """Retrieve all confirmed and heuristic threat intelligence context linked to an incident."""
    inc_query = select(IncidentModel).where(IncidentModel.id == incident_id)
    inc_res = await session.execute(inc_query)
    inc = inc_res.scalars().first()

    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    # 1. Fetch attached findings to classify matches and heuristics (bounded to 500)
    f_query = select(FindingModel).where(FindingModel.incident_id == incident_id).limit(500)
    f_res = await session.execute(f_query)
    findings = f_res.scalars().all()

    confirmed_count = 0
    heuristic_count = 0
    raw_matches: List[Dict[str, Any]] = []

    for f in findings:
        expl = f.explanation if isinstance(f.explanation, dict) else {}
        is_ti_match = expl.get("finding_type") == "THREAT_INTEL_MATCH"
        if is_ti_match:
            confirmed_count += 1
        else:
            heuristic_count += 1

        if "threat_intel_matches" in expl and isinstance(expl["threat_intel_matches"], list):
            raw_matches.extend(expl["threat_intel_matches"])

    # Also extract matches from incident risk_explanation
    if inc.risk_explanation and isinstance(inc.risk_explanation, dict):
        inc_matches = inc.risk_explanation.get("threat_intel_matches", [])
        if isinstance(inc_matches, list):
            raw_matches.extend(inc_matches)

    # Deduplicate matches by (indicator_type, value, source)
    deduped_matches: List[Dict[str, Any]] = []
    seen_keys = set()
    for m in raw_matches:
        if not isinstance(m, dict):
            continue
        k = (m.get("indicator_type"), m.get("value"), m.get("source"))
        if k not in seen_keys:
            seen_keys.add(k)
            deduped_matches.append(m)

    # 2. Query live database state for indicators to get current status and decay
    indicator_ids = []
    for m in deduped_matches:
        raw_id = m.get("indicator_id")
        if raw_id:
            try:
                indicator_ids.append(UUID(str(raw_id)))
            except Exception:
                pass

    live_indicators: Dict[UUID, ThreatIndicatorModel] = {}
    if indicator_ids:
        ind_query = select(ThreatIndicatorModel).where(ThreatIndicatorModel.id.in_(indicator_ids))
        ind_res = await session.execute(ind_query)
        for ind in ind_res.scalars().all():
            live_indicators[ind.id] = ind

    now_utc = datetime.now(timezone.utc)
    match_items: List[IncidentThreatIntelMatch] = []

    for m in deduped_matches:
        raw_id_str = m.get("indicator_id")
        ind_uuid = None
        if raw_id_str:
            try:
                ind_uuid = UUID(str(raw_id_str))
            except Exception:
                pass

        live_ind = live_indicators.get(ind_uuid) if ind_uuid else None

        source_name = live_ind.source if live_ind else m.get("source", "Unknown")
        prov_label = (
            f"Feed: {source_name}"
            if source_name.lower() in ("threatfox", "urlhaus")
            else f"Provider: {source_name}"
        )

        curr_conf = live_ind.confidence if live_ind else int(m.get("confidence", 50))
        is_active = live_ind.is_active if live_ind else bool(m.get("is_active", True))
        expires_at = live_ind.expires_at if live_ind else None
        is_exp = bool(expires_at and expires_at <= now_utc)

        matched_at_str = m.get("matched_at")
        matched_at_dt = now_utc
        if matched_at_str:
            try:
                matched_at_dt = datetime.fromisoformat(matched_at_str)
            except Exception:
                pass

        match_items.append(
            IncidentThreatIntelMatch(
                indicator_id=ind_uuid or inc.id,
                indicator_type=live_ind.indicator_type if live_ind else str(m.get("indicator_type", "UNKNOWN")),
                value=live_ind.value if live_ind else str(m.get("value", m.get("observable", "unknown"))),
                observable=str(m.get("observable", m.get("value", "unknown"))),
                source=source_name,
                source_id=live_ind.source_id if live_ind else m.get("source_id"),
                confidence_at_match=int(m.get("confidence", 50)),
                current_confidence=curr_conf,
                severity=live_ind.severity if live_ind else str(m.get("severity", "MEDIUM")),
                threat_category=live_ind.threat_category if live_ind else m.get("threat_category"),
                threat_actor=live_ind.threat_actor if live_ind else m.get("threat_actor"),
                tags=live_ind.tags if live_ind else (m.get("tags") or []),
                description=live_ind.description if live_ind else m.get("description"),
                first_seen=live_ind.first_seen if live_ind else None,
                last_seen=live_ind.last_seen if live_ind else None,
                expires_at=expires_at,
                last_decayed_at=live_ind.last_decayed_at if live_ind else None,
                is_active=is_active,
                is_expired=is_exp,
                matched_at=matched_at_dt,
                investigative_note=str(m.get("investigative_note", f"Observable matched {source_name} indicator.")),
                provenance_label=prov_label,
                match_classification="CONFIRMED_MATCH",
            )
        )

    # Max confidence and bounded threat intelligence score bonus
    max_conf = max([item.current_confidence for item in match_items], default=0)
    ti_bonus = min(15.0, round(max_conf * 0.15, 1))

    decision_reason = (
        (inc.risk_explanation or {}).get("decision_reason")
        or f"Incident correlated with {len(match_items)} threat intelligence indicator(s)."
    )

    return IncidentThreatIntelSummary(
        incident_id=inc.id,
        incident_number=inc.incident_number,
        has_threat_intel=len(match_items) > 0,
        total_matched_indicators=len(match_items),
        max_confidence=max_conf,
        threat_intel_bonus=ti_bonus,
        confirmed_matches_count=confirmed_count,
        heuristic_findings_count=heuristic_count,
        matches=match_items,
        decision_reason=decision_reason,
    )


@router.post(
    "/{incident_id}/seal-evidence",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Cryptographically seal evidence manifest in durable database",
)
async def seal_incident_evidence(
    incident_id: UUID,
    _admin: str = Depends(verify_operator_or_admin),
    session: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Calculate and seal SHA-256 evidence manifest hash for non-repudiation."""
    inc_query = select(IncidentModel).where(IncidentModel.id == incident_id)
    inc_res = await session.execute(inc_query)
    inc = inc_res.scalars().first()

    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    findings_query = (
        select(FindingModel)
        .options(selectinload(FindingModel.event))
        .where(FindingModel.incident_id == incident_id)
    )
    f_res = await session.execute(findings_query)
    findings = f_res.scalars().all()

    item_hashes = []
    for f in findings:
        payload_data = f.event.normalized_payload if f.event else f.explanation
        sha_hash = hashlib.sha256(
            json.dumps(payload_data, sort_keys=True).encode("utf-8")
        ).hexdigest()
        item_hashes.append(sha_hash)

    if not item_hashes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot seal an incident with zero associated evidence findings.",
        )

    manifest_hash = hashlib.sha256(
        "".join(sorted(item_hashes)).encode("utf-8")
    ).hexdigest()

    now_utc = datetime.now(timezone.utc)
    inc.evidence_manifest_hash = manifest_hash

    history = list(inc.update_history or [])
    history.append({
        "timestamp": now_utc.isoformat(),
        "action": "EVIDENCE_SEALED",
        "manifest_hash": manifest_hash,
        "items_count": len(item_hashes),
    })
    inc.update_history = history

    await session.commit()
    logger.info("Incident %s evidence sealed with manifest hash: %s", incident_id, manifest_hash)

    return {
        "incident_id": str(inc.id),
        "manifest_hash": manifest_hash,
        "sealed_at": now_utc.isoformat(),
        "status": "VERIFIED",
        "items_sealed": len(item_hashes),
    }


@router.get(
    "/{incident_id}/export",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Export complete tamper-evident forensic case dossier",
)
async def export_incident_dossier(
    incident_id: UUID,
    _admin: str = Depends(verify_viewer_or_above),
    session: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Generate structured, validated JSON case dossier for digital forensics and compliance."""
    evidence_data = await get_incident_evidence(incident_id=incident_id, _admin=_admin, session=session)
    detail_data = await get_incident(incident_id=incident_id, _admin=_admin, session=session)
    graph_data = await get_incident_graph(incident_id=incident_id, _admin=_admin, session=session)

    now_utc = datetime.now(timezone.utc)

    dossier = {
        "platform": "Waliya-IR Ethio-SOAR Digital Forensics Platform",
        "version": "2.0.0",
        "dossier_generated_at": now_utc.isoformat(),
        "incident": detail_data.model_dump(mode="json"),
        "evidence_manifest": evidence_data.get("evidence_manifest"),
        "forensic_timeline": evidence_data.get("timeline"),
        "entity_graph": graph_data.model_dump(mode="json"),
        "update_history": detail_data.update_history,
    }

    # Generate dossier integrity digest
    dossier_digest = hashlib.sha256(
        json.dumps(dossier, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
    dossier["dossier_integrity_hash"] = dossier_digest

    return dossier


@router.get(
    "/{incident_id}/graph",
    response_model=GraphSnapshot,
    status_code=status.HTTP_200_OK,
    summary="Get incident-specific entity graph snapshot",
)
async def get_incident_graph(
    incident_id: UUID,
    _admin: str = Depends(verify_viewer_or_above),
    session: AsyncSession = Depends(get_db_session),
) -> GraphSnapshot:
    """Retrieve the incident-specific entity correlation subgraph, rebuilding from evidence if needed."""
    inc_query = select(IncidentModel).where(IncidentModel.id == incident_id)
    inc_res = await session.execute(inc_query)
    inc = inc_res.scalars().first()

    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    if inc.entity_graph_snapshot:
        try:
            snapshot = GraphSnapshot(**inc.entity_graph_snapshot)
            if snapshot.nodes:
                return snapshot
        except Exception:
            pass

    # Reconstruct from authoritative findings and events
    try:
        return await IncidentGraphService.build_incident_attack_graph(
            session=session,
            incident_id=inc.id,
            persist=True,
        )
    except Exception as exc:
        logger.warning("Could not reconstruct attack graph for incident %s: %s", incident_id, exc)
        return GraphSnapshot(incident_id=inc.id, nodes=[], edges=[])


@router.get(
    "/{incident_id}/attack-paths",
    response_model=List[AttackPath],
    status_code=status.HTTP_200_OK,
    summary="Get discovered attack paths for a specific incident",
)
async def get_incident_attack_paths(
    incident_id: UUID,
    _admin: str = Depends(verify_viewer_or_above),
    session: AsyncSession = Depends(get_db_session),
) -> List[AttackPath]:
    """Retrieve computed directed attack progression paths for an incident."""
    snapshot = await get_incident_graph(incident_id=incident_id, _admin=_admin, session=session)
    return snapshot.attack_paths


@router.post(
    "/{incident_id}/graph/refresh",
    response_model=GraphSnapshot,
    status_code=status.HTTP_200_OK,
    summary="Rebuild incident attack graph directly from stored events and findings",
)
async def refresh_incident_graph(
    incident_id: UUID,
    _admin: str = Depends(verify_operator_or_admin),
    session: AsyncSession = Depends(get_db_session),
) -> GraphSnapshot:
    """Force deterministic re-extraction of attack graph and paths from PostgreSQL evidence."""
    inc_query = select(IncidentModel).where(IncidentModel.id == incident_id)
    inc_res = await session.execute(inc_query)
    inc = inc_res.scalars().first()

    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    return await IncidentGraphService.build_incident_attack_graph(
        session=session,
        incident_id=inc.id,
        persist=True,
    )


@router.get(
    "/{incident_id}/mitre-coverage",
    response_model=IncidentAttackCoverageResponse,
    status_code=status.HTTP_200_OK,
    summary="Get evidence-backed MITRE ATT&CK coverage summary for an incident",
)
async def get_incident_mitre_coverage(
    incident_id: UUID,
    _admin: str = Depends(verify_viewer_or_above),
    session: AsyncSession = Depends(get_db_session),
) -> IncidentAttackCoverageResponse:
    """Retrieve explainable, evidence-backed MITRE ATT&CK technique coverage and mapping state for an incident."""
    inc_query = select(IncidentModel).where(IncidentModel.id == incident_id)
    inc_res = await session.execute(inc_query)
    inc = inc_res.scalars().first()

    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    try:
        return await IncidentMitreService.get_incident_mitre_coverage(
            session=session,
            incident_id=inc.id,
        )
    except Exception as exc:
        logger.error("Failed to compute MITRE coverage for incident %s: %s", incident_id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to compute MITRE coverage: {str(exc)}",
        )


@router.get(
    "/{incident_id}/reconstruction",
    response_model=IncidentReconstructionResponse,
    status_code=status.HTTP_200_OK,
    summary="Get unified evidence-backed incident reconstruction and cross-layer integrity report",
)
async def get_incident_reconstruction(
    incident_id: UUID,
    max_items: int = Query(default=200, ge=1, le=500, description="Max chronological timeline items"),
    _admin: str = Depends(verify_viewer_or_above),
    session: AsyncSession = Depends(get_db_session),
) -> IncidentReconstructionResponse:
    """Retrieve deterministic incident reconstruction synthesizing entity graphs, ATT&CK, and chronological telemetry."""
    inc_query = select(IncidentModel).where(IncidentModel.id == incident_id)
    inc_res = await session.execute(inc_query)
    inc = inc_res.scalars().first()

    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    try:
        return await IncidentReconstructionService.reconstruct_incident(
            session=session,
            incident_id=inc.id,
            max_timeline_items=max_items,
        )
    except Exception as exc:
        logger.error("Failed to reconstruct incident %s: %s", incident_id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to reconstruct incident: {str(exc)}",
        )


@router.patch(
    "/{incident_id}/status",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Update incident lifecycle status",
)
async def update_incident_status(
    incident_id: UUID,
    payload: IncidentStatusUpdateRequest,
    _admin: str = Depends(verify_operator_or_admin),
    session: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Transition incident status (e.g., OPEN -> INVESTIGATING -> CONTAINED -> RESOLVED -> CLOSED) with audit trail."""
    inc_query = select(IncidentModel).where(IncidentModel.id == incident_id)
    inc_res = await session.execute(inc_query)
    inc = inc_res.scalars().first()

    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    old_status = inc.status
    inc.status = payload.status.value
    now_utc = datetime.now(timezone.utc)

    if payload.status in (IncidentStatusEnum.RESOLVED, IncidentStatusEnum.CLOSED):
        inc.closed_at = now_utc

    history = list(inc.update_history or [])
    history.append({
        "timestamp": now_utc.isoformat(),
        "action": "STATUS_CHANGED",
        "previous_status": old_status,
        "new_status": payload.status.value,
        "note": payload.note,
    })
    inc.update_history = history

    # Queue outbound notification for non-simulation incident status changes
    if not getattr(inc, "is_simulation", False):
        try:
            from waliya.integrations.delivery_service import NotificationDeliveryService
            from waliya.integrations.payloads import (
                NotificationEventType,
                build_incident_status_changed_payload,
            )
            notif_payload = build_incident_status_changed_payload(
                incident_id=inc.id,
                title=inc.title,
                previous_status=old_status,
                new_status=payload.status.value,
                updated_at=now_utc,
                note=payload.note,
            )
            await NotificationDeliveryService.queue_notification(
                session=session,
                event_type=NotificationEventType.INCIDENT_STATUS_CHANGED.value,
                event_id=str(inc.id),
                payload=notif_payload,
            )
        except Exception as notif_err:
            logger.warning("Failed queuing incident status notification for %s: %s", inc.id, notif_err)

    await session.commit()
    logger.info("Incident %s status changed: %s -> %s", incident_id, old_status, payload.status.value)

    return {
        "incident_id": str(inc.id),
        "previous_status": old_status,
        "current_status": inc.status,
        "updated_at": inc.updated_at.isoformat() if inc.updated_at else now_utc.isoformat(),
    }
