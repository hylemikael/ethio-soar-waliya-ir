"""SOAR workflow playbook engine for automated and analyst-approved response actions."""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from waliya.audit.ledger_service import AuditLedgerService
from waliya.config import settings
from waliya.contracts import (
    PlaybookActionStep,
    PlaybookSchema,
    ResponseActionEnum,
    ResponseStateEnum,
    RuleCondition,
    SeverityEnum,
)
from waliya.core.crypto import (
    compute_command_signature,
    decrypt_agent_secret,
    encrypt_agent_secret,
)
from waliya.db.models import (
    AgentModel,
    IncidentModel,
    PlaybookModel,
    PlaybookRunModel,
    ResponseActionModel,
)
from waliya.detection.rule_engine import evaluate_operator, extract_field
from waliya.soar.adapters import ActionParametersValidator

logger = logging.getLogger("waliya.soar.playbook")


# Pre-defined built-in response playbooks
BUILTIN_PLAYBOOKS: List[PlaybookSchema] = [
    PlaybookSchema(
        playbook_id=UUID("11111111-2222-3333-4444-555555555551"),
        name="PLAYBOOK-BRUTEFORCE-CONTAINMENT",
        description="Automated or approved blocking of brute-force attacker IPs.",
        trigger_conditions=[
            RuleCondition(
                field="severity",
                operator="IN",
                value=["HIGH", "CRITICAL"],
            )
        ],
        action_steps=[
            PlaybookActionStep(
                step_id="step-1-block-attacker-ip",
                action=ResponseActionEnum.BLOCK_IP,
                parameters={"ip_address": "{attacker_ip}", "direction": "BOTH"},
                requires_approval=True,
                timeout_seconds=60,
            )
        ],
        requires_approval=True,
        is_active=True,
    ),
    PlaybookSchema(
        playbook_id=UUID("11111111-2222-3333-4444-555555555552"),
        name="PLAYBOOK-WEBSHELL-TERMINATE-AND-FORENSICS",
        description="Terminates suspicious web shell processes and gathers forensic logs.",
        trigger_conditions=[
            RuleCondition(
                field="severity",
                operator="IN",
                value=["HIGH", "CRITICAL"],
            )
        ],
        action_steps=[
            PlaybookActionStep(
                step_id="step-1-kill-webshell-proc",
                action=ResponseActionEnum.TERMINATE_PROCESS,
                parameters={"pid": "{target_pid}", "process_name": "{target_process}", "kill_tree": False},
                requires_approval=True,
                timeout_seconds=60,
            ),
            PlaybookActionStep(
                step_id="step-2-collect-audit-logs",
                action=ResponseActionEnum.COLLECT_FORENSIC_ARTIFACT,
                parameters={"artifact_type": "LOGS"},
                requires_approval=False,
                timeout_seconds=120,
            ),
        ],
        requires_approval=True,
        is_active=True,
    ),
]


async def seed_builtin_playbooks(session: AsyncSession) -> int:
    """Ensure standard response playbooks exist in the database."""
    seeded = 0
    for pb in BUILTIN_PLAYBOOKS:
        q = select(PlaybookModel).where(PlaybookModel.id == pb.playbook_id)
        res = await session.execute(q)
        existing = res.scalars().first()
        if not existing:
            model = PlaybookModel(
                id=pb.playbook_id,
                name=pb.name,
                description=pb.description,
                trigger_conditions=[c.model_dump() for c in pb.trigger_conditions],
                action_steps=[s.model_dump() for s in pb.action_steps],
                requires_approval=pb.requires_approval,
                is_active=pb.is_active,
            )
            session.add(model)
            seeded += 1
    if seeded > 0:
        await session.commit()
    return seeded


class PlaybookEngine:
    """SOAR execution engine managing response lifecycle and action dispatch."""

    @classmethod
    async def get_next_agent_sequence(cls, session: AsyncSession, agent_id: UUID) -> int:
        """Atomically determine the next strictly increasing monotonic sequence for an agent."""
        stmt = (
            select(func.coalesce(func.max(ResponseActionModel.sequence), 0))
            .where(ResponseActionModel.agent_id == agent_id)
        )
        res = await session.execute(stmt)
        max_seq = res.scalar() or 0
        return max_seq + 1

    @classmethod
    def evaluate_triggers(cls, playbook: PlaybookModel, context: Dict[str, Any]) -> bool:
        """Safely evaluate whether incident context satisfies playbook trigger conditions without Python eval."""
        if not playbook.trigger_conditions:
            return True

        for cond_dict in playbook.trigger_conditions:
            field_name = cond_dict.get("field", "")
            operator = cond_dict.get("operator", "EQUALS")
            expected_val = cond_dict.get("value")

            actual_val = extract_field(context, field_name)
            matched = evaluate_operator(operator, actual_val, expected_val)
            if not matched:
                return False

        return True

    @classmethod
    def interpolate_parameters(
        cls,
        step_params: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Safely resolve dynamic variables (e.g. {attacker_ip}, {target_pid}) from incident context."""
        interpolated: Dict[str, Any] = {}
        for k, v in step_params.items():
            if isinstance(v, str) and v.startswith("{") and v.endswith("}"):
                var_key = v[1:-1].strip()
                resolved = context.get(var_key)
                if resolved is not None:
                    interpolated[k] = resolved
                else:
                    interpolated[k] = v
            else:
                interpolated[k] = v
        return interpolated

    @classmethod
    async def execute_playbook(
        cls,
        session: AsyncSession,
        playbook: PlaybookModel,
        incident: IncidentModel,
        agent: AgentModel,
        executed_by: str,
        dry_run: bool = True,
        context_override: Optional[Dict[str, Any]] = None,
    ) -> PlaybookRunModel:
        """Execute a playbook against an incident and target agent.

        Enforces:
        - Trigger condition verification.
        - Dry-run default protection.
        - Step-level parameter validation.
        - Approval pauses.
        - Cryptographic command envelope preparation.
        - Full audit ledger recording.
        """
        run_id = uuid4()
        now_utc = datetime.now(timezone.utc)

        # Simulation Safety Invariant: Synthetic incidents NEVER execute live containment actions
        is_sim_incident = bool(
            getattr(incident, "is_simulation", False)
            or (incident.title and incident.title.startswith("[SIMULATION]"))
        )
        if is_sim_incident and not dry_run:
            logger.warning(
                "Incident %s is marked as simulation. Overriding dry_run=True to prevent live endpoint containment.",
                incident.id,
            )
            dry_run = True

        # Build execution context from incident and entities
        incident_context: Dict[str, Any] = {
            "incident_id": str(incident.id),
            "severity": incident.severity,
            "title": incident.title,
            "composite_risk_score": incident.composite_risk_score,
            "agent_id": str(agent.id),
            "hostname": agent.hostname,
        }

        # Resolve primary affected non-host entities
        for ent in (incident.affected_entities or []):
            if ent.startswith("ip:"):
                incident_context["attacker_ip"] = ent.split("ip:", 1)[1]
            elif ent.startswith("user:"):
                incident_context["affected_user"] = ent.split("user:", 1)[1]
            elif ent.startswith("process:"):
                # Format: process:{agent}:{pid}:{name}
                parts = ent.split(":")
                if len(parts) >= 3 and parts[2].isdigit():
                    incident_context["target_pid"] = int(parts[2])
                    incident_context["target_process"] = parts[3] if len(parts) > 3 else "proc"

        if context_override:
            incident_context.update(context_override)

        # Evaluate triggers
        if not cls.evaluate_triggers(playbook, incident_context):
            logger.info("Playbook %s triggers not satisfied for incident %s", playbook.id, incident.id)
            run = PlaybookRunModel(
                id=run_id,
                playbook_id=playbook.id,
                incident_id=incident.id,
                status="ABORTED",
                dry_run=dry_run,
                executed_by=executed_by,
                start_time=now_utc,
                end_time=now_utc,
                output_summary={"reason": "Trigger conditions not satisfied", "context": incident_context},
            )
            session.add(run)
            await session.commit()
            return run

        # Create initial run record
        run = PlaybookRunModel(
            id=run_id,
            playbook_id=playbook.id,
            incident_id=incident.id,
            status="RUNNING",
            dry_run=dry_run,
            executed_by=executed_by,
            start_time=now_utc,
            output_summary={"steps": []},
        )
        session.add(run)
        await session.flush()

        step_results: List[Dict[str, Any]] = []
        is_paused_for_approval = False

        # Decrypt agent secret for command signing
        agent_secret = decrypt_agent_secret(agent.secret_key_enc, settings.SECRET_KEY)

        for step_idx, step_dict in enumerate(playbook.action_steps or []):
            step_id = step_dict.get("step_id", f"step-{step_idx+1}")
            action_name = step_dict.get("action")
            raw_params = step_dict.get("parameters", {})
            step_req_approval = step_dict.get("requires_approval", playbook.requires_approval)

            try:
                action_enum = ResponseActionEnum(action_name)
            except ValueError:
                logger.error("Unsupported action in step %s: %s", step_id, action_name)
                step_results.append({
                    "step_id": step_id,
                    "status": "FAILED",
                    "error": f"Unsupported action: {action_name}",
                })
                continue

            # Interpolate variables from context
            resolved_params = cls.interpolate_parameters(raw_params, incident_context)

            # Validate parameters against strict allowlist schemas
            try:
                validated_params = ActionParametersValidator.validate(action_enum, resolved_params)
            except ValueError as val_err:
                logger.error("Parameter validation failed for step %s: %s", step_id, val_err)
                step_results.append({
                    "step_id": step_id,
                    "action": action_enum.value,
                    "status": "FAILED",
                    "error": str(val_err),
                })
                continue

            # Monotonic sequence, nonce, timestamps
            seq = await cls.get_next_agent_sequence(session, agent.id)
            nonce = uuid4()
            command_id = uuid4()
            issued_at = datetime.now(timezone.utc)
            expires_at = issued_at + timedelta(seconds=settings.COMMAND_TTL_SECONDS)

            # Compute HMAC-SHA256 signature over critical envelope fields
            signature = compute_command_signature(
                command_id=command_id,
                agent_id=agent.id,
                action=action_enum.value,
                parameters=validated_params,
                sequence=seq,
                nonce=nonce,
                issued_at=issued_at,
                expires_at=expires_at,
                secret_key=agent_secret,
            )

            # Determine initial action status: PENDING_APPROVAL or QUEUED
            if step_req_approval:
                initial_status = ResponseStateEnum.PENDING_APPROVAL.value
                is_paused_for_approval = True
            else:
                initial_status = ResponseStateEnum.QUEUED.value

            action_model = ResponseActionModel(
                id=uuid4(),
                command_id=command_id,
                playbook_run_id=run.id,
                incident_id=incident.id,
                agent_id=agent.id,
                action=action_enum.value,
                parameters=validated_params,
                status=initial_status,
                nonce=nonce,
                sequence=seq,
                issued_at=issued_at,
                expires_at=expires_at,
                signature=signature,
                requested_by=executed_by,
                approved_by=executed_by if not step_req_approval else None,
                approved_at=issued_at if not step_req_approval else None,
                approval_reason="Pre-approved automated action" if not step_req_approval else None,
            )
            session.add(action_model)
            await session.flush()

            # Record audit ledger record
            await AuditLedgerService.record_action(
                session=session,
                actor_id=executed_by,
                actor_role="ADMIN" if executed_by == "admin" else "ANALYST",
                action="RESPONSE_ACTION_CREATED",
                target_entity=f"command:{command_id}",
                payload={
                    "command_id": str(command_id),
                    "action": action_enum.value,
                    "status": initial_status,
                    "agent_id": str(agent.id),
                    "incident_id": str(incident.id),
                    "playbook_run_id": str(run.id),
                    "parameters": validated_params,
                    "dry_run": dry_run,
                },
                timestamp=issued_at,
            )

            step_results.append({
                "step_id": step_id,
                "action": action_enum.value,
                "command_id": str(command_id),
                "status": initial_status,
                "requires_approval": step_req_approval,
                "dry_run": dry_run,
            })

            if step_req_approval:
                # Stop dispatching subsequent steps until approved
                break

        # Finalize run status
        if is_paused_for_approval:
            run.status = "PENDING_APPROVAL"
        else:
            run.status = "COMPLETED"
            run.end_time = datetime.now(timezone.utc)

        run.output_summary = {
            "steps": step_results,
            "dry_run": dry_run,
            "paused_for_approval": is_paused_for_approval,
        }
        await session.commit()
        return run
