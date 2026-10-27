"""Typed action registry for allowlisted security response operations.

Declares risk classifications, approval mandates, retry policies, and parameter validation
for every supported response action. Arbitrary commands and external execution paths are strictly rejected.
"""

import hashlib
import json
from typing import Any, Dict, List, Optional
from pydantic import BaseModel

from waliya.contracts import (
    ActionRegistryEntryResponse,
    ActionRiskClassificationEnum,
    ResponseActionEnum,
)


def compute_actions_approval_hash(actions: List[Dict[str, Any]]) -> str:
    """Compute deterministic SHA-256 hash of response plan action definitions.

    Used to guarantee action specifications are not modified between approval and execution.
    """
    canonical_json = json.dumps(actions, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


class ActionMetadata(BaseModel):
    """Metadata definition for an allowlisted response action."""
    action_type: ResponseActionEnum
    risk_classification: ActionRiskClassificationEnum
    default_requires_approval: bool
    default_timeout_seconds: int
    max_retries: int
    is_reversible: bool
    description: str
    parameter_fields: List[str]


# Authoritative registry of explicitly supported response actions
ACTION_REGISTRY: Dict[ResponseActionEnum, ActionMetadata] = {
    ResponseActionEnum.COLLECT_FORENSIC_ARTIFACT: ActionMetadata(
        action_type=ResponseActionEnum.COLLECT_FORENSIC_ARTIFACT,
        risk_classification=ActionRiskClassificationEnum.READ_ONLY,
        default_requires_approval=False,
        default_timeout_seconds=120,
        max_retries=2,
        is_reversible=True,
        description="Gathers volatile forensic evidence (audit logs, process maps, socket tables) without modifying system state.",
        parameter_fields=["artifact_type", "destination_path"],
    ),
    ResponseActionEnum.BLOCK_IP: ActionMetadata(
        action_type=ResponseActionEnum.BLOCK_IP,
        risk_classification=ActionRiskClassificationEnum.REVERSIBLE,
        default_requires_approval=True,
        default_timeout_seconds=30,
        max_retries=1,
        is_reversible=True,
        description="Injects iptables firewall drop rule to block inbound/outbound communication with target IP address.",
        parameter_fields=["ip_address", "direction"],
    ),
    ResponseActionEnum.UNBLOCK_IP: ActionMetadata(
        action_type=ResponseActionEnum.UNBLOCK_IP,
        risk_classification=ActionRiskClassificationEnum.REVERSIBLE,
        default_requires_approval=True,
        default_timeout_seconds=30,
        max_retries=1,
        is_reversible=True,
        description="Removes firewall drop rule for previously blocked IP address.",
        parameter_fields=["ip_address"],
    ),
    ResponseActionEnum.ISOLATE_HOST: ActionMetadata(
        action_type=ResponseActionEnum.ISOLATE_HOST,
        risk_classification=ActionRiskClassificationEnum.CONTAINMENT,
        default_requires_approval=True,
        default_timeout_seconds=60,
        max_retries=0,
        is_reversible=True,
        description="Isolates endpoint network interface, dropping non-management traffic while preserving C2 command channel.",
        parameter_fields=["direction", "allowed_subnets"],
    ),
    ResponseActionEnum.RESTORE_HOST: ActionMetadata(
        action_type=ResponseActionEnum.RESTORE_HOST,
        risk_classification=ActionRiskClassificationEnum.REVERSIBLE,
        default_requires_approval=True,
        default_timeout_seconds=60,
        max_retries=1,
        is_reversible=True,
        description="Flushes containment iptables rules, restoring normal endpoint network communication.",
        parameter_fields=["flush_rules"],
    ),
    ResponseActionEnum.TERMINATE_PROCESS: ActionMetadata(
        action_type=ResponseActionEnum.TERMINATE_PROCESS,
        risk_classification=ActionRiskClassificationEnum.DESTRUCTIVE,
        default_requires_approval=True,
        default_timeout_seconds=30,
        max_retries=0,
        is_reversible=False,
        description="Terminates suspicious process by verified PID and expected binary name; optionally terminates descendant process tree.",
        parameter_fields=["pid", "process_name", "kill_tree"],
    ),
    ResponseActionEnum.QUARANTINE_FILE: ActionMetadata(
        action_type=ResponseActionEnum.QUARANTINE_FILE,
        risk_classification=ActionRiskClassificationEnum.DESTRUCTIVE,
        default_requires_approval=True,
        default_timeout_seconds=60,
        max_retries=0,
        is_reversible=False,
        description="Relocates malicious file into restricted quarantine directory and strips execute permissions.",
        parameter_fields=["file_path", "quarantine_directory"],
    ),
    ResponseActionEnum.RECOVER_WEBSITE_FILE: ActionMetadata(
        action_type=ResponseActionEnum.RECOVER_WEBSITE_FILE,
        risk_classification=ActionRiskClassificationEnum.REVERSIBLE,
        default_requires_approval=True,
        default_timeout_seconds=60,
        max_retries=1,
        is_reversible=True,
        description="Restores defaced or modified web file from verified cryptographic backup with evidence quarantine.",
        parameter_fields=["target_file", "backup_file", "expected_hash", "quarantine_directory", "web_root"],
    ),
}

# Strict priority order for determining plan-level risk classification
RISK_PRIORITY = {
    ActionRiskClassificationEnum.DESTRUCTIVE: 4,
    ActionRiskClassificationEnum.CONTAINMENT: 3,
    ActionRiskClassificationEnum.REVERSIBLE: 2,
    ActionRiskClassificationEnum.READ_ONLY: 1,
}


class ResponseActionRegistry:
    """Registry query and policy evaluation service for SOAR actions."""

    @classmethod
    def is_supported(cls, action_name: str) -> bool:
        """Check if action name belongs to the allowlisted enum."""
        try:
            enum_val = ResponseActionEnum(action_name)
            return enum_val in ACTION_REGISTRY
        except (ValueError, KeyError):
            return False

    @classmethod
    def get_metadata(cls, action: ResponseActionEnum) -> ActionMetadata:
        """Retrieve metadata for a supported action type."""
        if action not in ACTION_REGISTRY:
            raise ValueError(f"Action '{action}' is not supported in the response action registry")
        return ACTION_REGISTRY[action]

    @classmethod
    def list_entries(cls) -> List[ActionRegistryEntryResponse]:
        """List all registered response actions with operational metadata."""
        return [
            ActionRegistryEntryResponse(
                action_type=meta.action_type,
                risk_classification=meta.risk_classification,
                default_requires_approval=meta.default_requires_approval,
                default_timeout_seconds=meta.default_timeout_seconds,
                max_retries=meta.max_retries,
                is_reversible=meta.is_reversible,
                description=meta.description,
                parameter_fields=meta.parameter_fields,
            )
            for meta in ACTION_REGISTRY.values()
        ]

    @classmethod
    def compute_plan_risk(cls, actions: List[Dict[str, Any]]) -> ActionRiskClassificationEnum:
        """Determine aggregate plan risk based on the highest risk action included."""
        highest_risk = ActionRiskClassificationEnum.READ_ONLY
        highest_score = RISK_PRIORITY[highest_risk]

        for act in actions:
            act_type_str = act.get("action")
            try:
                act_enum = ResponseActionEnum(act_type_str)
                meta = cls.get_metadata(act_enum)
                score = RISK_PRIORITY[meta.risk_classification]
                if score > highest_score:
                    highest_score = score
                    highest_risk = meta.risk_classification
            except Exception:
                continue

        return highest_risk

    @classmethod
    def plan_requires_approval(cls, actions: List[Dict[str, Any]]) -> bool:
        """Determine if a plan requires explicit approval.

        Requires approval if ANY action has requires_approval=True or is classified as
        CONTAINMENT or DESTRUCTIVE.
        """
        for act in actions:
            # Explicit flag in step
            if act.get("requires_approval", True):
                return True
            act_type_str = act.get("action")
            try:
                act_enum = ResponseActionEnum(act_type_str)
                meta = cls.get_metadata(act_enum)
                if meta.risk_classification in (
                    ActionRiskClassificationEnum.CONTAINMENT,
                    ActionRiskClassificationEnum.DESTRUCTIVE,
                ):
                    return True
            except Exception:
                return True
        return False
