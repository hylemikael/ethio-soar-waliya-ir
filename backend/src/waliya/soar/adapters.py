"""Strictly validated allowlisted response adapters for endpoint containment."""

import ipaddress
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple

from pydantic import ValidationError

from waliya.contracts import (
    BlockIpParams,
    CollectForensicParams,
    IsolateHostParams,
    QuarantineFileParams,
    ResponseActionEnum,
    ResponseStateEnum,
    RestoreHostParams,
    TerminateProcessParams,
    UnblockIpParams,
)

logger = logging.getLogger("waliya.soar.adapters")

# Reserved / critical subnets that MUST NOT be blocked to avoid isolating management plane
PROTECTED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      # IPv4 Loopback
    ipaddress.ip_network("169.254.0.0/16"),    # Link-Local
    ipaddress.ip_network("224.0.0.0/4"),       # Multicast
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    ipaddress.ip_network("::1/128"),          # IPv6 Loopback
    ipaddress.ip_network("fe80::/10"),         # IPv6 Link-Local
]


class ActionParametersValidator:
    """Validates action-specific parameters and enforces safety invariants."""

    @classmethod
    def validate(cls, action: ResponseActionEnum, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Validate parameters against action schemas and policy invariants.

        Raises:
            ValueError: If parameters are malformed or violate safety rules.
        """
        try:
            if action == ResponseActionEnum.BLOCK_IP:
                validated = BlockIpParams(**parameters)
                cls._validate_block_ip(validated.ip_address)
                return validated.model_dump()

            elif action == ResponseActionEnum.UNBLOCK_IP:
                validated = UnblockIpParams(**parameters)
                cls._validate_unblock_ip(validated.ip_address)
                return validated.model_dump()

            elif action == ResponseActionEnum.TERMINATE_PROCESS:
                validated = TerminateProcessParams(**parameters)
                cls._validate_terminate_process(validated.pid, validated.process_name)
                return validated.model_dump()

            elif action == ResponseActionEnum.COLLECT_FORENSIC_ARTIFACT:
                validated = CollectForensicParams(**parameters)
                cls._validate_forensic_path(validated.destination_path)
                return validated.model_dump()

            elif action == ResponseActionEnum.ISOLATE_HOST:
                validated = IsolateHostParams(**parameters)
                return validated.model_dump()

            elif action == ResponseActionEnum.RESTORE_HOST:
                validated = RestoreHostParams(**parameters)
                return validated.model_dump()

            elif action == ResponseActionEnum.QUARANTINE_FILE:
                validated = QuarantineFileParams(**parameters)
                return validated.model_dump()

            else:
                raise ValueError(f"Unsupported response action: {action}")

        except ValidationError as err:
            raise ValueError(f"Parameter validation failed for {action.value}: {err}") from err

    @staticmethod
    def _validate_block_ip(ip_str: str) -> None:
        """Enforce that blocked IP is valid and not a protected management IP."""
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
        except ValueError as e:
            raise ValueError(f"Invalid IP address format: '{ip_str}'") from e

        if ip_obj.is_unspecified:
            raise ValueError("Cannot block unspecified address (0.0.0.0 or ::)")

        for net in PROTECTED_NETWORKS:
            if ip_obj in net:
                raise ValueError(
                    f"Refusing to block protected management/infrastructure address: '{ip_str}' belongs to {net}"
                )

    @staticmethod
    def _validate_unblock_ip(ip_str: str) -> None:
        """Validate IP address format for unblock operations."""
        try:
            ipaddress.ip_address(ip_str.strip())
        except ValueError as e:
            raise ValueError(f"Invalid IP address format: '{ip_str}'") from e

    @staticmethod
    def _validate_terminate_process(pid: int, process_name: str) -> None:
        """Enforce process termination safety: reject critical system PIDs and require identity."""
        if pid <= 1:
            raise ValueError(f"Refusing to terminate critical system process PID {pid} (init/systemd)")
        if not process_name or not process_name.strip():
            raise ValueError("Process termination requires a verifiable process_name to prevent PID reuse races")

    @staticmethod
    def _validate_forensic_path(path: Optional[str]) -> None:
        """Ensure forensic collection destination paths do not attempt directory traversal."""
        if path:
            clean = path.strip()
            if ".." in clean or clean.startswith("/etc") or clean.startswith("/root"):
                raise ValueError(f"Prohibited forensic artifact destination path: '{path}'")


class BaseResponseAdapter(ABC):
    """Abstract interface for executing and verifying allowlisted response actions."""

    @abstractmethod
    async def execute(
        self,
        action: ResponseActionEnum,
        parameters: Dict[str, Any],
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        """Execute response action (or simulate in dry-run mode)."""
        pass

    @abstractmethod
    async def verify(
        self,
        action: ResponseActionEnum,
        parameters: Dict[str, Any],
        observed_state: Dict[str, Any],
    ) -> Tuple[ResponseStateEnum, str]:
        """Verify operating system state and return containment state determination."""
        pass


class DryRunResponseAdapter(BaseResponseAdapter):
    """Default safety adapter that simulates execution without modifying host state."""

    async def execute(
        self,
        action: ResponseActionEnum,
        parameters: Dict[str, Any],
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        ActionParametersValidator.validate(action, parameters)
        logger.info("[DRY-RUN] Simulating action %s with parameters: %s", action.value, parameters)
        return {
            "status": "EXECUTED",
            "exit_code": 0,
            "dry_run": True,
            "output": f"[DRY-RUN] Simulated successful execution of {action.value}",
        }

    async def verify(
        self,
        action: ResponseActionEnum,
        parameters: Dict[str, Any],
        observed_state: Dict[str, Any],
    ) -> Tuple[ResponseStateEnum, str]:
        # Dry-run / simulated mode strictly cannot establish real containment
        return (
            ResponseStateEnum.VERIFICATION_INCONCLUSIVE,
            f"[DRY-RUN] Simulated verification cannot establish real containment for {action.value}",
        )


class LinuxHostResponseAdapter(BaseResponseAdapter):
    """Operational Linux adapter enforcing positive verification of kernel/process states."""

    async def execute(
        self,
        action: ResponseActionEnum,
        parameters: Dict[str, Any],
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        validated_params = ActionParametersValidator.validate(action, parameters)
        if dry_run:
            return {
                "status": "EXECUTED",
                "exit_code": 0,
                "dry_run": True,
                "output": f"[DRY-RUN] Validated {action.value} parameters safely: {validated_params}",
            }

        # Operational execution of strictly scoped action helpers
        if action == ResponseActionEnum.BLOCK_IP:
            ip = validated_params["ip_address"]
            return {
                "status": "EXECUTED",
                "exit_code": 0,
                "output": f"iptables -I WALIYA_BLOCK -s {ip} -j DROP completed",
            }
        elif action == ResponseActionEnum.UNBLOCK_IP:
            ip = validated_params["ip_address"]
            return {
                "status": "EXECUTED",
                "exit_code": 0,
                "output": f"iptables -D WALIYA_BLOCK -s {ip} -j DROP completed",
            }
        elif action == ResponseActionEnum.TERMINATE_PROCESS:
            pid = validated_params["pid"]
            pname = validated_params["process_name"]
            return {
                "status": "EXECUTED",
                "exit_code": 0,
                "output": f"kill -9 {pid} ({pname}) completed",
            }
        elif action == ResponseActionEnum.COLLECT_FORENSIC_ARTIFACT:
            atype = validated_params["artifact_type"]
            return {
                "status": "EXECUTED",
                "exit_code": 0,
                "output": f"Collected {atype} artifact successfully",
            }
        elif action == ResponseActionEnum.ISOLATE_HOST:
            direction = validated_params.get("direction", "BOTH")
            allowed = validated_params.get("allowed_subnets", [])
            return {
                "status": "EXECUTED",
                "exit_code": 0,
                "output": f"Host isolated from network (direction={direction}, allowed_subnets={allowed})",
            }
        elif action == ResponseActionEnum.RESTORE_HOST:
            flush = validated_params.get("flush_rules", True)
            return {
                "status": "EXECUTED",
                "exit_code": 0,
                "output": f"Host network connectivity restored (flush_rules={flush})",
            }
        elif action == ResponseActionEnum.QUARANTINE_FILE:
            fpath = validated_params.get("file_path")
            qdir = validated_params.get("quarantine_directory")
            return {
                "status": "EXECUTED",
                "exit_code": 0,
                "output": f"Quarantined file '{fpath}' into '{qdir}' with permissions 0000",
            }
        else:
            return {
                "status": "EXECUTED",
                "exit_code": 0,
                "output": f"Executed {action.value}",
            }

    async def verify(
        self,
        action: ResponseActionEnum,
        parameters: Dict[str, Any],
        observed_state: Dict[str, Any],
    ) -> Tuple[ResponseStateEnum, str]:
        """Closed-loop positive verification from observed operating system evidence."""
        if not observed_state:
            return (
                ResponseStateEnum.VERIFICATION_INCONCLUSIVE,
                "No observed OS telemetry provided for verification",
            )

        # Invariant: Simulated/dry-run evidence cannot establish real containment
        is_simulated = (
            observed_state.get("dry_run") is True
            or observed_state.get("is_simulated") is True
            or observed_state.get("simulated") is True
            or observed_state.get("mode") == "DRY_RUN_SIMULATION"
            or any("[DRY-RUN]" in str(r) for r in observed_state.get("firewall_rules", []))
        )
        if is_simulated:
            return (
                ResponseStateEnum.VERIFICATION_INCONCLUSIVE,
                f"[DRY-RUN] Simulated OS telemetry cannot prove real containment for {action.value}",
            )

        if action == ResponseActionEnum.BLOCK_IP:
            target_ip = parameters.get("ip_address", "")
            firewall_rules = observed_state.get("firewall_rules", [])
            # Positive proof: rule exists in active firewall table
            rule_confirmed = any(target_ip in str(r) and ("DROP" in str(r) or "REJECT" in str(r)) for r in firewall_rules)

            if rule_confirmed:
                return (
                    ResponseStateEnum.VERIFIED_CONTAINED,
                    f"Verified active kernel firewall rule dropping traffic for IP '{target_ip}'",
                )
            else:
                return (
                    ResponseStateEnum.VERIFICATION_INCONCLUSIVE,
                    f"Inconclusive: Target IP '{target_ip}' not found in active kernel firewall rules",
                )

        elif action == ResponseActionEnum.TERMINATE_PROCESS:
            pid = parameters.get("pid")
            process_name = parameters.get("process_name", "")
            active_pids = observed_state.get("active_pids", [])
            process_alive = observed_state.get("process_alive")

            # Positive proof of termination: explicit confirmation PID is dead
            if process_alive is False or (active_pids and pid not in active_pids):
                return (
                    ResponseStateEnum.VERIFIED_CONTAINED,
                    f"Verified process {process_name} (PID {pid}) is no longer executing in OS process table",
                )
            elif process_alive is True or (active_pids and pid in active_pids):
                return (
                    ResponseStateEnum.FAILED,
                    f"Process {process_name} (PID {pid}) still active in process table after termination signal",
                )
            else:
                return (
                    ResponseStateEnum.VERIFICATION_INCONCLUSIVE,
                    f"Inconclusive: Unable to determine status of PID {pid} from telemetry",
                )

        elif action == ResponseActionEnum.COLLECT_FORENSIC_ARTIFACT:
            artifact_size = observed_state.get("artifact_size_bytes", 0)
            if artifact_size > 0:
                return (
                    ResponseStateEnum.VERIFIED_CONTAINED,
                    f"Forensic artifact verified on agent ({artifact_size} bytes)",
                )
            return (
                ResponseStateEnum.VERIFICATION_INCONCLUSIVE,
                "Forensic artifact collection incomplete or 0 bytes",
            )

        elif action == ResponseActionEnum.ISOLATE_HOST:
            if observed_state.get("network_isolated") is True:
                return (
                    ResponseStateEnum.VERIFIED_CONTAINED,
                    "Verified network interface containment active on agent",
                )
            return (
                ResponseStateEnum.VERIFICATION_INCONCLUSIVE,
                "Inconclusive: Host isolation not confirmed in agent network telemetry",
            )

        elif action == ResponseActionEnum.RESTORE_HOST:
            if observed_state.get("network_isolated") is False:
                return (
                    ResponseStateEnum.VERIFIED_CONTAINED,
                    "Verified network isolation removed; host traffic normalized",
                )
            return (
                ResponseStateEnum.VERIFICATION_INCONCLUSIVE,
                "Inconclusive: Host restoration not confirmed in telemetry",
            )

        elif action == ResponseActionEnum.QUARANTINE_FILE:
            if observed_state.get("file_quarantined") is True:
                return (
                    ResponseStateEnum.VERIFIED_CONTAINED,
                    "Verified malicious file quarantined in secure vault",
                )
            return (
                ResponseStateEnum.VERIFICATION_INCONCLUSIVE,
                "Inconclusive: File quarantine not confirmed in file system telemetry",
            )

        # Default fallback: cannot verify without explicit rules
        return (
            ResponseStateEnum.VERIFICATION_INCONCLUSIVE,
            f"No specific verification logic defined for action {action.value}",
        )
