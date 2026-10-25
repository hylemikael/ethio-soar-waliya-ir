"""Registry and dispatcher for agent defensive response actions."""

import logging
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from waliya_agent.config import ResponseConfig
from waliya_agent.response.handlers.base import BaseActionHandler, ExecutionResult
from waliya_agent.response.handlers.block_ip import BlockIpHandler, UnblockIpHandler
from waliya_agent.response.handlers.forensic import CollectForensicHandler
from waliya_agent.response.handlers.process import TerminateProcessHandler
from waliya_agent.response.validator import ActionValidator

logger = logging.getLogger("waliya_agent.response.registry")


class ResponseActionRegistry:
    """Manages available defensive response handlers, validates parameters, and dispatches actions."""

    def __init__(self, config: ResponseConfig, server_url: Optional[str] = None):
        self.config = config
        self.server_ip = self._extract_server_ip(server_url)

        self._handlers: Dict[str, BaseActionHandler] = {
            "BLOCK_IP": BlockIpHandler(),
            "UNBLOCK_IP": UnblockIpHandler(),
            "TERMINATE_PROCESS": TerminateProcessHandler(),
            "COLLECT_FORENSIC_ARTIFACT": CollectForensicHandler(
                forensic_dir=config.forensic_artifact_dir,
                max_size_mb=config.max_forensic_size_mb,
            ),
        }

    @staticmethod
    def _extract_server_ip(server_url: Optional[str]) -> Optional[str]:
        if not server_url:
            return None
        try:
            parsed = urlparse(server_url)
            return parsed.hostname
        except Exception:
            return None

    def is_action_allowed(self, action_name: str) -> bool:
        """Check whether action is in the configured allowlist."""
        return action_name.upper() in [a.upper() for a in self.config.allowed_actions]

    def validate_action_parameters(self, action_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Strictly validate parameters according to action schemas and safety boundaries."""
        act = action_name.upper()
        if act == "BLOCK_IP":
            return ActionValidator.validate_block_ip(parameters, server_ip=self.server_ip)
        elif act == "UNBLOCK_IP":
            return ActionValidator.validate_unblock_ip(parameters)
        elif act == "TERMINATE_PROCESS":
            return ActionValidator.validate_terminate_process(parameters)
        elif act == "COLLECT_FORENSIC_ARTIFACT":
            return ActionValidator.validate_collect_forensic(parameters)
        else:
            raise ValueError(f"Unknown or unsupported response action: '{action_name}'")

    async def dispatch(self, action_name: str, parameters: Dict[str, Any]) -> ExecutionResult:
        """Dispatch command to appropriate handler enforcing configuration gates and dry-run safety."""
        act = action_name.upper()

        # 1. Gate: Verify action is allowlisted
        if not self.is_action_allowed(act):
            msg = f"Response action '{act}' is not in allowed_actions list: {self.config.allowed_actions}"
            logger.warning("REJECTED: %s", msg)
            return ExecutionResult(
                status="FAILED",
                exit_code=1,
                dry_run=True,
                output=msg,
                observed_state={},
            )

        # 2. Gate: Look up handler
        handler = self._handlers.get(act)
        if not handler:
            msg = f"No handler registered for action '{act}'"
            logger.error(msg)
            return ExecutionResult(
                status="FAILED",
                exit_code=1,
                dry_run=True,
                output=msg,
                observed_state={},
            )

        # 3. Gate: Parameter Validation
        try:
            validated_params = self.validate_action_parameters(act, parameters)
        except ValueError as exc:
            msg = f"Parameter validation failed for {act}: {exc}"
            logger.warning(msg)
            return ExecutionResult(
                status="FAILED",
                exit_code=1,
                dry_run=True,
                output=msg,
                observed_state={},
            )

        # 4. Gate: Dry-Run Enforcement
        # If enable_response_actions is False (default), force dry_run=True
        is_dry_run = not self.config.enable_response_actions
        if is_dry_run:
            logger.info("Response actions globally disabled (enable_response_actions=false); executing in DRY-RUN mode")

        # 5. Execution
        try:
            result = await handler.execute(validated_params, dry_run=is_dry_run)
            return result
        except Exception as exc:
            logger.critical("Unexpected exception executing response action %s: %s", act, exc, exc_info=True)
            return ExecutionResult(
                status="FAILED",
                exit_code=1,
                dry_run=is_dry_run,
                output=f"Execution error: {exc}",
                observed_state={},
            )

    async def collect_verification_state(self, action_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Collect post-execution OS evidence for containment verification."""
        act = action_name.upper()
        handler = self._handlers.get(act)
        if not handler:
            return {}

        is_dry_run = not self.config.enable_response_actions
        try:
            return await handler.verify_state(parameters, dry_run=is_dry_run)
        except Exception as exc:
            logger.warning("Error collecting verification state for %s: %s", act, exc)
            return {"error": str(exc)}
