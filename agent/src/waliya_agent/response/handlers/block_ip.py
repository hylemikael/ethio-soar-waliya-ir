"""IP address blocking and unblocking response action handlers."""

import asyncio
import ipaddress
import logging
from typing import Any, Dict, List

from waliya_agent.response.handlers.base import BaseActionHandler, ExecutionResult

logger = logging.getLogger("waliya_agent.response.block_ip")


class BlockIpHandler(BaseActionHandler):
    """Executes and verifies host firewall IP containment rules with bidirectional support."""

    def __init__(self):
        super().__init__("BLOCK_IP")

    @staticmethod
    def _get_firewall_tool(ip_str: str) -> str:
        """Determine whether iptables (IPv4) or ip6tables (IPv6) should be used."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return "ip6tables" if ip_obj.version == 6 else "iptables"
        except ValueError:
            return "iptables"

    async def _query_active_firewall_rules(self, tool: str = "iptables") -> List[str]:
        """Query kernel firewall rules safely without shell interpretation."""
        rules: List[str] = []
        for chain in ("WALIYA_BLOCK_IN", "WALIYA_BLOCK_OUT", "WALIYA_BLOCK"):
            try:
                proc = await asyncio.create_subprocess_exec(
                    tool, "-S", chain,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                if proc.returncode == 0:
                    lines = [line.strip() for line in stdout.decode("utf-8", errors="replace").splitlines() if line.strip()]
                    rules.extend(lines)
            except FileNotFoundError:
                logger.debug("%s binary not found on host system", tool)
            except PermissionError:
                logger.warning("Permission denied running %s -S", tool)
            except Exception as exc:
                logger.debug("Error querying %s rules for %s: %s", tool, chain, exc)
        return rules

    async def execute(self, parameters: Dict[str, Any], dry_run: bool) -> ExecutionResult:
        ip = parameters["ip_address"]
        direction = str(parameters.get("direction", "BOTH")).upper()
        tool = self._get_firewall_tool(ip)

        if dry_run:
            logger.info("[DRY-RUN] Simulating firewall block for %s (direction: %s)", ip, direction)
            simulated_rules = []
            if direction in ("IN", "BOTH"):
                simulated_rules.append(f"-A WALIYA_BLOCK_IN -s {ip}/32 -j DROP")
            if direction in ("OUT", "BOTH"):
                simulated_rules.append(f"-A WALIYA_BLOCK_OUT -d {ip}/32 -j DROP")

            return ExecutionResult(
                status="EXECUTED",
                exit_code=0,
                dry_run=True,
                output=f"[DRY-RUN] Simulated firewall block for IP {ip} (direction: {direction})",
                observed_state={
                    "firewall_rules": simulated_rules,
                    "dry_run": True,
                    "is_simulated": True,
                },
            )

        # Operational execution (requires root / CAP_NET_ADMIN)
        logger.info("Executing real firewall block for IP %s using %s (direction: %s)", ip, tool, direction)
        try:
            # 1. Setup inbound blocking if direction is IN or BOTH
            if direction in ("IN", "BOTH"):
                # Ensure chain exists
                p = await asyncio.create_subprocess_exec(tool, "-N", "WALIYA_BLOCK_IN", stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
                await p.communicate()
                # Ensure hooked to INPUT
                p = await asyncio.create_subprocess_exec(tool, "-C", "INPUT", "-j", "WALIYA_BLOCK_IN", stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
                await p.communicate()
                if p.returncode != 0:
                    hook_p = await asyncio.create_subprocess_exec(tool, "-I", "INPUT", "1", "-j", "WALIYA_BLOCK_IN", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                    await hook_p.communicate()
                # Check rule exists
                p = await asyncio.create_subprocess_exec(tool, "-C", "WALIYA_BLOCK_IN", "-s", ip, "-j", "DROP", stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
                await p.communicate()
                if p.returncode != 0:
                    ins_p = await asyncio.create_subprocess_exec(tool, "-I", "WALIYA_BLOCK_IN", "1", "-s", ip, "-j", "DROP", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                    _, stderr = await ins_p.communicate()
                    if ins_p.returncode != 0:
                        err_msg = stderr.decode("utf-8", errors="replace").strip()
                        return ExecutionResult(
                            status="FAILED",
                            exit_code=ins_p.returncode,
                            output=f"{tool} rule insertion (inbound) failed: {err_msg}",
                            observed_state={"firewall_rules": [], "dry_run": False},
                        )

            # 2. Setup outbound blocking if direction is OUT or BOTH
            if direction in ("OUT", "BOTH"):
                p = await asyncio.create_subprocess_exec(tool, "-N", "WALIYA_BLOCK_OUT", stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
                await p.communicate()
                p = await asyncio.create_subprocess_exec(tool, "-C", "OUTPUT", "-j", "WALIYA_BLOCK_OUT", stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
                await p.communicate()
                if p.returncode != 0:
                    hook_p = await asyncio.create_subprocess_exec(tool, "-I", "OUTPUT", "1", "-j", "WALIYA_BLOCK_OUT", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                    await hook_p.communicate()
                p = await asyncio.create_subprocess_exec(tool, "-C", "WALIYA_BLOCK_OUT", "-d", ip, "-j", "DROP", stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
                await p.communicate()
                if p.returncode != 0:
                    ins_p = await asyncio.create_subprocess_exec(tool, "-I", "WALIYA_BLOCK_OUT", "1", "-d", ip, "-j", "DROP", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                    _, stderr = await ins_p.communicate()
                    if ins_p.returncode != 0:
                        err_msg = stderr.decode("utf-8", errors="replace").strip()
                        return ExecutionResult(
                            status="FAILED",
                            exit_code=ins_p.returncode,
                            output=f"{tool} rule insertion (outbound) failed: {err_msg}",
                            observed_state={"firewall_rules": [], "dry_run": False},
                        )

            # Query post-action state for independent verification
            active_rules = await self._query_active_firewall_rules(tool)
            return ExecutionResult(
                status="EXECUTED",
                exit_code=0,
                dry_run=False,
                output=f"Successfully added {tool} DROP rule for {ip} (direction: {direction}) in Waliya chains",
                observed_state={"firewall_rules": active_rules, "dry_run": False, "is_simulated": False},
            )

        except FileNotFoundError:
            return ExecutionResult(
                status="FAILED",
                exit_code=1,
                dry_run=False,
                output=f"Firewall utility '{tool}' not found on endpoint",
                observed_state={"firewall_rules": [], "dry_run": False},
            )
        except PermissionError:
            return ExecutionResult(
                status="FAILED",
                exit_code=1,
                dry_run=False,
                output=f"Permission denied modifying firewall rules with '{tool}' (requires CAP_NET_ADMIN)",
                observed_state={"firewall_rules": [], "dry_run": False},
            )
        except Exception as exc:
            logger.error("Exception executing BLOCK_IP for %s: %s", ip, exc)
            return ExecutionResult(
                status="FAILED",
                exit_code=1,
                dry_run=False,
                output=f"Exception during firewall rule modification: {exc}",
                observed_state={"firewall_rules": [], "dry_run": False},
            )

    async def verify_state(self, parameters: Dict[str, Any], dry_run: bool) -> Dict[str, Any]:
        ip = parameters["ip_address"]
        direction = str(parameters.get("direction", "BOTH")).upper()
        tool = self._get_firewall_tool(ip)

        if dry_run:
            simulated = [f"-A WALIYA_BLOCK_IN -s {ip}/32 -j DROP"]
            return {"firewall_rules": simulated, "dry_run": True, "is_simulated": True}

        rules = await self._query_active_firewall_rules(tool)
        return {"firewall_rules": rules, "dry_run": False, "is_simulated": False}


class UnblockIpHandler(BaseActionHandler):
    """Removes defensive IP blocking rules from WALIYA_BLOCK chains."""

    def __init__(self):
        super().__init__("UNBLOCK_IP")

    async def execute(self, parameters: Dict[str, Any], dry_run: bool) -> ExecutionResult:
        ip = parameters["ip_address"]
        tool = BlockIpHandler._get_firewall_tool(ip)

        if dry_run:
            logger.info("[DRY-RUN] Simulating firewall unblock for %s", ip)
            return ExecutionResult(
                status="EXECUTED",
                exit_code=0,
                dry_run=True,
                output=f"[DRY-RUN] Simulated firewall unblock for IP {ip}",
                observed_state={"firewall_rules": [], "dry_run": True, "is_simulated": True},
            )

        logger.info("Executing real firewall unblock for IP %s using %s", ip, tool)
        try:
            # Delete inbound rule if present
            await asyncio.create_subprocess_exec(
                tool, "-D", "WALIYA_BLOCK_IN", "-s", ip, "-j", "DROP",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            # Delete outbound rule if present
            await asyncio.create_subprocess_exec(
                tool, "-D", "WALIYA_BLOCK_OUT", "-d", ip, "-j", "DROP",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            # Delete legacy chain rule if present
            await asyncio.create_subprocess_exec(
                tool, "-D", "WALIYA_BLOCK", "-s", ip, "-j", "DROP",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )

            return ExecutionResult(
                status="EXECUTED",
                exit_code=0,
                dry_run=False,
                output=f"Successfully removed firewall rules for IP {ip}",
                observed_state={"firewall_rules": [], "dry_run": False, "is_simulated": False},
            )
        except Exception as exc:
            return ExecutionResult(
                status="FAILED",
                exit_code=1,
                dry_run=False,
                output=f"Failed to unblock IP {ip}: {exc}",
                observed_state={"firewall_rules": [], "dry_run": False},
            )

    async def verify_state(self, parameters: Dict[str, Any], dry_run: bool) -> Dict[str, Any]:
        ip = parameters["ip_address"]
        tool = BlockIpHandler._get_firewall_tool(ip)
        if dry_run:
            return {"firewall_rules": [], "dry_run": True, "is_simulated": True}
        rules = await BlockIpHandler()._query_active_firewall_rules(tool)
        remaining = [r for r in rules if ip in r]
        return {"firewall_rules": remaining, "dry_run": False, "is_simulated": False}
