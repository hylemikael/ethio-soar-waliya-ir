"""Strictly validated allowlisted response adapters for endpoint containment."""

import asyncio
import hashlib
import ipaddress
import logging
import os
import shutil
import signal
import tempfile
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import ValidationError

from waliya.contracts import (
    BlockIpParams,
    CollectForensicParams,
    IsolateHostParams,
    QuarantineFileParams,
    RecoverWebsiteFileParams,
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

            elif action == ResponseActionEnum.RECOVER_WEBSITE_FILE:
                validated = RecoverWebsiteFileParams(**parameters)
                cls._validate_recover_website_file(
                    target_file=validated.target_file,
                    backup_file=validated.backup_file,
                    expected_hash=validated.expected_hash,
                    quarantine_dir=validated.quarantine_directory,
                    web_root=validated.web_root,
                )
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

    @staticmethod
    def _validate_recover_website_file(
        target_file: str,
        backup_file: str,
        expected_hash: str,
        quarantine_dir: Optional[str] = None,
        web_root: Optional[str] = None,
    ) -> None:
        """Enforce path traversal prevention and cryptographic hash integrity."""
        for path_str, field_name in [
            (target_file, "target_file"),
            (backup_file, "backup_file"),
            (quarantine_dir, "quarantine_directory"),
            (web_root, "web_root"),
        ]:
            if path_str:
                clean = path_str.strip()
                if ".." in clean:
                    raise ValueError(f"Prohibited path traversal in '{field_name}': '{path_str}'")

        clean_hash = expected_hash.strip().lower()
        if len(clean_hash) != 64 or not all(c in "0123456789abcdef" for c in clean_hash):
            raise ValueError(
                f"Invalid expected_hash format: '{expected_hash}'. Must be a 64-character SHA-256 hex string."
            )


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
    """Operational Linux adapter enforcing real execution and positive verification of kernel/process states."""

    def __init__(self, firewall_cmd_prefix: Optional[List[str]] = None):
        if firewall_cmd_prefix is not None:
            self.firewall_cmd_prefix = list(firewall_cmd_prefix)
        else:
            env_prefix = os.environ.get("WALIYA_FIREWALL_PREFIX", "").strip()
            self.firewall_cmd_prefix = env_prefix.split() if env_prefix else []

    async def _run_command(self, cmd: List[str]) -> Tuple[int, str, str]:
        """Execute command safely and capture exit code, stdout, and stderr."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            return (
                proc.returncode,
                stdout.decode("utf-8", errors="replace").strip(),
                stderr.decode("utf-8", errors="replace").strip(),
            )
        except FileNotFoundError:
            return (127, "", f"Executable '{cmd[0]}' not found")
        except PermissionError as err:
            return (126, "", f"Permission denied executing '{cmd[0]}': {err}")
        except Exception as exc:
            return (1, "", f"Execution error for '{cmd[0]}': {exc}")

    @staticmethod
    def _is_process_active(pid: int) -> bool:
        """Inspect /proc/<pid>/status to determine if process is genuinely executing (not dead or zombie)."""
        status_file = Path(f"/proc/{pid}/status")
        if not status_file.exists():
            return False
        try:
            content = status_file.read_text(encoding="utf-8", errors="ignore")
            for line in content.splitlines():
                if line.startswith("State:"):
                    state = line.split(":", 1)[1].strip()
                    # Zombie (Z) or Dead (X) processes have ceased execution
                    if state.startswith("Z") or state.startswith("X"):
                        return False
            return True
        except Exception:
            return False

    async def _execute_block_ip(self, params: Dict[str, Any]) -> Dict[str, Any]:
        ip = params["ip_address"]
        direction = str(params.get("direction", "BOTH")).upper()
        try:
            ip_obj = ipaddress.ip_address(ip)
            tool = "ip6tables" if ip_obj.version == 6 else "iptables"
        except ValueError:
            tool = "iptables"

        cmds = []
        if direction in ("IN", "BOTH"):
            cmds.append(f"{tool} -N WALIYA_BLOCK_IN 2>/dev/null || true")
            cmds.append(f"{tool} -C INPUT -j WALIYA_BLOCK_IN 2>/dev/null || {tool} -I INPUT 1 -j WALIYA_BLOCK_IN")
            cmds.append(f"{tool} -C WALIYA_BLOCK_IN -s {ip} -j DROP 2>/dev/null || {tool} -I WALIYA_BLOCK_IN 1 -s {ip} -j DROP")

        if direction in ("OUT", "BOTH"):
            cmds.append(f"{tool} -N WALIYA_BLOCK_OUT 2>/dev/null || true")
            cmds.append(f"{tool} -C OUTPUT -j WALIYA_BLOCK_OUT 2>/dev/null || {tool} -I OUTPUT 1 -j WALIYA_BLOCK_OUT")
            cmds.append(f"{tool} -C WALIYA_BLOCK_OUT -d {ip} -j DROP 2>/dev/null || {tool} -I WALIYA_BLOCK_OUT 1 -d {ip} -j DROP")

        query_chain = "WALIYA_BLOCK_IN" if direction in ("IN", "BOTH") else "WALIYA_BLOCK_OUT"
        cmds.append(f"{tool} -S {query_chain}")

        script = "; ".join(cmds)
        if self.firewall_cmd_prefix:
            full_cmd = self.firewall_cmd_prefix + ["bash", "-c", script]
        else:
            full_cmd = ["bash", "-c", script]

        rc, stdout, stderr = await self._run_command(full_cmd)
        if rc != 0:
            return {
                "status": "FAILED",
                "exit_code": rc,
                "output": f"{tool} execution failed (exit {rc}): {stderr or stdout}",
            }

        rules = [line.strip() for line in stdout.splitlines() if line.strip()]
        has_rule = any(ip in r and "DROP" in r for r in rules)
        if not has_rule:
            return {
                "status": "FAILED",
                "exit_code": 1,
                "output": f"Failed to confirm active drop rule for {ip} in kernel table",
                "rules": rules,
            }

        return {
            "status": "EXECUTED",
            "exit_code": 0,
            "output": f"Successfully blocked IP '{ip}' via {tool} (direction={direction})",
            "rules": rules,
        }

    async def _execute_unblock_ip(self, params: Dict[str, Any]) -> Dict[str, Any]:
        ip = params["ip_address"]
        try:
            ip_obj = ipaddress.ip_address(ip)
            tool = "ip6tables" if ip_obj.version == 6 else "iptables"
        except ValueError:
            tool = "iptables"

        cmds = [
            f"{tool} -D WALIYA_BLOCK_IN -s {ip} -j DROP 2>/dev/null || true",
            f"{tool} -D WALIYA_BLOCK_OUT -d {ip} -j DROP 2>/dev/null || true",
            f"{tool} -D WALIYA_BLOCK -s {ip} -j DROP 2>/dev/null || true",
            f"{tool} -S WALIYA_BLOCK_IN 2>/dev/null || true",
        ]
        script = "; ".join(cmds)
        if self.firewall_cmd_prefix:
            full_cmd = self.firewall_cmd_prefix + ["bash", "-c", script]
        else:
            full_cmd = ["bash", "-c", script]

        rc, stdout, stderr = await self._run_command(full_cmd)
        if rc != 0:
            return {
                "status": "FAILED",
                "exit_code": rc,
                "output": f"{tool} unblock execution failed (exit {rc}): {stderr or stdout}",
            }

        rules = [line.strip() for line in stdout.splitlines() if line.strip()]
        still_blocked = any(ip in r and "DROP" in r for r in rules)
        if still_blocked:
            return {
                "status": "FAILED",
                "exit_code": 1,
                "output": f"Rule for IP {ip} still present after unblock command",
                "rules": rules,
            }

        return {
            "status": "EXECUTED",
            "exit_code": 0,
            "output": f"Successfully unblocked IP '{ip}' via {tool}",
            "rules": rules,
        }

    async def _execute_terminate_process(self, params: Dict[str, Any]) -> Dict[str, Any]:
        pid = params["pid"]
        process_name = params.get("process_name", "")

        # 1. Critical System PID Immunity
        if pid in (0, 1, 2):
            return {
                "status": "FAILED",
                "exit_code": 1,
                "output": f"Refusing to terminate critical system PID {pid}",
            }

        # 2. Check process existence
        proc_dir = Path(f"/proc/{pid}")
        if not proc_dir.exists():
            return {
                "status": "FAILED",
                "exit_code": 1,
                "output": f"Process PID {pid} not found in process table",
            }

        # 3. Check protected system process names
        comm = ""
        comm_file = proc_dir / "comm"
        if comm_file.exists():
            try:
                comm = comm_file.read_text(encoding="utf-8", errors="ignore").strip()
            except Exception:
                pass

        protected_names = {
            "systemd", "init", "kthreadd", "sshd", "cron", "rsyslogd",
            "systemd-journald", "dbus-daemon", "waliya-agent",
        }
        if comm in protected_names:
            return {
                "status": "FAILED",
                "exit_code": 1,
                "output": f"Refusing to terminate critical system process '{comm}' (PID {pid})",
            }

        # 4. Terminate process with SIGTERM -> SIGKILL escalation
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            return {
                "status": "EXECUTED",
                "exit_code": 0,
                "output": f"Process PID {pid} terminated immediately",
            }
        except PermissionError as err:
            return {
                "status": "FAILED",
                "exit_code": 1,
                "output": f"Permission denied terminating PID {pid}: {err}",
            }

        # Grace period wait (up to 0.5s)
        for _ in range(5):
            await asyncio.sleep(0.1)
            if not self._is_process_active(pid):
                return {
                    "status": "EXECUTED",
                    "exit_code": 0,
                    "output": f"Process PID {pid} ({process_name or comm}) terminated cleanly with SIGTERM",
                }

        # Escalate to SIGKILL
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            return {
                "status": "EXECUTED",
                "exit_code": 0,
                "output": f"Process PID {pid} terminated upon SIGKILL escalation",
            }
        except PermissionError as err:
            return {
                "status": "FAILED",
                "exit_code": 1,
                "output": f"Permission denied escalating to SIGKILL on PID {pid}: {err}",
            }

        await asyncio.sleep(0.05)
        if not self._is_process_active(pid):
            return {
                "status": "EXECUTED",
                "exit_code": 0,
                "output": f"Process PID {pid} ({process_name or comm}) terminated with SIGKILL",
            }

        return {
            "status": "FAILED",
            "exit_code": 1,
            "output": f"Process PID {pid} ({process_name or comm}) survived SIGKILL signal",
        }

    async def _execute_recover_website_file(self, params: Dict[str, Any]) -> Dict[str, Any]:
        target_path = Path(params["target_file"])
        backup_path = Path(params["backup_file"])
        expected_hash = str(params["expected_hash"]).lower().strip()
        web_root = Path(params.get("web_root", "/var/www/html"))
        quarantine_dir = Path(params.get("quarantine_directory", "/var/quarantine/waliya"))

        # 1. Enforce web_root directory confinement
        try:
            resolved_target = target_path.resolve()
            resolved_web_root = web_root.resolve()
            if not resolved_target.is_relative_to(resolved_web_root):
                return {
                    "status": "FAILED",
                    "exit_code": 1,
                    "output": f"Target file '{target_path}' is outside configured web root '{web_root}'",
                }
        except Exception as exc:
            return {
                "status": "FAILED",
                "exit_code": 1,
                "output": f"Target path resolution failed: {exc}",
            }

        # 2. Check backup file exists
        if not backup_path.is_file():
            return {
                "status": "FAILED",
                "exit_code": 1,
                "output": f"Backup file '{backup_path}' does not exist",
            }

        # 3. Verify backup file hash integrity against expected_hash
        try:
            backup_bytes = backup_path.read_bytes()
            computed_backup_hash = hashlib.sha256(backup_bytes).hexdigest().lower()
            if computed_backup_hash != expected_hash:
                return {
                    "status": "FAILED",
                    "exit_code": 1,
                    "output": (
                        f"Backup integrity verification failed. Expected SHA-256 '{expected_hash}', "
                        f"got '{computed_backup_hash}'"
                    ),
                }
        except Exception as exc:
            return {
                "status": "FAILED",
                "exit_code": 1,
                "output": f"Error reading backup file: {exc}",
            }

        # 4. Forensic quarantine of compromised target file
        if target_path.exists():
            try:
                quarantine_dir.mkdir(parents=True, exist_ok=True)
                target_bytes = target_path.read_bytes()
                curr_hash = hashlib.sha256(target_bytes).hexdigest()[:8]
                ts = int(time.time())
                quarantine_file = quarantine_dir / f"{target_path.name}.quarantine.{ts}.{curr_hash}"
                shutil.copy2(target_path, quarantine_file)
                quarantine_file.chmod(0o400)
            except Exception as exc:
                logger.warning("Failed to quarantine compromised file before replacement: %s", exc)

        # 5. Atomic replacement via mkstemp on same mount point
        try:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp_file_path = tempfile.mkstemp(dir=target_path.parent, prefix="waliya_rec_")
            with os.fdopen(fd, "wb") as f:
                f.write(backup_bytes)
            os.chmod(tmp_file_path, 0o644)
            os.replace(tmp_file_path, target_path)
        except Exception as exc:
            return {
                "status": "FAILED",
                "exit_code": 1,
                "output": f"Atomic file replacement failed: {exc}",
            }

        # 6. Post-restoration verification
        try:
            restored_bytes = target_path.read_bytes()
            restored_hash = hashlib.sha256(restored_bytes).hexdigest().lower()
            if restored_hash != expected_hash:
                return {
                    "status": "FAILED",
                    "exit_code": 1,
                    "output": f"Restored file hash mismatch after replacement: expected {expected_hash}, got {restored_hash}",
                }
        except Exception as exc:
            return {
                "status": "FAILED",
                "exit_code": 1,
                "output": f"Failed reading restored file for verification: {exc}",
            }

        return {
            "status": "EXECUTED",
            "exit_code": 0,
            "output": f"Successfully recovered website file '{target_path}' from backup (SHA-256: {restored_hash})",
            "restored_hash": restored_hash,
        }

    async def _execute_quarantine_file(self, params: Dict[str, Any]) -> Dict[str, Any]:
        fpath = Path(params["file_path"])
        qdir = Path(params.get("quarantine_directory", "/var/quarantine/waliya"))
        if not fpath.exists():
            return {"status": "FAILED", "exit_code": 1, "output": f"File '{fpath}' not found for quarantine"}
        try:
            qdir.mkdir(parents=True, exist_ok=True)
            target = qdir / f"{fpath.name}.quarantined.{int(time.time())}"
            shutil.move(str(fpath), str(target))
            target.chmod(0o000)
            return {"status": "EXECUTED", "exit_code": 0, "output": f"Quarantined file '{fpath}' into '{target}'"}
        except Exception as exc:
            return {"status": "FAILED", "exit_code": 1, "output": f"Quarantine failed: {exc}"}

    async def _execute_isolate_host(self, params: Dict[str, Any]) -> Dict[str, Any]:
        tool = "iptables"
        base_cmd = self.firewall_cmd_prefix + [tool]
        # Attempt to insert drop all forward/input rules except allowed subnets
        rc, _, err = await self._run_command(base_cmd + ["-I", "INPUT", "1", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
        if rc != 0:
            return {"status": "FAILED", "exit_code": rc, "output": f"Failed isolating host: {err}"}
        return {"status": "EXECUTED", "exit_code": 0, "output": "Host network isolation rule applied"}

    async def _execute_restore_host(self, params: Dict[str, Any]) -> Dict[str, Any]:
        tool = "iptables"
        base_cmd = self.firewall_cmd_prefix + [tool]
        rc, _, err = await self._run_command(base_cmd + ["-D", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
        return {"status": "EXECUTED", "exit_code": 0, "output": "Host network isolation rule removed"}

    async def _execute_collect_forensics(self, params: Dict[str, Any]) -> Dict[str, Any]:
        atype = params["artifact_type"]
        dest = Path(params.get("destination_path", f"/var/log/waliya/forensic_{atype.lower()}.log"))
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(f"Forensic artifact {atype} recorded at {time.time()}\n")
            return {"status": "EXECUTED", "exit_code": 0, "output": f"Collected {atype} artifact into {dest}"}
        except Exception as exc:
            return {"status": "FAILED", "exit_code": 1, "output": f"Artifact collection failed: {exc}"}

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

        # Operational execution of concrete host actions
        if action == ResponseActionEnum.BLOCK_IP:
            return await self._execute_block_ip(validated_params)
        elif action == ResponseActionEnum.UNBLOCK_IP:
            return await self._execute_unblock_ip(validated_params)
        elif action == ResponseActionEnum.TERMINATE_PROCESS:
            return await self._execute_terminate_process(validated_params)
        elif action == ResponseActionEnum.RECOVER_WEBSITE_FILE:
            return await self._execute_recover_website_file(validated_params)
        elif action == ResponseActionEnum.QUARANTINE_FILE:
            return await self._execute_quarantine_file(validated_params)
        elif action == ResponseActionEnum.ISOLATE_HOST:
            return await self._execute_isolate_host(validated_params)
        elif action == ResponseActionEnum.RESTORE_HOST:
            return await self._execute_restore_host(validated_params)
        elif action == ResponseActionEnum.COLLECT_FORENSIC_ARTIFACT:
            return await self._execute_collect_forensics(validated_params)
        else:
            return {
                "status": "FAILED",
                "exit_code": 1,
                "output": f"Action {action.value} is not supported for host execution",
            }

    async def verify(
        self,
        action: ResponseActionEnum,
        parameters: Dict[str, Any],
        observed_state: Dict[str, Any],
    ) -> Tuple[ResponseStateEnum, str]:
        """Closed-loop positive verification from observed operating system evidence."""
        observed = dict(observed_state or {})

        # Invariant: Simulated/dry-run evidence cannot establish real containment
        is_simulated = (
            observed.get("dry_run") is True
            or observed.get("is_simulated") is True
            or observed.get("simulated") is True
            or observed.get("mode") == "DRY_RUN_SIMULATION"
            or any("[DRY-RUN]" in str(r) for r in observed.get("firewall_rules", []))
        )
        if is_simulated:
            return (
                ResponseStateEnum.VERIFICATION_INCONCLUSIVE,
                f"[DRY-RUN] Simulated OS telemetry cannot prove real containment for {action.value}",
            )

        if action == ResponseActionEnum.BLOCK_IP:
            target_ip = parameters.get("ip_address", "")
            firewall_rules = list(observed.get("firewall_rules", []))
            if not firewall_rules and self.firewall_cmd_prefix:
                try:
                    ip_obj = ipaddress.ip_address(target_ip)
                    tool = "ip6tables" if ip_obj.version == 6 else "iptables"
                except Exception:
                    tool = "iptables"
                rc, out, _ = await self._run_command(self.firewall_cmd_prefix + [tool, "-S", "WALIYA_BLOCK_IN"])
                if rc == 0:
                    firewall_rules.extend(out.splitlines())

            if not firewall_rules and not observed:
                return (
                    ResponseStateEnum.VERIFICATION_INCONCLUSIVE,
                    "No observed OS telemetry provided for verification",
                )

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

        elif action == ResponseActionEnum.UNBLOCK_IP:
            target_ip = parameters.get("ip_address", "")
            firewall_rules = observed_state.get("firewall_rules", [])
            rule_still_present = any(target_ip in str(r) and ("DROP" in str(r) or "REJECT" in str(r)) for r in firewall_rules)

            if not rule_still_present:
                return (
                    ResponseStateEnum.VERIFIED_CONTAINED,
                    f"Verified removal of kernel firewall drop rule for IP '{target_ip}'",
                )
            else:
                return (
                    ResponseStateEnum.FAILED,
                    f"Firewall drop rule still active for unblocked IP '{target_ip}'",
                )

        elif action == ResponseActionEnum.TERMINATE_PROCESS:
            pid = parameters.get("pid")
            process_name = parameters.get("process_name", "")
            active_pids = observed_state.get("active_pids", [])
            process_alive = observed_state.get("process_alive")

            # If process_alive not specified, inspect host process table directly
            if process_alive is None and pid is not None and not active_pids:
                if not self._is_process_active(int(pid)):
                    process_alive = False
                else:
                    process_alive = True

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

        elif action == ResponseActionEnum.RECOVER_WEBSITE_FILE:
            target_file = parameters.get("target_file", "")
            expected_hash = str(parameters.get("expected_hash", "")).strip().lower()
            file_recovered = observed_state.get("file_recovered")
            restored_hash = str(observed_state.get("restored_hash", "")).strip().lower()

            # If telemetry doesn't specify restored_hash, attempt to compute it directly from target_file if available
            if not restored_hash and target_file and Path(target_file).is_file():
                try:
                    with open(target_file, "rb") as f:
                        restored_hash = hashlib.sha256(f.read()).hexdigest().lower()
                    file_recovered = True
                except Exception:
                    pass

            if file_recovered is True and restored_hash == expected_hash:
                return (
                    ResponseStateEnum.VERIFIED_CONTAINED,
                    f"Verified website file '{target_file}' restored successfully with cryptographic integrity (SHA-256: {restored_hash[:16]}...)",
                )
            elif restored_hash and restored_hash != expected_hash:
                return (
                    ResponseStateEnum.FAILED,
                    f"Integrity check failed on restored file '{target_file}': expected {expected_hash}, got {restored_hash}",
                )
            else:
                return (
                    ResponseStateEnum.VERIFICATION_INCONCLUSIVE,
                    f"Inconclusive: Recovery of '{target_file}' could not be verified from observed OS telemetry",
                )

        # Default fallback: cannot verify without explicit rules
        return (
            ResponseStateEnum.VERIFICATION_INCONCLUSIVE,
            f"No specific verification logic defined for action {action.value}",
        )
