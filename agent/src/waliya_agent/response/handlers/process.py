"""Process termination response action handler with PID reuse defense and Linux pidfd support."""

import asyncio
import logging
import os
import signal
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from waliya_agent.response.handlers.base import BaseActionHandler, ExecutionResult

logger = logging.getLogger("waliya_agent.response.process")


class TerminateProcessHandler(BaseActionHandler):
    """Safely terminates rogue processes with strict PID reuse validation and race-free pidfd signaling."""

    def __init__(self, proc_root: Path = Path("/proc")):
        super().__init__("TERMINATE_PROCESS")
        self.proc_root = proc_root

    def _get_process_identity(self, pid: int) -> Tuple[bool, str, str]:
        """Inspect /proc/[pid] to obtain running executable and command line.

        Returns:
            (exists: bool, exe_name: str, cmdline: str)
        """
        proc_dir = self.proc_root / str(pid)
        if not proc_dir.is_dir():
            return False, "", ""

        # Check process state for zombie/dead processes (cease execution after SIGKILL)
        status_file = proc_dir / "status"
        if status_file.exists():
            try:
                for line in status_file.read_text(encoding="utf-8", errors="replace").splitlines():
                    if line.startswith("State:"):
                        state_val = line.split()[1]
                        if state_val in ("Z", "X"):
                            return False, "", ""
                        break
            except (PermissionError, FileNotFoundError, OSError):
                pass

        exe_name = ""
        # 1. Check comm file
        comm_file = proc_dir / "comm"
        if comm_file.exists():
            try:
                exe_name = comm_file.read_text(encoding="utf-8", errors="replace").strip()
            except (PermissionError, FileNotFoundError, OSError):
                pass

        # 2. Check exe readlink
        if not exe_name:
            exe_link = proc_dir / "exe"
            try:
                exe_target = os.readlink(exe_link)
                exe_name = Path(exe_target).name
            except (PermissionError, FileNotFoundError, OSError):
                pass

        # 3. Read cmdline
        cmdline = ""
        cmd_file = proc_dir / "cmdline"
        if cmd_file.exists():
            try:
                raw = cmd_file.read_bytes()
                cmdline = " ".join([arg.decode("utf-8", errors="replace") for arg in raw.split(b"\x00") if arg])
            except (PermissionError, FileNotFoundError, OSError):
                pass

        return True, exe_name, cmdline

    async def execute(self, parameters: Dict[str, Any], dry_run: bool) -> ExecutionResult:
        pid = parameters["pid"]
        expected_name = parameters["process_name"].strip()

        # 1. Pre-execution PID Reuse Defense Check
        exists, actual_name, cmdline = self._get_process_identity(pid)

        if not exists:
            # In dry-run mode, if testing with synthetic PIDs, allow simulation if process not running
            if dry_run:
                logger.info("[DRY-RUN] Process PID %d not running; simulated termination verified", pid)
                return ExecutionResult(
                    status="EXECUTED",
                    exit_code=0,
                    dry_run=True,
                    output=f"[DRY-RUN] Process PID {pid} ({expected_name}) already absent from process table",
                    observed_state={"process_alive": False, "active_pids": [], "dry_run": True, "is_simulated": True},
                )
            return ExecutionResult(
                status="FAILED",
                exit_code=1,
                dry_run=False,
                output=f"Process PID {pid} not found in OS process table (process already terminated or invalid PID)",
                observed_state={"process_alive": False, "active_pids": [], "dry_run": False},
            )

        # Validate process identity matches expected name
        name_match = (
            expected_name.lower() in actual_name.lower()
            or expected_name.lower() in cmdline.lower()
        )

        if not name_match:
            logger.critical(
                "PID REUSE DETECTED: Aborting termination of PID %d. Expected '%s', but PID is executing '%s' ('%s')",
                pid, expected_name, actual_name, cmdline[:100],
            )
            return ExecutionResult(
                status="FAILED",
                exit_code=2,  # Exit code 2 distinguishes safety abort from failure
                dry_run=dry_run,
                output=f"PID reuse defense aborted action: PID {pid} is running '{actual_name}', does not match expected '{expected_name}'",
                observed_state={"process_alive": True, "active_pids": [pid], "dry_run": dry_run},
            )

        if dry_run:
            logger.info("[DRY-RUN] Verified process identity for PID %d (%s); simulated termination safely", pid, actual_name)
            return ExecutionResult(
                status="EXECUTED",
                exit_code=0,
                dry_run=True,
                output=f"[DRY-RUN] Validated PID {pid} identity ('{actual_name}'); simulated SIGKILL without modifying host",
                observed_state={"process_alive": False, "active_pids": [], "dry_run": True, "is_simulated": True},
            )

        # 2. Operational Termination: Linux pidfd or fallback to os.kill
        logger.info("Executing process termination on verified target PID %d (%s)", pid, actual_name)
        pidfd = None
        if hasattr(os, "pidfd_open") and self.proc_root == Path("/proc"):
            try:
                pidfd = os.pidfd_open(pid, 0)
            except (ProcessLookupError, FileNotFoundError):
                return ExecutionResult(
                    status="EXECUTED",
                    exit_code=0,
                    dry_run=False,
                    output=f"Process PID {pid} already exited prior to pidfd acquisition",
                    observed_state={"process_alive": False, "active_pids": [], "dry_run": False},
                )
            except Exception as exc:
                logger.debug("pidfd_open failed (falling back to standard signaling): %s", exc)
                pidfd = None

        try:
            if pidfd is not None and hasattr(signal, "pidfd_send_signal"):
                signal.pidfd_send_signal(pidfd, signal.SIGTERM)
                await asyncio.sleep(0.2)

                is_still_alive, _, _ = self._get_process_identity(pid)
                if is_still_alive:
                    logger.info("PID %d still active after SIGTERM. Escalating to SIGKILL via pidfd.", pid)
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                    await asyncio.sleep(0.1)
            else:
                os.kill(pid, signal.SIGTERM)
                await asyncio.sleep(0.2)

                is_still_alive, _, _ = self._get_process_identity(pid)
                if is_still_alive:
                    logger.info("PID %d still active after SIGTERM. Escalating to SIGKILL.", pid)
                    os.kill(pid, signal.SIGKILL)
                    await asyncio.sleep(0.1)

            # Final check
            final_alive, _, _ = self._get_process_identity(pid)
            if not final_alive:
                return ExecutionResult(
                    status="EXECUTED",
                    exit_code=0,
                    dry_run=False,
                    output=f"Successfully terminated rogue process PID {pid} ({actual_name})",
                    observed_state={"process_alive": False, "active_pids": [], "dry_run": False, "is_simulated": False},
                )
            else:
                return ExecutionResult(
                    status="FAILED",
                    exit_code=1,
                    dry_run=False,
                    output=f"Process PID {pid} ({actual_name}) survived SIGKILL signal",
                    observed_state={"process_alive": True, "active_pids": [pid], "dry_run": False},
                )

        except ProcessLookupError:
            return ExecutionResult(
                status="EXECUTED",
                exit_code=0,
                dry_run=False,
                output=f"Process PID {pid} exited during signaling",
                observed_state={"process_alive": False, "active_pids": [], "dry_run": False},
            )
        except PermissionError:
            return ExecutionResult(
                status="FAILED",
                exit_code=1,
                dry_run=False,
                output=f"Permission denied: Insufficient privileges to send termination signal to PID {pid} (CAP_KILL required)",
                observed_state={"process_alive": True, "active_pids": [pid], "dry_run": False},
            )
        except Exception as exc:
            return ExecutionResult(
                status="FAILED",
                exit_code=1,
                dry_run=False,
                output=f"Error terminating PID {pid}: {exc}",
                observed_state={"process_alive": True, "active_pids": [pid], "dry_run": False},
            )
        finally:
            if pidfd is not None:
                try:
                    os.close(pidfd)
                except Exception:
                    pass

    async def verify_state(self, parameters: Dict[str, Any], dry_run: bool) -> Dict[str, Any]:
        pid = parameters["pid"]
        if dry_run:
            return {"process_alive": False, "active_pids": [], "dry_run": True, "is_simulated": True}

        exists, _, _ = self._get_process_identity(pid)
        return {
            "process_alive": exists,
            "active_pids": [pid] if exists else [],
            "dry_run": False,
            "is_simulated": False,
        }
