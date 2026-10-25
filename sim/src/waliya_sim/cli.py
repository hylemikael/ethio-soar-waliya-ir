"""Command Line Interface (CLI) for Waliya-Sim purple-team simulation."""

import argparse
import asyncio
import json
import os
import sys
from typing import Optional
from uuid import uuid4

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from waliya_sim import __version__
from waliya_sim.config import load_config
from waliya_sim.engine import SimulationEngine
from waliya_sim.models import ScenarioOutcome, SimulationRunRecord
from waliya_sim.scenarios import get_scenario, list_scenarios
from waliya_sim.storage import ReportStorage

console = Console()
err_console = Console(stderr=True)


def cmd_list(args: argparse.Namespace) -> int:
    """List all available purple-team simulation scenarios."""
    scenarios = list_scenarios()

    if getattr(args, "json", False):
        data = [s.get_metadata().model_dump() for s in scenarios]
        print(json.dumps(data, indent=2))
        return 0

    table = Table(
        title="Waliya-Sim: Registered Purple-Team Scenarios",
        box=box.ROUNDED,
        header_style="bold cyan",
    )
    table.add_column("Scenario ID", style="bold green")
    table.add_column("Scenario Name", style="white")
    table.add_column("MITRE ATT&CK", style="yellow")
    table.add_column("Target Detection Rule", style="magenta")
    table.add_column("Event Type", style="cyan")
    table.add_column("Threshold / Trigger", style="dim")

    for s in scenarios:
        meta = s.get_metadata()
        table.add_row(
            meta.scenario_id,
            meta.name,
            meta.mitre_attack_id,
            meta.target_rule_id,
            meta.event_type,
            meta.threshold_description,
        )

    console.print(table)
    console.print("\n[dim]Run 'waliya-sim preview <scenario>' to inspect events side-effect free.[/dim]")
    return 0


def cmd_preview(args: argparse.Namespace) -> int:
    """Preview scenario events side-effect free without submitting to backend."""
    scenario = get_scenario(args.scenario)
    if not scenario:
        err_console.print(f"[bold red]Error:[/bold red] Unknown scenario '{args.scenario}'. Run 'waliya-sim list' for valid options.")
        return 1

    is_negative = getattr(args, "negative", False)
    meta = scenario.get_metadata()
    expected = scenario.expected_outcome(is_negative=is_negative)

    dummy_run_id = f"sim-preview-{uuid4().hex[:8]}"
    dummy_trace_id = f"trace-preview-{uuid4().hex[:8]}"
    dummy_agent_id = uuid4()

    events = scenario.generate_events(
        run_id=dummy_run_id,
        trace_id=dummy_trace_id,
        agent_id=dummy_agent_id,
        is_negative=is_negative,
    )

    if getattr(args, "json", False):
        output = {
            "metadata": meta.model_dump(),
            "is_negative": is_negative,
            "expected_outcome": expected.model_dump(),
            "events": events,
        }
        print(json.dumps(output, indent=2))
        return 0

    mode_label = "[bold red][NEGATIVE BOUNDARY TEST][/bold red]" if is_negative else "[bold green][POSITIVE DETECTION TEST][/bold green]"
    console.print(Panel(
        f"[bold cyan]Scenario:[/bold cyan] {meta.name} ({meta.scenario_id})\n"
        f"[bold cyan]MITRE Technique:[/bold cyan] {meta.mitre_attack_id}\n"
        f"[bold cyan]Target Rule:[/bold cyan] {meta.target_rule_id}\n"
        f"[bold cyan]Mode:[/bold cyan] {mode_label}\n"
        f"[bold cyan]Trigger Expectation:[/bold cyan] {expected.description}\n"
        f"[bold cyan]Events Count:[/bold cyan] {len(events)}",
        title=f"Waliya-Sim Preview: {meta.name}",
        border_style="cyan",
        box=box.ROUNDED,
    ))

    table = Table(title="Generated Synthetic Telemetry Events (Side-Effect Free)", box=box.SIMPLE_HEAVY)
    table.add_column("#", justify="right", style="cyan")
    table.add_column("Event Type", style="green")
    table.add_column("Severity", style="yellow")
    table.add_column("Timestamp", style="dim")
    table.add_column("Key Payload Attributes", style="white")

    for i, ev in enumerate(events, 1):
        payload_summary = {k: v for k, v in ev.get("payload", {}).items() if k not in ("simulation_run_id", "trace_id", "is_simulation")}
        table.add_row(
            str(i),
            ev.get("event_type", ""),
            ev.get("severity", ""),
            ev.get("timestamp", ""),
            json.dumps(payload_summary, indent=None),
        )

    console.print(table)
    console.print("[dim green]✓ Preview completed with zero network calls, zero file changes, and zero execution side effects.[/dim green]\n")
    return 0


async def _run_scenario_async(args: argparse.Namespace) -> int:
    scenario = get_scenario(args.scenario)
    if not scenario:
        err_console.print(f"[bold red]Error:[/bold red] Unknown scenario '{args.scenario}'. Run 'waliya-sim list' for valid options.")
        return 1

    config = load_config(
        backend_url=getattr(args, "url", None),
        agent_id=getattr(args, "agent_id", None),
        agent_token=getattr(args, "agent_token", None),
        admin_key=getattr(args, "admin_key", None),
        timeout_seconds=getattr(args, "timeout", None),
        reports_dir=getattr(args, "reports_dir", None),
    )

    # Require explicit agent credentials to submit telemetry
    if not config.agent_id or not config.agent_token:
        err_console.print(
            "[bold red]Error:[/bold red] Authenticated agent credentials required to submit telemetry.\n"
            "Provide --agent-id and --agent-token, or export WALIYA_AGENT_ID and WALIYA_AGENT_TOKEN."
        )
        return 2

    # Require admin key to verify detections
    if not config.admin_key:
        err_console.print(
            "[bold red]Error:[/bold red] Admin API key required for detection verification and outbox dispatch.\n"
            "Provide --admin-key or export WALIYA_ADMIN_KEY."
        )
        return 2

    is_negative = getattr(args, "negative", False)
    engine = SimulationEngine(config)

    def on_step(step: str) -> None:
        if not getattr(args, "json", False):
            console.print(f"[dim]→ {step}[/dim]")

    if not getattr(args, "json", False):
        console.print(f"[bold cyan]Starting simulation for '{scenario.name}' against {config.backend_url}...[/bold cyan]")

    record: SimulationRunRecord = await engine.execute_scenario(
        scenario=scenario,
        is_negative=is_negative,
        progress_callback=on_step,
    )

    if getattr(args, "json", False):
        print(json.dumps(record.model_dump(mode="json"), indent=2))
    else:
        # Formatted Result Card
        color = "green" if record.status == ScenarioOutcome.PASS else ("red" if record.status == ScenarioOutcome.FAIL else "yellow")
        status_badge = f"[bold {color}][{record.status.value}][/bold {color}]"

        result_table = Table(box=box.ROUNDED, show_header=False)
        result_table.add_column("Key", style="bold cyan")
        result_table.add_column("Value", style="white")

        result_table.add_row("Simulation Run ID", record.run_id)
        result_table.add_row("Trace ID", record.trace_id)
        result_table.add_row("Scenario", f"{record.scenario_name} ({record.scenario_id})")
        result_table.add_row("MITRE ATT&CK", record.mitre_attack_id)
        result_table.add_row("Target Rule", record.target_rule_id)
        result_table.add_row("Test Type", "Negative Boundary Test" if record.is_negative_test else "Positive Detection Test")
        result_table.add_row("Status", status_badge)
        result_table.add_row("Summary", record.summary)
        result_table.add_row("Events Generated / Accepted", f"{record.events_generated_count} / {record.events_accepted_count}")
        result_table.add_row("Matching Findings", f"{len(record.matching_finding_ids)} ({', '.join(record.matching_finding_ids) or 'None'})")
        result_table.add_row("Correlated Incidents", f"{len(record.matching_incident_ids)} ({', '.join(record.matching_incident_ids) or 'None'})")
        result_table.add_row("Duration", f"{record.duration_seconds}s")

        if record.latency_metrics.measurement_established:
            result_table.add_row("Detection Latency", f"[bold green]{record.latency_metrics.latency_seconds}s[/bold green]")
        else:
            result_table.add_row("Detection Latency", f"[dim]{record.latency_metrics.measurement_notes}[/dim]")

        console.print("\n", Panel(result_table, title=f"Simulation Result: {status_badge}", border_style=color, box=box.ROUNDED))

    if record.status == ScenarioOutcome.PASS:
        return 0
    elif record.status == ScenarioOutcome.FAIL:
        return 1
    return 2


def cmd_run(args: argparse.Namespace) -> int:
    """Run controlled simulation scenario and evaluate outcomes."""
    return asyncio.run(_run_scenario_async(args))


def cmd_report(args: argparse.Namespace) -> int:
    """Show details of a previously completed simulation run."""
    storage = ReportStorage(getattr(args, "reports_dir", None) or Path("./sim_reports"))
    record = storage.load_report(args.run_id)

    if not record:
        err_console.print(f"[bold red]Error:[/bold red] Report not found for run ID '{args.run_id}'.")
        return 1

    if getattr(args, "json", False):
        print(json.dumps(record.model_dump(mode="json"), indent=2))
        return 0

    color = "green" if record.status == ScenarioOutcome.PASS else ("red" if record.status == ScenarioOutcome.FAIL else "yellow")
    status_badge = f"[bold {color}][{record.status.value}][/bold {color}]"

    table = Table(box=box.ROUNDED, show_header=False)
    table.add_column("Key", style="bold cyan")
    table.add_column("Value", style="white")

    table.add_row("Run ID", record.run_id)
    table.add_row("Trace ID", record.trace_id)
    table.add_row("Scenario", f"{record.scenario_name} ({record.scenario_id})")
    table.add_row("MITRE ATT&CK", record.mitre_attack_id)
    table.add_row("Target Rule", record.target_rule_id)
    table.add_row("Test Mode", "Negative Boundary" if record.is_negative_test else "Positive Detection")
    table.add_row("Outcome", status_badge)
    table.add_row("Execution Period", f"{record.start_time} to {record.end_time}")
    table.add_row("Duration", f"{record.duration_seconds}s")
    table.add_row("Telemetry Counts", f"Generated: {record.events_generated_count}, Accepted: {record.events_accepted_count}")
    table.add_row("Persisted Findings", f"{len(record.matching_finding_ids)} ({', '.join(record.matching_finding_ids) or 'None'})")
    table.add_row("Correlated Incidents", f"{len(record.matching_incident_ids)} ({', '.join(record.matching_incident_ids) or 'None'})")

    if record.latency_metrics.measurement_established:
        table.add_row("Detection Latency", f"{record.latency_metrics.latency_seconds}s")
    else:
        table.add_row("Detection Latency", record.latency_metrics.measurement_notes or "Not established")

    if record.error_detail:
        table.add_row("Error Details", f"[red]{record.error_detail}[/red]")

    console.print(Panel(table, title=f"Simulation Report: {record.run_id}", border_style=color, box=box.ROUNDED))
    return 0


def cmd_clean(args: argparse.Namespace) -> int:
    """Clean up stored simulation reports without touching production database."""
    storage = ReportStorage(getattr(args, "reports_dir", None) or Path("./sim_reports"))

    if getattr(args, "run_id", None):
        success = storage.delete_report(args.run_id)
        if success:
            console.print(f"[green]Successfully deleted report '{args.run_id}.json'.[/green]")
            return 0
        err_console.print(f"[red]Report '{args.run_id}' not found.[/red]")
        return 1

    reports = storage.list_reports()
    if not reports:
        console.print("[dim]No simulation reports found to clean.[/dim]")
        return 0

    count = 0
    for p in reports:
        p.unlink()
        count += 1

    console.print(f"[green]Cleaned {count} simulation report(s) from {storage.reports_dir}.[/green]")
    return 0


def cmd_matrix(args: argparse.Namespace) -> int:
    """Fetch and display the MITRE ATT&CK detection validation coverage matrix."""
    config = load_config()
    backend_url = getattr(args, "url", None) or config.backend_url
    admin_key = getattr(args, "admin_key", None) or config.admin_key

    from waliya_sim.client import SimClient
    client = SimClient(base_url=backend_url, admin_key=admin_key)

    async def _fetch():
        return await client.fetch_simulation_coverage()

    try:
        data = asyncio.run(_fetch())
    except Exception as exc:
        err_console.print(f"[red]Failed fetching coverage matrix from {backend_url}: {exc}[/red]")
        return 1

    if getattr(args, "json", False):
        print(json.dumps(data, indent=2))
        return 0

    table = Table(
        title=f"Waliya-Sim: MITRE ATT&CK Detection Validation Matrix ({data.get('validated_rules_count', 0)}/{data.get('total_rules_count', 0)} Rules Validated)",
        box=box.ROUNDED,
        header_style="bold cyan",
    )
    table.add_column("Scenario ID", style="bold green")
    table.add_column("Scenario Name", style="white")
    table.add_column("MITRE ATT&CK", style="yellow")
    table.add_column("Target Rule", style="magenta")
    table.add_column("Positive Status", style="cyan")
    table.add_column("Negative Status", style="blue")
    table.add_column("Rule Validated", style="bold")

    for s in data.get("scenarios", []):
        pos = s.get("positive_status", "NOT_TESTED")
        neg = s.get("negative_status", "NOT_TESTED")
        is_val = (pos == "VALIDATED" and neg != "FAILED")
        val_str = "[green]YES[/green]" if is_val else "[dim]NO[/dim]"
        pos_str = f"[green]{pos}[/green]" if pos == "VALIDATED" else f"[yellow]{pos}[/yellow]" if pos in ("NOT_TESTED", "UNTESTED") else f"[red]{pos}[/red]"
        neg_str = f"[green]{neg}[/green]" if neg == "VALIDATED" else f"[yellow]{neg}[/yellow]" if neg in ("NOT_TESTED", "UNTESTED") else f"[red]{neg}[/red]"
        table.add_row(
            s.get("scenario_id", ""),
            s.get("scenario_name", ""),
            s.get("mitre_attack_id", ""),
            s.get("target_rule_id", ""),
            pos_str,
            neg_str,
            val_str,
        )

    console.print(table)
    return 0


def main() -> None:
    """Main CLI entrypoint."""
    parser = argparse.ArgumentParser(
        prog="waliya-sim",
        description="Waliya-Sim: Safe, deterministic purple-team simulation and detection validation CLI",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. list
    parser_list = subparsers.add_parser("list", help="List all available purple-team simulation scenarios")
    parser_list.add_argument("--json", action="store_true", help="Output scenarios as JSON")
    parser_list.set_defaults(func=cmd_list)

    # 2. preview
    parser_preview = subparsers.add_parser("preview", help="Preview scenario events side-effect free")
    parser_preview.add_argument("scenario", help="Scenario ID or alias (e.g., brute-force, web-shell, port-scan, priv-esc)")
    parser_preview.add_argument("--negative", "--boundary", dest="negative", action="store_true", help="Preview negative boundary test (below threshold)")
    parser_preview.add_argument("--json", action="store_true", help="Output preview events as JSON")
    parser_preview.set_defaults(func=cmd_preview)

    # 3. run
    parser_run = subparsers.add_parser("run", help="Execute controlled simulation against Waliya-IR")
    parser_run.add_argument("scenario", help="Scenario ID or alias")
    parser_run.add_argument("--negative", "--boundary", dest="negative", action="store_true", help="Execute negative boundary test (below threshold)")
    parser_run.add_argument("--url", help="Waliya-IR backend URL (default: http://127.0.0.1:8000)")
    parser_run.add_argument("--agent-id", help="Authenticated agent UUID")
    parser_run.add_argument("--agent-token", help="Authenticated agent bearer token")
    parser_run.add_argument("--admin-key", help="Admin API key for verification")
    parser_run.add_argument("--timeout", type=float, default=15.0, help="Maximum detection wait timeout in seconds")
    parser_run.add_argument("--reports-dir", default="./sim_reports", help="Directory for storing JSON run reports")
    parser_run.add_argument("--json", action="store_true", help="Output execution results as JSON")
    parser_run.set_defaults(func=cmd_run)

    # 4. report
    parser_report = subparsers.add_parser("report", help="Inspect completed simulation run report")
    parser_report.add_argument("run_id", help="Simulation run ID (e.g. sim-a1b2c3d4e5f6)")
    parser_report.add_argument("--reports-dir", default="./sim_reports", help="Directory where reports are stored")
    parser_report.add_argument("--json", action="store_true", help="Output report as JSON")
    parser_report.set_defaults(func=cmd_report)

    # 5. clean
    parser_clean = subparsers.add_parser("clean", help="Safely clean up stored simulation reports")
    parser_clean.add_argument("--run-id", help="Specific simulation run ID to remove")
    parser_clean.add_argument("--reports-dir", default="./sim_reports", help="Directory where reports are stored")
    parser_clean.set_defaults(func=cmd_clean)

    # 6. matrix / coverage
    parser_matrix = subparsers.add_parser("matrix", help="View MITRE ATT&CK detection validation coverage matrix")
    parser_matrix.add_argument("--url", help="Waliya-IR backend URL (default: http://127.0.0.1:8000)")
    parser_matrix.add_argument("--admin-key", help="Admin API key for verification")
    parser_matrix.add_argument("--json", action="store_true", help="Output coverage matrix as JSON")
    parser_matrix.set_defaults(func=cmd_matrix)

    args = parser.parse_args()
    try:
        ret = args.func(args)
        sys.exit(ret)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
