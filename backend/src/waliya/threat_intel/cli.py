"""Command-line interface for threat intelligence feed synchronization and management."""

import asyncio
import sys
from typing import List, Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from waliya.db.session import async_session_factory
from waliya.threat_intel.sync_service import ThreatIntelSyncService

console = Console()


def run_async(coro):
    """Run an async coroutine to completion."""
    return asyncio.run(coro)


@click.group(name="waliya-ti")
def cli():
    """Waliya-IR Threat Intelligence Feed Ingestion & Operations CLI."""


# ------------------------------------------------------------------------------
# feeds list / status
# ------------------------------------------------------------------------------
@cli.group(name="feeds")
def feeds_group():
    """Manage external threat intelligence feeds."""


@feeds_group.command(name="list")
def list_feeds_cmd():
    """List all configured threat intelligence feeds and their status."""
    async def _impl():
        async with async_session_factory() as session:
            feed_data = await ThreatIntelSyncService.list_feeds(session)

            table = Table(title="Configured Threat Intelligence Feeds", show_header=True, header_style="bold cyan")
            table.add_column("Feed ID", style="bold white")
            table.add_column("Provider", style="green")
            table.add_column("Enabled", justify="center")
            table.add_column("Interval", justify="right")
            table.add_column("Last Sync", style="yellow")
            table.add_column("Status", justify="center")
            table.add_column("Active Indicators", justify="right", style="bold magenta")

            for feed, count in feed_data:
                status_color = "green" if feed.last_status == "SUCCESS" else "yellow" if feed.last_status == "PARTIAL" else "red" if feed.last_status == "FAILED" else "dim"
                enabled_str = "[green]YES[/green]" if feed.is_enabled else "[dim red]NO[/dim red]"
                last_sync = feed.last_sync_at.strftime("%Y-%m-%d %H:%M:%S") if feed.last_sync_at else "Never"

                table.add_row(
                    feed.feed_id,
                    feed.provider,
                    enabled_str,
                    f"{feed.refresh_interval_minutes}m",
                    last_sync,
                    f"[{status_color}]{feed.last_status}[/{status_color}]",
                    f"{count:,}",
                )

            console.print(table)

    run_async(_impl())


# ------------------------------------------------------------------------------
# decay command
# ------------------------------------------------------------------------------
@cli.command(name="decay")
@click.option("--stale-days", type=int, default=14, help="Days of inactivity before decay begins (default: 14)")
@click.option("--decay-points", type=int, default=10, help="Confidence points decayed per interval (default: 10)")
@click.option("--interval-days", type=int, default=7, help="Decay cycle interval in days (default: 7)")
@click.option("--min-confidence", type=int, default=10, help="Minimum confidence floor (default: 10)")
@click.option("--dry-run", is_flag=True, default=False, help="Preview decay without applying changes")
@click.option("--type", "indicator_type", type=str, default=None, help="Filter by indicator type")
@click.option("--source", type=str, default=None, help="Filter by indicator source")
def decay_cmd(stale_days: int, decay_points: int, interval_days: int, min_confidence: int, dry_run: bool, indicator_type: Optional[str], source: Optional[str]):
    """Execute deterministic confidence decay on stale threat intelligence indicators."""
    from waliya.threat_intel.decay_service import ThreatIntelDecayService

    async def _impl():
        async with async_session_factory() as session:
            console.print(Panel(
                f"[bold cyan]Threat Intelligence Indicator Confidence Decay[/bold cyan]\n"
                f"Stale Threshold: [yellow]{stale_days} days[/yellow] | "
                f"Rate: [yellow]{decay_points} pts / {interval_days} days[/yellow] | "
                f"Floor: [yellow]{min_confidence}[/yellow] | "
                f"Dry-Run: [bold]{dry_run}[/bold]",
                border_style="cyan"
            ))

            result = await ThreatIntelDecayService.run_decay(
                session=session,
                actor_id="CLI:admin",
                stale_days=stale_days,
                decay_points=decay_points,
                decay_interval_days=interval_days,
                min_confidence=min_confidence,
                dry_run=dry_run,
                indicator_type=indicator_type,
                source=source,
            )

            decayed = result["decayed_indicators"]
            console.print(f"Evaluated candidates: [bold]{result['total_evaluated']}[/bold]")
            console.print(f"Indicators decayed: [bold green]{result['decayed_count']}[/bold green]")
            console.print(f"Unaffected (fresh / floor reached): [dim]{result['unaffected_count']}[/dim]")

            if decayed:
                table = Table(title="Decayed Threat Indicators", show_header=True)
                table.add_column("Type", style="cyan")
                table.add_column("Value", style="bold white")
                table.add_column("Source", style="green")
                table.add_column("Previous Conf", justify="right", style="red")
                table.add_column("New Conf", justify="right", style="bold green")
                table.add_column("Intervals", justify="right")

                for d in decayed[:20]:
                    table.add_row(
                        d["indicator_type"],
                        d["value"][:30] + ("..." if len(d["value"]) > 30 else ""),
                        d["source"],
                        str(d["previous_confidence"]),
                        str(d["new_confidence"]),
                        str(d["intervals_decayed"]),
                    )

                console.print(table)
                if len(decayed) > 20:
                    console.print(f"[dim]... and {len(decayed) - 20} more decayed indicators.[/dim]")

    run_async(_impl())


# ------------------------------------------------------------------------------
# indicators group
# ------------------------------------------------------------------------------
@cli.group(name="indicators")
def indicators_group():
    """Manage individual threat intelligence indicator lifecycles."""


@indicators_group.command(name="list")
@click.option("--limit", type=int, default=20, help="Maximum indicators to display")
@click.option("--type", "indicator_type", type=str, default=None, help="Filter by indicator type")
def list_indicators_cmd(limit: int, indicator_type: Optional[str]):
    """List threat indicators with lifecycle status."""
    from sqlalchemy import select, desc
    from waliya.db.models import ThreatIndicatorModel
    from datetime import datetime, timezone

    async def _impl():
        async with async_session_factory() as session:
            now_utc = datetime.now(timezone.utc)
            query = select(ThreatIndicatorModel).order_by(desc(ThreatIndicatorModel.created_at)).limit(limit)
            if indicator_type:
                query = query.where(ThreatIndicatorModel.indicator_type == indicator_type.upper().strip())

            res = await session.execute(query)
            indicators = res.scalars().all()

            if not indicators:
                console.print("[dim]No indicators found.[/dim]")
                return

            table = Table(title=f"Threat Indicators (Showing {len(indicators)})", show_header=True)
            table.add_column("ID", style="dim")
            table.add_column("Type", style="cyan")
            table.add_column("Value", style="bold white")
            table.add_column("Source", style="green")
            table.add_column("Confidence", justify="right", style="bold yellow")
            table.add_column("Active", justify="center")
            table.add_column("Expires", style="dim")

            for ind in indicators:
                is_expired = bool(ind.expires_at and ind.expires_at <= now_utc)
                active_str = "[green]YES[/green]" if ind.is_active and not is_expired else "[red]EXPIRED[/red]" if is_expired else "[dim red]NO[/dim red]"
                exp_str = ind.expires_at.strftime("%Y-%m-%d") if ind.expires_at else "Never"

                table.add_row(
                    str(ind.id)[:8] + "...",
                    ind.indicator_type,
                    ind.value[:30] + ("..." if len(ind.value) > 30 else ""),
                    ind.source,
                    f"{ind.confidence}%",
                    active_str,
                    exp_str,
                )

            console.print(table)

    run_async(_impl())


@indicators_group.command(name="activate")
@click.argument("indicator_id")
def activate_indicator_cmd(indicator_id: str):
    """Explicitly activate a threat indicator."""
    from uuid import UUID
    from datetime import datetime, timezone
    from sqlalchemy import select
    from waliya.db.models import ThreatIndicatorModel
    from waliya.threat_intel.matcher import ThreatIntelMatcher

    async def _impl():
        async with async_session_factory() as session:
            res = await session.execute(
                select(ThreatIndicatorModel).where(ThreatIndicatorModel.id == UUID(indicator_id))
            )
            ind = res.scalars().first()
            if not ind:
                console.print(f"[bold red]Indicator '{indicator_id}' not found.[/bold red]")
                return

            now_utc = datetime.now(timezone.utc)
            if ind.expires_at and ind.expires_at <= now_utc:
                console.print(f"[bold red]Cannot silently reactivate expired indicator {ind.id}. Extend expiry first.[/bold red]")
                return

            ind.is_active = True
            ind.updated_at = now_utc
            await session.commit()
            ThreatIntelMatcher.clear_cache()
            console.print(f"[bold green]Indicator {ind.id} ({ind.value}) successfully activated.[/bold green]")

    run_async(_impl())


@indicators_group.command(name="deactivate")
@click.argument("indicator_id")
def deactivate_indicator_cmd(indicator_id: str):
    """Deactivate a threat indicator."""
    from uuid import UUID
    from datetime import datetime, timezone
    from sqlalchemy import select
    from waliya.db.models import ThreatIndicatorModel
    from waliya.threat_intel.matcher import ThreatIntelMatcher

    async def _impl():
        async with async_session_factory() as session:
            res = await session.execute(
                select(ThreatIndicatorModel).where(ThreatIndicatorModel.id == UUID(indicator_id))
            )
            ind = res.scalars().first()
            if not ind:
                console.print(f"[bold red]Indicator '{indicator_id}' not found.[/bold red]")
                return

            ind.is_active = False
            ind.updated_at = datetime.now(timezone.utc)
            await session.commit()
            ThreatIntelMatcher.clear_cache()
            console.print(f"[bold yellow]Indicator {ind.id} ({ind.value}) deactivated.[/bold yellow]")

    run_async(_impl())


@indicators_group.command(name="expire")
@click.argument("indicator_id")
def expire_indicator_cmd(indicator_id: str):
    """Immediately expire a threat indicator."""
    from uuid import UUID
    from datetime import datetime, timezone
    from sqlalchemy import select
    from waliya.db.models import ThreatIndicatorModel
    from waliya.threat_intel.matcher import ThreatIntelMatcher

    async def _impl():
        async with async_session_factory() as session:
            res = await session.execute(
                select(ThreatIndicatorModel).where(ThreatIndicatorModel.id == UUID(indicator_id))
            )
            ind = res.scalars().first()
            if not ind:
                console.print(f"[bold red]Indicator '{indicator_id}' not found.[/bold red]")
                return

            now_utc = datetime.now(timezone.utc)
            ind.expires_at = now_utc
            ind.updated_at = now_utc
            await session.commit()
            ThreatIntelMatcher.clear_cache()
            console.print(f"[bold red]Indicator {ind.id} ({ind.value}) expired.[/bold red]")

    run_async(_impl())


@indicators_group.command(name="extend")
@click.argument("indicator_id")
@click.option("--days", type=int, default=30, help="Days to extend expiration (default: 30)")
def extend_indicator_cmd(indicator_id: str, days: int):
    """Extend expiration deadline for a threat indicator."""
    from uuid import UUID
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import select
    from waliya.db.models import ThreatIndicatorModel
    from waliya.threat_intel.matcher import ThreatIntelMatcher

    async def _impl():
        async with async_session_factory() as session:
            res = await session.execute(
                select(ThreatIndicatorModel).where(ThreatIndicatorModel.id == UUID(indicator_id))
            )
            ind = res.scalars().first()
            if not ind:
                console.print(f"[bold red]Indicator '{indicator_id}' not found.[/bold red]")
                return

            now_utc = datetime.now(timezone.utc)
            base_time = max(now_utc, ind.expires_at or now_utc)
            new_expiry = base_time + timedelta(days=days)
            ind.expires_at = new_expiry
            ind.updated_at = now_utc
            await session.commit()
            ThreatIntelMatcher.clear_cache()
            console.print(f"[bold green]Indicator {ind.id} expiry extended to {new_expiry.strftime('%Y-%m-%d %H:%M:%S')}.[/bold green]")

    run_async(_impl())


@cli.command(name="status")
def status_cmd():
    """Display overall threat intelligence feed health and ingestion metrics."""
    # Alias to feeds list
    list_feeds_cmd()


# ------------------------------------------------------------------------------
# sync
# ------------------------------------------------------------------------------
@cli.command(name="sync")
@click.option("--feed", required=True, help="Feed ID to synchronize ('threatfox', 'urlhaus', or 'all').")
@click.option("--dry-run", is_flag=True, default=False, help="Preview synchronization without committing changes.")
@click.option("--force", is_flag=True, default=False, help="Bypass minimum refresh interval guard.")
def sync_cmd(feed: str, dry_run: bool, force: bool):
    """Synchronize indicators from external threat intelligence feeds."""
    target_feed = feed.strip().lower()

    async def _impl():
        async with async_session_factory() as session:
            # Determine target feeds
            feed_configs = await ThreatIntelSyncService.list_feeds(session)
            all_feed_ids = [f.feed_id for f, _ in feed_configs]

            if target_feed == "all":
                targets = all_feed_ids
            elif target_feed in all_feed_ids:
                targets = [target_feed]
            else:
                console.print(f"[red]Error:[/red] Unknown feed '{target_feed}'. Available feeds: {', '.join(all_feed_ids)}")
                sys.exit(1)

            console.print(Panel(
                f"[bold cyan]Initiating Threat Intel Sync[/bold cyan]\n"
                f"Targets: {', '.join(targets)}\n"
                f"Dry-run: {'[yellow]YES[/yellow]' if dry_run else '[green]NO (Live Ingestion)[/green]'}\n"
                f"Force: {'[red]YES[/red]' if force else 'NO'}",
                title="Waliya-IR Threat Intelligence",
            ))

            overall_exit_code = 0
            runs_summary = []

            for fid in targets:
                console.print(f"\n[cyan]Synchronizing feed:[/cyan] [bold]{fid}[/bold]...")
                try:
                    run = await ThreatIntelSyncService.sync_feed(
                        session=session,
                        feed_id=fid,
                        is_dry_run=dry_run,
                        force=force,
                        triggered_by="cli:waliya-ti",
                    )
                    runs_summary.append(run)

                    status_style = "green" if run.status == "SUCCESS" else "yellow" if run.status == "PARTIAL" else "red"
                    console.print(
                        f"Status: [{status_style}]{run.status}[/{status_style}] | "
                        f"Fetched: {run.fetched_count} | "
                        f"Normalized: {run.normalized_count} | "
                        f"Inserted: {run.inserted_count} | "
                        f"Updated: {run.updated_count} | "
                        f"Rejected: {run.rejected_count} | "
                        f"Skipped: {run.skipped_count}"
                    )
                    if run.error_summary:
                        console.print(f"[dim]{run.error_summary}[/dim]")

                    if run.status == "FAILED" and overall_exit_code != 1:
                        overall_exit_code = 1
                    elif run.status == "PARTIAL" and overall_exit_code == 0:
                        overall_exit_code = 2

                except Exception as exc:
                    console.print(f"[bold red]Sync Failed for {fid}:[/bold red] {exc}")
                    overall_exit_code = 1

            # Summary Table
            if runs_summary:
                summary_table = Table(title="Feed Synchronization Results", show_header=True)
                summary_table.add_column("Feed", style="white")
                summary_table.add_column("Status", justify="center")
                summary_table.add_column("Fetched", justify="right")
                summary_table.add_column("Inserted", justify="right", style="green")
                summary_table.add_column("Updated", justify="right", style="yellow")
                summary_table.add_column("Rejected", justify="right", style="red")
                summary_table.add_column("Skipped", justify="right", style="dim")
                summary_table.add_column("Mode", justify="center")

                for r in runs_summary:
                    mode_str = "[yellow]DRY-RUN[/yellow]" if r.is_dry_run else "[green]LIVE[/green]"
                    stat_style = "green" if r.status == "SUCCESS" else "yellow" if r.status == "PARTIAL" else "red"
                    summary_table.add_row(
                        r.feed_id,
                        f"[{stat_style}]{r.status}[/{stat_style}]",
                        str(r.fetched_count),
                        str(r.inserted_count),
                        str(r.updated_count),
                        str(r.rejected_count),
                        str(r.skipped_count),
                        mode_str,
                    )
                console.print(summary_table)

            sys.exit(overall_exit_code)

    run_async(_impl())


# ------------------------------------------------------------------------------
# history
# ------------------------------------------------------------------------------
@cli.command(name="history")
@click.option("--feed", default=None, help="Filter history by feed ID.")
@click.option("--limit", default=20, type=int, help="Maximum number of historical runs to display.")
def history_cmd(feed: Optional[str], limit: int):
    """View synchronization history and diagnostics."""
    from sqlalchemy import select
    from waliya.db.models import FeedSyncRunModel

    async def _impl():
        async with async_session_factory() as session:
            query = select(FeedSyncRunModel).order_by(FeedSyncRunModel.started_at.desc()).limit(limit)
            if feed:
                query = query.where(FeedSyncRunModel.feed_id == feed.strip().lower())

            res = await session.execute(query)
            runs = list(res.scalars().all())

            if not runs:
                console.print("[dim]No synchronization history found.[/dim]")
                return

            table = Table(title=f"Synchronization History (Last {len(runs)} Runs)", show_header=True)
            table.add_column("Run ID", style="dim")
            table.add_column("Feed", style="bold white")
            table.add_column("Started At", style="yellow")
            table.add_column("Status", justify="center")
            table.add_column("Counts (F/I/U/R/S)", justify="right")
            table.add_column("Dry Run", justify="center")
            table.add_column("Triggered By", style="cyan")

            for r in runs:
                stat_style = "green" if r.status == "SUCCESS" else "yellow" if r.status == "PARTIAL" else "red"
                counts_str = f"{r.fetched_count} / {r.inserted_count} / {r.updated_count} / {r.rejected_count} / {r.skipped_count}"
                dry_str = "[yellow]YES[/yellow]" if r.is_dry_run else "NO"
                started = r.started_at.strftime("%Y-%m-%d %H:%M:%S")

                table.add_row(
                    str(r.id)[:8] + "...",
                    r.feed_id,
                    started,
                    f"[{stat_style}]{r.status}[/{stat_style}]",
                    counts_str,
                    dry_str,
                    r.triggered_by,
                )

            console.print(table)

    run_async(_impl())


# ------------------------------------------------------------------------------
# decay command
# ------------------------------------------------------------------------------
@cli.command(name="decay")
@click.option("--stale-days", type=int, default=14, help="Days of inactivity before decay begins (default: 14)")
@click.option("--decay-points", type=int, default=10, help="Confidence points decayed per interval (default: 10)")
@click.option("--interval-days", type=int, default=7, help="Decay cycle interval in days (default: 7)")
@click.option("--min-confidence", type=int, default=10, help="Minimum confidence floor (default: 10)")
@click.option("--dry-run", is_flag=True, default=False, help="Preview decay without applying changes")
@click.option("--type", "indicator_type", type=str, default=None, help="Filter by indicator type")
@click.option("--source", type=str, default=None, help="Filter by indicator source")
def decay_cmd(stale_days: int, decay_points: int, interval_days: int, min_confidence: int, dry_run: bool, indicator_type: Optional[str], source: Optional[str]):
    """Execute deterministic confidence decay on stale threat intelligence indicators."""
    from waliya.threat_intel.decay_service import ThreatIntelDecayService

    async def _impl():
        async with async_session_factory() as session:
            console.print(Panel(
                f"[bold cyan]Threat Intelligence Indicator Confidence Decay[/bold cyan]\n"
                f"Stale Threshold: [yellow]{stale_days} days[/yellow] | "
                f"Rate: [yellow]{decay_points} pts / {interval_days} days[/yellow] | "
                f"Floor: [yellow]{min_confidence}[/yellow] | "
                f"Dry-Run: [bold]{dry_run}[/bold]",
                border_style="cyan"
            ))

            result = await ThreatIntelDecayService.run_decay(
                session=session,
                actor_id="CLI:admin",
                stale_days=stale_days,
                decay_points=decay_points,
                decay_interval_days=interval_days,
                min_confidence=min_confidence,
                dry_run=dry_run,
                indicator_type=indicator_type,
                source=source,
            )

            decayed = result["decayed_indicators"]
            console.print(f"Evaluated candidates: [bold]{result['total_evaluated']}[/bold]")
            console.print(f"Indicators decayed: [bold green]{result['decayed_count']}[/bold green]")
            console.print(f"Unaffected (fresh / floor reached): [dim]{result['unaffected_count']}[/dim]")

            if decayed:
                table = Table(title="Decayed Threat Indicators", show_header=True)
                table.add_column("Type", style="cyan")
                table.add_column("Value", style="bold white")
                table.add_column("Source", style="green")
                table.add_column("Previous Conf", justify="right", style="red")
                table.add_column("New Conf", justify="right", style="bold green")
                table.add_column("Intervals", justify="right")

                for d in decayed[:20]:
                    table.add_row(
                        d["indicator_type"],
                        d["value"][:30] + ("..." if len(d["value"]) > 30 else ""),
                        d["source"],
                        str(d["previous_confidence"]),
                        str(d["new_confidence"]),
                        str(d["intervals_decayed"]),
                    )

                console.print(table)
                if len(decayed) > 20:
                    console.print(f"[dim]... and {len(decayed) - 20} more decayed indicators.[/dim]")

    run_async(_impl())


# ------------------------------------------------------------------------------
# indicators group
# ------------------------------------------------------------------------------
@cli.group(name="indicators")
def indicators_group():
    """Manage individual threat intelligence indicator lifecycles."""


@indicators_group.command(name="list")
@click.option("--limit", type=int, default=20, help="Maximum indicators to display")
@click.option("--type", "indicator_type", type=str, default=None, help="Filter by indicator type")
def list_indicators_cmd(limit: int, indicator_type: Optional[str]):
    """List threat indicators with lifecycle status."""
    from sqlalchemy import select, desc
    from waliya.db.models import ThreatIndicatorModel
    from datetime import datetime, timezone

    async def _impl():
        async with async_session_factory() as session:
            now_utc = datetime.now(timezone.utc)
            query = select(ThreatIndicatorModel).order_by(desc(ThreatIndicatorModel.created_at)).limit(limit)
            if indicator_type:
                query = query.where(ThreatIndicatorModel.indicator_type == indicator_type.upper().strip())

            res = await session.execute(query)
            indicators = res.scalars().all()

            if not indicators:
                console.print("[dim]No indicators found.[/dim]")
                return

            table = Table(title=f"Threat Indicators (Showing {len(indicators)})", show_header=True)
            table.add_column("ID", style="dim")
            table.add_column("Type", style="cyan")
            table.add_column("Value", style="bold white")
            table.add_column("Source", style="green")
            table.add_column("Confidence", justify="right", style="bold yellow")
            table.add_column("Active", justify="center")
            table.add_column("Expires", style="dim")

            for ind in indicators:
                is_expired = bool(ind.expires_at and ind.expires_at <= now_utc)
                active_str = "[green]YES[/green]" if ind.is_active and not is_expired else "[red]EXPIRED[/red]" if is_expired else "[dim red]NO[/dim red]"
                exp_str = ind.expires_at.strftime("%Y-%m-%d") if ind.expires_at else "Never"

                table.add_row(
                    str(ind.id)[:8] + "...",
                    ind.indicator_type,
                    ind.value[:30] + ("..." if len(ind.value) > 30 else ""),
                    ind.source,
                    f"{ind.confidence}%",
                    active_str,
                    exp_str,
                )

            console.print(table)

    run_async(_impl())


@indicators_group.command(name="activate")
@click.argument("indicator_id")
def activate_indicator_cmd(indicator_id: str):
    """Explicitly activate a threat indicator."""
    from uuid import UUID
    from datetime import datetime, timezone
    from sqlalchemy import select
    from waliya.db.models import ThreatIndicatorModel
    from waliya.threat_intel.matcher import ThreatIntelMatcher

    async def _impl():
        async with async_session_factory() as session:
            res = await session.execute(
                select(ThreatIndicatorModel).where(ThreatIndicatorModel.id == UUID(indicator_id))
            )
            ind = res.scalars().first()
            if not ind:
                console.print(f"[bold red]Indicator '{indicator_id}' not found.[/bold red]")
                return

            now_utc = datetime.now(timezone.utc)
            if ind.expires_at and ind.expires_at <= now_utc:
                console.print(f"[bold red]Cannot silently reactivate expired indicator {ind.id}. Extend expiry first.[/bold red]")
                return

            ind.is_active = True
            ind.updated_at = now_utc
            await session.commit()
            ThreatIntelMatcher.clear_cache()
            console.print(f"[bold green]Indicator {ind.id} ({ind.value}) successfully activated.[/bold green]")

    run_async(_impl())


@indicators_group.command(name="deactivate")
@click.argument("indicator_id")
def deactivate_indicator_cmd(indicator_id: str):
    """Deactivate a threat indicator."""
    from uuid import UUID
    from datetime import datetime, timezone
    from sqlalchemy import select
    from waliya.db.models import ThreatIndicatorModel
    from waliya.threat_intel.matcher import ThreatIntelMatcher

    async def _impl():
        async with async_session_factory() as session:
            res = await session.execute(
                select(ThreatIndicatorModel).where(ThreatIndicatorModel.id == UUID(indicator_id))
            )
            ind = res.scalars().first()
            if not ind:
                console.print(f"[bold red]Indicator '{indicator_id}' not found.[/bold red]")
                return

            ind.is_active = False
            ind.updated_at = datetime.now(timezone.utc)
            await session.commit()
            ThreatIntelMatcher.clear_cache()
            console.print(f"[bold yellow]Indicator {ind.id} ({ind.value}) deactivated.[/bold yellow]")

    run_async(_impl())


@indicators_group.command(name="expire")
@click.argument("indicator_id")
def expire_indicator_cmd(indicator_id: str):
    """Immediately expire a threat indicator."""
    from uuid import UUID
    from datetime import datetime, timezone
    from sqlalchemy import select
    from waliya.db.models import ThreatIndicatorModel
    from waliya.threat_intel.matcher import ThreatIntelMatcher

    async def _impl():
        async with async_session_factory() as session:
            res = await session.execute(
                select(ThreatIndicatorModel).where(ThreatIndicatorModel.id == UUID(indicator_id))
            )
            ind = res.scalars().first()
            if not ind:
                console.print(f"[bold red]Indicator '{indicator_id}' not found.[/bold red]")
                return

            now_utc = datetime.now(timezone.utc)
            ind.expires_at = now_utc
            ind.updated_at = now_utc
            await session.commit()
            ThreatIntelMatcher.clear_cache()
            console.print(f"[bold red]Indicator {ind.id} ({ind.value}) expired.[/bold red]")

    run_async(_impl())


@indicators_group.command(name="extend")
@click.argument("indicator_id")
@click.option("--days", type=int, default=30, help="Days to extend expiration (default: 30)")
def extend_indicator_cmd(indicator_id: str, days: int):
    """Extend expiration deadline for a threat indicator."""
    from uuid import UUID
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import select
    from waliya.db.models import ThreatIndicatorModel
    from waliya.threat_intel.matcher import ThreatIntelMatcher

    async def _impl():
        async with async_session_factory() as session:
            res = await session.execute(
                select(ThreatIndicatorModel).where(ThreatIndicatorModel.id == UUID(indicator_id))
            )
            ind = res.scalars().first()
            if not ind:
                console.print(f"[bold red]Indicator '{indicator_id}' not found.[/bold red]")
                return

            now_utc = datetime.now(timezone.utc)
            base_time = max(now_utc, ind.expires_at or now_utc)
            new_expiry = base_time + timedelta(days=days)
            ind.expires_at = new_expiry
            ind.updated_at = now_utc
            await session.commit()
            ThreatIntelMatcher.clear_cache()
            console.print(f"[bold green]Indicator {ind.id} expiry extended to {new_expiry.strftime('%Y-%m-%d %H:%M:%S')}.[/bold green]")

    run_async(_impl())


def main():
    """Main CLI entrypoint."""
    cli()


if __name__ == "__main__":
    main()
