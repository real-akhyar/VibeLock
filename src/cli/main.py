"""
VibeLock — CLI Tool
Command-line interface for manual scan triggers, remediation status checks,
and system administration.
"""

import os
import sys
import json
import asyncio
import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint

console = Console()

DEFAULT_API_URL = os.getenv("VIBELOCK_API_URL", "http://localhost:8000")
DEFAULT_TOKEN = os.getenv("VIBELOCK_TOKEN", "")


# --- CLI Entry Point ---

def main():
    parser = argparse.ArgumentParser(
        prog="vibelock",
        description="VibeLock — Autonomous Security Remediation CLI",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # scan
    scan_parser = subparsers.add_parser("scan", help="Trigger a manual scan")
    scan_parser.add_argument("repo", help="Repository full name (owner/repo)")
    scan_parser.add_argument("--branch", default="main", help="Branch to scan")
    scan_parser.add_argument("--commit", help="Specific commit SHA")
    scan_parser.add_argument("--files", nargs="*", help="Specific files to scan")

    # status
    status_parser = subparsers.add_parser("status", help="Check remediation status")
    status_parser.add_argument("--repo", help="Filter by repository")
    status_parser.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    status_parser.add_argument("--limit", type=int, default=20)

    # dashboard
    dashboard_parser = subparsers.add_parser("dashboard", help="Show dashboard summary")
    dashboard_parser.add_argument("--days", type=int, default=30)

    # health
    subparsers.add_parser("health", help="Check system health")

    # metrics
    subparsers.add_parser("metrics", help="Show Prometheus metrics")

    # queue
    queue_parser = subparsers.add_parser("queue", help="Show queue statistics")
    queue_parser.add_argument("--replay-dead", type=int, default=0, help="Replay N dead-letter messages")

    # token
    token_parser = subparsers.add_parser("token", help="Generate a JWT token")
    token_parser.add_argument("--user", default="admin", help="User ID")
    token_parser.add_argument("--org", help="Organization ID")
    token_parser.add_argument("--role", default="admin", choices=["admin", "viewer", "scanner"])
    token_parser.add_argument("--expiry", type=int, default=60, help="Expiry in minutes")

    # config
    subparsers.add_parser("config", help="Show current configuration")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return

    asyncio.run(_handle_command(args))


async def _handle_command(args):
    command = args.command

    if command == "scan":
        await cmd_scan(args)
    elif command == "status":
        await cmd_status(args)
    elif command == "dashboard":
        await cmd_dashboard(args)
    elif command == "health":
        await cmd_health()
    elif command == "metrics":
        await cmd_metrics()
    elif command == "queue":
        await cmd_queue(args)
    elif command == "token":
        cmd_token(args)
    elif command == "config":
        cmd_config()


# --- Command Implementations ---

async def cmd_scan(args):
    """Trigger a manual scan."""
    console.print(f"[bold cyan]🔍 Triggering scan for {args.repo}...[/bold cyan]")

    payload = {
        "repository": args.repo,
        "branch": args.branch,
        "commit_sha": args.commit or "",
        "files": args.files or [],
    }

    async with httpx.AsyncClient(timeout=30) as client:
        try:
            resp = await client.post(
                f"{DEFAULT_API_URL}/api/v1/scan/trigger",
                json=payload,
                headers=_auth_headers(),
            )
            if resp.status_code == 200:
                data = resp.json()
                console.print(f"[green]✅ Scan queued: {data.get('scan_id', 'unknown')}[/green]")
            else:
                console.print(f"[red]❌ Failed: {resp.status_code} — {resp.text}[/red]")
        except Exception as e:
            console.print(f"[red]❌ Connection error: {e}[/red]")


async def cmd_status(args):
    """Show remediation status."""
    console.print("[bold cyan]📊 Vulnerability Status[/bold cyan]")

    params = {"limit": args.limit}
    if args.repo:
        params["repository"] = args.repo
    if args.severity:
        params["severity"] = args.severity

    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.get(
                f"{DEFAULT_API_URL}/api/v1/dashboard/summary",
                params=params,
                headers=_auth_headers(),
            )
            if resp.status_code == 200:
                data = resp.json()
                _print_summary_table(data)
            else:
                console.print(f"[red]❌ Failed: {resp.status_code}[/red]")
        except Exception as e:
            console.print(f"[red]❌ Connection error: {e}[/red]")


async def cmd_dashboard(args):
    """Show dashboard summary."""
    console.print("[bold cyan]📈 VibeLock Dashboard[/bold cyan]")

    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.get(
                f"{DEFAULT_API_URL}/api/v1/dashboard/full",
                params={"days": args.days},
                headers=_auth_headers(),
            )
            if resp.status_code == 200:
                data = resp.json()
                summary = data.get("summary", {})
                scans = data.get("scans", {})
                repos = data.get("top_repositories", [])

                _print_summary_table(summary)

                # Scan stats
                console.print(f"\n[bold]Scan Stats:[/bold] {scans.get('total_scans', 0)} total, "
                             f"{scans.get('completed_scans', 0)} completed, "
                             f"{scans.get('failed_scans', 0)} failed")

                # Top repos
                if repos:
                    table = Table(title="Top Repositories")
                    table.add_column("Repository", style="cyan")
                    table.add_column("Total", justify="right")
                    table.add_column("Critical", justify="right", style="red")
                    table.add_column("High", justify="right", style="yellow")
                    table.add_column("Open PRs", justify="right", style="green")
                    for r in repos[:10]:
                        table.add_row(
                            r.get("repository", "?"),
                            str(r.get("total_vulns", 0)),
                            str(r.get("critical", 0)),
                            str(r.get("high", 0)),
                            str(r.get("open_prs", 0)),
                        )
                    console.print(table)
            else:
                console.print(f"[red]❌ Failed: {resp.status_code}[/red]")
        except Exception as e:
            console.print(f"[red]❌ Connection error: {e}[/red]")


async def cmd_health():
    """Check system health."""
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.get(f"{DEFAULT_API_URL}/health")
            if resp.status_code == 200:
                data = resp.json()
                console.print(f"[green]✅ Status: {data.get('status', 'unknown')}[/green]")
                console.print(f"   Service: {data.get('service', '?')}")
                console.print(f"   Version: {data.get('version', '?')}")
                console.print(f"   Uptime: {data.get('uptime_seconds', 0):.0f}s")

                system = data.get("system", {})
                if system and "cpu_percent" in system:
                    console.print(f"\n[bold]System:[/bold]")
                    console.print(f"   CPU: {system['cpu_percent']}%")
                    console.print(f"   Memory: {system.get('memory_used_gb', '?')}/{system.get('memory_total_gb', '?')} GB ({system.get('memory_percent', '?')}%)")
                    console.print(f"   Disk: {system.get('disk_used_gb', '?')}/{system.get('disk_total_gb', '?')} GB ({system.get('disk_percent', '?')}%)")
            else:
                console.print(f"[red]❌ Health check failed: {resp.status_code}[/red]")
        except Exception as e:
            console.print(f"[red]❌ Connection error: {e}[/red]")


async def cmd_metrics():
    """Show Prometheus metrics."""
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.get(f"{DEFAULT_API_URL}/metrics/json")
            if resp.status_code == 200:
                data = resp.json()
                console.print("[bold cyan]📊 Metrics[/bold cyan]")
                for name, metric in sorted(data.items()):
                    console.print(f"\n[bold]{name}[/bold] ({metric['type']})")
                    for sample in metric.get("samples", [])[:5]:
                        labels = ", ".join(f"{k}={v}" for k, v in sample.get("labels", {}).items())
                        console.print(f"  {labels}: {sample['value']}")
            else:
                console.print(f"[red]❌ Failed: {resp.status_code}[/red]")
        except Exception as e:
            console.print(f"[red]❌ Connection error: {e}[/red]")


async def cmd_queue(args):
    """Show queue statistics."""
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.get(
                f"{DEFAULT_API_URL}/api/v1/queue/stats",
                headers=_auth_headers(),
            )
            if resp.status_code == 200:
                data = resp.json()
                console.print("[bold cyan]📬 Queue Statistics[/bold cyan]")
                console.print(f"  Scan queue: {data.get('scan_queue_length', 0)}")
                console.print(f"  Remediate queue: {data.get('remediate_queue_length', 0)}")
                console.print(f"  Dead letter: {data.get('dead_letter_length', 0)}")
                console.print(f"  Stuck scan jobs: {len(data.get('stuck_scan_jobs', []))}")
                console.print(f"  Stuck remediate jobs: {len(data.get('stuck_remediate_jobs', []))}")

                if args.replay_dead > 0:
                    replay_resp = await client.post(
                        f"{DEFAULT_API_URL}/api/v1/queue/replay-dead",
                        json={"count": args.replay_dead},
                        headers=_auth_headers(),
                    )
                    if replay_resp.status_code == 200:
                        console.print(f"[green]✅ Replayed {replay_resp.json().get('replayed', 0)} messages[/green]")
            else:
                console.print(f"[red]❌ Failed: {resp.status_code}[/red]")
        except Exception as e:
            console.print(f"[red]❌ Connection error: {e}[/red]")


def cmd_token(args):
    """Generate a JWT token."""
    from vibelock.src.api.auth import create_token

    token = create_token(
        user_id=args.user,
        org_id=args.org,
        role=args.role,
        expiry_minutes=args.expiry,
    )

    console.print("[bold green]🔑 Generated Token:[/bold green]")
    console.print(token)
    console.print(f"\n[dim]Expires in {args.expiry} minutes | User: {args.user} | Role: {args.role}[/dim]")


def cmd_config():
    """Show current configuration."""
    console.print("[bold cyan]⚙️  VibeLock Configuration[/bold cyan]")
    console.print(f"  API URL: {DEFAULT_API_URL}")
    console.print(f"  Token set: {'Yes' if DEFAULT_TOKEN else 'No'}")
    console.print(f"  Redis URL: {os.getenv('REDIS_URL', 'redis://localhost:6379/0')}")
    console.print(f"  Supabase URL: {os.getenv('SUPABASE_URL', 'not set')}")
    console.print(f"  Notifications: {os.getenv('VIBELOCK_NOTIFICATIONS_ENABLED', 'true')}")


# --- Helpers ---

def _auth_headers() -> dict:
    headers = {}
    if DEFAULT_TOKEN:
        headers["Authorization"] = f"Bearer {DEFAULT_TOKEN}"
    return headers


def _print_summary_table(data: dict):
    """Print vulnerability summary as a rich table."""
    table = Table(title="Vulnerability Summary")
    table.add_column("Category", style="bold")
    table.add_column("Count", justify="right")

    table.add_row("[bold]Total[/bold]", str(data.get("total", 0)))

    by_severity = data.get("by_severity", {})
    for sev in ["critical", "high", "medium", "low"]:
        count = by_severity.get(sev, 0)
        style = {"critical": "red", "high": "yellow", "medium": "cyan", "low": "green"}.get(sev, "")
        table.add_row(f"  [{style}]{sev}[/{style}]", str(count))

    by_status = data.get("by_status", {})
    for status, count in by_status.items():
        table.add_row(f"  [{status}]", str(count))

    console.print(table)


if __name__ == "__main__":
    main()