"""
Campaign commands and engagement profiles.

Profiles select existing detection modules. They do not impersonate threat actors.
"""

import asyncio
import json
import sys

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


# ── Campaign commands ───────────────────────────────────────────────


@click.group()
def campaign():
    """Manage red team campaigns."""
    pass


@campaign.command("create")
@click.option("--name", "-n", required=True, help="Campaign name")
@click.option("--scope", "-s", required=True, help='Campaign scope as JSON: \'{"allowed_domains": ["example.com"]}\'')
@click.option("--description", "-d", default="", help="Campaign description")
@click.option("--objectives", default="", help="Comma-separated objectives")
def campaign_create(name: str, scope: str, description: str, objectives: str):
    """Create an engagement and store it."""
    from src.core.engagements import EngagementStore

    try:
        scope_data = json.loads(scope)
    except json.JSONDecodeError:
        console.print('[red]Invalid JSON scope. Example: \'{"allowed_domains": ["example.com"]}\'[/red]')
        sys.exit(1)

    domains = scope_data.get("allowed_domains")
    if not isinstance(domains, list) or not domains:
        console.print("[red]Scope must include an 'allowed_domains' list.[/red]")
        sys.exit(1)

    obj_list = [item.strip() for item in objectives.split(",") if item.strip()] if objectives else []
    try:
        engagement = EngagementStore().create(name, domains, description, obj_list)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        sys.exit(1)

    console.print(
        Panel(
            f"[bold green]Engagement stored[/bold green]\n\n"
            f"[cyan]ID:[/cyan] {engagement['id']}\n"
            f"[cyan]Name:[/cyan] {engagement['name']}\n"
            f"[cyan]Scope:[/cyan] {', '.join(engagement['allowed_domains'])}\n"
            f"[cyan]File:[/cyan] output/engagements.json",
            title="ENGAGEMENT",
            border_style="red",
        )
    )


@campaign.command("list")
def campaign_list():
    """List stored engagements."""
    from src.core.engagements import EngagementStore

    store = EngagementStore()
    table = Table(title="Engagements")
    table.add_column("ID", style="cyan", width=10)
    table.add_column("Name", style="green")
    table.add_column("Phase", style="yellow")
    table.add_column("Services", justify="right")
    table.add_column("Findings", justify="right")
    for engagement in store.list_all():
        summary = store.summary(engagement)
        table.add_row(
            summary["id"],
            summary["name"],
            summary["phase"],
            str(summary["services_count"]),
            str(summary["findings_count"]),
        )
    console.print(table)


@campaign.command("status")
@click.argument("campaign_id")
def campaign_status(campaign_id: str):
    """Show one stored engagement."""
    from src.core.engagements import EngagementStore

    store = EngagementStore()
    engagement = store.get(campaign_id)
    if engagement is None:
        console.print("[red]Engagement not found.[/red]")
        sys.exit(1)
    summary = store.summary(engagement)
    console.print(
        Panel(
            f"[cyan]ID:[/cyan] {summary['id']}\n"
            f"[cyan]Name:[/cyan] {summary['name']}\n"
            f"[cyan]Phase:[/cyan] {summary['phase']}\n"
            f"[cyan]Scope:[/cyan] {', '.join(summary['allowed_domains'])}\n"
            f"[cyan]Services:[/cyan] {summary['services_count']}\n"
            f"[cyan]Findings:[/cyan] {summary['findings_count']}",
            title="ENGAGEMENT",
            border_style="red",
        )
    )


@campaign.command("report")
@click.argument("campaign_id")
def campaign_report(campaign_id: str):
    """Write the markdown report for a stored engagement."""
    from src.core.assessment import AssessmentError, write_report

    try:
        result = write_report(campaign_id)
    except AssessmentError as exc:
        console.print(f"[red]{exc}[/red]")
        sys.exit(1)
    console.print(f"Report: {result['path']}")


@campaign.command("scan")
@click.argument("campaign_id")
@click.option("--target", "-t", required=True, help="Target URL inside the engagement scope")
def campaign_scan(campaign_id: str, target: str):
    """Map open services with nmap version detection. Does not run scripts."""
    from src.core.assessment import AssessmentError, run_scan

    try:
        result = asyncio.run(run_scan(campaign_id, target))
    except AssessmentError as exc:
        console.print(f"[red]{exc}[/red]")
        sys.exit(1)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        sys.exit(1)
    console.print(f"{result['status']}: {result['detail']}")


@campaign.command("verify")
@click.argument("campaign_id")
@click.option("--target", "-t", required=True, help="Target URL inside the engagement scope")
@click.option("--modules", "-m", default="", help="Comma-separated module ids. Default: bounty profile.")
def campaign_verify(campaign_id: str, target: str, modules: str):
    """Run check modules against one in-scope URL and record the evidence."""
    from src.core.assessment import AssessmentError, run_verify

    module_list = [item.strip() for item in modules.split(",") if item.strip()] or None
    try:
        result = asyncio.run(run_verify(campaign_id, target, module_list))
    except AssessmentError as exc:
        console.print(f"[red]{exc}[/red]")
        sys.exit(1)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        sys.exit(1)
    console.print(f"Findings added: {result['findings_added']}. Incidents opened: {result['incidents_opened']}.")


# ── Engagement profiles ─────────────────────────────────────────────


def _engagement_profiles() -> dict[str, dict]:
    from src.core.scan_templates import API_MODULES, BOUNTY_MODULES, CONFIG_MODULES, RECON_MODULES

    return {
        "bounty": {"name": "Bounty baseline", "modules": list(BOUNTY_MODULES)},
        "recon": {"name": "Recon", "modules": list(RECON_MODULES)},
        "api": {"name": "API", "modules": list(API_MODULES)},
        "config": {"name": "Configuration", "modules": list(CONFIG_MODULES)},
    }


@click.command("redteam")
@click.option(
    "--profile",
    "-p",
    type=click.Choice(["bounty", "recon", "api", "config"]),
    required=True,
    help="Engagement profile",
)
@click.option("--target", "-t", required=True, help="Target URL")
@click.option("--output", "-o", type=click.Choice(["txt", "json", "html", "md"]), default="json", help="Report format")
def redteam_scan(profile: str, target: str, output: str):
    """Run a named module preset against one target. Stays on that host."""
    profile_data = _engagement_profiles()[profile]

    console.print(
        Panel(
            f"[cyan]Profile:[/cyan] {profile_data['name']}\n"
            f"[cyan]Target:[/cyan] {target}\n"
            f"[cyan]Modules:[/cyan] {', '.join(profile_data['modules'])}\n",
            title="SENTINEL",
            border_style="cyan",
        )
    )

    try:
        from src.core.config import Config
        from src.core.scanner_engine import ScannerEngine

        scanner = ScannerEngine(Config())
        console.print(f"Scanning with {len(profile_data['modules'])} modules.")

        results = asyncio.run(scanner.scan_target(target, profile_data["modules"]))
        summary = scanner.get_scan_summary()
        _display_redteam_results(results, summary, profile_data)

        from pathlib import Path

        report_dir = Path("output/reports")
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / f"{profile}.{output}"
        report_path.write_text(scanner.export_results(output), encoding="utf-8")
        console.print(f"Report: {report_path}")

    except Exception as e:
        console.print(f"[red]Scan failed: {e}[/red]")
        sys.exit(1)


def _display_redteam_results(results, summary, profile_data):
    """Display red team scan results with MITRE mapping."""
    console.print("\n[bold]FINDINGS[/bold]\n")

    table = Table(title=profile_data["name"])
    table.add_column("Module", style="cyan")
    table.add_column("Severity", style="red")
    table.add_column("Finding", style="white")
    table.add_column("MITRE", style="yellow")

    total_findings = 0
    for result in results:
        if hasattr(result, "vulnerabilities"):
            for vuln in result.vulnerabilities:
                sev = vuln.get("severity", "info") if isinstance(vuln, dict) else getattr(vuln, "severity", "info")
                title = vuln.get("title", "N/A") if isinstance(vuln, dict) else getattr(vuln, "title", "N/A")
                vtype = vuln.get("type", "") if isinstance(vuln, dict) else getattr(vuln, "type", "")

                sev_style = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "blue"}.get(sev, "white")
                table.add_row(
                    result.module_name,
                    f"[{sev_style}]{sev.upper()}[/{sev_style}]",
                    title[:60],
                    vtype,
                )
                total_findings += 1

    console.print(table)
    console.print(
        f"\n[cyan]Total findings:[/cyan] {total_findings}"
        f"\n[cyan]Duration:[/cyan] {summary.get('scan_duration', 0):.2f}s"
    )


# ── Payload CLI ─────────────────────────────────────────────────────


@click.group()
def payload():
    """Build and mutate payloads."""
    pass


@payload.command("build")
@click.argument("payload_str")
@click.option("--encoders", "-e", required=True, help="Comma-separated encoder chain: base64,url_encode,hex")
def payload_build(payload_str: str, encoders: str):
    """Build an encoded payload with an encoder chain."""
    from src.core.payload_builder import PayloadBuilder

    builder = PayloadBuilder()
    encoder_list = [e.strip() for e in encoders.split(",")]

    encoded = builder.build(payload_str, encoder_list)

    console.print(
        Panel(
            f"[cyan]Original:[/cyan] {payload_str}\n"
            f"[cyan]Chain:[/cyan] {' -> '.join(encoder_list)}\n"
            f"[green]Encoded:[/green] {encoded}",
            title="PAYLOAD BUILDER",
            border_style="red",
        )
    )


@payload.command("mutate")
@click.argument("payload_str")
@click.option("--mutations", "-m", required=True, help="Comma-separated mutations: random_case,space_to_comment")
@click.option("--count", "-c", default=5, help="Number of mutations to generate")
def payload_mutate(payload_str: str, mutations: str, count: int):
    """Generate payload mutations for WAF bypass."""
    from src.core.mutation_engine import MutationEngine

    engine = MutationEngine()
    mutation_list = [m.strip() for m in mutations.split(",")]

    results = engine.mutate(payload_str, mutation_list, count)

    table = Table(title="Payload Mutations")
    table.add_column("#", style="cyan", width=4)
    table.add_column("Mutation", style="green")
    table.add_column("Applied", style="yellow")

    for i, r in enumerate(results, 1):
        table.add_row(str(i), r["payload"], ", ".join(r["applied"]))

    console.print(table)
