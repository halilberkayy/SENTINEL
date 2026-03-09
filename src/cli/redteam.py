"""
SENTINEL Red Team CLI commands.
Campaign management, threat profiling, payload building, and stealth scanning.
"""

import asyncio
import json
import sys
from typing import Optional

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
    """Create a new red team campaign."""
    try:
        scope_data = json.loads(scope)
    except json.JSONDecodeError:
        console.print("[red]Invalid JSON scope. Example: '{\"allowed_domains\": [\"example.com\"]}'[/red]")
        sys.exit(1)

    if "allowed_domains" not in scope_data:
        console.print("[red]Scope must include 'allowed_domains' list.[/red]")
        sys.exit(1)

    obj_list = [o.strip() for o in objectives.split(",") if o.strip()] if objectives else []

    console.print(Panel(
        f"[bold green]Campaign Created[/bold green]\n\n"
        f"[cyan]Name:[/cyan] {name}\n"
        f"[cyan]Description:[/cyan] {description or '(none)'}\n"
        f"[cyan]Scope:[/cyan] {json.dumps(scope_data, indent=2)}\n"
        f"[cyan]Objectives:[/cyan] {', '.join(obj_list) or '(none)'}\n\n"
        f"[yellow]Note:[/yellow] Campaign created locally. Use the API to persist:\n"
        f"  POST /api/v1/campaigns",
        title="RED TEAM CAMPAIGN",
        border_style="red",
    ))


@campaign.command("list")
@click.option("--api-url", default="http://localhost:8000", help="SENTINEL API base URL")
def campaign_list(api_url: str):
    """List all campaigns."""
    console.print("[bold red]RED TEAM CAMPAIGNS[/bold red]\n")

    table = Table(title="Campaigns")
    table.add_column("ID", style="cyan", width=10)
    table.add_column("Name", style="green")
    table.add_column("Phase", style="yellow")
    table.add_column("Status", style="white")
    table.add_column("Targets", style="magenta", justify="right")
    table.add_column("Findings", style="red", justify="right")

    console.print(table)
    console.print(f"\n[dim]Connect to API at {api_url} for live data.[/dim]")


@campaign.command("status")
@click.argument("campaign_id")
def campaign_status(campaign_id: str):
    """Show detailed status of a campaign."""
    console.print(Panel(
        f"[cyan]Campaign ID:[/cyan] {campaign_id}\n\n"
        f"Use the API to fetch live status:\n"
        f"  GET /api/v1/campaigns/{campaign_id}",
        title="CAMPAIGN STATUS",
        border_style="red",
    ))


@campaign.command("report")
@click.argument("campaign_id")
@click.option("--format", "-f", type=click.Choice(["json", "html", "md"]), default="json", help="Report format")
def campaign_report(campaign_id: str, format: str):
    """Generate a campaign report."""
    console.print(Panel(
        f"[cyan]Campaign ID:[/cyan] {campaign_id}\n"
        f"[cyan]Format:[/cyan] {format}\n\n"
        f"Use the API to generate:\n"
        f"  GET /api/v1/campaigns/{campaign_id}/report?format={format}",
        title="CAMPAIGN REPORT",
        border_style="red",
    ))


@campaign.command("scan")
@click.argument("campaign_id")
@click.option("--target", "-t", required=True, help="Target URL to scan")
@click.option("--modules", "-m", default="xss,sqli,ssrf,headers", help="Comma-separated modules")
def campaign_scan(campaign_id: str, target: str, modules: str):
    """Launch a scan against a campaign target."""
    module_list = [m.strip() for m in modules.split(",")]

    console.print(Panel(
        f"[bold green]Campaign Scan Initiated[/bold green]\n\n"
        f"[cyan]Campaign:[/cyan] {campaign_id}\n"
        f"[cyan]Target:[/cyan] {target}\n"
        f"[cyan]Modules:[/cyan] {', '.join(module_list)}\n\n"
        f"[yellow]Launching scan via existing ScannerEngine...[/yellow]",
        title="RED TEAM SCAN",
        border_style="red",
    ))

    # Run scan using existing infrastructure
    try:
        from src.core.config import Config
        from src.core.scanner_engine import ScannerEngine

        config = Config()
        scanner = ScannerEngine(config)

        console.print("[bold green]Starting scan...[/bold green]")
        results = asyncio.run(scanner.scan_target(target, module_list))
        summary = scanner.get_scan_summary()

        # Show results
        table = Table(title="Scan Results")
        table.add_column("Module", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Findings", style="red", justify="right")

        for result in results:
            vuln_count = len(result.vulnerabilities) if hasattr(result, "vulnerabilities") else 0
            status_style = "green" if result.status == "completed" else "yellow"
            table.add_row(
                result.module_name,
                f"[{status_style}]{result.status}[/{status_style}]",
                str(vuln_count),
            )

        console.print(table)
        console.print(
            f"\n[cyan]Total vulnerabilities:[/cyan] {summary.get('total_vulnerabilities', 0)}"
            f"\n[cyan]Duration:[/cyan] {summary.get('scan_duration', 0):.2f}s"
        )

    except Exception as e:
        console.print(f"[red]Scan failed: {e}[/red]")
        sys.exit(1)


# ── Red Team quick scan ─────────────────────────────────────────────


THREAT_PROFILES = {
    "apt28": {
        "name": "APT28 (Fancy Bear)",
        "modules": [
            "recon_scanner", "credential_scanner", "ldap_ad_scanner",
            "evasion_scanner", "persistence_scanner", "c2_detection",
            "exfiltration_scanner", "stealth_ops",
        ],
        "stealth": True,
    },
    "apt29": {
        "name": "APT29 (Cozy Bear)",
        "modules": [
            "recon_scanner", "xss_scanner", "ssrf_scanner",
            "supply_chain_scanner", "persistence_scanner",
            "stealth_ops", "c2_detection",
        ],
        "stealth": True,
    },
    "lazarus": {
        "name": "Lazarus Group",
        "modules": [
            "credential_scanner", "xss_scanner", "sqli_scanner",
            "social_engineering_scanner", "exfiltration_scanner",
            "persistence_scanner", "post_exploit",
        ],
        "stealth": False,
    },
    "fin7": {
        "name": "FIN7",
        "modules": [
            "xss_scanner", "sqli_scanner", "credential_scanner",
            "social_engineering_scanner", "js_secrets_scanner",
            "evasion_scanner",
        ],
        "stealth": False,
    },
    "full": {
        "name": "Full Red Team Assessment",
        "modules": [
            "recon_scanner", "xss_scanner", "sqli_scanner", "ssrf_scanner",
            "xxe_scanner", "ssti_scanner", "cmd_injection",
            "credential_scanner", "ldap_ad_scanner",
            "c2_detection", "post_exploit", "persistence_scanner",
            "evasion_scanner", "stealth_ops", "exfiltration_scanner",
            "social_engineering_scanner",
        ],
        "stealth": True,
    },
}


@click.command("redteam")
@click.option("--profile", "-p", type=click.Choice(list(THREAT_PROFILES.keys())), required=True, help="Threat actor profile")
@click.option("--target", "-t", required=True, help="Target URL")
@click.option("--stealth/--no-stealth", default=None, help="Override stealth mode")
@click.option("--output", "-o", type=click.Choice(["txt", "json", "html", "md"]), default="json", help="Report format")
def redteam_scan(profile: str, target: str, stealth: Optional[bool], output: str):
    """Quick red team scan using threat actor profiles."""
    profile_data = THREAT_PROFILES[profile]
    use_stealth = stealth if stealth is not None else profile_data["stealth"]

    console.print(Panel(
        f"[bold red]RED TEAM SCAN[/bold red]\n\n"
        f"[cyan]Profile:[/cyan] {profile_data['name']}\n"
        f"[cyan]Target:[/cyan] {target}\n"
        f"[cyan]Stealth:[/cyan] {'Enabled' if use_stealth else 'Disabled'}\n"
        f"[cyan]Modules:[/cyan] {', '.join(profile_data['modules'])}\n",
        title="SENTINEL RED TEAM",
        border_style="red",
    ))

    try:
        from src.core.config import Config
        from src.core.scanner_engine import ScannerEngine

        config = Config()

        # Apply stealth settings
        if use_stealth:
            config.rate_limit = 2  # 2 requests per second
            config.timeout = 30
            console.print("[yellow]Stealth mode: slow scan, human-like timing[/yellow]")

        scanner = ScannerEngine(config)
        console.print(f"[green]Scanning with {len(profile_data['modules'])} modules...[/green]")

        results = asyncio.run(scanner.scan_target(target, profile_data["modules"]))
        summary = scanner.get_scan_summary()

        # Display results
        _display_redteam_results(results, summary, profile_data)

    except Exception as e:
        console.print(f"[red]Red team scan failed: {e}[/red]")
        sys.exit(1)


def _display_redteam_results(results, summary, profile_data):
    """Display red team scan results with MITRE mapping."""
    console.print("\n[bold red]FINDINGS[/bold red]\n")

    table = Table(title=f"Red Team Assessment - {profile_data['name']}")
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

    console.print(Panel(
        f"[cyan]Original:[/cyan] {payload_str}\n"
        f"[cyan]Chain:[/cyan] {' -> '.join(encoder_list)}\n"
        f"[green]Encoded:[/green] {encoded}",
        title="PAYLOAD BUILDER",
        border_style="red",
    ))


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
