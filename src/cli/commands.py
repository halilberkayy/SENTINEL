"""
SENTINEL CLI commands.
Main entry point for the command-line vulnerability scanner.
"""

import asyncio
import sys
from pathlib import Path
from urllib.parse import urlparse

import click
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Confirm, Prompt

from src.core.config import Config
from src.core.exceptions import ConfigurationError

from .display import console, show_banner, show_ethical_warning, show_module_menu, show_scan_info, show_scan_results

__all__ = ["main"]


def validate_url(url: str) -> bool:
    """Validate and sanitize the input URL."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


@click.command()
@click.option("--url", "-u", help="Target URL to scan")
@click.option("--modules", "-m", help="Comma-separated module ids. Overrides --profile.")
@click.option(
    "--profile",
    type=click.Choice(["bounty", "recon", "api", "config"]),
    default=None,
    help="Module preset. Default when not interactive: bounty.",
)
@click.option(
    "--scope",
    multiple=True,
    help="Extra domain the scan may touch, besides the target host. Repeatable.",
)
@click.option(
    "--output",
    "-o",
    type=click.Choice(["txt", "json", "html", "md", "sarif"]),
    default="txt",
    help="Report output format",
)
@click.option("--config", "-c", help="Path to configuration file")
@click.option("--interactive/--no-interactive", "-i", default=True, help="Run in interactive mode")
@click.option("--fast/--no-fast", help="Fast scan mode (reduced payloads)")
@click.option("--verbose/--no-verbose", "-v", help="Verbose output")
def main(
    url: str | None,
    modules: str | None,
    profile: str | None,
    scope: tuple[str, ...],
    output: str,
    config: str | None,
    interactive: bool,
    fast: bool,
    verbose: bool,
) -> None:
    """SENTINEL. Authorized web assessment. Requests stay on the target host unless --scope says otherwise."""
    try:
        if interactive:
            console.clear()
            show_banner()
            show_ethical_warning()
            if not Confirm.ask("\n[yellow]Do you have authorization to scan this target?[/yellow]"):
                console.print("[red]Exiting...[/red]")
                sys.exit(0)
        else:
            console.print("Authorized testing only. Off-scope hosts are not requested.")

        # Load configuration
        try:
            config_obj = Config(config)
        except ConfigurationError as e:
            console.print(Panel(f"[bold red]Configuration error: {e}[/bold red]", border_style="red"))
            sys.exit(1)

        # Import here to avoid circular imports and enable lazy loading
        from src.core.scanner_engine import ScannerEngine

        # Performance health check
        dummy_scanner = ScannerEngine(config_obj)
        health = asyncio.run(dummy_scanner.diagnostic_check())
        if health["status"] != "healthy":
            console.print(f"[bold yellow]Diagnostic Warning:[/bold yellow] {', '.join(health['issues'])}")
            if health["status"] == "critical":
                console.print("[bold red]Critical system issues detected. Exiting.[/bold red]")
                sys.exit(1)

        # URL handling
        if not url:
            if interactive:
                console.print("\n[bold cyan]Enter your target URL for security assessment[/bold cyan]")
                url = Prompt.ask("Target URL")
            else:
                console.print(Panel("[bold red]Error: URL is required[/bold red]", border_style="red"))
                sys.exit(1)

        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        if not validate_url(url):
            console.print(Panel("[bold red]Error: Invalid URL format[/bold red]", border_style="red"))
            sys.exit(1)

        if modules:
            selected_modules = [m.strip() for m in modules.split(",") if m.strip()]
        elif profile or not interactive:
            from src.core.scan_templates import get_template_manager

            chosen = profile or "bounty"
            template = get_template_manager().get_template(chosen)
            if template is None:
                console.print(Panel(f"[bold red]Unknown profile: {chosen}[/bold red]", border_style="red"))
                sys.exit(1)
            selected_modules = list(template.modules)
        else:
            selected_modules = show_module_menu()

        # Show scan configuration
        show_scan_info(url, selected_modules, output)

        # Initialize scanner
        try:
            scanner = ScannerEngine(config_obj)
            scanner.scope_domains = list(scope)
        except Exception as e:
            console.print(Panel(f"[bold red]Failed to initialize scanner: {e}[/bold red]", border_style="red"))
            sys.exit(1)

        # Run scan
        console.print("\n[bold green]Starting Vulnerability Scan...[/bold green]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ):
            try:
                results = asyncio.run(scanner.scan_target(url, selected_modules))
                summary = scanner.get_scan_summary()
                show_scan_results(results, summary)

                # Generate reports
                console.print("\n[bold cyan]Generating comprehensive security reports...[/bold cyan]")

                try:
                    scanner.target_url = url
                    report_files = scanner.generate_comprehensive_report()

                    console.print(
                        Panel(
                            f"[bold green]Scan completed successfully![/bold green]\n"
                            f"[cyan]Total modules scanned:[/cyan] [white]{summary.get('total_modules', 0)}[/white]\n"
                            f"[cyan]Total vulnerabilities found:[/cyan] [white]{summary.get('total_vulnerabilities', 0)}[/white]\n"
                            f"[cyan]Scan duration:[/cyan] [white]{summary.get('scan_duration', 0):.2f} seconds[/white]\n\n"
                            f"[cyan]Generated Reports:[/cyan]\n"
                            f"   JSON Report: {report_files.get('json', 'N/A')}\n"
                            f"   Text Report: {report_files.get('txt', 'N/A')}\n"
                            f"   HTML Report: {report_files.get('html', 'N/A')}\n"
                            f"   Executive Summary: {report_files.get('executive', 'N/A')}\n"
                            f"   Technical Report: {report_files.get('technical', 'N/A')}\n"
                            f"   Remediation Guide: {report_files.get('remediation', 'N/A')}\n\n"
                            f"[cyan]All reports saved to:[/cyan] [yellow]output/reports/[/yellow]",
                            title="[bold green]SUCCESS[/bold green]",
                            border_style="green",
                        )
                    )

                except Exception as e:
                    console.print(
                        Panel(
                            f"[bold yellow]Comprehensive report generation failed: {e!s}[/bold yellow]\n"
                            f"[green]Falling back to basic report...[/green]",
                            title="[bold yellow]WARNING[/bold yellow]",
                            border_style="yellow",
                        )
                    )

                    try:
                        export_data = scanner.export_results(output)
                        output_dir = Path("output/reports")
                        output_dir.mkdir(parents=True, exist_ok=True)

                        timestamp = summary.get("start_time", "").replace(":", "-").split(".")[0]
                        filename = f"scan_report_{timestamp}.{output}"
                        output_path = output_dir / filename

                        with open(output_path, "w", encoding="utf-8") as f:
                            f.write(export_data)

                        console.print(
                            Panel(
                                f"[bold green]Basic report saved successfully![/bold green]\n"
                                f"[cyan]Report saved to:[/cyan] [yellow]{output_path}[/yellow]",
                                title="[bold green]SUCCESS[/bold green]",
                                border_style="green",
                            )
                        )

                    except Exception as fallback_error:
                        console.print(
                            Panel(
                                f"[bold red]Basic report generation also failed: {fallback_error!s}[/bold red]",
                                title="[bold red]ERROR[/bold red]",
                                border_style="red",
                            )
                        )

            except Exception as e:
                console.print(
                    Panel(
                        f"[bold red]Scan failed: {e!s}[/bold red]",
                        title="[bold red]ERROR[/bold red]",
                        border_style="red",
                    )
                )
                sys.exit(1)

    except KeyboardInterrupt:
        console.print(
            Panel(
                "[bold yellow]Scan interrupted by user[/bold yellow]",
                title="[bold yellow]INTERRUPTED[/bold yellow]",
                border_style="yellow",
            )
        )
        sys.exit(1)
    except Exception as e:
        console.print(
            Panel(
                f"[bold red]An unexpected error occurred: {e!s}[/bold red]",
                title="[bold red]ERROR[/bold red]",
                border_style="red",
            )
        )
        sys.exit(1)
