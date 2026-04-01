"""
CLI display utilities for SENTINEL scanner.
Handles banners, menus, progress display, and result formatting.
"""

from typing import Any

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()


def show_banner() -> None:
    """Display the scanner banner."""
    ascii_art = """
     ██████╗ ███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
    ██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
    ╚█████╗  █████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
     ╚═══██╗ ██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
    ██████╔╝ ███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
    ╚═════╝  ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
    """

    banner_content = Text()
    banner_content.append(ascii_art, style="bold cyan")
    banner_content.append("\n\n")
    banner_content.append("Red Team & Blue Team Security Platform v6.0.0", style="bold white")
    banner_content.append("\n")
    banner_content.append("-" * 70, style="cyan")
    banner_content.append("\n")
    banner_content.append("Developer: ", style="yellow")
    banner_content.append("Halil Berkay Sahin", style="bold green")
    banner_content.append("\n")
    banner_content.append("Version: ", style="yellow")
    banner_content.append("6.0.0", style="bold white")
    banner_content.append("\n")
    banner_content.append("Usage: ", style="yellow")
    banner_content.append("Authorized Testing Only", style="bold yellow")
    banner_content.append("\n")
    banner_content.append("-" * 70, style="cyan")

    console.print(
        Panel(
            Align.center(banner_content),
            border_style="bright_cyan",
            box=box.DOUBLE,
            padding=(1, 2),
        )
    )


def show_ethical_warning() -> None:
    """Display ethical usage warning."""
    warning_text = """
[bold red]ETHICAL USAGE WARNING[/bold red]

This tool is designed for:
- Educational purposes
- Authorized penetration testing
- Security research with proper consent
- Vulnerability assessment of your own systems

[bold red]DO NOT USE THIS TOOL TO:[/bold red]
- Attack systems without authorization
- Perform unauthorized security testing
- Violate any laws or regulations
- Harm or compromise any systems

[bold yellow]By using this tool, you agree to use it responsibly and ethically.[/bold yellow]
    """

    console.print(Panel(warning_text, title="[bold red]ETHICAL USAGE[/bold red]", border_style="red"))


# Module information for the selection menu
MODULE_INFO = [
    ("1", "XSS Scanner", "Cross-Site Scripting detection", "High"),
    ("2", "SQL Injection", "SQL Injection detection", "High"),
    ("3", "Command Injection", "OS Command & SSTI detection", "Critical"),
    ("4", "LFI/RFI", "File Inclusion detection", "Critical"),
    ("5", "SSRF Scanner", "Request Forgery detection", "High"),
    ("6", "CSRF Scanner", "Cross-Site Request Forgery", "Medium"),
    ("7", "Webshell Scanner", "Backdoor & Shell detection", "Critical"),
    ("8", "Auth Security", "Authentication audit", "High"),
    ("9", "API Security", "REST/GraphQL API audit", "High"),
    ("10", "Subdomain Enum", "Subdomain discovery", "Info"),
    ("11", "SSI Injection", "Server-Side Includes", "High"),
    ("12", "CORS Scanner", "CORS misconfiguration", "Medium"),
    ("13", "Open Redirect", "Unvalidated redirects", "Medium"),
    ("14", "Security Misconfig", "Sensitive files & leaks", "High"),
    ("15", "Access Control", "IDOR & admin bypass", "High"),
    ("16", "JWT Security", "JWT configuration audit", "High"),
    ("17", "Proto Pollution", "Prototype Pollution (JS)", "High"),
    ("18", "Cloud Security", "S3 & Cloud config leaks", "High"),
    ("19", "GraphQL Scanner", "Specific GraphQL attacks", "High"),
    ("20", "Directory Brute", "Path enumeration", "Medium"),
    ("21", "Security Headers", "HTTP header analysis", "Low"),
    ("22", "security.txt", "security.txt audit", "Low"),
    ("23", "robots.txt", "robots.txt audit", "Low"),
    ("24", "XXE Scanner", "XML External Entity attacks", "Critical"),
    ("25", "SSTI Scanner", "Template Injection (RCE)", "Critical"),
    ("26", "Deserialization", "Insecure deserialization", "Critical"),
    ("27", "Race Condition", "TOCTOU & parallel attacks", "High"),
    ("28", "Recon Scanner", "WAF/CMS/Tech fingerprint", "Info"),
    ("29", "-------------", "--- EXTERNAL TOOLS ---", "-----"),
    ("30", "Nmap Scanner", "Network & service discovery", "High"),
    ("31", "Gobuster", "Fast directory brute-force", "Medium"),
    ("32", "Nikto", "Web server vulnerabilities", "High"),
    ("33", "Hash Cracker", "Password hash analysis", "High"),
    ("34", "Wordlist Gen", "Custom wordlist builder", "Utility"),
    ("35", "SSE Scanner", "Server-Sent Events audit", "Medium"),
    ("36", "Protocol Scan", "SSL/TLS & multi-protocol", "Medium"),
    ("99", "All Modules", "Full comprehensive scan", "Maximum"),
    ("p", "Attack Payloads", "View/Get Red Team Payloads", "Utility"),
]

# Maps menu number to module ID
MODULE_MAP: dict[int, str] = {
    1: "xss_scanner", 2: "sqli_scanner", 3: "cmd_injection", 4: "lfi_scanner",
    5: "ssrf_scanner", 6: "csrf_scanner", 7: "webshell_scanner", 8: "auth_scanner",
    9: "api_scanner", 10: "subdomain_scanner", 11: "ssi_scanner", 12: "cors_scanner",
    13: "open_redirect", 14: "misconfig", 15: "broken_access_control", 16: "jwt_scanner",
    17: "proto_pollution", 18: "cloud_scanner", 19: "graphql_scanner",
    20: "directory_scanner", 21: "headers_scanner", 22: "security_txt_scanner",
    23: "robots_scanner", 24: "xxe_scanner", 25: "ssti_scanner",
    26: "deserialization", 27: "race_condition", 28: "recon_scanner",
    30: "nmap_scanner", 31: "gobuster_scanner", 32: "nikto_scanner",
    33: "hash_cracker", 34: "wordlist_builder", 35: "sse_scanner", 36: "protocol_scanner",
}

ALL_MODULES = list(MODULE_MAP.values())


def show_module_menu() -> list[str]:
    """Display module selection menu and return selected module IDs."""
    from rich.prompt import Prompt

    title = Text("VULNERABILITY SCANNER MODULES", style="bold cyan")
    console.print(Align.center(title))
    console.print()

    table = Table(
        title="Select Your Scanning Modules",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold white on blue",
    )
    table.add_column("No.", style="bold cyan", width=5, justify="center")
    table.add_column("Module", style="bold green", width=25)
    table.add_column("Description", style="yellow", width=40)
    table.add_column("Capability", style="magenta", width=15)

    for no, module, desc, capability in MODULE_INFO:
        cap_style = "bold red" if capability in ["High", "Critical", "Maximum"] else "bold green"
        table.add_row(no, module, desc, f"[{cap_style}]{capability}[/{cap_style}]")

    console.print(table)

    instructions = """
[bold green]Instructions:[/bold green]
- Enter numbers (e.g., [cyan]1,2,5[/cyan])
- Enter [cyan]all[/cyan] or [cyan]99[/cyan] for full scan
- Enter [cyan]p[/cyan] to access Payload Database
- Press [cyan]Ctrl+C[/cyan] to exit
    """
    console.print(Panel(instructions, title="[bold yellow]How to Select[/bold yellow]", border_style="yellow"))

    while True:
        choice = Prompt.ask("\nSelect modules", default="all")

        if choice.lower() == "p":
            return ["payload_db"]

        if choice.lower() == "all" or choice == "99":
            console.print("[green]Selected: All modules for comprehensive scan[/green]")
            return ALL_MODULES

        try:
            selected_indices = [int(x.strip()) for x in choice.split(",")]
            selected_modules = []
            valid_selection = True
            for idx in selected_indices:
                if idx in MODULE_MAP:
                    selected_modules.append(MODULE_MAP[idx])
                else:
                    valid_selection = False
                    break

            if valid_selection and selected_modules:
                console.print(f"[green]Selected {len(selected_modules)} modules[/green]")
                return selected_modules
        except (ValueError, KeyError):
            pass

        console.print("[red]Invalid selection. Please try again.[/red]")


def show_scan_info(url: str, modules: list[str], output_format: str) -> None:
    """Display scan configuration information."""
    info_table = Table(show_header=False, box=box.ROUNDED, border_style="blue")
    info_table.add_column("Property", style="cyan", width=20)
    info_table.add_column("Value", style="green")

    info_table.add_row("Target URL", url)
    info_table.add_row("Modules", ", ".join(modules))
    info_table.add_row("Output Format", output_format.upper())
    info_table.add_row("Status", "[yellow]Initializing...[/yellow]")

    console.print(Panel(info_table, title="[bold blue]Scan Configuration[/bold blue]", border_style="blue"))


def show_scan_results(results: list[Any], summary: dict[str, Any]) -> None:
    """Display scan results in formatted tables."""
    console.print("\n")
    console.print("[bold cyan]SCAN RESULTS SUMMARY[/bold cyan]")
    console.print("-" * 70)

    vuln_counts = summary.get("vulnerability_counts", {})
    critical_count = vuln_counts.get("critical", 0)
    high_count = vuln_counts.get("high", 0)
    medium_count = vuln_counts.get("medium", 0)
    low_count = vuln_counts.get("low", 0)
    successful_modules = summary.get("successful_modules", 0)
    error_modules = summary.get("error_modules", 0)

    # Statistics panel
    stats_table = Table(show_header=False, box=box.SIMPLE)
    stats_table.add_column("Metric", style="cyan", width=20)
    stats_table.add_column("Count", style="white", width=10)

    stats_table.add_row("Critical", str(critical_count))
    stats_table.add_row("High", str(high_count))
    stats_table.add_row("Medium", str(medium_count))
    stats_table.add_row("Low", str(low_count))
    stats_table.add_row("Successful", str(successful_modules))
    stats_table.add_row("Errors", str(error_modules))

    console.print(Panel(stats_table, title="[bold green]Security Assessment[/bold green]", border_style="green"))

    # Detailed results
    if results:
        results_table = Table(
            title="Detailed Results",
            box=box.ROUNDED,
            border_style="blue",
            header_style="bold white on blue",
        )
        results_table.add_column("Module", style="cyan", width=20)
        results_table.add_column("Status", style="white", width=15)
        results_table.add_column("Risk Level", style="white", width=15)
        results_table.add_column("Vulnerabilities", style="yellow", width=15)
        results_table.add_column("Duration", style="magenta", width=15)

        chain_results = [r for r in results if r.module_name == "ChainAnalyzer"]
        standard_results = [r for r in results if r.module_name != "ChainAnalyzer"]

        for result in standard_results:
            status_val = result.status
            risk_level = result.risk_level
            vuln_count = len(result.vulnerabilities)
            duration = f"{result.duration:.2f}s"

            if status_val == "Vulnerable":
                status_styled = f"[bold red]{status_val}[/bold red]"
            elif status_val == "Error":
                status_styled = f"[bold red]{status_val}[/bold red]"
            else:
                status_styled = f"[bold green]{status_val}[/bold green]"

            if risk_level == "critical":
                risk_styled = f"[bold red]{risk_level}[/bold red]"
            elif risk_level == "high":
                risk_styled = f"[bold orange]{risk_level}[/bold orange]"
            elif risk_level == "medium":
                risk_styled = f"[bold yellow]{risk_level}[/bold yellow]"
            else:
                risk_styled = f"[bold green]{risk_level}[/bold green]"

            results_table.add_row(result.module_name, status_styled, risk_styled, str(vuln_count), duration)

        console.print(results_table)

        # Display Chain Analysis Results
        if chain_results:
            for chain_res in chain_results:
                if chain_res.vulnerabilities:
                    console.print("\n")
                    chain_panel_text = Text()
                    chain_panel_text.append("ATTACK CHAINS DETECTED\n", style="bold red")
                    chain_panel_text.append(
                        f"{len(chain_res.vulnerabilities)} complex attack paths identified.\n\n",
                        style="bold white",
                    )

                    for idx, vuln in enumerate(chain_res.vulnerabilities, 1):
                        chain_panel_text.append(f"Chain #{idx}: {vuln.get('title')}\n", style="bold yellow")
                        chain_panel_text.append(f"Severity: {vuln.get('severity', '').upper()}\n", style="bold red")
                        chain_panel_text.append(f"Impact: {vuln.get('description')}\n", style="white")
                        chain_panel_text.append("-" * 40 + "\n", style="dim white")

                    console.print(
                        Panel(
                            chain_panel_text,
                            title="[bold red]ADVANCED THREAT ANALYSIS[/bold red]",
                            border_style="red",
                            box=box.DOUBLE,
                        )
                    )
