#!/usr/bin/env python3
"""
Enterprise Web Vulnerability Scanner v5.0.0
A professional-grade security scanning tool for educational and authorized testing purposes.

Developed by: Halil Berkay Şahin
License: MIT
"""

import sys
import asyncio
import click
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich import box
from rich.prompt import Prompt, Confirm
from rich.live import Live
from rich.layout import Layout

from src.core.config import Config
from src.core.scanner_engine import ScannerEngine
from src.core.exceptions import ScannerException, ConfigurationError, ValidationError

console = Console()

def validate_url(url: str) -> bool:
    """Validate and sanitize the input URL."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def show_banner():
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
    banner_content.append("🔍 ENTERPRISE WEB VULNERABILITY SCANNER v5.0.0", style="bold white")
    banner_content.append("\n")
    banner_content.append("━" * 70, style="cyan")
    banner_content.append("\n")
    banner_content.append("👨‍💻 Developer: ", style="yellow")
    banner_content.append("Halil Berkay Şahin", style="bold green")
    banner_content.append("\n")
    banner_content.append("📅 Version: ", style="yellow")
    banner_content.append("5.0.0 (Enterprise Edition)", style="bold white")
    banner_content.append("\n")
    banner_content.append("⚠️  Purpose: ", style="yellow")
    banner_content.append("Educational & Authorized Testing Only", style="bold yellow")
    banner_content.append("\n")
    banner_content.append("━" * 70, style="cyan")
    
    console.print(
        Panel(
            Align.center(banner_content),
            border_style="bright_cyan",
            box=box.DOUBLE,
            padding=(1, 2)
        )
    )

def show_ethical_warning():
    """Display ethical usage warning."""
    warning_text = """
[bold red]⚠️  ETHICAL USAGE WARNING ⚠️[/bold red]

This tool is designed for:
• Educational purposes
• Authorized penetration testing
• Security research with proper consent
• Vulnerability assessment of your own systems

[bold red]DO NOT USE THIS TOOL TO:[/bold red]
• Attack systems without authorization
• Perform unauthorized security testing
• Violate any laws or regulations
• Harm or compromise any systems

[bold yellow]By using this tool, you agree to use it responsibly and ethically.[/bold yellow]
    """
    
    console.print(Panel(warning_text, title="[bold red]ETHICAL USAGE[/bold red]", border_style="red"))

def show_module_menu() -> List[str]:
    """Display module selection menu."""
    title = Text("🛡️  VULNERABILITY SCANNER MODULES", style="bold cyan")
    console.print(Align.center(title))
    console.print()
    
    table = Table(
        title="Select Your Scanning Modules",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold white on blue"
    )
    table.add_column("No.", style="bold cyan", width=5, justify="center")
    table.add_column("🔍 Module", style="bold green", width=25)
    table.add_column("📝 Description", style="yellow", width=40)
    table.add_column("🚀 Capability", style="magenta", width=15)

    module_info = [
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
        ("24", "🔴 XXE Scanner", "XML External Entity attacks", "Critical"),
        ("25", "🔴 SSTI Scanner", "Template Injection (RCE)", "Critical"),
        ("26", "🔴 Deserialization", "Insecure deserialization", "Critical"),
        ("27", "🔴 Race Condition", "TOCTOU & parallel attacks", "High"),
        ("28", "🔍 Recon Scanner", "WAF/CMS/Tech fingerprint", "Info"),
        ("29", "─────────────", "─── EXTERNAL TOOLS ───", "─────"),
        ("30", "🛠️ Nmap Scanner", "Network & service discovery", "High"),
        ("31", "🛠️ Gobuster", "Fast directory brute-force", "Medium"),
        ("32", "🛠️ Nikto", "Web server vulnerabilities", "High"),
        ("33", "🛠️ Hash Cracker", "Password hash analysis", "High"),
        ("34", "🛠️ Wordlist Gen", "Custom wordlist builder", "Utility"),
        ("35", "🛠️ SSE Scanner", "Server-Sent Events audit", "Medium"),
        ("36", "🛠️ Protocol Scan", "SSL/TLS & multi-protocol", "Medium"),
        ("99", "🎯 All Modules", "Full comprehensive scan", "Maximum"),
        ("p", "💣 Attack Payloads", "View/Get Red Team Payloads", "Utility")
    ]

    for no, module, desc, capability in module_info:
        cap_style = "bold red" if capability in ["High", "Critical", "Maximum"] else "bold green"
        table.add_row(no, module, desc, f"[{cap_style}]{capability}[/{cap_style}]")

    console.print(table)
    
    instructions = """
[bold green]Instructions:[/bold green]
• Enter numbers (e.g., [cyan]1,2,5[/cyan])
• Enter [cyan]all[/cyan] or [cyan]99[/cyan] for full scan
• Enter [cyan]p[/cyan] to access Payload Database
• Press [cyan]Ctrl+C[/cyan] to exit
    """
    
    console.print(Panel(instructions, title="[bold yellow]How to Select[/bold yellow]", border_style="yellow"))
    
    all_modules = [
        'xss_scanner', 'sqli_scanner', 'cmd_injection', 'lfi_scanner', 'ssrf_scanner', 
        'csrf_scanner', 'webshell_scanner', 'auth_scanner', 'api_scanner', 'subdomain_scanner', 
        'ssi_scanner', 'cors_scanner', 'open_redirect', 'misconfig', 'broken_access_control', 
        'jwt_scanner', 'proto_pollution', 'cloud_scanner', 'graphql_scanner', 'directory_scanner', 
        'headers_scanner', 'security_txt_scanner', 'robots_scanner', 'xxe_scanner', 'ssti_scanner',
        'deserialization', 'race_condition', 'recon_scanner',
        # External Tools
        'nmap_scanner', 'gobuster_scanner', 'nikto_scanner', 'hash_cracker', 
        'wordlist_builder', 'sse_scanner', 'protocol_scanner'
    ]

    while True:
        choice = Prompt.ask("\n🎯 Select modules", default="all")
        
        if choice.lower() == 'p':
            return ['payload_db']

        if choice.lower() == 'all' or choice == '99':
            console.print("[green]✓ Selected: All modules for comprehensive scan[/green]")
            return all_modules
        
        try:
            selected_indices = [int(x.strip()) for x in choice.split(',')]
            module_map = {
                1: 'xss_scanner', 2: 'sqli_scanner', 3: 'cmd_injection', 4: 'lfi_scanner', 
                5: 'ssrf_scanner', 6: 'csrf_scanner', 7: 'webshell_scanner', 8: 'auth_scanner', 
                9: 'api_scanner', 10: 'subdomain_scanner', 11: 'ssi_scanner', 12: 'cors_scanner', 
                13: 'open_redirect', 14: 'misconfig', 15: 'broken_access_control', 16: 'jwt_scanner', 
                17: 'proto_pollution', 18: 'cloud_scanner', 19: 'graphql_scanner', 
                20: 'directory_scanner', 21: 'headers_scanner', 22: 'security_txt_scanner', 
                23: 'robots_scanner', 24: 'xxe_scanner', 25: 'ssti_scanner',
                26: 'deserialization', 27: 'race_condition', 28: 'recon_scanner',
                # External Tools
                30: 'nmap_scanner', 31: 'gobuster_scanner', 32: 'nikto_scanner',
                33: 'hash_cracker', 34: 'wordlist_builder', 35: 'sse_scanner', 36: 'protocol_scanner'
            }
            
            selected_modules = []
            valid_selection = True
            for idx in selected_indices:
                if idx in module_map:
                    selected_modules.append(module_map[idx])
                else:
                    valid_selection = False
                    break
            
            if valid_selection and selected_modules:
                console.print(f"[green]✓ Selected {len(selected_modules)} modules[/green]")
                return selected_modules
        except (ValueError, KeyError):
            pass
        
        console.print("[red]❌ Invalid selection. Please try again.[/red]")

def show_scan_info(url: str, modules: List[str], output_format: str):
    """Display scan information."""
    info_table = Table(show_header=False, box=box.ROUNDED, border_style="blue")
    info_table.add_column("Property", style="cyan", width=20)
    info_table.add_column("Value", style="green")
    
    info_table.add_row("🎯 Target URL", url)
    info_table.add_row("🔧 Modules", ", ".join(modules))
    info_table.add_row("📊 Output Format", output_format.upper())
    info_table.add_row("⏰ Status", "[yellow]Initializing...[/yellow]")
    
    console.print(Panel(info_table, title="[bold blue]Scan Configuration[/bold blue]", border_style="blue"))

def progress_callback(module_name: str, status: str, progress: int):
    """Progress callback for scan updates."""
    # This will be called by the scanner engine
    pass

def show_scan_results(results, summary):
    """Display scan results."""
    console.print("\n")
    console.print("📊 [bold cyan]SCAN RESULTS SUMMARY[/bold cyan]")
    console.print("━" * 70)
    
    # Results statistics
    total_modules = summary.get('total_modules', 0)
    successful_modules = summary.get('successful_modules', 0)
    error_modules = summary.get('error_modules', 0)
    total_vulnerabilities = summary.get('total_vulnerabilities', 0)
    
    # Statistics panel
    stats_table = Table(show_header=False, box=box.SIMPLE)
    stats_table.add_column("Metric", style="cyan", width=20)
    stats_table.add_column("Count", style="white", width=10)
    stats_table.add_column("Bar", style="white", width=20)
    
    vuln_counts = summary.get('vulnerability_counts', {})
    critical_count = vuln_counts.get('critical', 0)
    high_count = vuln_counts.get('high', 0)
    medium_count = vuln_counts.get('medium', 0)
    low_count = vuln_counts.get('low', 0)
    
    stats_table.add_row("🔴 Critical", str(critical_count), "█" * critical_count + "░" * (10 - critical_count))
    stats_table.add_row("🟠 High", str(high_count), "█" * high_count + "░" * (10 - high_count))
    stats_table.add_row("🟡 Medium", str(medium_count), "█" * medium_count + "░" * (10 - medium_count))
    stats_table.add_row("🟢 Low", str(low_count), "█" * low_count + "░" * (10 - low_count))
    stats_table.add_row("✅ Successful", str(successful_modules), "█" * successful_modules + "░" * (10 - successful_modules))
    stats_table.add_row("❌ Errors", str(error_modules), "█" * error_modules + "░" * (10 - error_modules))
    
    console.print(Panel(stats_table, title="[bold green]Security Assessment[/bold green]", border_style="green"))
    
    # Detailed results
    if results:
        results_table = Table(
            title="Detailed Results",
            box=box.ROUNDED,
            border_style="blue",
            header_style="bold white on blue"
        )
        results_table.add_column("Module", style="cyan", width=20)
        results_table.add_column("Status", style="white", width=15)
        results_table.add_column("Risk Level", style="white", width=15)
        results_table.add_column("Vulnerabilities", style="yellow", width=15)
        results_table.add_column("Duration", style="magenta", width=15)
        
        # Filter out ChainAnalyzer results for special display
        chain_results = [r for r in results if r.module_name == "ChainAnalyzer"]
        standard_results = [r for r in results if r.module_name != "ChainAnalyzer"]

        for result in standard_results:
            status = result.status
            risk_level = result.risk_level
            vuln_count = len(result.vulnerabilities)
            duration = f"{result.duration:.2f}s"
            
            # Status styling
            if status == 'Vulnerable':
                status_styled = f"[bold red]{status}[/bold red]"
            elif status == 'Error':
                status_styled = f"[bold red]{status}[/bold red]"
            else:
                status_styled = f"[bold green]{status}[/bold green]"
            
            # Risk level styling
            if risk_level == 'critical':
                risk_styled = f"[bold red]{risk_level}[/bold red]"
            elif risk_level == 'high':
                risk_styled = f"[bold orange]{risk_level}[/bold orange]"
            elif risk_level == 'medium':
                risk_styled = f"[bold yellow]{risk_level}[/bold yellow]"
            else:
                risk_styled = f"[bold green]{risk_level}[/bold green]"
                
            results_table.add_row(
                result.module_name,
                status_styled,
                risk_styled,
                str(vuln_count),
                duration
            )
        
        console.print(results_table)

        # Display Chain Analysis Results
        if chain_results:
            for chain_res in chain_results:
                if chain_res.vulnerabilities:
                    console.print("\n")
                    chain_panel_text = Text()
                    chain_panel_text.append("🔗 ATTACK CHAINS DETECTED 🔗\n", style="bold red blink")
                    chain_panel_text.append(f"{len(chain_res.vulnerabilities)} complex attack paths identified.\n\n", style="bold white")
                    
                    for idx, vuln in enumerate(chain_res.vulnerabilities, 1):
                        chain_panel_text.append(f"Chain #{idx}: {vuln.get('title')}\n", style="bold yellow")
                        chain_panel_text.append(f"Severity: {vuln.get('severity').upper()}\n", style="bold red")
                        chain_panel_text.append(f"Impact: {vuln.get('description')}\n", style="white")
                        chain_panel_text.append("━" * 40 + "\n", style="dim white")
                    
                    console.print(Panel(
                        chain_panel_text,
                        title="[bold red]ADVANCED THREAT ANALYSIS[/bold red]",
                        border_style="red",
                        box=box.DOUBLE
                    ))

@click.command()
@click.option('--url', '-u', help='Target URL to scan')
@click.option('--modules', '-m', help='Comma-separated list of modules to run')
@click.option('--output', '-o', type=click.Choice(['txt', 'json', 'html', 'md']), 
              default='txt', help='Report output format')
@click.option('--config', '-c', help='Path to configuration file')
@click.option('--interactive/--no-interactive', '-i', 
              default=True, help='Run in interactive mode')
@click.option('--fast/--no-fast', 
              help='Fast scan mode (reduced payloads)')
@click.option('--verbose/--no-verbose', '-v',
              help='Verbose output')
def main(url, modules, output, config, interactive, fast, verbose):
    """🛡️ Simple Web Vulnerability Scanner - Educational Use Only"""
    try:
        # Clear screen and show banner
        console.clear()
        show_banner()
        
        # Show ethical warning
        show_ethical_warning()
        
        if not Confirm.ask("\n[yellow]Do you agree to use this tool ethically and responsibly?[/yellow]"):
            console.print("[red]Exiting...[/red]")
            sys.exit(0)
        
        # Load configuration
        try:
            config_obj = Config(config)
        except ConfigurationError as e:
            console.print(Panel(f"[bold red]Configuration error: {e}[/bold red]", border_style="red"))
            sys.exit(1)

        # Performance health check
        dummy_scanner = ScannerEngine(config_obj)
        health = asyncio.run(dummy_scanner.diagnostic_check())
        if health["status"] != "healthy":
            console.print(f"[bold yellow]⚠️  Diagnostic Warning:[/bold yellow] {', '.join(health['issues'])}")
            if health["status"] == "critical":
                console.print("[bold red]Critical system issues detected. Exiting.[/bold red]")
                sys.exit(1)
        
        # URL handling
        if not url:
            if interactive:
                console.print("\n💡 [bold cyan]Enter your target URL for security assessment[/bold cyan]")
                url = Prompt.ask("🎯 Target URL")
            else:
                console.print(Panel("[bold red]❌ Error: URL is required[/bold red]", border_style="red"))
                sys.exit(1)
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        if not validate_url(url):
            console.print(Panel("[bold red]❌ Error: Invalid URL format[/bold red]", border_style="red"))
            sys.exit(1)

        # Module selection
        if modules:
            selected_modules = [m.strip() for m in modules.split(',')]
        elif interactive:
            selected_modules = show_module_menu()
            
            # Special Handling for Payload DB
            if 'payload_db' in selected_modules:
                from src.core.payload_manager import PayloadManager
                pm = PayloadManager()
                
                console.print("\n💣 [bold red]RED TEAM PAYLOAD DATABASE[/bold red]")
                console.print("Select a category to view payloads:")
                console.print("1. XSS")
                console.print("2. SSRF")
                console.print("3. SQLi")
                console.print("4. LFI")
                
                cat_choice = Prompt.ask("Select Category", choices=["1", "2", "3", "4"], default="1")
                cat_map = {"1": "XSS", "2": "SSRF", "3": "SQLi", "4": "LFI"}
                category = cat_map[cat_choice]
                
                payloads = pm.get_payloads_by_category(category)
                
                table = Table(title=f"{category} Payloads")
                table.add_column("ID", style="cyan")
                table.add_column("Name", style="green")
                table.add_column("Risk", style="red")
                table.add_column("Payload", style="white")
                
                for p in payloads:
                    table.add_row(p['id'], p['name'], p['risk'], p['payload'])
                
                console.print(table)
                
                # Payload Guide
                if Confirm.ask("\nView detailed attack guide for a payload?"):
                    pid = Prompt.ask("Enter Payload ID")
                    guide = pm.get_attack_guide(pid)
                    if guide:
                         console.print(Panel(
                            f"[bold]Payload:[/bold] {guide['Payload']}\n"
                            f"[bold]Targeting:[/bold] {guide['Target Params']}\n\n"
                            f"[bold yellow]Execution Guide:[/bold yellow]\n{guide['Execution Guide']}\n\n"
                            f"[bold red]Evasion Tips:[/bold red]\n{guide['Evasion Tips']}",
                            title=f"⚔️ Attack Guide: {guide['Title']}",
                            border_style="red"
                         ))
                    else:
                        console.print("[red]Payload not found.[/red]")
                
                sys.exit(0) # Exit after payload browser
        else:
            selected_modules = ['xss', 'sqli', 'directory', 'headers', 'security_txt', 'robots_txt']

        # Show scan configuration
        show_scan_info(url, selected_modules, output)
        
        # Initialize scanner
        try:
            scanner = ScannerEngine(config_obj)
        except Exception as e:
            console.print(Panel(f"[bold red]Failed to initialize scanner: {e}[/bold red]", border_style="red"))
            sys.exit(1)

        # Run scan
        console.print("\n🚀 [bold green]Starting Vulnerability Scan...[/bold green]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
            transient=False
        ) as progress:
            
            try:
                # Run the scan
                results = asyncio.run(scanner.scan_target(url, selected_modules))
                
                # Get summary
                summary = scanner.get_scan_summary()
                
                # Show results
                show_scan_results(results, summary)
                
                # Generate comprehensive reports
                console.print("\n📄 [bold cyan]Generating comprehensive security reports...[/bold cyan]")
                
                try:
                    # Set target URL for scanner engine
                    scanner.target_url = url
                    
                    # Generate all report formats
                    report_files = scanner.generate_comprehensive_report()
                    
                    console.print(Panel(
                        f"[bold green]🎉 Scan completed successfully![/bold green]\n"
                        f"[cyan]📊 Total modules scanned:[/cyan] [white]{summary.get('total_modules', 0)}[/white]\n"
                        f"[cyan]🔍 Total vulnerabilities found:[/cyan] [white]{summary.get('total_vulnerabilities', 0)}[/white]\n"
                        f"[cyan]⏱️  Scan duration:[/cyan] [white]{summary.get('scan_duration', 0):.2f} seconds[/white]\n\n"
                        f"[cyan]📁 Generated Reports:[/cyan]\n"
                        f"   📊 JSON Report: {report_files.get('json', 'N/A')}\n"
                        f"   📝 Text Report: {report_files.get('txt', 'N/A')}\n"
                        f"   🌐 HTML Report: {report_files.get('html', 'N/A')}\n"
                        f"   👔 Executive Summary: {report_files.get('executive', 'N/A')}\n"
                        f"   🔧 Technical Report: {report_files.get('technical', 'N/A')}\n"
                        f"   🛠️  Remediation Guide: {report_files.get('remediation', 'N/A')}\n\n"
                        f"[cyan]📂 All reports saved to:[/cyan] [yellow]output/reports/[/yellow]",
                        title="[bold green]SUCCESS[/bold green]",
                        border_style="green"
                    ))
                    
                except Exception as e:
                    console.print(Panel(
                        f"[bold yellow]⚠️  Comprehensive report generation failed: {str(e)}[/bold yellow]\n"
                        f"[green]📄 Falling back to basic report...[/green]",
                        title="[bold yellow]WARNING[/bold yellow]",
                        border_style="yellow"
                    ))
                    
                    # Fallback to basic report
                    try:
                        export_data = scanner.export_results(output)
                        
                        # Save to file
                        output_dir = Path("output/reports")
                        output_dir.mkdir(parents=True, exist_ok=True)
                        
                        timestamp = summary.get('start_time', '').replace(':', '-').split('.')[0]
                        filename = f"scan_report_{timestamp}.{output}"
                        output_path = output_dir / filename
                        
                        with open(output_path, 'w', encoding='utf-8') as f:
                            f.write(export_data)
                        
                        console.print(Panel(
                            f"[bold green]✅ Basic report saved successfully![/bold green]\n"
                            f"[cyan]📄 Report saved to:[/cyan] [yellow]{output_path}[/yellow]",
                            title="[bold green]SUCCESS[/bold green]",
                            border_style="green"
                        ))
                        
                    except Exception as fallback_error:
                        console.print(Panel(
                            f"[bold red]Basic report generation also failed: {str(fallback_error)}[/bold red]",
                            title="[bold red]ERROR[/bold red]",
                            border_style="red"
                        ))

            except Exception as e:
                console.print(Panel(
                    f"[bold red]Scan failed: {str(e)}[/bold red]",
                    title="[bold red]ERROR[/bold red]",
                    border_style="red"
                ))
                sys.exit(1)

    except KeyboardInterrupt:
        console.print(Panel(
            "[bold yellow]🛑 Scan interrupted by user[/bold yellow]",
            title="[bold yellow]INTERRUPTED[/bold yellow]",
            border_style="yellow"
        ))
        sys.exit(1)
    except Exception as e:
        console.print(Panel(
            f"[bold red]An unexpected error occurred: {str(e)}[/bold red]",
            title="[bold red]ERROR[/bold red]",
            border_style="red"
        ))
        sys.exit(1)

if __name__ == '__main__':
    main()
