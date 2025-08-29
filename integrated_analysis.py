#!/usr/bin/env python3
"""
Integrated Pi-hole LLM Analytics Script.

This script provides comprehensive DNS log analysis using
the new integrated architecture with proper error handling and logging.

Usage:
    python integrated_analysis.py [--count COUNT] [--model MODEL] [--output FORMAT]
"""

import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.text import Text
from rich.tree import Tree
from rich.columns import Columns
from rich.align import Align
from rich import box

from pihole_analytics.analytics.llm_analyzer import LLMAnalyzer, LLMAnalysisError
from pihole_analytics.analytics.llm_providers.base import LLMConfig
from pihole_analytics.core.pihole_client import PiholeClient
from pihole_analytics.utils.config import PiholeConfig
from pihole_analytics.utils.logging import setup_logging, get_logger

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Initialize Rich console
console = Console()


def print_header():
    """Print a fancy header for the application."""
    header_text = Text("🛡️  Pi-hole LLM Analytics", style="bold magenta")
    subtitle = Text("Intelligent DNS Analysis with AI", style="dim cyan")

    header_panel = Panel(
        Align.center(f"{header_text}\n{subtitle}"),
        box=box.DOUBLE,
        border_style="bright_blue",
        padding=(1, 2)
    )
    console.print(header_panel)
    console.print()


def print_config_info(pihole_config: PiholeConfig, llm_config):
    """Print configuration information in a nice table."""
    config_table = Table(title="🔧 Configuration", box=box.ROUNDED)
    config_table.add_column("Service", style="cyan")
    config_table.add_column("Configuration", style="green")

    config_table.add_row(
        "Pi-hole",
        f"[bold]{pihole_config.host}:{pihole_config.port}[/bold]\nTimeout: {pihole_config.timeout}s"
    )
    config_table.add_row(
        "LLM Service",
        f"[bold]{llm_config.provider.value}[/bold]\n"
        f"Model: {llm_config.model}\n"
        f"URL: {llm_config.api_base_url or 'default'}"
    )

    console.print(config_table)
    console.print()


def print_connection_test_results(pihole_success: bool, pihole_info: dict,
                                  llm_success: bool, llm_models: list):
    """Print connection test results with status indicators."""
    # Create connection status table
    status_table = Table(title="🔗 Connection Test Results", box=box.ROUNDED)
    status_table.add_column("Service", style="cyan")
    status_table.add_column("Status", justify="center")
    status_table.add_column("Details", style="dim")

    pihole_status = "✅ Connected" if pihole_success else "❌ Failed"
    pihole_details = (f"Status: {pihole_info.get('status', 'unknown')}"
                      if pihole_success else "Connection failed")

    llm_status = "✅ Connected" if llm_success else "❌ Failed"
    llm_details = (f"Models available: {len(llm_models)}"
                   if llm_success else "Connection failed")

    status_table.add_row("Pi-hole", pihole_status, pihole_details)
    status_table.add_row("LLM Service", llm_status, llm_details)

    console.print(status_table)

    if llm_success and llm_models:
        models_text = Text("Available Models: ", style="bold cyan")
        models_text.append(", ".join(llm_models[:5]), style="green")
        if len(llm_models) > 5:
            models_text.append(
                f" ... (+{len(llm_models) - 5} more)", style="dim")
        console.print(Panel(models_text, border_style="cyan"))

    console.print()


def create_analysis_summary_table(analysis_result) -> Table:
    """Create a summary table of analysis results."""
    summary_table = Table(title="📊 Analysis Summary", box=box.ROUNDED)
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", justify="right", style="green")
    summary_table.add_column("Details", style="wheat1")

    # Calculate block rate
    block_rate = 0
    if analysis_result.total_queries > 0:
        block_rate = (analysis_result.blocked_queries /
                      analysis_result.total_queries) * 100

    summary_table.add_row(
        "Total Queries",
        f"{analysis_result.total_queries:,}",
        f"Analyzed at {analysis_result.timestamp.strftime('%H:%M:%S')}"
    )
    summary_table.add_row(
        "Blocked Queries",
        f"{analysis_result.blocked_queries:,}",
        f"{block_rate:.1f}% block rate"
    )
    summary_table.add_row(
        "Unique Domains",
        f"{analysis_result.unique_domains:,}",
        "Different domains accessed"
    )
    summary_table.add_row(
        "Unique Clients",
        f"{analysis_result.unique_clients:,}",
        "Active network devices"
    )

    # Risk level with color coding
    risk_level = analysis_result.threat_summary.get(
        'risk_level', 'unknown').upper()
    risk_colors = {
        'LOW': 'green',
        'MEDIUM': 'yellow',
        'HIGH': 'red',
        'CRITICAL': 'bright_red bold',
        'UNKNOWN': 'navajo_white1'
    }
    risk_color = risk_colors.get(risk_level, 'dim')

    summary_table.add_row(
        "Risk Level",
        f"[{risk_color}]{risk_level}[/{risk_color}]",
        f"{len(analysis_result.anomalies)} anomalies detected"
    )

    return summary_table


def create_top_domains_table(top_domains) -> Table:
    """Create a table showing top domains."""
    domains_table = Table(title="🌐 Top Domains", box=box.ROUNDED)
    domains_table.add_column("Rank", justify="center", style="cyan")
    domains_table.add_column("Domain", style="green")
    domains_table.add_column("Queries", justify="right", style="yellow")
    domains_table.add_column("Type", style="navajo_white1")

    for i, domain in enumerate(top_domains[:10], 1):
        if isinstance(domain, dict):
            domain_name = domain.get('domain', 'Unknown')
            query_count = domain.get('count', 0)

            # Determine domain type based on common patterns
            domain_type = "Unknown"
            if any(x in domain_name.lower() for x in ['google', 'gmail', 'youtube']):
                domain_type = "Google Services"
            elif any(x in domain_name.lower() for x in ['facebook', 'instagram', 'whatsapp']):
                domain_type = "Social Media"
            elif any(x in domain_name.lower() for x in ['amazon', 'aws']):
                domain_type = "Amazon Services"
            elif any(x in domain_name.lower() for x in ['microsoft', 'office', 'outlook']):
                domain_type = "Microsoft"
            elif any(x in domain_name.lower() for x in ['ad', 'ads', 'analytics', 'tracking']):
                domain_type = "Advertising"
            elif domain_name.endswith('.local'):
                domain_type = "Local Network"

            domains_table.add_row(
                f"{i}",
                domain_name,
                f"{query_count:,}",
                domain_type
            )
        else:
            domains_table.add_row(f"{i}", str(domain), "N/A", "Unknown")

    return domains_table


def create_top_clients_table(top_clients) -> Table:
    """Create a table showing top clients."""
    clients_table = Table(title="💻 Top Clients", box=box.ROUNDED)
    clients_table.add_column("Rank", justify="center", style="cyan")
    clients_table.add_column("Client IP", style="green")
    clients_table.add_column("Total Queries", justify="right", style="yellow")
    clients_table.add_column("Blocked", justify="right", style="red")
    clients_table.add_column("Block Rate", justify="right", style="magenta")

    for i, client in enumerate(top_clients[:10], 1):
        if isinstance(client, dict):
            client_ip = client.get('client', 'Unknown')
            total_queries = client.get('total', 0)
            blocked_queries = client.get('blocked', 0)

            block_rate = 0
            if total_queries > 0:
                block_rate = (blocked_queries / total_queries) * 100

            clients_table.add_row(
                f"{i}",
                client_ip,
                f"{total_queries:,}",
                f"{blocked_queries:,}",
                f"{block_rate:.1f}%"
            )
        else:
            clients_table.add_row(f"{i}", str(client), "N/A", "N/A", "N/A")

    return clients_table


def create_anomalies_display(anomalies) -> Panel:
    """Create a display for security anomalies."""
    if not anomalies:
        return Panel(
            "[green]✅ No security anomalies detected[/green]",
            title="🛡️ Security Analysis",
            border_style="green"
        )

    anomaly_tree = Tree("🚨 Security Anomalies Detected")

    severity_colors = {
        'low': 'yellow',
        'medium': 'orange',
        'high': 'red',
        'critical': 'bright_red bold'
    }

    for anomaly in anomalies[:10]:  # Show max 10 anomalies
        severity_color = severity_colors.get(
            anomaly.severity.value.lower(), 'white')

        anomaly_branch = anomaly_tree.add(
            f"[{severity_color}]{anomaly.severity.value.upper()}[/{severity_color}] - "
            f"{anomaly.description}"
        )

        if anomaly.affected_domain:
            anomaly_branch.add(f"🌐 Domain: {anomaly.affected_domain}")
        if anomaly.affected_client:
            anomaly_branch.add(f"💻 Client: {anomaly.affected_client}")
        anomaly_branch.add(f"🎯 Confidence: {anomaly.confidence:.1%}")
        anomaly_branch.add(f"⏰ Time: {anomaly.timestamp.strftime('%H:%M:%S')}")

    return Panel(
        anomaly_tree,
        title="🛡️ Security Analysis",
        border_style="red" if any(a.severity.value.lower() in [
                                  'high', 'critical'] for a in anomalies) else "yellow"
    )


def load_config_from_env() -> PiholeConfig:
    """Load configuration from environment variables."""
    # Load environment variables
    load_dotenv()

    # Pi-hole configuration
    pihole_config = PiholeConfig(
        host=os.getenv("PIHOLE_HOST", "127.0.0.1"),
        port=int(os.getenv("PIHOLE_PORT", "80")),
        password=os.getenv("PIHOLE_PASSWORD", ""),
        timeout=int(os.getenv("PIHOLE_TIMEOUT", "10"))
    )

    if not pihole_config.password:
        raise ValueError("PIHOLE_PASSWORD environment variable is required")

    return pihole_config


def format_analysis_output(analysis_result, output_format: str = "json", queries=None) -> str:
    """Format analysis results for output with rich console formatting."""
    if output_format.lower() == "json":
        # Convert to JSON-serializable format (unchanged for JSON output)
        result_dict = {
            "timestamp": analysis_result.timestamp.isoformat(),
            "total_queries": analysis_result.total_queries,
            "blocked_queries": analysis_result.blocked_queries,
            "unique_domains": analysis_result.unique_domains,
            "unique_clients": analysis_result.unique_clients,
            "top_domains": analysis_result.top_domains,
            "top_clients": analysis_result.top_clients,
            "anomalies": [
                {
                    "timestamp": anomaly.timestamp.isoformat(),
                    "type": anomaly.anomaly_type,
                    "description": anomaly.description,
                    "severity": anomaly.severity.value,
                    "affected_domain": anomaly.affected_domain,
                    "affected_client": anomaly.affected_client,
                    "confidence": anomaly.confidence
                }
                for anomaly in analysis_result.anomalies
            ],
            "threat_summary": analysis_result.threat_summary
        }
        return json.dumps(result_dict, indent=2)

    if output_format.lower() == "text":
        # Use rich console for fancy output
        console.print()
        console.print(create_analysis_summary_table(analysis_result))
        console.print()

        # Generate top domains and clients from queries if not provided by LLM
        top_domains = analysis_result.top_domains
        top_clients = analysis_result.top_clients

        if not top_domains and queries:
            # Generate top domains from queries
            domain_counts = Counter(q.domain for q in queries)
            top_domains = [
                {"domain": domain, "count": count}
                for domain, count in domain_counts.most_common(10)
            ]

        if not top_clients and queries:
            # Generate top clients from queries
            client_stats = defaultdict(lambda: {"total": 0, "blocked": 0})
            for q in queries:
                client_stats[q.client_ip]["total"] += 1
                if q.status.value == "blocked":
                    client_stats[q.client_ip]["blocked"] += 1

            top_clients = [
                {"client": client, **stats}
                for client, stats in sorted(
                    client_stats.items(),
                    key=lambda x: x[1]["total"],
                    reverse=True
                )[:10]
            ]

        # Create columns for side-by-side display
        if top_domains and top_clients:
            columns = Columns([
                create_top_domains_table(top_domains),
                create_top_clients_table(top_clients)
            ], equal=True)
            console.print(columns)
        elif top_domains:
            console.print(create_top_domains_table(top_domains))
        elif top_clients:
            console.print(create_top_clients_table(top_clients))

        console.print()
        console.print(create_anomalies_display(analysis_result.anomalies))

        # Final risk assessment
        risk_level = analysis_result.threat_summary.get(
            'risk_level', 'unknown').upper()
        risk_colors = {
            'LOW': 'green',
            'MEDIUM': 'yellow',
            'HIGH': 'red',
            'CRITICAL': 'bright_red bold',
            'UNKNOWN': 'dim'
        }
        risk_color = risk_colors.get(risk_level, 'dim')

        risk_panel = Panel(
            f"[{risk_color}]Overall Risk Level: {risk_level}[/{risk_color}]",
            title="🎯 Final Assessment",
            border_style=risk_color.split()[0],  # Remove 'bold' for border
            expand=False
        )
        console.print(Align.center(risk_panel))
        console.print()

        return ""  # Rich console prints directly, no need to return string

    raise ValueError(f"Unsupported output format: {output_format}")


def main():
    """Main function for integrated analysis with rich console interface."""
    parser = argparse.ArgumentParser(
        description="Pi-hole LLM Analytics - Integrated Analysis Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This script integrates Pi-hole DNS log analysis with local LLM services.
It provides comprehensive analysis with better error handling and structure.

Environment Variables:
  PIHOLE_HOST         Pi-hole server hostname/IP (default: 127.0.0.1)
  PIHOLE_PORT         Pi-hole server port (default: 80)
  PIHOLE_PASSWORD     Pi-hole admin password (REQUIRED)
  PIHOLE_TIMEOUT      Pi-hole API timeout in seconds (default: 10)
  
  OLLAMA_URL          Ollama server URL (default: http://localhost:11434)
  OLLAMA_MODEL        Ollama model name (default: gpt-oss:latest)
  OLLAMA_TIMEOUT      Ollama timeout in seconds (default: 120)
  OLLAMA_TEMPERATURE  LLM temperature (default: 0.2)
  OLLAMA_MAX_TOKENS   Maximum tokens for LLM response (default: 512)
  MAX_PROMPT_CHARS    Maximum characters in LLM prompt (default: 18000)

Examples:
  python integrated_analysis.py --count 500 --output text
  python integrated_analysis.py --model llama3.2:latest --output json
        """
    )

    parser.add_argument(
        "--count",
        type=int,
        default=100,
        help="Number of recent queries to analyze (default: 100)"
    )

    parser.add_argument(
        "--model",
        type=str,
        help="Override LLM model (default: from OLLAMA_MODEL env var)"
    )

    parser.add_argument(
        "--output",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)"
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )

    parser.add_argument(
        "--test-connection",
        action="store_true",
        help="Test connections to Pi-hole and LLM services without analysis"
    )

    args = parser.parse_args()

    # Print fancy header
    print_header()

    # Set up logging
    setup_logging(verbose=args.verbose)
    logger = get_logger(__name__)

    logger.info("Starting Pi-hole LLM Analytics")

    try:
        # Load configuration
        with console.status("[bold green]Loading configuration...", spinner="dots"):
            pihole_config = load_config_from_env()

            # Initialize LLM analyzer using factory pattern with environment config
            llm_config = LLMConfig.from_env()
            llm_analyzer = LLMAnalyzer(llm_config)

            # Override model if specified via CLI
            if args.model:
                # Create new config with overridden model
                llm_config.model = args.model
                llm_analyzer = LLMAnalyzer(llm_config)
                logger.info("Using LLM model: %s", args.model)

        console.print("[green]✅ Configuration loaded successfully[/green]")

        # Display configuration
        print_config_info(pihole_config, llm_config)

        # Initialize Pi-hole client
        pihole_client = PiholeClient(pihole_config)

        # Test connections if requested
        if args.test_connection:
            console.print(
                "[bold yellow]🔍 Testing Connections...[/bold yellow]")

            pihole_success = False
            pihole_info = {}
            llm_success = False
            llm_models = []

            with console.status("[bold blue]Testing Pi-hole connection...", spinner="dots"):
                try:
                    with pihole_client:
                        pihole_info = pihole_client.get_summary()
                        pihole_success = True
                        logger.info("✅ Pi-hole connection successful")
                except (ConnectionError, TimeoutError, ValueError) as e:
                    logger.error("❌ Pi-hole connection failed: %s", e)

            with console.status("[bold blue]Testing LLM connection...", spinner="dots"):
                if llm_analyzer.test_connection():
                    llm_success = True
                    llm_models = llm_analyzer.get_available_models()
                    logger.info("✅ LLM connection successful")
                else:
                    logger.error("❌ LLM connection failed")

            print_connection_test_results(
                pihole_success, pihole_info, llm_success, llm_models)

            if pihole_success and llm_success:
                console.print(
                    "[bold green]🎉 All connections successful![/bold green]")
                return 0
            else:
                console.print("[bold red]❌ Some connections failed[/bold red]")
                return 1

        # Fetch DNS queries with progress bar
        console.print(
            f"[bold cyan]📡 Fetching {args.count:,} recent queries from Pi-hole...[/bold cyan]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:

            fetch_task = progress.add_task(
                "Fetching DNS queries...", total=100)

            with pihole_client:
                progress.update(fetch_task, advance=30)
                queries = pihole_client.fetch_queries(args.count)
                progress.update(fetch_task, advance=70)

        if not queries:
            console.print(
                "[bold red]❌ Error: No DNS queries available for analysis[/bold red]")
            error_panel = Panel(
                "This could be due to:\n"
                "• Pi-hole API restrictions\n"
                "• Incorrect authentication\n"
                "• Network connectivity issues",
                title="❌ No Data Available",
                border_style="red"
            )
            console.print(error_panel)
            return 1

        console.print(
            f"[green]✅ Successfully fetched {len(queries):,} queries[/green]")

        # Perform LLM analysis with progress
        console.print(
            "[bold magenta]🤖 Performing AI-powered analysis...[/bold magenta]")

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console
            ) as progress:

                analysis_task = progress.add_task(
                    "Analyzing with LLM...", total=100)

                progress.update(analysis_task, advance=20,
                                description="Preparing data...")
                progress.update(analysis_task, advance=50,
                                description="Running AI analysis...")

                analysis_result = llm_analyzer.analyze_queries(queries)

                progress.update(analysis_task, advance=30,
                                description="Processing results...")

            console.print(
                "[green]✅ LLM analysis completed successfully[/green]")

            # Format and output results
            if args.output == "json":
                output = format_analysis_output(
                    analysis_result, args.output, queries=queries)
                console.print(output)
            else:
                # Rich formatted output is printed directly in format_analysis_output
                format_analysis_output(
                    analysis_result, args.output, queries=queries)

            # Log summary for debugging
            logger.info("Analysis Summary:")
            logger.info("  Total queries: %d", analysis_result.total_queries)
            logger.info("  Blocked queries: %d",
                        analysis_result.blocked_queries)
            logger.info("  Unique domains: %d", analysis_result.unique_domains)
            logger.info("  Unique clients: %d", analysis_result.unique_clients)
            logger.info("  Anomalies detected: %d",
                        len(analysis_result.anomalies))
            logger.info("  Risk level: %s", analysis_result.threat_summary.get(
                'risk_level', 'unknown'))

            # Final success message
            console.print(
                "[bold green]🎯 Analysis completed successfully![/bold green]")
            return 0

        except LLMAnalysisError as e:
            logger.error("LLM analysis failed: %s", e)
            error_panel = Panel(
                f"LLM analysis failed: {e}\n\n"
                "This could be due to:\n"
                "• Ollama service not running\n"
                "• Model not available\n"
                "• Network connectivity issues",
                title="❌ LLM Analysis Failed",
                border_style="red"
            )
            console.print(error_panel)
            return 1

    except ValueError as e:
        logger.error("Configuration error: %s", e)
        error_panel = Panel(
            f"Configuration error: {e}",
            title="❌ Configuration Error",
            border_style="red"
        )
        console.print(error_panel)
        return 1

    except KeyboardInterrupt:
        logger.info("Analysis interrupted by user")
        console.print("\n[yellow]⚠️ Analysis interrupted by user[/yellow]")
        return 130

    except (LLMAnalysisError, ConnectionError, TimeoutError) as e:
        logger.error("Analysis error: %s", e, exc_info=True)
        error_panel = Panel(
            f"Analysis error: {e}",
            title="❌ Analysis Error",
            border_style="red"
        )
        console.print(error_panel)
        return 1

    finally:
        logger.info("Analysis completed")


if __name__ == "__main__":
    sys.exit(main())
