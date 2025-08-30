#!/usr/bin/env python3
"""
Command-line interface for Pi-hole LLM Analytics.

This script provides a command-line interface for running analytics
and generating reports on Pi-hole DNS logs with rich console formatting.
"""

import argparse
import json
import sys
import traceback
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.tree import Tree
from rich.columns import Columns
from rich.align import Align
from rich import box

from pihole_analytics.main import PiholeAnalytics
from pihole_analytics.utils.config import get_config
from pihole_analytics.utils.logging import setup_logging

# Initialize Rich console
console = Console()


def print_cli_header(command: str):
    """Print a fancy header for CLI commands."""
    header_text = Text(
        f"🛡️  Pi-hole LLM Analytics - {command.title()}", style="bold magenta")
    subtitle = Text("Intelligent DNS Analysis with AI", style="dim cyan")

    header_panel = Panel(
        Align.center(f"{header_text}\n{subtitle}"),
        box=box.DOUBLE,
        border_style="bright_blue",
        padding=(1, 2)
    )
    console.print(header_panel)
    console.print()


def format_json_output(data: dict) -> str:
    """Format output as pretty JSON."""
    return json.dumps(data, indent=2, default=str)


def create_summary_table(summary: dict, timestamp: Optional[str] = None) -> Table:
    """Create a Rich table for summary data."""
    summary_table = Table(title="📊 Analysis Summary", box=box.ROUNDED)
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", justify="right", style="green")
    summary_table.add_column("Details", style="dim")

    # Calculate block rate
    block_rate = summary.get('block_rate', 0) * 100

    summary_table.add_row(
        "Total Queries",
        f"{summary.get('total_queries', 'N/A'):,}",
        f"Analyzed at {timestamp or 'N/A'}"
    )
    summary_table.add_row(
        "Blocked Queries",
        f"{summary.get('blocked_queries', 'N/A'):,}",
        f"{block_rate:.1f}% block rate"
    )
    summary_table.add_row(
        "Unique Domains",
        f"{summary.get('unique_domains', 'N/A'):,}",
        "Different domains accessed"
    )
    summary_table.add_row(
        "Unique Clients",
        f"{summary.get('unique_clients', 'N/A'):,}",
        "Active network devices"
    )
    summary_table.add_row(
        "Anomalies",
        f"{summary.get('anomalies_detected', 'N/A'):,}",
        "Security anomalies detected"
    )
    summary_table.add_row(
        "Alerts",
        f"{summary.get('alerts_generated', 'N/A'):,}",
        "Security alerts generated"
    )

    return summary_table


def create_alerts_display(alerts: list) -> Panel:
    """Create a display for security alerts."""
    if not alerts:
        return Panel(
            "[green]✅ No security alerts detected[/green]",
            title="🚨 Security Alerts",
            border_style="green"
        )

    alerts_tree = Tree("🚨 Security Alerts")

    severity_colors = {
        'low': 'yellow',
        'medium': 'orange',
        'high': 'red',
        'critical': 'bright_red bold'
    }

    for alert in alerts[:10]:  # Show max 10 alerts
        severity = alert.get('severity', 'unknown').lower()
        severity_color = severity_colors.get(severity, 'white')

        alert_branch = alerts_tree.add(
            f"[{severity_color}]{severity.upper()}[/{severity_color}] - "
            f"{alert.get('title', 'Unknown Alert')}"
        )

        if alert.get('description'):
            alert_branch.add(f"📝 {alert['description']}")
        if alert.get('timestamp'):
            alert_branch.add(f"⏰ Time: {alert['timestamp']}")

    return Panel(
        alerts_tree,
        title="🚨 Security Alerts",
        border_style="red" if any(a.get('severity', '').lower() in [
                                  'high', 'critical'] for a in alerts) else "yellow"
    )


def format_table_output(data: dict) -> str:
    """Format summary data as a Rich table with colors and styling."""
    # Handle status command first (has "components" but no "summary")
    if "components" in data and "summary" not in data:
        # Print header for status
        print_cli_header("Status")

        # Show system status table
        status_table = Table(title="🔗 System Status", box=box.ROUNDED)
        status_table.add_column("Component", style="cyan")
        status_table.add_column("Status", justify="center")
        status_table.add_column("Details", style="dim")

        for component, info in data["components"].items():
            status = info.get("status", "unknown")
            status_display = {
                "healthy": "✅ Healthy",
                "unhealthy": "⚠️ Unhealthy",
                "error": "❌ Error"
            }.get(status, f"❓ {status}")

            details = info.get("error", info.get("note", "OK"))
            if info.get("model"):
                details = f"Model: {info['model']}"

            status_table.add_row(component.replace(
                "_", " ").title(), status_display, details)

        console.print(status_table)
        console.print()

        # Overall status
        overall_status = data.get("overall_status", "unknown").upper()
        status_colors = {"HEALTHY": "green",
                         "DEGRADED": "yellow", "ERROR": "red"}
        status_color = status_colors.get(overall_status, "dim")

        status_panel = Panel(
            f"[{status_color}]Overall Status: {overall_status}[/{status_color}]",
            title="🎯 System Health",
            border_style=status_color,
            expand=False
        )
        console.print(Align.center(status_panel))
        return ""  # Rich console prints directly

    # Handle analysis/report commands (have "summary")
    if "summary" not in data:
        return format_json_output(data)

    # Print header
    command_name = "Analysis" if "analysis" in data else "Report"
    print_cli_header(command_name)

    # Show summary table
    timestamp_str = data.get("timestamp")
    console.print(create_summary_table(data["summary"], timestamp_str))
    console.print()

    # Show alerts if present
    if data.get("alerts"):
        console.print(create_alerts_display(data["alerts"]))
        console.print()

    return ""  # Rich console prints directly


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Pi-hole LLM Analytics - DNS log analysis and threat detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m pihole_analytics analyze --count 1000
  python -m pihole_analytics report --type security --days 7
  python -m pihole_analytics search "suspicious DNS queries from last hour"
  python -m pihole_analytics status
  python -m pihole_analytics client-analysis 192.168.1.100 --hours 24
        """
    )

    # Global options
    parser.add_argument(
        "--config",
        type=str,
        help="Path to configuration file"
    )
    parser.add_argument(
        "--output",
        choices=["json", "table", "text"],
        default="table",
        help="Output format (default: table)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )

    # Subcommands
    subparsers = parser.add_subparsers(
        dest="command", help="Available commands")

    # Analyze command
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Run comprehensive DNS log analysis"
    )
    analyze_parser.add_argument(
        "--count",
        type=int,
        help="Number of recent queries to analyze"
    )

    # Report command
    report_parser = subparsers.add_parser(
        "report",
        help="Generate analytics reports"
    )
    report_parser.add_argument(
        "--type",
        choices=["daily", "weekly", "security"],
        default="daily",
        help="Type of report to generate (default: daily)"
    )
    report_parser.add_argument(
        "--days",
        type=int,
        default=1,
        help="Number of days to include in report (default: 1)"
    )

    # Search command
    search_parser = subparsers.add_parser(
        "search",
        help="Search DNS logs with natural language queries"
    )
    search_parser.add_argument(
        "query",
        type=str,
        help="Natural language search query"
    )
    search_parser.add_argument(
        "--count",
        type=int,
        help="Number of recent queries to search through"
    )

    # Status command
    subparsers.add_parser(
        "status",
        help="Check system status and health"
    )

    # Categorize command
    categorize_parser = subparsers.add_parser(
        "categorize",
        help="Categorize domains using LLM"
    )
    categorize_parser.add_argument(
        "domains",
        nargs="+",
        help="List of domains to categorize"
    )

    # Reputation command
    reputation_parser = subparsers.add_parser(
        "reputation",
        help="Check domain reputation"
    )
    reputation_parser.add_argument(
        "domain",
        type=str,
        help="Domain to check"
    )

    # Client analysis command
    client_parser = subparsers.add_parser(
        "client-analysis",
        help="Analyze specific client activity"
    )
    client_parser.add_argument(
        "client_ip",
        type=str,
        help="IP address of client to analyze"
    )
    client_parser.add_argument(
        "--hours",
        type=int,
        default=24,
        help="Number of hours to analyze (default: 24)"
    )

    # Parse arguments
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Set up logging
    setup_logging()

    try:
        # Initialize analytics
        config = get_config()
        analytics = PiholeAnalytics(config)

        # Execute command
        result = None

        if args.command == "analyze":
            result = analytics.run_analysis(args.count)

        elif args.command == "report":
            result = analytics.generate_report(args.type, args.days)

        elif args.command == "search":
            result = analytics.search_logs(args.query, args.count)

        elif args.command == "status":
            result = analytics.get_system_status()

        elif args.command == "categorize":
            result = analytics.categorize_domains(args.domains)

        elif args.command == "reputation":
            result = analytics.check_domain_reputation(args.domain)

        elif args.command == "client-analysis":
            result = analytics.get_client_analysis(args.client_ip, args.hours)

        # Format and output result
        if result:
            if args.output == "json":
                print(format_json_output(result))
            elif args.output == "text":
                print(analytics.export_results(result, "txt"))
            else:  # table - use Rich formatting
                # This prints directly via Rich console
                format_table_output(result)

        # Return appropriate exit code
        if result and result.get("error"):
            return 1
        return 0

    except (KeyboardInterrupt, SystemExit) as e:
        if isinstance(e, KeyboardInterrupt):
            print("\nOperation cancelled by user", file=sys.stderr)
            return 130
        raise
    except (ConnectionError, TimeoutError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
