#!/usr/bin/env python3
"""
Command-line interface for Pi-hole LLM Analytics.

This script provides a command-line interface for running analytics
and generating reports on Pi-hole DNS logs.
"""

import argparse
import json
import sys
import traceback

from pihole_analytics.main import PiholeAnalytics
from pihole_analytics.utils.config import get_config
from pihole_analytics.utils.logging import setup_logging


def format_json_output(data: dict) -> str:
    """Format output as pretty JSON."""
    return json.dumps(data, indent=2, default=str)


def format_table_output(data: dict) -> str:
    """Format summary data as a simple table."""
    if "summary" not in data:
        return format_json_output(data)

    summary = data["summary"]
    lines = []
    lines.append("=== Pi-hole DNS Analytics Summary ===")
    lines.append(f"Timestamp: {data.get('timestamp', 'N/A')}")
    lines.append("")
    lines.append(f"{'Metric':<20} {'Value':<15}")
    lines.append("-" * 35)
    lines.append(
        f"{'Total Queries':<20} {summary.get('total_queries', 'N/A'):<15}")
    lines.append(
        f"{'Blocked Queries':<20} {summary.get('blocked_queries', 'N/A'):<15}")
    lines.append(f"{'Block Rate':<20} {summary.get('block_rate', 0)*100:.1f}%")
    lines.append(
        f"{'Unique Domains':<20} {summary.get('unique_domains', 'N/A'):<15}")
    lines.append(
        f"{'Unique Clients':<20} {summary.get('unique_clients', 'N/A'):<15}")
    lines.append(
        f"{'Anomalies':<20} {summary.get('anomalies_detected', 'N/A'):<15}")
    lines.append(
        f"{'Alerts':<20} {summary.get('alerts_generated', 'N/A'):<15}")

    # Add alerts if present
    if data.get("alerts"):
        lines.append("")
        lines.append("=== Security Alerts ===")
        for alert in data["alerts"]:
            lines.append(
                f"• {alert.get('title', 'Unknown Alert')} [{alert.get('severity', 'Unknown')}]")
            if alert.get('description'):
                lines.append(f"  {alert['description']}")

    return "\n".join(lines)


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
            else:  # table
                print(format_table_output(result))

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
