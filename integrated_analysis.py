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
from pathlib import Path

from dotenv import load_dotenv

from pihole_analytics.analytics.llm_analyzer import LLMAnalyzer, LLMAnalysisError
from pihole_analytics.analytics.llm_providers.base import LLMConfig
from pihole_analytics.core.pihole_client import PiholeClient
from pihole_analytics.utils.config import PiholeConfig
from pihole_analytics.utils.logging import setup_logging, get_logger

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))


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


def format_analysis_output(analysis_result, output_format: str = "json") -> str:
    """Format analysis results for output."""
    if output_format.lower() == "json":
        # Convert to JSON-serializable format
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
        lines = []
        lines.append("=== Pi-hole LLM Analysis Results ===")
        lines.append(f"Analysis Time: {analysis_result.timestamp}")
        lines.append(
            f"Total Queries Analyzed: {analysis_result.total_queries}")
        lines.append(f"Blocked Queries: {analysis_result.blocked_queries}")
        # Calculate block rate with proper line length
        if analysis_result.total_queries > 0:
            block_rate = (analysis_result.blocked_queries /
                          analysis_result.total_queries * 100)
            lines.append(f"Block Rate: {block_rate:.1f}%")
        else:
            lines.append("Block Rate: 0%")
        lines.append(f"Unique Domains: {analysis_result.unique_domains}")
        lines.append(f"Unique Clients: {analysis_result.unique_clients}")
        lines.append("")

        if analysis_result.top_domains:
            lines.append("=== Top Domains ===")
            for domain in analysis_result.top_domains[:10]:
                if isinstance(domain, dict):
                    lines.append(
                        f"  {domain.get('domain', 'Unknown')}: {domain.get('count', 0)} queries")
                else:
                    lines.append(f"  {domain}")
            lines.append("")

        if analysis_result.top_clients:
            lines.append("=== Top Clients ===")
            for client in analysis_result.top_clients[:10]:
                if isinstance(client, dict):
                    total = client.get('total', 0)
                    blocked = client.get('blocked', 0)
                    lines.append(
                        f"  {client.get('client', 'Unknown')}: {total} queries ({blocked} blocked)")
                else:
                    lines.append(f"  {client}")
            lines.append("")

        if analysis_result.anomalies:
            lines.append("=== Security Anomalies ===")
            for anomaly in analysis_result.anomalies:
                lines.append(f"  • {anomaly.description}")
                lines.append(f"    Severity: {anomaly.severity.value}")
                if anomaly.affected_domain:
                    lines.append(f"    Domain: {anomaly.affected_domain}")
                if anomaly.affected_client:
                    lines.append(f"    Client: {anomaly.affected_client}")
                lines.append(f"    Confidence: {anomaly.confidence:.1%}")
                lines.append("")

        risk_level = analysis_result.threat_summary.get(
            'risk_level', 'unknown')
        lines.append(f"=== Overall Risk Level: {risk_level.upper()} ===")

        return "\n".join(lines)

    raise ValueError(f"Unsupported output format: {output_format}")


def main():
    """Main function for integrated analysis."""
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

    # Set up logging
    setup_logging(verbose=args.verbose)
    logger = get_logger(__name__)

    logger.info("Starting Pi-hole LLM Analytics")

    try:
        # Load configuration
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

        logger.info("Configuration loaded successfully")
        logger.info("Pi-hole: %s:%d", pihole_config.host, pihole_config.port)
        logger.info("LLM: %s (model: %s)",
                    llm_config.provider.value, llm_config.model)

        # Initialize Pi-hole client
        pihole_client = PiholeClient(pihole_config)

        # Test connections if requested
        if args.test_connection:
            logger.info("Testing Pi-hole connection...")
            try:
                with pihole_client:
                    summary = pihole_client.get_summary()
                    logger.info("✅ Pi-hole connection successful")
                    logger.info("Pi-hole status: %s",
                                summary.get('status', 'unknown'))
            except (ConnectionError, TimeoutError, ValueError) as e:
                logger.error("❌ Pi-hole connection failed: %s", e)
                return 1

            logger.info("Testing LLM connection...")
            if llm_analyzer.test_connection():
                logger.info("✅ LLM connection successful")
                models = llm_analyzer.get_available_models()
                logger.info("Available models: %s", models[:5])
            else:
                logger.error("❌ LLM connection failed")
                return 1

            logger.info("All connections successful!")
            return 0

        # Fetch DNS queries
        logger.info("Fetching %d recent queries from Pi-hole...", args.count)

        with pihole_client:
            queries = pihole_client.fetch_queries(args.count)

        if not queries:
            logger.error("No queries retrieved from Pi-hole")
            print("Error: No DNS queries available for analysis", file=sys.stderr)
            print("This could be due to:", file=sys.stderr)
            print("  - Pi-hole API restrictions", file=sys.stderr)
            print("  - Incorrect authentication", file=sys.stderr)
            print("  - Network connectivity issues", file=sys.stderr)
            return 1

        logger.info("Successfully fetched %d queries", len(queries))

        # Perform LLM analysis
        logger.info("Performing LLM analysis...")

        try:
            analysis_result = llm_analyzer.analyze_queries(queries)
            logger.info("LLM analysis completed successfully")

            # Format and output results
            output = format_analysis_output(analysis_result, args.output)
            print(output)

            # Log summary
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

            return 0

        except LLMAnalysisError as e:
            logger.error("LLM analysis failed: %s", e)
            print(f"Error: LLM analysis failed: {e}", file=sys.stderr)
            print("This could be due to:", file=sys.stderr)
            print("  - Ollama service not running", file=sys.stderr)
            print("  - Model not available", file=sys.stderr)
            print("  - Network connectivity issues", file=sys.stderr)
            return 1

    except ValueError as e:
        logger.error("Configuration error: %s", e)
        print(f"Configuration error: {e}", file=sys.stderr)
        return 1

    except KeyboardInterrupt:
        logger.info("Analysis interrupted by user")
        print("\nAnalysis interrupted by user", file=sys.stderr)
        return 130

    except (LLMAnalysisError, ConnectionError, TimeoutError) as e:
        logger.error("Analysis error: %s", e, exc_info=True)
        print(f"Analysis error: {e}", file=sys.stderr)
        return 1

    finally:
        logger.info("Analysis completed")


if __name__ == "__main__":
    sys.exit(main())
