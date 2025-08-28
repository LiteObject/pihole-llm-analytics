#!/usr/bin/env python3
"""
Example usage of the integrated Pi-hole LLM Analytics.

This script demonstrates how to use the new integrated architecture
to perform DNS log analysis with LLM insights.
"""

from pihole_analytics.utils.logging import setup_logging, get_logger
from pihole_analytics.utils.config import PiholeConfig
from pihole_analytics.analytics.llm_analyzer import LLMAnalyzer, LLMConfig
from pihole_analytics.core.pihole_client import PiholeClient
import os
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))


def main():
    """Demonstrate the integrated analytics functionality."""
    # Set up logging
    setup_logging(verbose=True)
    logger = get_logger(__name__)

    logger.info("Starting Pi-hole LLM Analytics Example")

    try:
        # Configuration (you can also use environment variables)
        pihole_config = PiholeConfig(
            host="192.168.7.99",  # Replace with your Pi-hole IP
            port=8080,            # Replace with your Pi-hole port
            password="your_actual_password_here",  # Replace with your password
            timeout=10
        )

        llm_config = LLMConfig(
            url="http://localhost:11434",
            model="gpt-oss:latest",
            timeout=120
        )

        logger.info("Initializing clients...")

        # Initialize clients
        pihole_client = PiholeClient(pihole_config)
        llm_analyzer = LLMAnalyzer(llm_config)

        # Test connections
        logger.info("Testing LLM connection...")
        if not llm_analyzer.test_connection():
            logger.warning(
                "LLM service not available, analysis may be limited")

        logger.info("Testing Pi-hole connection and fetching queries...")

        # Fetch and analyze queries
        with pihole_client:
            # Get version info
            try:
                version_info = pihole_client.get_version()
                logger.info("Pi-hole version: %s",
                            version_info.get('version', 'unknown'))
            except Exception as e:
                logger.warning("Could not get Pi-hole version: %s", e)

            # Get summary
            try:
                summary = pihole_client.get_summary()
                total_queries = summary.get('queries_all_types', 'unknown')
                logger.info("Pi-hole summary - Total queries: %s",
                            total_queries)
            except Exception as e:
                logger.warning("Could not get Pi-hole summary: %s", e)

            # Fetch recent queries
            queries = pihole_client.fetch_queries(
                50)  # Fetch 50 recent queries

            if not queries:
                logger.error("No queries retrieved from Pi-hole")
                print("❌ No DNS queries available for analysis")
                print(
                    "This could be due to Pi-hole API restrictions or authentication issues")
                return 1

            logger.info("✅ Successfully fetched %d queries", len(queries))

            # Show sample queries
            print(f"\n📋 Sample Queries (showing first 5 of {len(queries)}):")
            for i, query in enumerate(queries[:5]):
                print(f"  {i+1}. {query.timestamp.strftime('%H:%M:%S')} - "
                      f"{query.client_ip} -> {query.domain} ({query.status.value})")

            # Perform LLM analysis
            print("\n🤖 Performing LLM Analysis...")
            try:
                analysis_result = llm_analyzer.analyze_queries(queries)

                print("✅ LLM Analysis Complete!")
                print(f"\n📊 Analysis Results:")
                print(f"  Total Queries: {analysis_result.total_queries}")
                print(f"  Blocked Queries: {analysis_result.blocked_queries}")
                print(
                    f"  Block Rate: {(analysis_result.blocked_queries/analysis_result.total_queries*100):.1f}%")
                print(f"  Unique Domains: {analysis_result.unique_domains}")
                print(f"  Unique Clients: {analysis_result.unique_clients}")

                # Show top domains if available
                if analysis_result.top_domains:
                    print(f"\n🏆 Top Domains:")
                    for domain in analysis_result.top_domains[:5]:
                        if isinstance(domain, dict):
                            print(
                                f"  • {domain.get('domain', 'Unknown')}: {domain.get('count', 0)} queries")

                # Show top clients if available
                if analysis_result.top_clients:
                    print(f"\n👥 Top Clients:")
                    for client in analysis_result.top_clients[:5]:
                        if isinstance(client, dict):
                            total = client.get('total', 0)
                            blocked = client.get('blocked', 0)
                            print(
                                f"  • {client.get('client', 'Unknown')}: {total} queries ({blocked} blocked)")

                # Show anomalies if any
                if analysis_result.anomalies:
                    print(
                        f"\n⚠️  Security Anomalies Detected ({len(analysis_result.anomalies)}):")
                    # Show first 3
                    for anomaly in analysis_result.anomalies[:3]:
                        print(f"  • {anomaly.description}")
                        print(f"    Severity: {anomaly.severity.value}")
                        if anomaly.affected_domain:
                            print(f"    Domain: {anomaly.affected_domain}")

                # Show risk assessment
                risk_level = analysis_result.threat_summary.get(
                    'risk_level', 'unknown')
                risk_icons = {
                    'minimal': '🟢',
                    'low': '🟡',
                    'medium': '🟠',
                    'high': '🔴',
                    'unknown': '⚪'
                }
                risk_icon = risk_icons.get(risk_level, '⚪')
                print(f"\n{risk_icon} Overall Risk Level: {risk_level.upper()}")

                # Export as JSON
                print(f"\n💾 Analysis exported as JSON:")
                json_output = analysis_result.to_json()
                print(json_output[:500] +
                      "..." if len(json_output) > 500 else json_output)

            except Exception as e:
                logger.error("LLM analysis failed: %s", e)
                print(f"❌ LLM analysis failed: {e}")
                print("This could be due to:")
                print("  - Ollama service not running")
                print("  - Model not available")
                print("  - Network connectivity issues")
                return 1

    except Exception as e:
        logger.error("Example failed: %s", e, exc_info=True)
        print(f"❌ Example failed: {e}")
        return 1

    print(f"\n🎉 Example completed successfully!")
    print(f"\nNext steps:")
    print(f"  1. Update the configuration with your actual Pi-hole credentials")
    print(f"  2. Ensure Ollama is running with your preferred model")
    print(f"  3. Try the full CLI: python -m pihole_analytics analyze --count 100")
    print(f"  4. Use the integrated script: python integrated_analysis.py")

    return 0


if __name__ == "__main__":
    sys.exit(main())
