"""
Main Application Interface.

This module provides the primary interface for the Pi-hole LLM Analytics application,
orchestrating all components and providing high-level functionality.
"""

import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

from .core.pihole_client import PiholeClient, PiholeAPIError
from .core.llm_client import LLMClient
from .analytics.analyzer import DNSAnalyzer
from .analytics.llm_analyzer import LLMAnalyzer, LLMConfig, LLMAnalysisError
from .security.threat_detector import ThreatDetector
from .utils.config import get_config, AppConfig
from .utils.logging import setup_logging, LoggerMixin
from .utils.models import DNSQuery, AnalysisResult, Alert, QueryStatus


class PiholeAnalytics(LoggerMixin):
    """Main application class for Pi-hole LLM Analytics."""

    def __init__(self, config: Optional[AppConfig] = None):
        """Initialize the analytics application."""
        # Set up logging first
        setup_logging()

        # Use provided config or get default
        self.config = config or get_config()

        # Initialize clients
        self.pihole_client = PiholeClient(self.config.pihole)
        self.llm_client = LLMClient(self.config.llm)

        # Initialize analyzers
        self.dns_analyzer = DNSAnalyzer(self.llm_client, self.config.analytics)
        self.llm_analyzer = LLMAnalyzer(LLMConfig.from_env())
        self.threat_detector = ThreatDetector(
            self.llm_client, self.config.security)

        self.logger.info("Pi-hole Analytics application initialized")

    def run_analysis(self, count: Optional[int] = None) -> Dict[str, Any]:
        """
        Run comprehensive DNS log analysis.

        Args:
            count: Number of queries to analyze (uses config default if None)

        Returns:
            Complete analysis results
        """
        count = count or self.config.analytics.log_count
        self.log_method_call("run_analysis", count=count)

        try:
            # Check LLM health
            if not self.llm_analyzer.test_connection():
                self.logger.warning(
                    "LLM service is not available, continuing with basic analysis")

            # Fetch DNS queries
            with self.pihole_client as client:
                queries = client.fetch_queries(count)

            if not queries:
                self.logger.warning("No queries retrieved from Pi-hole")
                return {"error": "No queries available for analysis"}

            # Perform LLM-powered analysis if available
            llm_analysis_result = None
            try:
                llm_analysis_result = self.llm_analyzer.analyze_queries(
                    queries)
                self.logger.info("LLM analysis completed successfully")
            except LLMAnalysisError as e:
                self.logger.warning(
                    "LLM analysis failed, continuing with basic analysis: %s", e)

            # Perform traditional DNS analysis as fallback/supplement
            analysis_result = self.dns_analyzer.analyze_queries(queries)

            # Perform threat analysis
            threat_analysis = None
            alerts = []
            if self.config.security.enable_threat_detection:
                threat_analysis = self.threat_detector.analyze_threats(queries)
                alerts = self.threat_detector.generate_alerts(
                    threat_analysis, queries)

            # Compile results
            results = {
                "timestamp": datetime.now().isoformat(),
                "query_count": len(queries),
                "analysis": analysis_result.__dict__ if analysis_result else {},
                "llm_analysis": llm_analysis_result.__dict__ if llm_analysis_result else None,
                "threat_analysis": threat_analysis,
                "alerts": [alert.__dict__ for alert in alerts],
                "summary": self._generate_summary(
                    llm_analysis_result or analysis_result,
                    threat_analysis,
                    alerts
                )
            }

            self.logger.info("Analysis completed successfully")
            return results

        except (ConnectionError, TimeoutError, ValueError, RuntimeError) as error:
            self.log_error(error, {"operation": "run_analysis"})
            return {"error": str(error), "timestamp": datetime.now().isoformat()}

    def generate_report(self, report_type: str = "daily", days: int = 1) -> Dict[str, Any]:
        """
        Generate comprehensive reports.

        Args:
            report_type: Type of report (daily, weekly, security)
            days: Number of days to include in analysis

        Returns:
            Report data
        """
        self.log_method_call(
            "generate_report", report_type=report_type, days=days)

        try:
            # Calculate query count based on days and expected volume
            estimated_queries_per_day = 2000  # Configurable estimate
            count = min(days * estimated_queries_per_day,
                        10000)  # Cap at 10k for performance

            # Fetch queries
            with self.pihole_client as client:
                queries = client.fetch_queries(count)

            if not queries:
                return {"error": "No queries available for report generation"}

            # Filter queries by date range if needed
            if days < 30:  # Only filter for reasonable time ranges
                cutoff_date = datetime.now() - timedelta(days=days)
                queries = [q for q in queries if q.timestamp >= cutoff_date]

            # Generate report
            report = self.dns_analyzer.generate_report(queries, report_type)

            # Add threat analysis for security reports
            if report_type == "security":
                threat_analysis = self.threat_detector.analyze_threats(queries)
                alerts = self.threat_detector.generate_alerts(
                    threat_analysis, queries)

                report["threat_analysis"] = threat_analysis
                report["active_alerts"] = [alert.__dict__ for alert in alerts]

            self.logger.info("Report generated successfully: %s", report_type)
            return report

        except (ConnectionError, TimeoutError, ValueError, RuntimeError) as error:
            self.log_error(error, {"operation": "generate_report"})
            return {"error": str(error), "timestamp": datetime.now().isoformat()}

    def search_logs(self, search_query: str, count: Optional[int] = None) -> Dict[str, Any]:
        """
        Perform natural language search over DNS logs.

        Args:
            search_query: Natural language search query
            count: Number of recent queries to search through

        Returns:
            Search results
        """
        count = count or self.config.analytics.log_count * 2  # Search larger dataset
        self.log_method_call(
            "search_logs", search_query=search_query, count=count)

        try:
            # Fetch queries
            with self.pihole_client as client:
                queries = client.fetch_queries(count)

            if not queries:
                return {"error": "No queries available for search"}

            # Perform search
            search_results = self.dns_analyzer.search_queries(
                queries, search_query)

            self.logger.info("Search completed: %d matches found",
                             search_results.get("match_count", 0))
            return search_results

        except (ConnectionError, TimeoutError, ValueError, RuntimeError) as error:
            self.log_error(error, {"operation": "search_logs"})
            return {"error": str(error), "timestamp": datetime.now().isoformat()}

    def categorize_domains(self, domains: List[str]) -> Dict[str, Any]:
        """
        Categorize a list of domains using LLM.

        Args:
            domains: List of domain names to categorize

        Returns:
            Domain categorization results
        """
        self.log_method_call("categorize_domains", domain_count=len(domains))

        try:
            result = self.llm_client.analyze_dns_logs(
                domains, analysis_type="categorization")

            self.logger.info(
                "Domain categorization completed for %d domains", len(domains))
            return {
                "timestamp": datetime.now().isoformat(),
                "domains_categorized": len(domains),
                "categorization": result
            }

        except (ConnectionError, TimeoutError, ValueError, RuntimeError) as error:
            self.log_error(error, {"operation": "categorize_domains"})
            return {"error": str(error), "timestamp": datetime.now().isoformat()}

    def check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """
        Check reputation of a specific domain.

        Args:
            domain: Domain to check

        Returns:
            Domain reputation information
        """
        self.log_method_call("check_domain_reputation", domain=domain)

        try:
            # Use threat detector to analyze domain
            fake_query = DNSQuery(
                timestamp=datetime.now(),
                domain=domain,
                client_ip="analysis",
                status=QueryStatus.UNKNOWN
            )

            threat_analysis = self.threat_detector.analyze_threats([
                                                                   fake_query])

            # Get LLM analysis
            llm_analysis = self.llm_client.analyze_dns_logs(
                [domain],
                analysis_type="security"
            )

            return {
                "domain": domain,
                "timestamp": datetime.now().isoformat(),
                "threat_analysis": threat_analysis,
                "llm_analysis": llm_analysis
            }

        except (ConnectionError, TimeoutError, ValueError, RuntimeError) as error:
            self.log_error(error, {"operation": "check_domain_reputation"})
            return {"error": str(error), "domain": domain}

    def get_client_analysis(self, client_ip: str, hours: int = 24) -> Dict[str, Any]:
        """
        Get detailed analysis for a specific client.

        Args:
            client_ip: IP address of the client
            hours: Number of hours to analyze

        Returns:
            Client analysis results
        """
        self.log_method_call("get_client_analysis",
                             client_ip=client_ip, hours=hours)

        try:
            # Fetch queries (larger dataset for client-specific analysis)
            count = self.config.analytics.log_count * 3

            with self.pihole_client as client:
                all_queries = client.fetch_queries(count)

            # Filter queries for the specific client
            cutoff_time = datetime.now() - timedelta(hours=hours)
            client_queries = [
                q for q in all_queries
                if q.client_ip == client_ip and q.timestamp >= cutoff_time
            ]

            if not client_queries:
                return {
                    "client_ip": client_ip,
                    "error": f"No queries found for client {client_ip} in the last {hours} hours"
                }

            # Analyze client queries
            analysis = self.dns_analyzer.analyze_queries(client_queries)
            threat_analysis = self.threat_detector.analyze_threats(
                client_queries)

            # Calculate client-specific metrics
            unique_domains = len(set(q.domain for q in client_queries))
            blocked_queries = sum(
                1 for q in client_queries if "block" in q.status.value.lower())

            return {
                "client_ip": client_ip,
                "analysis_period_hours": hours,
                "timestamp": datetime.now().isoformat(),
                "summary": {
                    "total_queries": len(client_queries),
                    "unique_domains": unique_domains,
                    "blocked_queries": blocked_queries,
                    "block_rate": blocked_queries / len(client_queries) if client_queries else 0
                },
                "analysis": analysis.__dict__,
                "threat_analysis": threat_analysis
            }

        except (ConnectionError, TimeoutError, ValueError, RuntimeError) as error:
            self.log_error(error, {"operation": "get_client_analysis"})
            return {"error": str(error), "client_ip": client_ip}

    def get_system_status(self) -> Dict[str, Any]:
        """
        Get system status and health information.

        Returns:
            System status information
        """
        self.log_method_call("get_system_status")

        status = {
            "timestamp": datetime.now().isoformat(),
            "version": self.config.version,
            "components": {}
        }

        # Check Pi-hole connectivity
        try:
            with self.pihole_client as client:
                # Try to get summary, but don't fail if endpoint doesn't exist
                try:
                    summary = client.get_summary()
                    status["components"]["pihole"] = {
                        "status": "healthy",
                        "summary": summary
                    }
                except (ConnectionError, TimeoutError, ValueError, RuntimeError, AttributeError, PiholeAPIError):
                    # If summary fails, just check basic connectivity
                    status["components"]["pihole"] = {
                        "status": "healthy",
                        "note": "Pi-hole connected but summary endpoint unavailable"
                    }
        except (ConnectionError, TimeoutError, ValueError, RuntimeError, PiholeAPIError) as error:
            status["components"]["pihole"] = {
                "status": "error",
                "error": str(error)
            }

        # Check LLM connectivity
        try:
            llm_healthy = self.llm_analyzer.test_connection()
            available_models = self.llm_analyzer.get_available_models()
            status["components"]["llm_analyzer"] = {
                "status": "healthy" if llm_healthy else "unhealthy",
                "model": self.llm_analyzer.config.model,
                "url": self.llm_analyzer.config.url,
                # Limit to first 5
                "available_models": available_models[:5] if available_models else []
            }
        except Exception as error:
            status["components"]["llm_analyzer"] = {
                "status": "error",
                "error": str(error)
            }

        # Check legacy LLM client (if still used)
        try:
            llm_healthy = self.llm_client.check_health()
            status["components"]["llm_client"] = {
                "status": "healthy" if llm_healthy else "unhealthy",
                "model": self.config.llm.model,
                "url": self.config.llm.url
            }
        except Exception as error:
            status["components"]["llm_client"] = {
                "status": "error",
                "error": str(error)
            }

        # Overall health
        all_healthy = all(
            comp.get("status") == "healthy"
            for comp in status["components"].values()
        )
        status["overall_status"] = "healthy" if all_healthy else "degraded"

        return status

    def _generate_summary(self,
                          analysis: AnalysisResult,
                          threat_analysis: Optional[Dict[str, Any]],
                          alerts: List[Alert]) -> Dict[str, Any]:
        """Generate high-level summary of analysis results."""
        summary = {
            "total_queries": analysis.total_queries,
            "blocked_queries": analysis.blocked_queries,
            "block_rate": analysis.blocked_queries / analysis.total_queries if analysis.total_queries > 0 else 0,
            "unique_domains": analysis.unique_domains,
            "unique_clients": analysis.unique_clients,
            "anomalies_detected": len(analysis.anomalies),
            "alerts_generated": len(alerts)
        }

        # Add threat summary if available
        if threat_analysis:
            summary["threats_detected"] = threat_analysis.get(
                "threats_detected", 0)
            summary["malicious_domains"] = len(
                threat_analysis.get("malicious_domains", []))
            summary["suspicious_clients"] = len(
                threat_analysis.get("suspicious_clients", []))

        # Add alert severity breakdown
        alert_severities = {}
        for alert in alerts:
            severity = alert.severity.value
            alert_severities[severity] = alert_severities.get(severity, 0) + 1
        summary["alert_severities"] = alert_severities

        return summary

    def export_results(self, results: Dict[str, Any], format_type: str = "json") -> str:
        """
        Export analysis results in specified format.

        Args:
            results: Analysis results to export
            format_type: Export format (json, csv, txt)

        Returns:
            Formatted results string
        """
        self.log_method_call("export_results", format_type=format_type)

        if format_type.lower() == "json":
            return json.dumps(results, indent=2, default=str)
        elif format_type.lower() == "txt":
            return self._format_results_as_text(results)
        else:
            raise ValueError(f"Unsupported export format: {format_type}")

    def _format_results_as_text(self, results: Dict[str, Any]) -> str:
        """Format results as human-readable text."""
        lines = []
        lines.append("=== Pi-hole DNS Analytics Report ===")
        lines.append(f"Generated: {results.get('timestamp', 'N/A')}")
        lines.append("")

        # Summary
        if "summary" in results:
            summary = results["summary"]
            lines.append("SUMMARY:")
            lines.append(
                f"  Total Queries: {summary.get('total_queries', 'N/A')}")
            lines.append(
                f"  Blocked Queries: {summary.get('blocked_queries', 'N/A')}")
            lines.append(
                f"  Block Rate: {summary.get('block_rate', 0)*100:.1f}%")
            lines.append(
                f"  Unique Domains: {summary.get('unique_domains', 'N/A')}")
            lines.append(
                f"  Unique Clients: {summary.get('unique_clients', 'N/A')}")
            lines.append(
                f"  Anomalies: {summary.get('anomalies_detected', 'N/A')}")
            lines.append(f"  Alerts: {summary.get('alerts_generated', 'N/A')}")
            lines.append("")

        # Alerts
        if "alerts" in results and results["alerts"]:
            lines.append("SECURITY ALERTS:")
            for alert in results["alerts"]:
                lines.append(f"  - {alert.get('title', 'Unknown Alert')}")
                lines.append(
                    f"    Severity: {alert.get('severity', 'Unknown')}")
                lines.append(
                    f"    Description: {alert.get('description', 'No description')}")
                lines.append("")

        return "\n".join(lines)
