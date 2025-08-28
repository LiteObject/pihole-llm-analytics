"""
DNS Analytics Engine.

This module provides comprehensive analysis capabilities for DNS logs,
including traffic categorization, anomaly detection, and insight generation.
"""

from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Any

from ..core.llm_client import LLMClient
from ..utils.config import AnalyticsConfig
from ..utils.logging import LoggerMixin
from ..utils.models import (
    DNSQuery, AnalysisResult, Anomaly, ThreatLevel,
    DomainCategory, ClientInfo, DomainInfo
)


class DNSAnalyzer(LoggerMixin):
    """Main DNS analytics engine."""

    def __init__(self, llm_client: LLMClient, config: AnalyticsConfig):
        """Initialize DNS analyzer."""
        self.llm_client = llm_client
        self.config = config

        # Caches for domain and client information
        self._domain_cache: Dict[str, DomainInfo] = {}
        self._client_cache: Dict[str, ClientInfo] = {}

        self.logger.info("Initialized DNS analyzer")

    def analyze_queries(self, queries: List[DNSQuery]) -> AnalysisResult:
        """
        Perform comprehensive analysis of DNS queries.

        Args:
            queries: List of DNS queries to analyze

        Returns:
            AnalysisResult containing analysis insights
        """
        self.log_method_call("analyze_queries", query_count=len(queries))

        if not queries:
            self.logger.warning("No queries provided for analysis")
            return AnalysisResult(
                timestamp=datetime.now(),
                total_queries=0,
                blocked_queries=0,
                unique_domains=0,
                unique_clients=0
            )

        # Basic statistics
        total_queries = len(queries)
        blocked_queries = sum(
            1 for q in queries if "block" in q.status.value.lower())
        unique_domains = len(set(q.domain for q in queries))
        unique_clients = len(set(q.client_ip for q in queries))

        # Generate analysis components
        top_domains = self._analyze_top_domains(queries)
        top_clients = self._analyze_top_clients(queries)
        domain_categories = self._categorize_domains(
            queries) if self.config.enable_domain_categorization else {}
        anomalies = self._detect_anomalies(
            queries) if self.config.enable_anomaly_detection else []
        threat_summary = self._generate_threat_summary(queries)

        result = AnalysisResult(
            timestamp=datetime.now(),
            total_queries=total_queries,
            blocked_queries=blocked_queries,
            unique_domains=unique_domains,
            unique_clients=unique_clients,
            top_domains=top_domains,
            top_clients=top_clients,
            domain_categories=domain_categories,
            anomalies=anomalies,
            threat_summary=threat_summary
        )

        self.logger.info("Completed analysis of %d queries", total_queries)
        return result

    def _analyze_top_domains(
        self, queries: List[DNSQuery], limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Analyze top queried domains."""
        domain_counts = Counter(q.domain for q in queries)

        top_domains = []
        for domain, count in domain_counts.most_common(limit):
            # Calculate additional metrics
            blocked_count = sum(1 for q in queries
                                if q.domain == domain and "block" in q.status.value.lower())
            unique_clients = len(
                set(q.client_ip for q in queries if q.domain == domain))

            top_domains.append({
                "domain": domain,
                "count": count,
                "blocked_count": blocked_count,
                "unique_clients": unique_clients,
                "block_rate": blocked_count / count if count > 0 else 0
            })

        return top_domains

    def _analyze_top_clients(
        self, queries: List[DNSQuery], limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Analyze top client devices."""
        client_counts = Counter(q.client_ip for q in queries)

        top_clients = []
        for client_ip, count in client_counts.most_common(limit):
            # Calculate additional metrics
            blocked_count = sum(1 for q in queries
                                if q.client_ip == client_ip and "block" in q.status.value.lower())
            unique_domains = len(
                set(q.domain for q in queries if q.client_ip == client_ip))

            # Calculate time span
            client_queries = [q for q in queries if q.client_ip == client_ip]
            timestamps = [q.timestamp for q in client_queries]
            time_span = max(
                timestamps) - min(timestamps) if len(timestamps) > 1 else timedelta(0)

            top_clients.append({
                "client_ip": client_ip,
                "total_queries": count,
                "blocked_queries": blocked_count,
                "unique_domains": unique_domains,
                "block_rate": blocked_count / count if count > 0 else 0,
                "time_span_hours": time_span.total_seconds() / 3600,
                "queries_per_hour": count / max(time_span.total_seconds() / 3600, 0.1)
            })

        return top_clients

    def _categorize_domains(self, queries: List[DNSQuery]) -> Dict[str, int]:
        """Categorize domains using LLM."""
        self.logger.info("Starting domain categorization")

        # Get unique domains
        unique_domains = list(set(q.domain for q in queries))

        # Limit domains for LLM processing
        if len(unique_domains) > 50:
            # Sort by frequency and take top domains
            domain_counts = Counter(q.domain for q in queries)
            unique_domains = [domain for domain,
                              _ in domain_counts.most_common(50)]

        try:
            # Use LLM to categorize domains
            categorization_result = self.llm_client.analyze_dns_logs(
                unique_domains,
                analysis_type="categorization"
            )

            # Count categories
            category_counts = defaultdict(int)
            if isinstance(categorization_result, dict):
                for domain, category in categorization_result.items():
                    if category in [cat.value for cat in DomainCategory]:
                        # Count queries for this domain
                        domain_query_count = sum(
                            1 for q in queries if q.domain == domain)
                        category_counts[category] += domain_query_count

            self.logger.info("Categorized %d domains into %d categories",
                             len(unique_domains), len(category_counts))
            return dict(category_counts)

        except (ConnectionError, TimeoutError, ValueError, KeyError) as error:
            self.log_error(error, {"operation": "categorize_domains"})
            return {}

    def _detect_anomalies(self, queries: List[DNSQuery]) -> List[Anomaly]:
        """Detect anomalies in DNS traffic."""
        self.logger.info("Starting anomaly detection")

        anomalies = []

        # Volume-based anomalies
        anomalies.extend(self._detect_volume_anomalies(queries))

        # Timing-based anomalies
        anomalies.extend(self._detect_timing_anomalies(queries))

        # Pattern-based anomalies
        anomalies.extend(self._detect_pattern_anomalies(queries))

        # Use LLM for advanced anomaly detection
        try:
            llm_anomalies = self._detect_llm_anomalies(queries)
            anomalies.extend(llm_anomalies)
        except (ConnectionError, TimeoutError, ValueError, KeyError) as error:
            self.log_error(error, {"operation": "llm_anomaly_detection"})

        self.logger.info("Detected %d anomalies", len(anomalies))
        return anomalies

    def _detect_volume_anomalies(self, queries: List[DNSQuery]) -> List[Anomaly]:
        """Detect volume-based anomalies."""
        anomalies = []

        # High-volume clients
        client_counts = Counter(q.client_ip for q in queries)
        for client_ip, count in client_counts.items():
            if count > self.config.high_volume_threshold:
                anomalies.append(Anomaly(
                    timestamp=datetime.now(),
                    anomaly_type="high_volume_client",
                    description=(
                        f"Client {client_ip} made {count} queries "
                        f"(threshold: {self.config.high_volume_threshold})"
                    ),
                    severity=ThreatLevel.MEDIUM if count < self.config.high_volume_threshold *
                    2 else ThreatLevel.HIGH,
                    affected_client=client_ip,
                    evidence={"query_count": count,
                              "threshold": self.config.high_volume_threshold},
                    confidence=0.8
                ))

        # High-volume domains
        domain_counts = Counter(q.domain for q in queries)
        for domain, count in domain_counts.items():
            if count > self.config.suspicious_query_threshold:
                anomalies.append(Anomaly(
                    timestamp=datetime.now(),
                    anomaly_type="high_volume_domain",
                    description=f"Domain {domain} queried {count} times",
                    severity=ThreatLevel.LOW,
                    affected_domain=domain,
                    evidence={"query_count": count},
                    confidence=0.6
                ))

        return anomalies

    def _detect_timing_anomalies(self, queries: List[DNSQuery]) -> List[Anomaly]:
        """Detect timing-based anomalies."""
        anomalies = []

        # Group queries by hour
        hourly_counts = defaultdict(int)
        for query in queries:
            hour = query.timestamp.hour
            hourly_counts[hour] += 1

        # Check for unusual activity hours (late night/early morning)
        for hour, count in hourly_counts.items():
            if hour in [0, 1, 2, 3, 4, 5] and count > 50:  # Configurable threshold
                anomalies.append(Anomaly(
                    timestamp=datetime.now(),
                    anomaly_type="unusual_timing",
                    description=f"High DNS activity at {hour}:00 ({count} queries)",
                    severity=ThreatLevel.LOW,
                    evidence={"hour": hour, "query_count": count},
                    confidence=0.5
                ))

        return anomalies

    def _detect_pattern_anomalies(self, queries: List[DNSQuery]) -> List[Anomaly]:
        """Detect pattern-based anomalies."""
        anomalies = []

        # Detect potential DGA (Domain Generation Algorithm) patterns
        suspicious_domains = []
        for query in queries:
            domain = query.domain.lower()

            # Simple heuristics for DGA detection
            if (len(domain.split('.')[0]) > 15 and  # Long subdomain
                # No numbers (simple heuristic)
                not any(char.isdigit() for char in domain) and
                    domain.count('.') <= 2):  # Not too many subdomains
                suspicious_domains.append(domain)

        if len(suspicious_domains) > 5:  # Multiple suspicious domains
            anomalies.append(Anomaly(
                timestamp=datetime.now(),
                anomaly_type="potential_dga",
                description=f"Detected {len(suspicious_domains)} potentially generated domains",
                severity=ThreatLevel.MEDIUM,
                # Limit for brevity
                evidence={"suspicious_domains": suspicious_domains[:10]},
                confidence=0.6
            ))

        # Detect repeated failed queries (potential malware)
        failed_queries = [
            q for q in queries if "block" in q.status.value.lower()]
        if failed_queries:
            failed_domain_counts = Counter(q.domain for q in failed_queries)
            for domain, count in failed_domain_counts.items():
                if count > 20:  # Configurable threshold
                    anomalies.append(Anomaly(
                        timestamp=datetime.now(),
                        anomaly_type="repeated_failed_queries",
                        description=f"Domain {domain} blocked {count} times",
                        severity=ThreatLevel.MEDIUM,
                        affected_domain=domain,
                        evidence={"blocked_count": count},
                        confidence=0.7
                    ))

        return anomalies

    def _detect_llm_anomalies(self, queries: List[DNSQuery]) -> List[Anomaly]:
        """Use LLM for advanced anomaly detection."""
        try:
            # Sample queries for LLM analysis (to avoid token limits)
            sample_size = min(len(queries), 200)
            sample_queries = queries[:sample_size]

            result = self.llm_client.analyze_dns_logs(
                sample_queries, analysis_type="anomaly")

            anomalies = []
            if isinstance(result, dict) and "anomalies" in result:
                for anomaly_data in result["anomalies"]:
                    try:
                        severity_str = anomaly_data.get(
                            "severity", "low").lower()
                        severity = ThreatLevel(severity_str) if severity_str in [
                            t.value for t in ThreatLevel] else ThreatLevel.LOW

                        anomaly = Anomaly(
                            timestamp=datetime.now(),
                            anomaly_type=f"llm_{anomaly_data.get('type', 'unknown')}",
                            description=anomaly_data.get(
                                "description", "LLM detected anomaly"),
                            severity=severity,
                            affected_client=anomaly_data.get("client"),
                            affected_domain=anomaly_data.get("domain"),
                            evidence=anomaly_data,
                            confidence=result.get("confidence", 0.5)
                        )
                        anomalies.append(anomaly)
                    except (KeyError, ValueError) as error:
                        self.logger.warning(
                            "Failed to parse LLM anomaly: %s", error)
                        continue

            return anomalies

        except (ConnectionError, TimeoutError, ValueError, KeyError) as error:
            self.log_error(error, {"operation": "llm_anomaly_detection"})
            return []

    def _generate_threat_summary(self, queries: List[DNSQuery]) -> Dict[str, Any]:
        """Generate overall threat summary."""
        blocked_queries = [
            q for q in queries if "block" in q.status.value.lower()]

        summary = {
            "total_queries": len(queries),
            "blocked_queries": len(blocked_queries),
            "block_rate": len(blocked_queries) / len(queries) if queries else 0,
            "unique_blocked_domains": len(set(q.domain for q in blocked_queries)),
            "clients_with_blocks": len(set(q.client_ip for q in blocked_queries)),
            "analysis_timestamp": datetime.now().isoformat()
        }

        # Add time-based analysis
        if queries:
            time_span = max(q.timestamp for q in queries) - \
                min(q.timestamp for q in queries)
            summary["time_span_hours"] = time_span.total_seconds() / 3600
            summary["queries_per_hour"] = len(
                queries) / max(time_span.total_seconds() / 3600, 0.1)

        return summary

    def search_queries(self, queries: List[DNSQuery], search_query: str) -> Dict[str, Any]:
        """
        Perform natural language search over DNS queries.

        Args:
            queries: List of DNS queries to search
            search_query: Natural language search query

        Returns:
            Search results and matching queries
        """
        self.log_method_call("search_queries",
                             query_count=len(queries),
                             search_query=search_query)

        try:
            # Use LLM to interpret the search query
            search_result = self.llm_client.analyze_dns_logs(
                search_query,
                analysis_type="search"
            )

            # Apply search criteria to filter queries
            matching_queries = self._apply_search_filters(
                queries, search_result)

            return {
                "search_query": search_query,
                "llm_interpretation": search_result,
                "matching_queries": [
                    {
                        "timestamp": q.timestamp.isoformat(),
                        "domain": q.domain,
                        "client_ip": q.client_ip,
                        "status": q.status.value
                    }
                    for q in matching_queries
                ],
                "match_count": len(matching_queries),
                "total_searched": len(queries)
            }

        except (ConnectionError, TimeoutError, ValueError, KeyError) as error:
            self.log_error(error, {"operation": "search_queries"})
            return {
                "search_query": search_query,
                "error": str(error),
                "matching_queries": [],
                "match_count": 0,
                "total_searched": len(queries)
            }

    def _apply_search_filters(
        self, queries: List[DNSQuery], search_result: Dict[str, Any]
    ) -> List[DNSQuery]:
        """Apply search filters based on LLM interpretation."""
        # This is a simplified implementation
        # In practice, you would parse the LLM's suggested_filters
        # and apply them programmatically

        matching = []

        # Extract search criteria from LLM response
        filters = search_result.get("suggested_filters", {})

        for query in queries:
            matches = True

            # Apply basic filters
            if "client" in filters and query.client_ip != filters["client"]:
                matches = False

            if "status" in filters and query.status.value != filters["status"]:
                matches = False

            if "domain" in filters and filters["domain"].lower() not in query.domain.lower():
                matches = False

            # Apply time filters
            if "time_range" in filters:
                # Implement time range filtering
                pass

            if matches:
                matching.append(query)

        return matching

    def generate_report(
        self, queries: List[DNSQuery], report_type: str = "daily"
    ) -> Dict[str, Any]:
        """
        Generate comprehensive reports.

        Args:
            queries: DNS queries to analyze
            report_type: Type of report (daily, weekly, security)

        Returns:
            Report data
        """
        self.log_method_call("generate_report",
                             query_count=len(queries),
                             report_type=report_type)

        # Perform full analysis
        analysis = self.analyze_queries(queries)

        # Generate report based on type
        if report_type == "security":
            return self._generate_security_report(analysis, queries)
        elif report_type == "weekly":
            return self._generate_weekly_report(analysis, queries)
        else:
            return self._generate_daily_report(analysis, queries)

    def _generate_daily_report(
        self, analysis: AnalysisResult, _queries: List[DNSQuery]
    ) -> Dict[str, Any]:
        """Generate daily summary report."""
        return {
            "report_type": "daily",
            "date": datetime.now().date().isoformat(),
            "summary": {
                "total_queries": analysis.total_queries,
                "blocked_queries": analysis.blocked_queries,
                "block_rate": (
                    analysis.blocked_queries / analysis.total_queries
                    if analysis.total_queries > 0 else 0
                ),
                "unique_domains": analysis.unique_domains,
                "unique_clients": analysis.unique_clients
            },
            "top_domains": analysis.top_domains[:10],
            "top_clients": analysis.top_clients[:10],
            "categories": analysis.domain_categories,
            "anomalies_count": len(analysis.anomalies),
            "high_severity_anomalies": [
                {
                    "type": a.anomaly_type,
                    "description": a.description,
                    "severity": a.severity.value
                }
                for a in analysis.anomalies
                if a.severity in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]
            ]
        }

    def _generate_weekly_report(
        self, analysis: AnalysisResult, queries: List[DNSQuery]
    ) -> Dict[str, Any]:
        """Generate weekly summary report."""
        # Group queries by day
        daily_stats = defaultdict(lambda: {"queries": 0, "blocked": 0})

        for query in queries:
            day = query.timestamp.date().isoformat()
            daily_stats[day]["queries"] += 1
            if "block" in query.status.value.lower():
                daily_stats[day]["blocked"] += 1

        return {
            "report_type": "weekly",
            "week_ending": datetime.now().date().isoformat(),
            "summary": {
                "total_queries": analysis.total_queries,
                "blocked_queries": analysis.blocked_queries,
                "unique_domains": analysis.unique_domains,
                "unique_clients": analysis.unique_clients,
                "days_analyzed": len(daily_stats)
            },
            "daily_breakdown": dict(daily_stats),
            "top_domains": analysis.top_domains[:20],
            "top_clients": analysis.top_clients[:15],
            "categories": analysis.domain_categories,
            "security_events": len([
                a for a in analysis.anomalies
                if a.severity in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]
            ])
        }

    def _generate_security_report(
        self, analysis: AnalysisResult, queries: List[DNSQuery]
    ) -> Dict[str, Any]:
        """Generate security-focused report."""
        # Security-specific analysis
        blocked_queries = [
            q for q in queries if "block" in q.status.value.lower()]

        # Analyze blocked domains
        blocked_domains = Counter(q.domain for q in blocked_queries)

        # Analyze clients with most blocks
        clients_with_blocks = Counter(q.client_ip for q in blocked_queries)

        return {
            "report_type": "security",
            "timestamp": datetime.now().isoformat(),
            "threat_level": self._assess_overall_threat_level(analysis.anomalies),
            "summary": {
                "total_security_events": len(analysis.anomalies),
                "critical_events": len([
                    a for a in analysis.anomalies
                    if a.severity == ThreatLevel.CRITICAL
                ]),
                "high_events": len([
                    a for a in analysis.anomalies
                    if a.severity == ThreatLevel.HIGH
                ]),
                "blocked_queries": len(blocked_queries),
                "unique_blocked_domains": len(blocked_domains)
            },
            "top_blocked_domains": [
                {"domain": domain, "count": count}
                for domain, count in blocked_domains.most_common(10)
            ],
            "clients_at_risk": [
                {"client_ip": client, "blocked_count": count}
                for client, count in clients_with_blocks.most_common(5)
            ],
            "anomalies": [
                {
                    "type": a.anomaly_type,
                    "description": a.description,
                    "severity": a.severity.value,
                    "confidence": a.confidence,
                    "affected_client": a.affected_client,
                    "affected_domain": a.affected_domain
                }
                for a in analysis.anomalies
            ]
        }

    def _assess_overall_threat_level(self, anomalies: List[Anomaly]) -> str:
        """Assess overall threat level based on anomalies."""
        if any(a.severity == ThreatLevel.CRITICAL for a in anomalies):
            return "critical"
        elif any(a.severity == ThreatLevel.HIGH for a in anomalies):
            return "high"
        elif any(a.severity == ThreatLevel.MEDIUM for a in anomalies):
            return "medium"
        else:
            return "low"
