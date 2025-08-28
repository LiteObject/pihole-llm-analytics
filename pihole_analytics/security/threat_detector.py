"""
Security Threat Detection Module.

This module provides advanced threat detection capabilities including
domain reputation analysis, threat intelligence integration, and alert generation.
"""

import hashlib
import re
from datetime import datetime
from typing import Dict, List, Set, Any

import requests

from ..core.llm_client import LLMClient
from ..utils.config import SecurityConfig
from ..utils.logging import LoggerMixin
from ..utils.models import (
    DNSQuery, Alert, ThreatLevel, DomainInfo, DomainCategory
)


class ThreatDetector(LoggerMixin):
    """Advanced threat detection and security analysis."""

    def __init__(self, llm_client: LLMClient, config: SecurityConfig):
        """Initialize threat detector."""
        self.llm_client = llm_client
        self.config = config

        # Threat intelligence data
        self._threat_domains: Set[str] = set()
        self._last_threat_update = datetime.min

        # Domain reputation cache
        self._domain_reputation: Dict[str, DomainInfo] = {}

        # Known malicious patterns
        self._malicious_patterns = [
            r'.*\.tk$',  # .tk domains often used for malicious purposes
            r'.*\.ml$',  # .ml domains often used for malicious purposes
            r'[0-9a-f]{8,}\..*',  # Long hex strings in domains
            # IP-like patterns
            r'.*[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}.*',
        ]

        self.logger.info("Initialized threat detector")

        # Load initial threat intelligence
        if self.config.enable_threat_detection:
            self._update_threat_intelligence()

    def analyze_threats(self, queries: List[DNSQuery]) -> Dict[str, Any]:
        """
        Perform comprehensive threat analysis on DNS queries.

        Args:
            queries: List of DNS queries to analyze

        Returns:
            Threat analysis results
        """
        self.log_method_call("analyze_threats", query_count=len(queries))

        # Update threat intelligence if needed
        self._update_threat_intelligence_if_needed()

        # Analyze different threat categories
        threat_analysis = {
            "timestamp": datetime.now().isoformat(),
            "total_queries": len(queries),
            "threats_detected": 0,
            "malicious_domains": [],
            "suspicious_clients": [],
            "threat_categories": {},
            "reputation_analysis": {},
            "llm_security_analysis": {}
        }

        # Domain-based threat detection
        malicious_domains = self._detect_malicious_domains(queries)
        threat_analysis["malicious_domains"] = malicious_domains

        # Client behavior analysis
        suspicious_clients = self._analyze_client_behavior(queries)
        threat_analysis["suspicious_clients"] = suspicious_clients

        # Pattern-based detection
        pattern_threats = self._detect_pattern_threats(queries)
        threat_analysis["pattern_threats"] = pattern_threats

        # Domain reputation analysis
        if self.config.enable_domain_reputation:
            reputation_analysis = self._analyze_domain_reputation(queries)
            threat_analysis["reputation_analysis"] = reputation_analysis

        # LLM-powered security analysis
        llm_analysis = self._perform_llm_security_analysis(queries)
        threat_analysis["llm_security_analysis"] = llm_analysis

        # Calculate total threats
        threat_analysis["threats_detected"] = (
            len(malicious_domains) +
            len(suspicious_clients) +
            len(pattern_threats)
        )

        self.logger.info("Threat analysis completed: %d threats detected",
                         threat_analysis["threats_detected"])

        return threat_analysis

    def _detect_malicious_domains(self, queries: List[DNSQuery]) -> List[Dict[str, Any]]:
        """Detect known malicious domains."""
        malicious_detections = []

        for query in queries:
            domain = query.domain.lower()

            # Check against threat intelligence feeds
            if domain in self._threat_domains:
                malicious_detections.append({
                    "domain": domain,
                    "client_ip": query.client_ip,
                    "timestamp": query.timestamp.isoformat(),
                    "threat_type": "known_malicious",
                    "source": "threat_intelligence",
                    "confidence": 0.9
                })

            # Check against malicious patterns
            for pattern in self._malicious_patterns:
                if re.match(pattern, domain):
                    malicious_detections.append({
                        "domain": domain,
                        "client_ip": query.client_ip,
                        "timestamp": query.timestamp.isoformat(),
                        "threat_type": "suspicious_pattern",
                        "source": f"pattern_match: {pattern}",
                        "confidence": 0.6
                    })
                    break

            # Check for potential typosquatting
            if self._is_potential_typosquatting(domain):
                malicious_detections.append({
                    "domain": domain,
                    "client_ip": query.client_ip,
                    "timestamp": query.timestamp.isoformat(),
                    "threat_type": "potential_typosquatting",
                    "source": "heuristic_analysis",
                    "confidence": 0.5
                })

        return malicious_detections

    def _analyze_client_behavior(self, queries: List[DNSQuery]) -> List[Dict[str, Any]]:
        """Analyze client behavior for suspicious patterns."""
        suspicious_clients = []

        # Group queries by client
        client_queries = {}
        for query in queries:
            if query.client_ip not in client_queries:
                client_queries[query.client_ip] = []
            client_queries[query.client_ip].append(query)

        for client_ip, client_query_list in client_queries.items():
            suspicion_score = 0.0
            reasons = []

            # Check for high volume
            if len(client_query_list) > 1000:
                suspicion_score += 0.3
                reasons.append(f"High query volume: {len(client_query_list)}")

            # Check for many unique domains
            unique_domains = len(set(q.domain for q in client_query_list))
            if unique_domains > 500:
                suspicion_score += 0.3
                reasons.append(f"Many unique domains: {unique_domains}")

            # Check for DGA-like domains
            dga_count = sum(
                1 for q in client_query_list if self._is_dga_like(q.domain))
            if dga_count > 10:
                suspicion_score += 0.4
                reasons.append(f"DGA-like domains: {dga_count}")

            # Check for failed DNS queries (potential C2 communication)
            failed_queries = [
                q for q in client_query_list if "block" in q.status.value.lower()]
            if len(failed_queries) > 50:
                suspicion_score += 0.2
                reasons.append(f"Many blocked queries: {len(failed_queries)}")

            # Check for periodic patterns (beaconing)
            if self._detect_beaconing_pattern(client_query_list):
                suspicion_score += 0.5
                reasons.append("Potential beaconing behavior detected")

            # If suspicion score is high enough, flag the client
            if suspicion_score > 0.6:
                suspicious_clients.append({
                    "client_ip": client_ip,
                    "suspicion_score": suspicion_score,
                    "reasons": reasons,
                    "query_count": len(client_query_list),
                    "unique_domains": unique_domains,
                    "blocked_queries": len(failed_queries),
                    "threat_level": self._calculate_threat_level(suspicion_score)
                })

        return suspicious_clients

    def _detect_pattern_threats(self, queries: List[DNSQuery]) -> List[Dict[str, Any]]:
        """Detect threat patterns in DNS queries."""
        pattern_threats = []

        # DNS tunneling detection
        tunneling_domains = self._detect_dns_tunneling(queries)
        for domain in tunneling_domains:
            pattern_threats.append({
                "threat_type": "dns_tunneling",
                "domain": domain,
                "description": "Potential DNS tunneling detected",
                "confidence": 0.7
            })

        # Fast flux detection
        fast_flux_domains = self._detect_fast_flux(queries)
        for domain in fast_flux_domains:
            pattern_threats.append({
                "threat_type": "fast_flux",
                "domain": domain,
                "description": "Fast flux network behavior detected",
                "confidence": 0.6
            })

        # Data exfiltration patterns
        exfiltration_patterns = self._detect_data_exfiltration(queries)
        for pattern in exfiltration_patterns:
            pattern_threats.append({
                "threat_type": "data_exfiltration",
                "pattern": pattern,
                "description": "Potential data exfiltration via DNS",
                "confidence": 0.8
            })

        return pattern_threats

    def _analyze_domain_reputation(self, queries: List[DNSQuery]) -> Dict[str, Any]:
        """Analyze domain reputation for queried domains."""
        unique_domains = list(set(q.domain for q in queries))

        reputation_analysis = {
            "total_domains": len(unique_domains),
            "analyzed_domains": 0,
            "high_risk_domains": [],
            "medium_risk_domains": [],
            "unknown_domains": []
        }

        for domain in unique_domains[:100]:  # Limit for performance
            reputation = self._get_domain_reputation(domain)

            if reputation:
                reputation_analysis["analyzed_domains"] += 1

                if reputation.threat_level == ThreatLevel.HIGH or reputation.threat_level == ThreatLevel.CRITICAL:
                    reputation_analysis["high_risk_domains"].append({
                        "domain": domain,
                        "threat_level": reputation.threat_level.value,
                        "category": reputation.category.value,
                        "reputation_score": reputation.reputation_score,
                        "description": reputation.description
                    })
                elif reputation.threat_level == ThreatLevel.MEDIUM:
                    reputation_analysis["medium_risk_domains"].append({
                        "domain": domain,
                        "threat_level": reputation.threat_level.value,
                        "category": reputation.category.value,
                        "reputation_score": reputation.reputation_score
                    })
            else:
                reputation_analysis["unknown_domains"].append(domain)

        return reputation_analysis

    def _perform_llm_security_analysis(self, queries: List[DNSQuery]) -> Dict[str, Any]:
        """Use LLM for advanced security analysis."""
        try:
            # Sample queries for LLM analysis
            sample_size = min(len(queries), 100)
            sample_queries = queries[:sample_size]

            analysis = self.llm_client.analyze_dns_logs(
                sample_queries, analysis_type="security")

            return {
                "analysis_performed": True,
                "sample_size": sample_size,
                "llm_response": analysis
            }

        except (ConnectionError, TimeoutError, ValueError, KeyError) as error:
            self.log_error(error, {"operation": "llm_security_analysis"})
            return {
                "analysis_performed": False,
                "error": str(error)
            }

    def generate_alerts(self, threat_analysis: Dict[str, Any], _queries: List[DNSQuery]) -> List[Alert]:
        """Generate security alerts based on threat analysis."""
        alerts = []

        # Generate alerts for malicious domains
        for threat in threat_analysis.get("malicious_domains", []):
            if threat["confidence"] > 0.8:
                alert = Alert(
                    id=self._generate_alert_id(threat),
                    timestamp=datetime.now(),
                    title=f"Malicious Domain Detected: {threat['domain']}",
                    description=f"Client {threat['client_ip']} attempted to access known malicious domain {threat['domain']}",
                    severity=ThreatLevel.HIGH,
                    source="threat_intelligence",
                    affected_entities=[threat['client_ip'], threat['domain']],
                    recommended_actions=[
                        f"Investigate client {threat['client_ip']} for potential compromise",
                        f"Block domain {threat['domain']} if not already blocked",
                        "Perform malware scan on affected device"
                    ],
                    evidence=threat
                )
                alerts.append(alert)

        # Generate alerts for suspicious clients
        for client in threat_analysis.get("suspicious_clients", []):
            if client["suspicion_score"] > 0.8:
                alert = Alert(
                    id=self._generate_alert_id(client),
                    timestamp=datetime.now(),
                    title=f"Suspicious Client Behavior: {client['client_ip']}",
                    description=f"Client {client['client_ip']} exhibits suspicious DNS behavior",
                    severity=self._score_to_threat_level(
                        client["suspicion_score"]),
                    source="behavior_analysis",
                    affected_entities=[client['client_ip']],
                    recommended_actions=[
                        f"Investigate device at {client['client_ip']}",
                        "Check for malware or unauthorized software",
                        "Monitor network traffic from this device"
                    ],
                    evidence=client
                )
                alerts.append(alert)

        # Generate alerts for pattern threats
        for threat in threat_analysis.get("pattern_threats", []):
            if threat["confidence"] > 0.7:
                alert = Alert(
                    id=self._generate_alert_id(threat),
                    timestamp=datetime.now(),
                    title=f"Security Pattern Detected: {threat['threat_type']}",
                    description=threat["description"],
                    severity=ThreatLevel.MEDIUM,
                    source="pattern_detection",
                    recommended_actions=[
                        "Investigate the detected pattern",
                        "Review network logs for additional evidence",
                        "Consider blocking related domains or IPs"
                    ],
                    evidence=threat
                )
                alerts.append(alert)

        self.logger.info("Generated %d security alerts", len(alerts))
        return alerts

    def _update_threat_intelligence(self) -> None:
        """Update threat intelligence from external sources."""
        if not self.config.threat_intel_urls:
            return

        self.logger.info("Updating threat intelligence data")

        for url in self.config.threat_intel_urls:
            try:
                response = requests.get(url, timeout=30)
                response.raise_for_status()

                # Parse different formats
                if "hosts" in url.lower():
                    domains = self._parse_hosts_file(response.text)
                else:
                    domains = self._parse_domain_list(response.text)

                self._threat_domains.update(domains)
                self.logger.info(
                    "Updated threat intelligence from %s: %d domains", url, len(domains))

            except requests.RequestException as error:
                self.log_error(
                    error, {"operation": "update_threat_intel", "url": url})
                continue

        self._last_threat_update = datetime.now()
        self.logger.info("Threat intelligence update completed: %d total domains", len(
            self._threat_domains))

    def _update_threat_intelligence_if_needed(self) -> None:
        """Update threat intelligence if cache is stale."""
        if (datetime.now() - self._last_threat_update).total_seconds() >= 24 * 3600:
            self._update_threat_intelligence()

    def _parse_hosts_file(self, content: str) -> Set[str]:
        """Parse domains from hosts file format."""
        domains = set()
        lines = content.split('\n')

        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                parts = line.split()
                if len(parts) >= 2:
                    domain = parts[1].lower()
                    if self._is_valid_domain(domain):
                        domains.add(domain)

        return domains

    def _parse_domain_list(self, content: str) -> Set[str]:
        """Parse domains from simple domain list."""
        domains = set()
        lines = content.split('\n')

        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                domain = line.lower()
                if self._is_valid_domain(domain):
                    domains.add(domain)

        return domains

    def _is_valid_domain(self, domain: str) -> bool:
        """Check if string is a valid domain name."""
        if not domain or len(domain) > 253:
            return False

        # Basic domain validation
        if domain.count('.') < 1:
            return False

        # Check for localhost or other local addresses
        local_patterns = ['localhost', '127.0.0.1', '0.0.0.0', 'local']
        if any(pattern in domain for pattern in local_patterns):
            return False

        return True

    def _get_domain_reputation(self, domain: str) -> DomainInfo:
        """Get domain reputation information."""
        # Check cache first
        if domain in self._domain_reputation:
            cached_info = self._domain_reputation[domain]
            # Check if cache is still valid
            if (cached_info.last_seen and
                (datetime.now() - cached_info.last_seen).total_seconds() <
                    self.config.reputation_cache_hours * 3600):
                return cached_info

        # Analyze domain reputation
        reputation_info = self._analyze_domain_characteristics(domain)

        # Cache the result
        self._domain_reputation[domain] = reputation_info

        return reputation_info

    def _analyze_domain_characteristics(self, domain: str) -> DomainInfo:
        """Analyze domain characteristics for reputation assessment."""
        # Basic domain analysis
        domain_parts = domain.split('.')
        tld = domain_parts[-1] if domain_parts else ""
        subdomain_length = len(domain_parts[0]) if domain_parts else 0

        # Risk scoring
        risk_score = 0.0
        threat_level = ThreatLevel.LOW
        category = DomainCategory.UNKNOWN

        # TLD-based scoring
        high_risk_tlds = ['.tk', '.ml', '.ga', '.cf']
        if any(domain.endswith(tld) for tld in high_risk_tlds):
            risk_score += 0.3

        # Length-based scoring (very long subdomains can be suspicious)
        if subdomain_length > 20:
            risk_score += 0.2

        # Check for known malicious domains
        if domain in self._threat_domains:
            risk_score = 0.9
            threat_level = ThreatLevel.HIGH
            category = DomainCategory.MALWARE

        # DGA-like characteristics
        if self._is_dga_like(domain):
            risk_score += 0.4
            category = DomainCategory.SUSPICIOUS

        # Determine threat level
        if risk_score >= 0.8:
            threat_level = ThreatLevel.HIGH
        elif risk_score >= 0.6:
            threat_level = ThreatLevel.MEDIUM
        elif risk_score >= 0.3:
            threat_level = ThreatLevel.LOW

        return DomainInfo(
            domain=domain,
            category=category,
            threat_level=threat_level,
            reputation_score=1.0 - risk_score,  # Invert for reputation
            last_seen=datetime.now(),
            description=f"Automated analysis - Risk score: {risk_score:.2f}"
        )

    def _is_potential_typosquatting(self, domain: str) -> bool:
        """Check if domain might be typosquatting."""
        # List of commonly typosquatted domains
        popular_domains = [
            'google.com', 'facebook.com', 'youtube.com', 'amazon.com',
            'twitter.com', 'instagram.com', 'linkedin.com', 'microsoft.com'
        ]

        for popular in popular_domains:
            if self._calculate_domain_similarity(domain, popular) > 0.8:
                return True

        return False

    def _calculate_domain_similarity(self, domain1: str, domain2: str) -> float:
        """Calculate similarity between two domains (simplified)."""
        # Simple Levenshtein-like similarity
        if len(domain1) == 0 or len(domain2) == 0:
            return 0.0

        # Count common characters
        common = sum(1 for a, b in zip(domain1, domain2) if a == b)
        max_len = max(len(domain1), len(domain2))

        return common / max_len if max_len > 0 else 0.0

    def _is_dga_like(self, domain: str) -> bool:
        """Check if domain exhibits DGA-like characteristics."""
        domain_name = domain.split('.')[0]

        # DGA characteristics
        if len(domain_name) < 6:
            return False

        # Check for random-looking patterns
        vowels = 'aeiou'
        consonants = 'bcdfghjklmnpqrstvwxyz'

        vowel_count = sum(1 for c in domain_name.lower() if c in vowels)
        consonant_count = sum(
            1 for c in domain_name.lower() if c in consonants)

        # Very low vowel ratio might indicate DGA
        total_letters = vowel_count + consonant_count
        if total_letters > 0:
            vowel_ratio = vowel_count / total_letters
            if vowel_ratio < 0.2:  # Less than 20% vowels
                return True

        # Check for entropy (simplified)
        unique_chars = len(set(domain_name.lower()))
        if unique_chars / len(domain_name) > 0.8:  # High character diversity
            return True

        return False

    def _detect_beaconing_pattern(self, queries: List[DNSQuery]) -> bool:
        """Detect potential beaconing behavior in queries."""
        if len(queries) < 10:
            return False

        # Sort by timestamp
        sorted_queries = sorted(queries, key=lambda q: q.timestamp)

        # Calculate time intervals
        intervals = []
        for i in range(1, len(sorted_queries)):
            interval = (sorted_queries[i].timestamp -
                        sorted_queries[i-1].timestamp).total_seconds()
            intervals.append(interval)

        if not intervals:
            return False

        # Check for regular intervals (simplified)
        avg_interval = sum(intervals) / len(intervals)
        if 60 <= avg_interval <= 3600:  # Between 1 minute and 1 hour
            # Check consistency
            consistent_intervals = sum(1 for interval in intervals
                                       if abs(interval - avg_interval) < avg_interval * 0.1)
            if consistent_intervals / len(intervals) > 0.7:  # 70% consistency
                return True

        return False

    def _detect_dns_tunneling(self, queries: List[DNSQuery]) -> List[str]:
        """Detect potential DNS tunneling."""
        tunneling_domains = []

        # Group by domain
        domain_queries = {}
        for query in queries:
            if query.domain not in domain_queries:
                domain_queries[query.domain] = []
            domain_queries[query.domain].append(query)

        for domain, domain_query_list in domain_queries.items():
            # Check for many unique subdomains
            subdomains = set()
            for query in domain_query_list:
                parts = query.domain.split('.')
                if len(parts) > 2:
                    subdomain = parts[0]
                    subdomains.add(subdomain)

            # If many unique subdomains and they look random/encoded
            if len(subdomains) > 20:
                random_looking = sum(
                    1 for sub in subdomains if self._looks_encoded(sub))
                if random_looking / len(subdomains) > 0.5:
                    tunneling_domains.append(domain)

        return tunneling_domains

    def _detect_fast_flux(self, queries: List[DNSQuery]) -> List[str]:
        """Detect fast flux network behavior."""
        # This is a simplified implementation
        # In practice, you'd need to analyze DNS responses and IP changes
        fast_flux_domains = []

        # Look for domains with many queries in short time
        domain_counts = {}
        for query in queries:
            if query.domain not in domain_counts:
                domain_counts[query.domain] = 0
            domain_counts[query.domain] += 1

        for domain, count in domain_counts.items():
            if count > 100:  # High query volume
                fast_flux_domains.append(domain)

        return fast_flux_domains

    def _detect_data_exfiltration(self, queries: List[DNSQuery]) -> List[str]:
        """Detect potential data exfiltration patterns."""
        exfiltration_patterns = []

        for query in queries:
            subdomain = query.domain.split('.')[0]

            # Check for long, encoded-looking subdomains
            if len(subdomain) > 50 and self._looks_encoded(subdomain):
                exfiltration_patterns.append(query.domain)

        return list(set(exfiltration_patterns))  # Remove duplicates

    def _looks_encoded(self, text: str) -> bool:
        """Check if text looks like it might be encoded data."""
        # Simple heuristics for encoded data
        if len(text) < 10:
            return False

        # Check for base64-like patterns
        base64_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
        base64_like = sum(1 for c in text if c in base64_chars) / len(text)

        if base64_like > 0.8:
            return True

        # Check for hex-like patterns
        hex_chars = '0123456789abcdefABCDEF'
        hex_like = sum(1 for c in text if c in hex_chars) / len(text)

        if hex_like > 0.8:
            return True

        return False

    def _generate_alert_id(self, data: Dict[str, Any]) -> str:
        """Generate unique alert ID."""
        content = str(data) + str(datetime.now())
        return hashlib.md5(content.encode()).hexdigest()[:12]

    def _calculate_threat_level(self, score: float) -> str:
        """Convert numeric score to threat level string."""
        if score >= 0.8:
            return "high"
        elif score >= 0.6:
            return "medium"
        else:
            return "low"

    def _score_to_threat_level(self, score: float) -> ThreatLevel:
        """Convert numeric score to ThreatLevel enum."""
        if score >= 0.9:
            return ThreatLevel.CRITICAL
        elif score >= 0.7:
            return ThreatLevel.HIGH
        elif score >= 0.4:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW
