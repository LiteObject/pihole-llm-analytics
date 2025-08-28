"""
Data models for Pi-hole analytics.

This module defines the data structures used throughout the application
for type safety and data validation.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
import json


class QueryStatus(Enum):
    """DNS query status enumeration."""
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    CACHED = "cached"
    FORWARDED = "forwarded"
    UNKNOWN = "unknown"


class DomainCategory(Enum):
    """Domain category classification."""
    SOCIAL_MEDIA = "social_media"
    ADVERTISING = "advertising"
    STREAMING = "streaming"
    GAMING = "gaming"
    CLOUD_SERVICES = "cloud_services"
    CDN = "cdn"
    ANALYTICS = "analytics"
    SUSPICIOUS = "suspicious"
    MALWARE = "malware"
    PHISHING = "phishing"
    UNKNOWN = "unknown"


class ThreatLevel(Enum):
    """Threat level classification."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DNSQuery:
    """Represents a single DNS query record."""
    timestamp: datetime
    domain: str
    client_ip: str
    status: QueryStatus
    query_type: str = "A"
    reply_time: Optional[float] = None

    @classmethod
    def from_pihole_data(cls, data: Dict[str, Any]) -> 'DNSQuery':
        """Create DNSQuery from Pi-hole API response data."""
        # Handle different timestamp formats
        timestamp_value = data.get("timestamp") or data.get(
            "time") or data.get("t")
        if isinstance(timestamp_value, (int, float)):
            timestamp = datetime.fromtimestamp(timestamp_value)
        elif isinstance(timestamp_value, str):
            try:
                timestamp = datetime.fromisoformat(timestamp_value)
            except ValueError:
                timestamp = datetime.now()
        else:
            timestamp = datetime.now()

        # Extract domain
        domain = data.get("domain") or data.get("query") or data.get("q") or ""

        # Extract client IP
        client_ip = (data.get("client") or data.get("client_ip") or
                     data.get("clientIP") or "unknown")

        # Parse status
        status_value = data.get("status") or data.get(
            "action") or data.get("blocked") or ""
        status = cls._parse_status(status_value)

        # Extract query type
        query_type = data.get("type") or data.get("query_type") or "A"

        # Extract reply time
        reply_time = data.get("reply_time") or data.get("duration")

        return cls(
            timestamp=timestamp,
            domain=domain,
            client_ip=client_ip,
            status=status,
            query_type=query_type,
            reply_time=reply_time
        )

    @staticmethod
    def _parse_status(status_value: Any) -> QueryStatus:
        """Parse status from various Pi-hole status formats."""
        if not status_value:
            return QueryStatus.UNKNOWN

        status_str = str(status_value).lower()

        if "block" in status_str or status_str in ["2", "3", "9", "10", "11"]:
            return QueryStatus.BLOCKED
        elif "allow" in status_str or status_str in ["1", "4", "5", "6", "7", "8"]:
            return QueryStatus.ALLOWED
        elif "cache" in status_str:
            return QueryStatus.CACHED
        elif "forward" in status_str:
            return QueryStatus.FORWARDED
        else:
            return QueryStatus.UNKNOWN


@dataclass
class DomainInfo:
    """Information about a domain including categorization and reputation."""
    domain: str
    category: DomainCategory
    threat_level: ThreatLevel
    reputation_score: float = 0.0  # 0.0 to 1.0, higher is more trustworthy
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    query_count: int = 0
    blocked_count: int = 0
    description: Optional[str] = None
    tags: List[str] = field(default_factory=list)


@dataclass
class ClientInfo:
    """Information about a client device."""
    ip_address: str
    hostname: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    total_queries: int = 0
    blocked_queries: int = 0
    unique_domains: int = 0
    risk_score: float = 0.0  # 0.0 to 1.0, higher is more risky


@dataclass
class Anomaly:
    """Represents a detected anomaly in DNS traffic."""
    timestamp: datetime
    anomaly_type: str
    description: str
    severity: ThreatLevel
    affected_client: Optional[str] = None
    affected_domain: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0  # 0.0 to 1.0


@dataclass
class AnalysisResult:
    """Result of DNS log analysis."""
    timestamp: datetime
    total_queries: int
    blocked_queries: int
    unique_domains: int
    unique_clients: int
    top_domains: List[Dict[str, Any]] = field(default_factory=list)
    top_clients: List[Dict[str, Any]] = field(default_factory=list)
    domain_categories: Dict[str, int] = field(default_factory=dict)
    anomalies: List[Anomaly] = field(default_factory=list)
    threat_summary: Dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        """Convert analysis result to JSON string."""
        def serialize_datetime(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            elif isinstance(obj, Enum):
                return obj.value
            elif hasattr(obj, '__dict__'):
                return obj.__dict__
            return str(obj)

        return json.dumps(self, default=serialize_datetime, indent=2)


@dataclass
class Alert:
    """Security alert generated by the system."""
    id: str
    timestamp: datetime
    title: str
    description: str
    severity: ThreatLevel
    source: str  # e.g., "anomaly_detector", "threat_intel"
    affected_entities: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    acknowledged: bool = False
