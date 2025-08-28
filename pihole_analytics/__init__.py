"""
Pi-hole LLM Analytics Package

A comprehensive analytics and security monitoring tool for Pi-hole DNS logs
using Large Language Models for intelligent analysis and threat detection.
"""

__version__ = "1.0.0"
__author__ = "LiteObject"
__email__ = ""
__license__ = "MIT"

from .core.pihole_client import PiholeClient
from .core.llm_client import LLMClient
from .analytics.analyzer import DNSAnalyzer
from .security.threat_detector import ThreatDetector

__all__ = [
    "PiholeClient",
    "LLMClient",
    "DNSAnalyzer",
    "ThreatDetector",
]
