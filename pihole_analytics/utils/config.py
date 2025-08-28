"""
Configuration management for Pi-hole Analytics.

This module handles all configuration settings, environment variables,
and provides default values with validation.
"""

import os
from dataclasses import dataclass, field
from typing import List, Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


@dataclass
class PiholeConfig:
    """Pi-hole connection configuration."""
    host: str = os.getenv("PIHOLE_HOST", "127.0.0.1")
    port: int = int(os.getenv("PIHOLE_PORT", "80"))
    password: Optional[str] = os.getenv("PIHOLE_PASSWORD")
    timeout: int = int(os.getenv("PIHOLE_TIMEOUT", "10"))

    def __post_init__(self):
        """Validate configuration after initialization."""
        if not self.password:
            raise ValueError("PIHOLE_PASSWORD is required")

    @property
    def base_url(self) -> str:
        """Get the base URL for Pi-hole API."""
        return f"http://{self.host}:{self.port}"


@dataclass
class LLMConfig:
    """LLM (Ollama) configuration."""
    url: str = os.getenv("OLLAMA_URL", "http://localhost:11434")
    model: str = os.getenv("OLLAMA_MODEL", "gpt-oss:latest")
    timeout: int = int(os.getenv("OLLAMA_TIMEOUT", "120"))
    temperature: float = float(os.getenv("OLLAMA_TEMPERATURE", "0.2"))
    max_tokens: int = int(os.getenv("OLLAMA_MAX_TOKENS", "512"))


@dataclass
class AnalyticsConfig:
    """Analytics and processing configuration."""
    log_count: int = int(os.getenv("LOG_COUNT", "100"))
    max_prompt_chars: int = int(os.getenv("MAX_PROMPT_CHARS", "18000"))
    analysis_interval_hours: int = int(
        os.getenv("ANALYSIS_INTERVAL_HOURS", "1"))
    anomaly_threshold: float = float(os.getenv("ANOMALY_THRESHOLD", "0.7"))

    # Report generation settings
    daily_report_time: str = os.getenv("DAILY_REPORT_TIME", "08:00")
    weekly_report_day: str = os.getenv("WEEKLY_REPORT_DAY", "monday")

    # Domain categorization
    enable_domain_categorization: bool = os.getenv(
        "ENABLE_DOMAIN_CATEGORIZATION", "true").lower() == "true"

    # Anomaly detection settings
    enable_anomaly_detection: bool = os.getenv(
        "ENABLE_ANOMALY_DETECTION", "true").lower() == "true"
    anomaly_window_hours: int = int(os.getenv("ANOMALY_WINDOW_HOURS", "24"))

    # Query volume thresholds
    high_volume_threshold: int = int(
        os.getenv("HIGH_VOLUME_THRESHOLD", "1000"))
    suspicious_query_threshold: int = int(
        os.getenv("SUSPICIOUS_QUERY_THRESHOLD", "100"))


@dataclass
class SecurityConfig:
    """Security monitoring configuration."""
    enable_threat_detection: bool = os.getenv(
        "ENABLE_THREAT_DETECTION", "true").lower() == "true"
    threat_intel_urls: List[str] = field(default_factory=lambda: [
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "https://someonewhocares.org/hosts/zero/hosts",
        "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt"
    ])

    # Domain reputation settings
    enable_domain_reputation: bool = os.getenv(
        "ENABLE_DOMAIN_REPUTATION", "true").lower() == "true"
    reputation_cache_hours: int = int(
        os.getenv("REPUTATION_CACHE_HOURS", "24"))

    # Alert settings
    enable_alerts: bool = os.getenv("ENABLE_ALERTS", "true").lower() == "true"
    alert_webhook_url: Optional[str] = os.getenv("ALERT_WEBHOOK_URL")
    alert_email: Optional[str] = os.getenv("ALERT_EMAIL")

    # Threat level thresholds
    critical_threat_threshold: float = float(
        os.getenv("CRITICAL_THREAT_THRESHOLD", "0.9"))
    high_threat_threshold: float = float(
        os.getenv("HIGH_THREAT_THRESHOLD", "0.7"))
    medium_threat_threshold: float = float(
        os.getenv("MEDIUM_THREAT_THRESHOLD", "0.4"))


@dataclass
class DatabaseConfig:
    """Database configuration for storing analysis results."""
    db_path: str = os.getenv("DB_PATH", "pihole_analytics.db")
    enable_persistence: bool = os.getenv(
        "ENABLE_PERSISTENCE", "true").lower() == "true"
    backup_interval_hours: int = int(os.getenv("BACKUP_INTERVAL_HOURS", "24"))
    retention_days: int = int(os.getenv("RETENTION_DAYS", "30"))


@dataclass
class LoggingConfig:
    """Logging configuration."""
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    log_file: Optional[str] = os.getenv("LOG_FILE")
    log_format: str = os.getenv(
        "LOG_FORMAT", "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    enable_json_logging: bool = os.getenv(
        "ENABLE_JSON_LOGGING", "false").lower() == "true"


@dataclass
class AppConfig:
    """Main application configuration."""
    pihole: PiholeConfig = field(default_factory=PiholeConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    analytics: AnalyticsConfig = field(default_factory=AnalyticsConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)

    # Global settings
    debug: bool = os.getenv("DEBUG", "false").lower() == "true"
    version: str = "1.0.0"


# Global configuration instance
config = AppConfig()


def get_config() -> AppConfig:
    """Get the global configuration instance."""
    return config


def reload_config() -> AppConfig:
    """Reload configuration from environment variables."""
    load_dotenv(override=True)
    # Create new config instead of using global
    return AppConfig()
