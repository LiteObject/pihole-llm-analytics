"""
Base LLM Provider interface and configuration.

This module defines the abstract base class for LLM providers and
common configuration structures.
"""

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, Any, List, Optional
import os

from ...utils.models import DNSQuery, AnalysisResult, Anomaly, ThreatLevel


class LLMProvider(Enum):
    """Supported LLM providers."""
    OLLAMA = "ollama"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    AZURE = "azure"
    HUGGINGFACE = "huggingface"
    LOCAL = "local"


@dataclass
class LLMConfig:
    """Configuration for LLM providers."""
    provider: LLMProvider
    model: str
    api_key: Optional[str] = None
    api_base_url: Optional[str] = None
    temperature: float = 0.7
    max_tokens: int = 2000
    timeout: int = 30
    max_prompt_chars: int = 18000
    extra_params: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_env(cls, provider: Optional[LLMProvider] = None) -> 'LLMConfig':
        """Create LLM config from environment variables."""
        if provider is None:
            provider_name = os.getenv("LLM_PROVIDER", "ollama").lower()
            try:
                provider = LLMProvider[provider_name.upper()]
            except KeyError:
                provider = LLMProvider.OLLAMA

        # Base configuration from environment
        config = cls(
            provider=provider,
            model=os.getenv("LLM_MODEL", "gpt-oss:latest"),
            api_key=os.getenv("LLM_API_KEY"),
            api_base_url=os.getenv("LLM_API_BASE_URL"),
            temperature=float(os.getenv("LLM_TEMPERATURE", "0.7")),
            max_tokens=int(os.getenv("LLM_MAX_TOKENS", "2000")),
            timeout=int(os.getenv("LLM_TIMEOUT", "30")),
            max_prompt_chars=int(os.getenv("MAX_PROMPT_CHARS", "18000"))
        )

        # Provider-specific defaults
        if provider == LLMProvider.OLLAMA:
            if not config.api_base_url:
                config.api_base_url = "http://localhost:11434"
            if config.model == "gpt-oss:latest":  # Keep existing default
                config.model = os.getenv("OLLAMA_MODEL", "gpt-oss:latest")
        elif provider == LLMProvider.OPENAI:
            if not config.model or config.model == "gpt-oss:latest":
                config.model = "gpt-3.5-turbo"
        elif provider == LLMProvider.ANTHROPIC:
            if not config.model or config.model == "gpt-oss:latest":
                config.model = "claude-3-haiku-20240307"

        return config


class BaseLLMProvider(ABC):
    """Abstract base class for LLM providers."""

    def __init__(self, config: LLMConfig):
        self.config = config
        self.validate_config()

    @abstractmethod
    def validate_config(self) -> None:
        """Validate provider-specific configuration."""
        raise NotImplementedError

    @abstractmethod
    def analyze_queries(self, queries: List[DNSQuery],
                        custom_instructions: Optional[str] = None) -> AnalysisResult:
        """
        Analyze DNS queries and return insights.

        Args:
            queries: List of DNS queries to analyze
            custom_instructions: Optional custom analysis instructions

        Returns:
            AnalysisResult containing the analysis
        """
        raise NotImplementedError

    @abstractmethod
    def test_connection(self) -> bool:
        """Test connection to the LLM service."""
        raise NotImplementedError

    @abstractmethod
    def get_available_models(self) -> List[str]:
        """Get list of available models for this provider."""
        raise NotImplementedError

    def get_provider_name(self) -> str:
        """Get the provider name."""
        return self.config.provider.value

    def _build_analysis_prompt(self, queries: List[DNSQuery],
                               custom_instructions: Optional[str] = None) -> str:
        """Build the analysis prompt for DNS queries."""
        # This is shared logic that all providers can use
        prompt_parts = []

        # Add custom instructions if provided
        if custom_instructions:
            prompt_parts.append(
                f"Analysis Instructions: {custom_instructions}\n")

        # Add default analysis instructions
        prompt_parts.append("""
You are a DNS security analyst. Analyze the provided DNS query logs and provide insights in JSON format.

Focus on:
1. Security threats and suspicious domains
2. Traffic patterns and anomalies  
3. Domain categorization (social media, advertising, streaming, etc.)
4. Client behavior analysis
5. Overall risk assessment

Return a JSON response with the following structure:
{
  "threat_summary": {
    "risk_level": "minimal|low|medium|high|critical",
    "threats_detected": 0,
    "description": "Brief summary"
  },
  "anomalies": [
    {
      "type": "anomaly_type",
      "description": "Description",
      "severity": "low|medium|high|critical",
      "confidence": 0.8
    }
  ],
  "domain_categories": {
    "social_media": 5,
    "advertising": 10,
    "streaming": 3
  },
  "insights": [
    "Key insight 1",
    "Key insight 2"
  ]
}

DNS Query Data:
""")

        # Add query data (truncated if needed)
        query_data = []
        for query in queries[:100]:  # Limit to 100 queries
            query_data.append({
                "timestamp": query.timestamp.isoformat(),
                "domain": query.domain,
                "client_ip": query.client_ip,
                "status": query.status.value,
                "type": query.query_type
            })

        prompt_parts.append(f"Queries to analyze: {len(queries)} total\n")
        prompt_parts.append(f"Sample data: {query_data}\n")

        full_prompt = "".join(prompt_parts)

        # Truncate if too long
        if len(full_prompt) > self.config.max_prompt_chars:
            full_prompt = full_prompt[:self.config.max_prompt_chars] + \
                "...[truncated]"

        return full_prompt

    def _parse_llm_response(self, llm_response: str, queries: List[DNSQuery]) -> AnalysisResult:
        """Parse LLM response and create AnalysisResult (shared implementation)."""
        try:
            # Try to extract JSON from the response
            analysis_data = self._extract_json_from_response(llm_response)

            if not analysis_data:
                return self._create_fallback_analysis(queries)

            # Extract threat summary
            threat_summary = analysis_data.get("threat_summary", {})

            # Extract anomalies
            anomalies = []
            for anomaly_data in analysis_data.get("anomalies", []):
                if isinstance(anomaly_data, dict):
                    anomaly = Anomaly(
                        timestamp=datetime.now(),
                        anomaly_type=anomaly_data.get("type", "unknown"),
                        description=anomaly_data.get(
                            "description", "No description"),
                        severity=self._parse_threat_level(
                            anomaly_data.get("severity", "low")),
                        confidence=float(anomaly_data.get("confidence", 0.5))
                    )
                    anomalies.append(anomaly)

            # Calculate basic statistics
            total_queries = len(queries)
            blocked_queries = sum(
                1 for q in queries if q.status.value == "blocked")
            unique_domains = len(set(q.domain for q in queries))
            unique_clients = len(set(q.client_ip for q in queries))

            return AnalysisResult(
                timestamp=datetime.now(),
                total_queries=total_queries,
                blocked_queries=blocked_queries,
                unique_domains=unique_domains,
                unique_clients=unique_clients,
                anomalies=anomalies,
                threat_summary=threat_summary,
                domain_categories=analysis_data.get("domain_categories", {})
            )

        except (ValueError, KeyError, TypeError):
            return self._create_fallback_analysis(queries)

    def _extract_json_from_response(self, response: str) -> Optional[Dict[str, Any]]:
        """Extract JSON data from LLM response."""
        if not response:
            return None

        # Try direct JSON parsing first
        try:
            return json.loads(response.strip())
        except json.JSONDecodeError:
            pass

        # Try to find JSON in the response
        json_match = re.search(r'\{.*\}', response, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass

        # Try to find JSON blocks
        lines = response.split('\n')
        for i, line in enumerate(lines):
            if line.strip().startswith('{'):
                # Try to parse from this line onwards
                remaining_text = '\n'.join(lines[i:])
                try:
                    return json.loads(remaining_text)
                except json.JSONDecodeError:
                    continue

        return None

    def _parse_threat_level(self, level_str: str) -> ThreatLevel:
        """Parse threat level string to ThreatLevel enum."""
        level_str = level_str.lower().strip()
        try:
            return ThreatLevel(level_str)
        except ValueError:
            return ThreatLevel.LOW

    def _create_fallback_analysis(self, queries: List[DNSQuery]) -> AnalysisResult:
        """Create a basic analysis when LLM parsing fails."""
        total_queries = len(queries)
        blocked_queries = sum(
            1 for q in queries if q.status.value == "blocked")
        unique_domains = len(set(q.domain for q in queries))
        unique_clients = len(set(q.client_ip for q in queries))

        return AnalysisResult(
            timestamp=datetime.now(),
            total_queries=total_queries,
            blocked_queries=blocked_queries,
            unique_domains=unique_domains,
            unique_clients=unique_clients,
            anomalies=[],
            threat_summary={
                "risk_level": "minimal",
                "threats_detected": 0,
                "description": "Basic analysis - LLM parsing failed"
            },
            domain_categories={}
        )
