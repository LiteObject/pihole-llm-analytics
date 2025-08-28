"""
LLM-powered DNS analytics.

This module provides AI-powered analysis of Pi-hole DNS logs using local LLM services
like Ollama. It integrates with the existing PiholeClient to fetch data and provides
structured analysis results.
"""

import json
import os
from typing import Dict, List, Optional, Any
from datetime import datetime

import requests

from ..utils.models import DNSQuery, AnalysisResult, Anomaly, ThreatLevel
from ..utils.logging import LoggerMixin
from ..utils.config import PiholeConfig


class LLMAnalysisError(Exception):
    """Custom exception for LLM analysis errors."""


class LLMConfig:
    """Configuration for LLM service."""

    def __init__(
        self,
        url: str = "http://localhost:11434",
        model: str = "gpt-oss:latest",
        timeout: int = 120,
        max_prompt_chars: int = 18000,
        temperature: float = 0.2,
        max_tokens: int = 512
    ):
        self.url = url.rstrip('/')
        self.model = model
        self.timeout = timeout
        self.max_prompt_chars = max_prompt_chars
        self.temperature = temperature
        self.max_tokens = max_tokens

    @classmethod
    def from_env(cls) -> 'LLMConfig':
        """Create LLM config from environment variables."""
        return cls(
            url=os.getenv("OLLAMA_URL", "http://localhost:11434"),
            model=os.getenv("OLLAMA_MODEL", "gpt-oss:latest"),
            timeout=int(os.getenv("OLLAMA_TIMEOUT", "120")),
            max_prompt_chars=int(os.getenv("MAX_PROMPT_CHARS", "18000")),
            temperature=float(os.getenv("OLLAMA_TEMPERATURE", "0.2")),
            max_tokens=int(os.getenv("OLLAMA_MAX_TOKENS", "512"))
        )


class LLMAnalyzer(LoggerMixin):
    """AI-powered DNS log analyzer using local LLM services."""

    def __init__(self, llm_config: Optional[LLMConfig] = None):
        """Initialize LLM analyzer with configuration."""
        self.config = llm_config or LLMConfig.from_env()
        self.logger.info("Initialized LLM analyzer with model: %s at %s",
                         self.config.model, self.config.url)

    def analyze_queries(
        self,
        queries: List[DNSQuery],
        custom_instructions: Optional[str] = None
    ) -> AnalysisResult:
        """
        Analyze DNS queries using LLM and return structured results.

        Args:
            queries: List of DNS queries to analyze
            custom_instructions: Optional custom analysis instructions

        Returns:
            AnalysisResult containing AI-powered insights

        Raises:
            LLMAnalysisError: If analysis fails
        """
        self.logger.info("Starting LLM analysis of %d queries", len(queries))

        if not queries:
            self.logger.warning("No queries provided for analysis")
            return self._create_empty_result()

        try:
            # Create analysis prompt
            prompt = self._create_analysis_prompt(queries, custom_instructions)

            # Get LLM analysis
            raw_analysis = self._call_llm(prompt)

            # Parse and structure the results
            structured_result = self._parse_llm_response(raw_analysis, queries)

            self.logger.info("Successfully completed LLM analysis")
            return structured_result

        except Exception as error:
            self.logger.error("LLM analysis failed: %s", error)
            raise LLMAnalysisError(f"Analysis failed: {error}") from error

    def _create_analysis_prompt(
        self,
        queries: List[DNSQuery],
        custom_instructions: Optional[str] = None
    ) -> str:
        """Create a structured prompt for LLM analysis."""

        # Default analysis instructions
        default_instructions = """
You are a cybersecurity DNS traffic analyst. Analyze the DNS query logs below and provide:

1) A summary of notable trends and patterns (3-5 bullet points)
2) Top 5 clients by query volume with blocked query counts
3) Top 10 most queried domains with counts
4) Suspicious domains or patterns with explanations
5) Security recommendations and next steps

Return your analysis as valid JSON with this exact structure:
{
    "summary": ["bullet point 1", "bullet point 2", ...],
    "top_clients": [{"client": "IP", "total": number, "blocked": number}, ...],
    "top_domains": [{"domain": "example.com", "count": number}, ...],
    "suspicious": [{"domain": "suspicious.com", "reason": "explanation"}, ...],
    "actions": ["recommendation 1", "recommendation 2", ...]
}
"""

        instructions = custom_instructions or default_instructions

        # Convert queries to compact log format
        log_lines = []
        for query in queries:
            timestamp = query.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            status_short = self._get_status_short(query.status.value)
            log_lines.append(
                f"{timestamp}\t{query.client_ip}\t{status_short}\t{query.domain}")

        # Create log block and truncate if necessary
        log_block = "\n".join(log_lines)
        if len(log_block) > self.config.max_prompt_chars:
            # Keep the most recent entries
            log_block = log_block[-self.config.max_prompt_chars:]
            # Ensure we start at a newline boundary
            newline_pos = log_block.find("\n")
            if newline_pos != -1:
                log_block = log_block[newline_pos + 1:]

        # Construct the full prompt
        prompt = f"""
{instructions}

DNS QUERY LOGS (timestamp \\t client_ip \\t status \\t domain):

{log_block}

Respond only with valid JSON following the specified structure.
"""

        self.logger.debug("Generated prompt with %d characters", len(prompt))
        return prompt

    def _get_status_short(self, status: str) -> str:
        """Convert status to short representation."""
        status_map = {
            "blocked": "BLOCK",
            "allowed": "ALLOW",
            "cached": "CACHE",
            "forwarded": "FORWD",
            "unknown": "UNK"
        }
        return status_map.get(status.lower(), "UNK")

    def _call_llm(self, prompt: str) -> str:
        """
        Call the LLM service and return the response.

        Args:
            prompt: The prompt to send to the LLM

        Returns:
            The LLM's response text

        Raises:
            LLMAnalysisError: If the LLM call fails
        """
        url = f"{self.config.url}/api/generate"
        payload = {
            "model": self.config.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "num_predict": self.config.max_tokens,
                "temperature": self.config.temperature
            }
        }

        self.logger.debug("Calling LLM at %s with model %s",
                          url, self.config.model)

        try:
            response = requests.post(
                url,
                json=payload,
                timeout=self.config.timeout
            )
            response.raise_for_status()

            # Extract response content based on known response formats
            try:
                data = response.json()
                content = self._extract_response_content(data)
                self.logger.debug(
                    "LLM response received (%d characters)", len(content))
                return content
            except ValueError:
                # Not JSON, return raw text
                return response.text

        except requests.RequestException as error:
            self.logger.error("LLM API call failed: %s", error)
            raise LLMAnalysisError(
                f"LLM service unavailable: {error}") from error

    def _extract_response_content(self, data: Dict[str, Any]) -> str:
        """Extract response content from various LLM response formats."""
        # Ollama standard format
        if "response" in data:
            return data["response"]

        # OpenAI-compatible format
        if "choices" in data and isinstance(data["choices"], list) and data["choices"]:
            choice = data["choices"][0]
            if "message" in choice and "content" in choice["message"]:
                content = choice["message"]["content"]
                if isinstance(content, dict):
                    return content.get("text", json.dumps(content))
                return content
            return choice.get("text", json.dumps(choice))

        # Alternative format with data array
        if "data" in data and isinstance(data["data"], list) and data["data"]:
            for item in data["data"]:
                if isinstance(item, dict) and ("response" in item or "message" in item):
                    return item.get("response") or item.get("message") or json.dumps(item)

        # Fallback to JSON representation
        return json.dumps(data, indent=2)

    def _parse_llm_response(self, raw_response: str, queries: List[DNSQuery]) -> AnalysisResult:
        """
        Parse LLM response and create structured AnalysisResult.

        Args:
            raw_response: Raw response from LLM
            queries: Original queries for context

        Returns:
            Structured AnalysisResult
        """
        try:
            # Try to extract JSON from the response
            analysis_data = self._extract_json_from_response(raw_response)

            # Create basic statistics
            total_queries = len(queries)
            blocked_queries = sum(
                1 for q in queries if q.status.value == "blocked")
            unique_domains = len(set(q.domain for q in queries))
            unique_clients = len(set(q.client_ip for q in queries))

            # Extract anomalies from suspicious domains
            anomalies = []
            if "suspicious" in analysis_data:
                for suspicious_item in analysis_data["suspicious"]:
                    if isinstance(suspicious_item, dict):
                        domain = suspicious_item.get("domain", "unknown")
                        reason = suspicious_item.get(
                            "reason", "Flagged as suspicious")
                        anomaly = Anomaly(
                            timestamp=datetime.now(),
                            anomaly_type="suspicious_domain",
                            description=f"Suspicious domain detected: {domain} - {reason}",
                            severity=ThreatLevel.MEDIUM,
                            affected_domain=domain,
                            evidence=suspicious_item,
                            confidence=0.7
                        )
                        anomalies.append(anomaly)

            # Create threat summary
            threat_summary = {
                "total_suspicious_domains": len(analysis_data.get("suspicious", [])),
                "block_rate": (blocked_queries / total_queries * 100) if total_queries > 0 else 0,
                "risk_level": self._assess_risk_level(analysis_data, blocked_queries, total_queries)
            }

            return AnalysisResult(
                timestamp=datetime.now(),
                total_queries=total_queries,
                blocked_queries=blocked_queries,
                unique_domains=unique_domains,
                unique_clients=unique_clients,
                top_domains=analysis_data.get("top_domains", []),
                top_clients=analysis_data.get("top_clients", []),
                domain_categories={},  # Could be enhanced with categorization
                anomalies=anomalies,
                threat_summary=threat_summary
            )

        except Exception as error:
            self.logger.warning(
                "Failed to parse LLM response as JSON: %s", error)
            # Create a basic result with raw analysis in threat summary
            return self._create_fallback_result(queries, raw_response)

    def _extract_json_from_response(self, response: str) -> Dict[str, Any]:
        """Extract JSON data from LLM response, handling various formats."""
        # Try direct JSON parsing
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            pass

        # Try to find JSON within the response
        lines = response.split('\n')
        for i, line in enumerate(lines):
            line = line.strip()
            if line.startswith('{'):
                # Try to parse from this line onwards
                remaining_text = '\n'.join(lines[i:])
                try:
                    # Find the end of JSON
                    brace_count = 0
                    end_pos = 0
                    for pos, char in enumerate(remaining_text):
                        if char == '{':
                            brace_count += 1
                        elif char == '}':
                            brace_count -= 1
                            if brace_count == 0:
                                end_pos = pos + 1
                                break

                    if end_pos > 0:
                        json_str = remaining_text[:end_pos]
                        return json.loads(json_str)
                except json.JSONDecodeError:
                    continue

        # If no valid JSON found, return a structured fallback
        return {
            "summary": ["LLM analysis completed but JSON parsing failed"],
            "top_clients": [],
            "top_domains": [],
            "suspicious": [],
            "actions": ["Review raw LLM output for insights"],
            "raw_response": response
        }

    def _assess_risk_level(self, analysis_data: Dict[str, Any], blocked: int, total: int) -> str:
        """Assess overall risk level based on analysis data."""
        if total == 0:
            return "unknown"

        block_rate = blocked / total
        suspicious_count = len(analysis_data.get("suspicious", []))

        if suspicious_count > 5 or block_rate > 0.3:
            return "high"
        elif suspicious_count > 2 or block_rate > 0.15:
            return "medium"
        elif suspicious_count > 0 or block_rate > 0.05:
            return "low"
        else:
            return "minimal"

    def _create_empty_result(self) -> AnalysisResult:
        """Create an empty analysis result for when no queries are provided."""
        return AnalysisResult(
            timestamp=datetime.now(),
            total_queries=0,
            blocked_queries=0,
            unique_domains=0,
            unique_clients=0,
            top_domains=[],
            top_clients=[],
            domain_categories={},
            anomalies=[],
            threat_summary={"risk_level": "none",
                            "message": "No data to analyze"}
        )

    def _create_fallback_result(self, queries: List[DNSQuery], raw_response: str) -> AnalysisResult:
        """Create a fallback result when LLM response parsing fails."""
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
            top_domains=[],
            top_clients=[],
            domain_categories={},
            anomalies=[],
            threat_summary={
                "risk_level": "unknown",
                "message": "LLM analysis completed but parsing failed",
                "raw_analysis": raw_response[:1000]  # Truncate for storage
            }
        )

    def test_connection(self) -> bool:
        """
        Test connection to the LLM service.

        Returns:
            True if connection is successful, False otherwise
        """
        try:
            url = f"{self.config.url}/api/generate"
            test_payload = {
                "model": self.config.model,
                "prompt": "Test connection. Respond with 'OK'.",
                "stream": False,
                "options": {"num_predict": 10}
            }

            response = requests.post(url, json=test_payload, timeout=10)
            response.raise_for_status()

            self.logger.info("LLM service connection test successful")
            return True

        except Exception as error:
            self.logger.error("LLM service connection test failed: %s", error)
            return False

    def get_available_models(self) -> List[str]:
        """
        Get list of available models from the LLM service.

        Returns:
            List of available model names
        """
        try:
            url = f"{self.config.url}/api/tags"
            response = requests.get(url, timeout=10)
            response.raise_for_status()

            data = response.json()
            models = []

            if "models" in data:
                for model in data["models"]:
                    if isinstance(model, dict) and "name" in model:
                        models.append(model["name"])
                    elif isinstance(model, str):
                        models.append(model)

            self.logger.info("Retrieved %d available models", len(models))
            return models

        except Exception as error:
            self.logger.error("Failed to get available models: %s", error)
            return []
