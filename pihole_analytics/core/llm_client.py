"""
LLM (Ollama) client for AI-powered analysis.

This module provides a client for interacting with Ollama for generating
intelligent analysis of DNS logs and security insights.
"""

import json
from typing import Dict, Any

import requests

from ..utils.config import LLMConfig
from ..utils.logging import LoggerMixin


class LLMError(Exception):
    """Custom exception for LLM-related errors."""


class LLMClient(LoggerMixin):
    """Client for interacting with Ollama LLM."""

    def __init__(self, config: LLMConfig):
        """Initialize LLM client with configuration."""
        self.config = config
        self._session = requests.Session()

        self.logger.info("Initialized LLM client for model: %s", config.model)

    def _api_url(self, endpoint: str) -> str:
        """Construct full Ollama API URL."""
        return f"{self.config.url.rstrip('/')}/api/{endpoint.lstrip('/')}"

    def generate(self, prompt: str, **kwargs) -> str:
        """
        Generate text using the LLM.

        Args:
            prompt: Input prompt for the LLM
            **kwargs: Additional generation parameters

        Returns:
            Generated text response

        Raises:
            LLMError: If generation fails
        """
        self.log_method_call("generate", prompt_length=len(prompt))

        url = self._api_url("generate")

        payload = {
            "model": self.config.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "num_predict": kwargs.get("max_tokens", self.config.max_tokens),
                "temperature": kwargs.get("temperature", self.config.temperature),
                **kwargs.get("options", {})
            }
        }

        try:
            response = self._session.post(
                url,
                json=payload,
                timeout=self.config.timeout
            )
            response.raise_for_status()

            # Parse response based on Ollama format
            try:
                data = response.json()
            except ValueError:
                # If not JSON, return raw text
                return response.text

            # Extract response content
            content = self._extract_response_content(data)

            self.logger.info(
                "Successfully generated LLM response (length: %d)", len(content))
            return content

        except requests.RequestException as error:
            self.log_error(
                error, {"operation": "generate", "model": self.config.model})
            raise LLMError(
                f"Failed to generate LLM response: {error}") from error

    def _extract_response_content(self, data: Dict[str, Any]) -> str:
        """Extract response content from various Ollama response formats."""
        # Standard Ollama response format
        if "response" in data:
            return data["response"]

        # OpenAI-compatible format
        if "choices" in data and isinstance(data["choices"], list) and data["choices"]:
            first_choice = data["choices"][0]
            if "message" in first_choice and "content" in first_choice["message"]:
                content = first_choice["message"]["content"]
                if isinstance(content, dict):
                    return (content.get("text") or content.get("content") or
                            json.dumps(content))
                return str(content)
            return first_choice.get("text", json.dumps(first_choice))

        # Alternative nested format
        if "data" in data and isinstance(data["data"], list) and data["data"]:
            for item in data["data"]:
                if isinstance(item, dict):
                    if "response" in item:
                        return item["response"]
                    if "message" in item:
                        return item["message"]

        # Fallback: return JSON representation
        return json.dumps(data, indent=2)

    def analyze_dns_logs(self, queries, analysis_type: str = "general") -> Dict[str, Any]:
        """
        Analyze DNS logs using LLM.

        Args:
            queries: List of DNS queries or formatted log data
            analysis_type: Type of analysis to perform

        Returns:
            Analysis results as dictionary

        Raises:
            LLMError: If analysis fails
        """
        self.log_method_call("analyze_dns_logs",
                             query_count=len(queries) if hasattr(
                                 queries, '__len__') else 0,
                             analysis_type=analysis_type)

        prompt = self._build_analysis_prompt(queries, analysis_type)

        try:
            response = self.generate(prompt)

            # Try to parse as JSON
            try:
                return json.loads(response)
            except json.JSONDecodeError:
                # If not valid JSON, return as text response
                self.logger.warning(
                    "LLM response is not valid JSON, returning as text")
                return {"analysis": response, "format": "text"}

        except LLMError:
            raise
        except Exception as error:
            self.log_error(error, {"operation": "analyze_dns_logs"})
            raise LLMError(f"Failed to analyze DNS logs: {error}") from error

    def _build_analysis_prompt(self, queries, analysis_type: str) -> str:
        """Build analysis prompt based on query data and analysis type."""
        if analysis_type == "security":
            return self._build_security_analysis_prompt(queries)
        elif analysis_type == "categorization":
            return self._build_categorization_prompt(queries)
        elif analysis_type == "anomaly":
            return self._build_anomaly_detection_prompt(queries)
        elif analysis_type == "search":
            return self._build_search_prompt(queries)
        else:
            return self._build_general_analysis_prompt(queries)

    def _build_general_analysis_prompt(self, queries) -> str:
        """Build general analysis prompt."""
        instructions = (
            "You are a network security analyst. Analyze the DNS query log entries below and provide:\n"
            "1) A summary of notable trends (3-5 bullets)\n"
            "2) Top 5 clients by query count with blocked query counts\n"
            "3) Top 10 domains queried with counts\n"
            "4) Any suspicious domains or patterns and explanations\n"
            "5) Recommended security actions (concise)\n\n"
            "Return response as JSON with keys: summary (list), top_clients (list), "
            "top_domains (list), suspicious (list), actions (list).\n"
        )

        log_block = self._format_queries_for_prompt(queries)

        return (
            "Below are DNS query log lines (timestamp | client_ip | status | domain).\n\n"
            f"INSTRUCTIONS:\n{instructions}\n\n"
            f"LOGS:\n{log_block}\n\n"
            "Return only valid JSON as specified."
        )

    def _build_security_analysis_prompt(self, queries) -> str:
        """Build security-focused analysis prompt."""
        instructions = (
            "You are a cybersecurity expert analyzing DNS traffic for threats. Focus on:\n"
            "1) Malware indicators (C2 domains, suspicious patterns)\n"
            "2) Data exfiltration attempts (DNS tunneling, unusual queries)\n"
            "3) Phishing domains (typosquatting, suspicious registrations)\n"
            "4) Botnet activity (periodic beaconing, bulk queries)\n"
            "5) Risk assessment and immediate actions needed\n\n"
            "Return JSON with: threats (list), risk_level (low/medium/high/critical), "
            "indicators (list), recommended_actions (list).\n"
        )

        log_block = self._format_queries_for_prompt(queries)

        return (
            "DNS SECURITY ANALYSIS\n\n"
            f"INSTRUCTIONS:\n{instructions}\n\n"
            f"LOGS:\n{log_block}\n\n"
            "Return only valid JSON as specified."
        )

    def _build_categorization_prompt(self, domains) -> str:
        """Build domain categorization prompt."""
        domain_list = "\n".join(domains) if isinstance(
            domains, list) else str(domains)

        return (
            "Categorize the following domains into these categories:\n"
            "- social_media\n- advertising\n- streaming\n- gaming\n- cloud_services\n"
            "- cdn\n- analytics\n- suspicious\n- malware\n- phishing\n- unknown\n\n"
            "Return JSON format: {\"domain\": \"category\", ...}\n\n"
            f"DOMAINS:\n{domain_list}\n\n"
            "Return only valid JSON."
        )

    def _build_anomaly_detection_prompt(self, queries) -> str:
        """Build anomaly detection prompt."""
        instructions = (
            "Detect anomalies in DNS traffic patterns. Look for:\n"
            "1) Unusual query volumes from specific clients\n"
            "2) Queries to non-existent or suspicious domains\n"
            "3) Unusual timing patterns (off-hours activity)\n"
            "4) Repeated failed queries (potential malware)\n"
            "5) DGA (Domain Generation Algorithm) patterns\n\n"
            "Return JSON with: anomalies (list of {type, description, severity, client, domain}), "
            "confidence (0-1), explanation (string).\n"
        )

        log_block = self._format_queries_for_prompt(queries)

        return (
            "ANOMALY DETECTION ANALYSIS\n\n"
            f"INSTRUCTIONS:\n{instructions}\n\n"
            f"LOGS:\n{log_block}\n\n"
            "Return only valid JSON as specified."
        )

    def _build_search_prompt(self, search_query) -> str:
        """Build natural language search prompt."""
        return (
            f"Answer this question about DNS logs: {search_query}\n\n"
            "Provide a clear, specific answer based on the log data. "
            "If you need to search or filter logs, describe what to look for.\n\n"
            "Return JSON with: answer (string), search_criteria (list), "
            "suggested_filters (dict)."
        )

    def _format_queries_for_prompt(self, queries) -> str:
        """Format DNS queries for inclusion in LLM prompt."""
        if not queries:
            return "No queries provided."

        lines = []

        # Handle different input formats
        if hasattr(queries[0], 'timestamp'):  # DNSQuery objects
            for query in queries:
                timestamp = query.timestamp.isoformat()
                lines.append(
                    f"{timestamp} | {query.client_ip} | {query.status.value} | {query.domain}")
        elif isinstance(queries[0], dict):  # Raw dict data
            for query in queries:
                timestamp = query.get("timestamp", "unknown")
                client = query.get("client", query.get("client_ip", "unknown"))
                status = query.get("status", "unknown")
                domain = query.get("domain", query.get("query", "unknown"))
                lines.append(f"{timestamp} | {client} | {status} | {domain}")
        else:  # Assume string format
            lines = [str(q) for q in queries]

        log_block = "\n".join(lines)

        # Truncate if too long
        if len(log_block) > self.config.max_tokens * 3:  # Rough estimate
            log_block = log_block[:self.config.max_tokens * 3]
            # Try to end at a line boundary
            last_newline = log_block.rfind("\n")
            if last_newline > len(log_block) * 0.8:  # Keep most of the content
                log_block = log_block[:last_newline]

        return log_block

    def check_health(self) -> bool:
        """
        Check if LLM service is healthy and responsive.

        Returns:
            True if healthy, False otherwise
        """
        try:
            url = self._api_url("tags")
            response = self._session.get(url, timeout=10)
            response.raise_for_status()

            self.logger.info("LLM service health check passed")
            return True

        except requests.RequestException as error:
            self.logger.warning("LLM service health check failed: %s", error)
            return False
