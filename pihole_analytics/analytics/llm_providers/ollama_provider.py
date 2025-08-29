"""
Ollama LLM provider implementation.

This provider integrates with local Ollama instances for DNS analysis.
"""

import json
import logging
from typing import List, Optional

import requests

from .base import BaseLLMProvider, LLMConfig
from ...utils.models import DNSQuery, AnalysisResult


class OllamaProvider(BaseLLMProvider):
    """Ollama LLM provider implementation."""

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)

    def validate_config(self) -> None:
        """Validate Ollama configuration."""
        if not self.config.api_base_url:
            self.config.api_base_url = "http://localhost:11434"

        # Ensure URL doesn't end with slash
        self.config.api_base_url = self.config.api_base_url.rstrip('/')

        if not self.config.model:
            raise ValueError("Ollama model name is required")

    def analyze_queries(self, queries: List[DNSQuery],
                        custom_instructions: Optional[str] = None) -> AnalysisResult:
        """Analyze queries using Ollama."""
        try:
            self.logger.info(
                "Starting LLM analysis of %d queries", len(queries))

            # Build the analysis prompt
            prompt = self._build_analysis_prompt(queries, custom_instructions)

            # Make request to Ollama
            response = requests.post(
                f"{self.config.api_base_url}/api/generate",
                json={
                    "model": self.config.model,
                    "prompt": prompt,
                    "temperature": self.config.temperature,
                    "stream": False,
                    "options": {
                        "num_predict": self.config.max_tokens,
                        "temperature": self.config.temperature
                    }
                },
                timeout=self.config.timeout
            )
            response.raise_for_status()

            # Parse Ollama response
            ollama_response = response.json()
            llm_text = ollama_response.get("response", "")

            # Parse the LLM response and create AnalysisResult
            analysis_result = self._parse_llm_response(llm_text, queries)

            self.logger.info("Successfully completed LLM analysis")
            return analysis_result

        except requests.exceptions.RequestException as e:
            self.logger.error("Ollama request failed: %s", e)
            raise ConnectionError(f"Failed to connect to Ollama: {e}") from e
        except json.JSONDecodeError as e:
            self.logger.error("Failed to parse Ollama response: %s", e)
            # Return fallback analysis
            return self._create_fallback_analysis(queries)
        except (ValueError, KeyError, TypeError) as e:
            self.logger.error("Ollama analysis failed: %s", e)
            return self._create_fallback_analysis(queries)

    def test_connection(self) -> bool:
        """Test Ollama connection."""
        try:
            response = requests.get(
                f"{self.config.api_base_url}/api/tags",
                timeout=5
            )
            return response.status_code == 200
        except (requests.exceptions.RequestException, requests.exceptions.Timeout) as e:
            self.logger.debug("Ollama connection test failed: %s", e)
            return False

    def get_available_models(self) -> List[str]:
        """Get available Ollama models."""
        try:
            response = requests.get(
                f"{self.config.api_base_url}/api/tags",
                timeout=10
            )
            response.raise_for_status()

            models_data = response.json()
            models = models_data.get("models", [])
            return [model.get("name", "") for model in models if model.get("name")]

        except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
            self.logger.debug("Failed to get Ollama models: %s", e)
            return []
