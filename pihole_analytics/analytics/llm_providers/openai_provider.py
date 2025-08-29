"""
OpenAI LLM provider implementation.

This provider integrates with OpenAI's API for DNS analysis.
"""

import logging
from typing import List, Optional

try:
    import openai  # pylint: disable=import-error
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    openai = None

from .base import BaseLLMProvider, LLMConfig
from ...utils.models import DNSQuery, AnalysisResult


class OpenAIProvider(BaseLLMProvider):
    """OpenAI LLM provider implementation."""

    def __init__(self, config: LLMConfig):
        if not OPENAI_AVAILABLE:
            raise ImportError(
                "OpenAI package not installed. Install with: pip install openai")

        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self._setup_client()

    def _setup_client(self):
        """Setup OpenAI client."""
        if openai is None:
            raise ImportError("OpenAI package not available")

        self.client = openai.OpenAI(
            api_key=self.config.api_key,
            base_url=self.config.api_base_url
        )

    def validate_config(self) -> None:
        """Validate OpenAI configuration."""
        if not self.config.api_key:
            raise ValueError("OpenAI API key is required")

        if not self.config.model:
            self.config.model = "gpt-3.5-turbo"

    def analyze_queries(self, queries: List[DNSQuery],
                        custom_instructions: Optional[str] = None) -> AnalysisResult:
        """Analyze queries using OpenAI."""
        try:
            self.logger.info(
                "Starting OpenAI analysis of %d queries", len(queries))

            # Build the analysis prompt
            prompt = self._build_analysis_prompt(queries, custom_instructions)

            # Make request to OpenAI
            response = self.client.chat.completions.create(
                model=self.config.model,
                messages=[
                    {"role": "system", "content": "You are a DNS security analyst expert."},
                    {"role": "user", "content": prompt}
                ],
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens
            )

            # Parse OpenAI response
            llm_text = response.choices[0].message.content

            # Parse the LLM response and create AnalysisResult
            analysis_result = self._parse_llm_response(llm_text, queries)

            self.logger.info("Successfully completed OpenAI analysis")
            return analysis_result

        except (ValueError, KeyError, TypeError, AttributeError) as e:
            self.logger.error("Failed to analyze with OpenAI: %s", e)
            return self._create_fallback_analysis(queries)
        except ImportError as e:
            self.logger.error("OpenAI package not available: %s", e)
            return self._create_fallback_analysis(queries)
        except ConnectionError as e:
            self.logger.error("OpenAI connection error: %s", e)
            return self._create_fallback_analysis(queries)

    def test_connection(self) -> bool:
        """Test OpenAI connection."""
        try:
            # Try to list models as a connection test
            list(self.client.models.list())
            return True
        except (ConnectionError, TimeoutError, AttributeError, ImportError) as e:
            self.logger.debug("OpenAI connection test failed: %s", e)
            return False

    def get_available_models(self) -> List[str]:
        """Get available OpenAI models."""
        try:
            models = self.client.models.list()
            # Filter for chat models
            chat_models = [
                model.id for model in models
                if any(prefix in model.id for prefix in ['gpt-3.5', 'gpt-4'])
            ]
            return sorted(chat_models)

        except (ConnectionError, TimeoutError, AttributeError, ImportError, ValueError) as e:
            self.logger.debug("Failed to get OpenAI models: %s", e)
            return ["gpt-3.5-turbo", "gpt-4"]  # Default fallback models
