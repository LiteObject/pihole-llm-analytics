"""
Updated LLM Analyzer with Factory Pattern Support.

This module provides the main LLM analyzer interface that uses the
factory pattern for pluggable LLM providers.
"""

import logging
from typing import List, Optional

from .llm_providers.factory import LLMFactory
from .llm_providers.base import LLMConfig, LLMProvider
from ..utils.models import DNSQuery, AnalysisResult
from ..utils.logging import LoggerMixin


class LLMAnalysisError(Exception):
    """Custom exception for LLM analysis errors."""


class LLMAnalyzer(LoggerMixin):
    """
    LLM-based DNS query analyzer with pluggable providers.

    This analyzer supports multiple LLM providers (Ollama, OpenAI, etc.)
    and provides a unified interface for DNS log analysis.
    """

    def __init__(self, config: Optional[LLMConfig] = None):
        """
        Initialize with LLM configuration.

        Args:
            config: LLM configuration. If None, loads from environment
                   with Ollama as default for backward compatibility.
        """
        super().__init__()

        if config is None:
            # Default to Ollama for backward compatibility
            config = LLMConfig.from_env(LLMProvider.OLLAMA)

        self.config = config

        try:
            self.provider = LLMFactory.create(config)
            self.logger.info("Initialized LLM analyzer with %s provider (model: %s)",
                             self.provider.get_provider_name(), config.model)
        except (ValueError, ImportError) as e:
            self.logger.error("Failed to initialize LLM provider: %s", e)
            raise LLMAnalysisError(
                f"Failed to initialize LLM provider: {e}") from e

    def analyze_queries(self, queries: List[DNSQuery],
                        custom_instructions: Optional[str] = None) -> AnalysisResult:
        """
        Analyze DNS queries using the configured LLM provider.

        Args:
            queries: List of DNS queries to analyze
            custom_instructions: Optional custom analysis instructions

        Returns:
            AnalysisResult containing the analysis

        Raises:
            LLMAnalysisError: If analysis fails
        """
        try:
            self.logger.info("Starting LLM analysis of %d queries using %s",
                             len(queries), self.provider.get_provider_name())

            result = self.provider.analyze_queries(
                queries, custom_instructions)

            self.logger.info("Successfully completed LLM analysis")
            return result

        except Exception as e:
            self.logger.error("LLM analysis failed: %s", e)
            raise LLMAnalysisError(f"Analysis failed: {e}") from e

    def test_connection(self) -> bool:
        """
        Test connection to the LLM service.

        Returns:
            True if connection is successful, False otherwise
        """
        try:
            result = self.provider.test_connection()
            if result:
                self.logger.info("LLM connection test successful (%s)",
                                 self.provider.get_provider_name())
            else:
                self.logger.warning("LLM connection test failed (%s)",
                                    self.provider.get_provider_name())
            return result
        except (ConnectionError, TimeoutError) as e:
            self.logger.error("LLM connection test error: %s", e)
            return False

    def get_available_models(self) -> List[str]:
        """
        Get list of available models from the LLM service.

        Returns:
            List of available model names
        """
        try:
            models = self.provider.get_available_models()
            self.logger.info("Retrieved %d available models from %s",
                             len(models), self.provider.get_provider_name())
            return models
        except (ConnectionError, LLMAnalysisError) as e:
            self.logger.error("Failed to get available models: %s", e)
            return []

    def switch_provider(self, new_config: LLMConfig) -> None:
        """
        Switch to a different LLM provider at runtime.

        Args:
            new_config: New LLM configuration

        Raises:
            LLMAnalysisError: If provider switch fails
        """
        try:
            old_provider = self.provider.get_provider_name()
            self.provider = LLMFactory.create(new_config)
            self.config = new_config

            self.logger.info("Switched LLM provider from %s to %s",
                             old_provider, self.provider.get_provider_name())
        except (ValueError, ImportError) as e:
            self.logger.error("Failed to switch LLM provider: %s", e)
            raise LLMAnalysisError(f"Failed to switch provider: {e}") from e

    def get_provider_info(self) -> dict:
        """
        Get information about the current provider.

        Returns:
            Dictionary with provider information
        """
        return {
            "provider": self.provider.get_provider_name(),
            "model": self.config.model,
            "url": self.config.api_base_url,
            "timeout": self.config.timeout,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature
        }

    @classmethod
    def create_with_fallback(cls, primary_config: LLMConfig,
                             fallback_providers: Optional[List[LLMProvider]] = None) -> 'LLMAnalyzer':
        """
        Create LLM analyzer with fallback providers.

        Args:
            primary_config: Primary LLM configuration to try first
            fallback_providers: List of fallback providers

        Returns:
            LLMAnalyzer instance

        Raises:
            LLMAnalysisError: If no providers are available
        """
        try:
            provider = LLMFactory.create_with_fallback(
                primary_config, fallback_providers)

            # Create analyzer instance with the working provider
            analyzer = cls.__new__(cls)
            LoggerMixin.__init__(analyzer)
            analyzer.provider = provider
            analyzer.config = provider.config

            analyzer.logger.info("Created LLM analyzer with %s provider (fallback)",
                                 provider.get_provider_name())

            return analyzer

        except ValueError as e:
            raise LLMAnalysisError(f"No LLM providers available: {e}") from e

    @staticmethod
    def get_available_providers() -> List[str]:
        """
        Get list of all available provider names.

        Returns:
            List of provider names
        """
        return LLMFactory.get_available_providers()


# For backward compatibility, keep the old class available
class LegacyLLMAnalyzer:
    """Legacy LLM analyzer - redirects to new implementation."""

    def __init__(self, *args, **_kwargs):
        import warnings
        warnings.warn(
            "LegacyLLMAnalyzer is deprecated. Use LLMAnalyzer instead.",
            DeprecationWarning,
            stacklevel=2
        )

        # Convert old-style config to new format if needed
        if args and hasattr(args[0], 'url'):
            old_config = args[0]
            new_config = LLMConfig(
                provider=LLMProvider.OLLAMA,
                model=getattr(old_config, 'model', 'gpt-oss:latest'),
                api_base_url=getattr(
                    old_config, 'url', 'http://localhost:11434'),
                timeout=getattr(old_config, 'timeout', 120),
                temperature=getattr(old_config, 'temperature', 0.2),
                max_tokens=getattr(old_config, 'max_tokens', 512)
            )
            self._analyzer = LLMAnalyzer(new_config)
        else:
            self._analyzer = LLMAnalyzer()

    def __getattr__(self, name):
        """Delegate all calls to new analyzer."""
        return getattr(self._analyzer, name)
