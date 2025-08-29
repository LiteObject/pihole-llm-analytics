"""
LLM Provider Factory for creating provider instances.

This module provides the factory pattern implementation for creating
different LLM provider instances based on configuration.
"""

from typing import Dict, Type, List, Optional

from .base import BaseLLMProvider, LLMProvider, LLMConfig
from .ollama_provider import OllamaProvider
from .openai_provider import OpenAIProvider


class LLMFactory:
    """Factory for creating LLM provider instances."""

    _providers: Dict[LLMProvider, Type[BaseLLMProvider]] = {
        LLMProvider.OLLAMA: OllamaProvider,
        LLMProvider.OPENAI: OpenAIProvider,
        # Add more providers as they are implemented
        # LLMProvider.ANTHROPIC: AnthropicProvider,
        # LLMProvider.GOOGLE: GoogleProvider,
    }

    @classmethod
    def create(cls, config: LLMConfig) -> BaseLLMProvider:
        """
        Create an LLM provider instance based on configuration.

        Args:
            config: LLM configuration specifying provider and settings

        Returns:
            BaseLLMProvider instance

        Raises:
            ValueError: If provider is not supported
            ImportError: If required dependencies are missing
        """
        provider_class = cls._providers.get(config.provider)

        if not provider_class:
            available_providers = list(cls._providers.keys())
            raise ValueError(
                f"Unsupported provider: {config.provider}. "
                f"Available providers: {[p.value for p in available_providers]}"
            )

        try:
            return provider_class(config)
        except ImportError as e:
            raise ImportError(
                f"Failed to create {config.provider.value} provider. "
                f"Missing dependencies: {e}"
            ) from e

    @classmethod
    def register_provider(cls, provider: LLMProvider,
                          provider_class: Type[BaseLLMProvider]) -> None:
        """
        Register a new provider (for extensibility).

        Args:
            provider: LLM provider enum value
            provider_class: Provider implementation class
        """
        cls._providers[provider] = provider_class

    @classmethod
    def get_available_providers(cls) -> List[str]:
        """
        Get list of available provider names.

        Returns:
            List of provider names as strings
        """
        return [p.value for p in cls._providers.keys()]

    @classmethod
    def is_provider_available(cls, provider: LLMProvider) -> bool:
        """
        Check if a provider is available.

        Args:
            provider: LLM provider to check

        Returns:
            True if provider is available, False otherwise
        """
        return provider in cls._providers

    @classmethod
    def create_with_fallback(cls, config: LLMConfig,
                             fallback_providers: Optional[List[LLMProvider]] = None) -> BaseLLMProvider:
        """
        Create a provider with fallback options.

        Args:
            config: Primary LLM configuration
            fallback_providers: List of fallback providers to try

        Returns:
            BaseLLMProvider instance

        Raises:
            ValueError: If no providers are available
        """
        if fallback_providers is None:
            fallback_providers = [LLMProvider.OLLAMA]

        # Try primary provider first
        try:
            return cls.create(config)
        except (ValueError, ImportError):
            pass

        # Try fallback providers
        for fallback_provider in fallback_providers:
            if fallback_provider == config.provider:
                continue  # Skip if same as primary

            try:
                fallback_config = LLMConfig(
                    provider=fallback_provider,
                    model=config.model,
                    api_key=config.api_key,
                    api_base_url=config.api_base_url,
                    temperature=config.temperature,
                    max_tokens=config.max_tokens,
                    timeout=config.timeout,
                    max_prompt_chars=config.max_prompt_chars
                )
                return cls.create(fallback_config)
            except (ValueError, ImportError):
                continue

        raise ValueError(
            f"No LLM providers available. Tried: {config.provider.value}, "
            f"{[p.value for p in fallback_providers]}"
        )
