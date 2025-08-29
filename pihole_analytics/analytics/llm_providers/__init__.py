"""
LLM Provider abstractions for Pi-hole Analytics.

This package provides a pluggable architecture for different LLM providers,
allowing easy switching between services like Ollama, OpenAI, Anthropic, etc.
"""

from .base import BaseLLMProvider, LLMProvider, LLMConfig
from .factory import LLMFactory

__all__ = ['BaseLLMProvider', 'LLMProvider', 'LLMConfig', 'LLMFactory']
