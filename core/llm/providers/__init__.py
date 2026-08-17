"""Provider adapters. Ollama ships in M1; the cloud adapters land in M3."""

from core.llm.providers.ollama import OllamaProvider

__all__ = ["OllamaProvider"]
