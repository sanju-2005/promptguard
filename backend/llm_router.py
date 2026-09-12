"""
PromptGuard - LLM Router

Routes requests to the selected LLM provider.
"""

from __future__ import annotations

from typing import Dict, Optional

from backend.providers.groq_provider import GroqProvider
from backend.providers.ollama_provider import OllamaProvider


class LLMRouter:
    """Central router for supported LLM providers."""

    SUPPORTED_PROVIDERS = {
        "groq": GroqProvider,
        "ollama": OllamaProvider,
    }

    def __init__(self) -> None:
        """Initialize the router."""

        self.providers = {}

    def _get_provider(self, provider_name: str):
        """Create and cache the requested provider."""

        provider_name = provider_name.lower().strip()

        if provider_name not in self.SUPPORTED_PROVIDERS:
            raise ValueError(
                f"Unsupported provider: {provider_name}. "
                f"Supported providers: "
                f"{', '.join(self.SUPPORTED_PROVIDERS.keys())}"
            )

        if provider_name not in self.providers:
            provider_class = self.SUPPORTED_PROVIDERS[provider_name]
            self.providers[provider_name] = provider_class()

        return self.providers[provider_name]

    def generate(
        self,
        provider: str,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 1000,
    ) -> Dict:
        """
        Generate an answer using the selected provider.
        """

        selected_provider = self._get_provider(provider)

        return selected_provider.generate(
            prompt=prompt,
            system_prompt=system_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    def available_providers(self) -> list[str]:
        """Return the names of all supported providers."""

        return list(self.SUPPORTED_PROVIDERS.keys())


if __name__ == "__main__":
    router = LLMRouter()

    print("\nSupported LLM providers:")

    for provider in router.available_providers():
        print(f"- {provider}")