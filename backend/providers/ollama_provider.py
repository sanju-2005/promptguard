"""
PromptGuard - Ollama Provider

Handles communication between PromptGuard and a local Ollama model.
"""

from __future__ import annotations

import os
from typing import Dict, Optional

import requests


class OllamaProvider:
    """Provider for generating responses using Ollama."""

    def __init__(self) -> None:
        """Initialize the Ollama provider."""

        self.base_url = os.getenv(
            "OLLAMA_BASE_URL",
            "http://localhost:11434",
        ).rstrip("/")

        self.model = os.getenv(
            "OLLAMA_MODEL",
            "llama3.2",
        )

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 1000,
    ) -> Dict:
        """
        Send a prompt to Ollama and return the generated response.
        """

        if not isinstance(prompt, str):
            raise TypeError("Prompt must be a string.")

        if not prompt.strip():
            raise ValueError("Prompt cannot be empty.")

        messages = []

        if system_prompt:
            messages.append(
                {
                    "role": "system",
                    "content": system_prompt,
                }
            )

        messages.append(
            {
                "role": "user",
                "content": prompt,
            }
        )

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }

        response = requests.post(
            f"{self.base_url}/api/chat",
            json=payload,
            timeout=120,
        )

        response.raise_for_status()

        data = response.json()

        generated_text = data.get("message", {}).get(
            "content",
            "",
        )

        usage = {
            "prompt_tokens": data.get("prompt_eval_count", 0),
            "completion_tokens": data.get("eval_count", 0),
            "total_tokens": (
                data.get("prompt_eval_count", 0)
                + data.get("eval_count", 0)
            ),
        }

        return {
            "provider": "ollama",
            "model": self.model,
            "response": generated_text,
            "usage": usage,
        }


if __name__ == "__main__":
    print("Ollama provider module loaded successfully.")