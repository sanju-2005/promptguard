"""
PromptGuard - Groq Provider

Handles communication between PromptGuard and the Groq API.
"""

from __future__ import annotations

import os
from typing import Dict, Optional

from groq import Groq


class GroqProvider:
    """Provider for generating responses using Groq."""

    def __init__(self) -> None:
        """Initialize the Groq client."""

        api_key = os.getenv("GROQ_API_KEY")

        if not api_key:
            raise ValueError(
                "GROQ_API_KEY is not configured."
            )

        self.client = Groq(api_key=api_key)

        self.model = os.getenv(
            "GROQ_MODEL",
            "openai/gpt-oss-20b",
        )

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 1000,
    ) -> Dict:
        """
        Send a prompt to Groq and return the generated response.

        Args:
            prompt: User prompt.
            system_prompt: Optional system instruction.
            temperature: Controls response randomness.
            max_tokens: Maximum number of output tokens.

        Returns:
            Dictionary containing provider, model, response, and usage.
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

        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=temperature,
            max_completion_tokens=max_tokens,
        )

        generated_text = response.choices[0].message.content

        usage = {}

        if response.usage:
            usage = {
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
                "total_tokens": response.usage.total_tokens,
            }

        return {
            "provider": "groq",
            "model": self.model,
            "response": generated_text,
            "usage": usage,
        }


if __name__ == "__main__":
    print("Groq provider module loaded successfully.")