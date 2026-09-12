"""
PromptGuard - Token & Context Analyzer

Estimates token usage and checks whether a prompt
is approaching the selected LLM's context window.
"""

from __future__ import annotations

from typing import Dict


# Approximate context-window sizes.
# These are used for warnings, not billing or exact token accounting.
PROVIDER_CONTEXT_LIMITS = {
    "groq": 131072,
    "ollama": 32768,
    "openai": 128000,
    "gemini": 1000000,
    "claude": 200000,
}


def estimate_tokens(text: str) -> int:
    """
    Estimate the number of tokens in a piece of text.

    This is an approximation.

    A rough estimate of:
        1 token ≈ 4 characters

    is used together with a word-based estimate.
    The larger estimate is returned to reduce the
    chance of underestimating usage.
    """

    if not isinstance(text, str):
        raise TypeError("Text must be a string.")

    if not text:
        return 0

    character_estimate = max(1, round(len(text) / 4))

    word_count = len(text.split())
    word_estimate = max(1, round(word_count * 1.3))

    return max(character_estimate, word_estimate)


def get_context_limit(provider: str) -> int:
    """
    Return the approximate context window for a provider.
    """

    if not isinstance(provider, str):
        raise TypeError("Provider must be a string.")

    provider = provider.lower().strip()

    return PROVIDER_CONTEXT_LIMITS.get(provider, 8192)


def analyze_tokens(
    prompt: str,
    provider: str = "groq",
    estimated_output_tokens: int = 1000,
) -> Dict:
    """
    Analyze estimated token usage for a prompt.

    Args:
        prompt:
            Prompt that will be sent to the LLM.

        provider:
            Selected LLM provider.

        estimated_output_tokens:
            Expected maximum output tokens.

    Returns:
        Dictionary containing token and context information.
    """

    if not isinstance(prompt, str):
        raise TypeError("Prompt must be a string.")

    if not isinstance(estimated_output_tokens, int):
        raise TypeError(
            "estimated_output_tokens must be an integer."
        )

    if estimated_output_tokens < 0:
        raise ValueError(
            "estimated_output_tokens cannot be negative."
        )

    input_tokens = estimate_tokens(prompt)

    context_limit = get_context_limit(provider)

    total_estimated_tokens = (
        input_tokens + estimated_output_tokens
    )

    usage_percentage = (
        total_estimated_tokens / context_limit
    ) * 100

    # Determine status.
    if total_estimated_tokens > context_limit:
        status = "EXCEEDED"

        warning = (
            "Estimated token usage exceeds the "
            "provider context limit."
        )

    elif usage_percentage >= 90:
        status = "CRITICAL"

        warning = (
            "Prompt is very close to the provider "
            "context limit."
        )

    elif usage_percentage >= 75:
        status = "WARNING"

        warning = (
            "Prompt is using a large portion of the "
            "provider context window."
        )

    else:
        status = "SAFE"

        warning = (
            "Token usage is within the estimated "
            "safe range."
        )

    return {
        "input_tokens": input_tokens,
        "estimated_output_tokens": estimated_output_tokens,
        "total_estimated_tokens": total_estimated_tokens,
        "context_limit": context_limit,
        "usage_percentage": round(usage_percentage, 2),
        "status": status,
        "warning": warning,
    }


if __name__ == "__main__":

    sample_prompt = (
        "Explain artificial intelligence to a beginner "
        "using simple examples."
    )

    result = analyze_tokens(
        prompt=sample_prompt,
        provider="groq",
        estimated_output_tokens=1000,
    )

    print("\nPromptGuard Token Analysis")
    print("-" * 40)

    for key, value in result.items():
        print(f"{key}: {value}")