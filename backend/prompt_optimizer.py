"""
PromptGuard - Prompt Optimizer

Converts a user's rough prompt into a clearer, more structured prompt
while preserving the user's original intent.

This first version is rule-based, so it does NOT require an LLM/API.
"""

from __future__ import annotations

import re
from typing import Dict


def _clean_text(text: str) -> str:
    """Clean unnecessary whitespace from the prompt."""
    text = text.strip()
    text = re.sub(r"\s+", " ", text)
    return text


def _detect_task_type(prompt: str) -> str:
    """Identify the general type of task requested by the user."""

    text = prompt.lower()

    if any(word in text for word in [
        "explain",
        "what is",
        "what are",
        "how does",
        "meaning of",
        "define",
    ]):
        return "explanation"

    if any(word in text for word in [
        "write code",
        "create code",
        "program",
        "implement",
        "code for",
        "python code",
        "javascript code",
    ]):
        return "coding"

    if any(word in text for word in [
        "compare",
        "difference between",
        "vs",
        "versus",
    ]):
        return "comparison"

    if any(word in text for word in [
        "summarize",
        "summary",
        "shorten",
        "summarise",
    ]):
        return "summarization"

    if any(word in text for word in [
        "translate",
        "translation",
    ]):
        return "translation"

    if any(word in text for word in [
        "debug",
        "error",
        "fix this",
        "not working",
    ]):
        return "debugging"

    return "general"


def _choose_role(task_type: str) -> str:
    """Choose a suitable AI role based on the task."""

    roles = {
        "explanation": "Act as a clear and patient subject-matter tutor.",
        "coding": "Act as an experienced software engineer and programming tutor.",
        "comparison": "Act as an objective technical analyst.",
        "summarization": "Act as an expert summarizer.",
        "translation": "Act as a professional translator.",
        "debugging": "Act as an experienced software debugging expert.",
        "general": "Act as a knowledgeable and helpful AI assistant.",
    }

    return roles.get(task_type, roles["general"])


def _choose_output_instruction(task_type: str) -> str:
    """Choose a useful output format."""

    instructions = {
        "explanation": (
            "Explain the topic clearly, use simple language, "
            "organize the answer with headings, and include examples "
            "where useful."
        ),
        "coding": (
            "Provide correct, readable code and explain the important "
            "parts of the solution."
        ),
        "comparison": (
            "Compare the concepts using clear criteria and highlight "
            "the key differences, similarities, advantages, and limitations."
        ),
        "summarization": (
            "Provide a concise summary containing the most important "
            "information while preserving the original meaning."
        ),
        "translation": (
            "Provide an accurate translation while preserving the original "
            "meaning, tone, and important terminology."
        ),
        "debugging": (
            "Identify the likely cause of the problem, explain why it occurs, "
            "and provide a corrected solution."
        ),
        "general": (
            "Answer the user's request directly, clearly, and accurately. "
            "Use headings or bullet points when they improve readability."
        ),
    }

    return instructions.get(task_type, instructions["general"])


def optimize_prompt(prompt: str) -> Dict[str, str]:
    """
    Improve a user's prompt without changing its original intent.

    Returns:
        Dictionary containing:
        - original_prompt
        - optimized_prompt
        - task_type
        - role
    """

    if not isinstance(prompt, str):
        raise TypeError("Prompt must be a string.")

    cleaned_prompt = _clean_text(prompt)

    if not cleaned_prompt:
        raise ValueError("Prompt cannot be empty.")

    task_type = _detect_task_type(cleaned_prompt)
    role = _choose_role(task_type)
    output_instruction = _choose_output_instruction(task_type)

    optimized_prompt = f"""ROLE:
{role}

USER REQUEST:
{cleaned_prompt}

INSTRUCTIONS:
{output_instruction}

IMPORTANT:
- Preserve the user's original intent.
- Do not invent requirements that were not requested.
- If important information is missing, clearly state the assumption being made.
- Give a useful and well-structured response.
"""

    return {
        "original_prompt": cleaned_prompt,
        "optimized_prompt": optimized_prompt.strip(),
        "task_type": task_type,
        "role": role,
    }


if __name__ == "__main__":
    # Simple local test
    test_prompt = "explain python functions"

    result = optimize_prompt(test_prompt)

    print("\n--- ORIGINAL PROMPT ---")
    print(result["original_prompt"])

    print("\n--- TASK TYPE ---")
    print(result["task_type"])

    print("\n--- OPTIMIZED PROMPT ---")
    print(result["optimized_prompt"])