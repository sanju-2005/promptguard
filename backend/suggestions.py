def generate_suggestions(detected, injection_detected=False):

    suggestions = []

    types = {item["type"] for item in detected}

    if "email" in types:
        suggestions.append(
            "Avoid sharing personal email addresses with external AI systems."
        )

    if "phone" in types:
        suggestions.append(
            "Replace personal phone numbers with placeholders."
        )

    if "credit_card" in types:
        suggestions.append(
            "Never include payment card information in an AI prompt."
        )

    if "api_key" in types:
        suggestions.append(
            "Never expose API keys or access tokens in prompts."
        )

    if "password" in types:
        suggestions.append(
            "Never include passwords or authentication secrets."
        )

    if injection_detected:
        suggestions.append(
            "Potential prompt injection detected. Review the instruction before processing it."
        )

    if not suggestions:
        suggestions.append(
            "No obvious privacy or security issue was detected."
        )

    return suggestions