def generate_suggestions(
    detected,
    injection_detected=False
):

    suggestions = []

    types = {
        item["type"]
        for item in detected
    }


    # =====================================
    # PERSONAL INFORMATION
    # =====================================

    if "email" in types:

        suggestions.append(
            "Avoid sharing personal email addresses with external AI systems."
        )


    if "phone" in types:

        suggestions.append(
            "Replace personal phone numbers with placeholders."
        )


    # =====================================
    # FINANCIAL INFORMATION
    # =====================================

    if "credit_card" in types:

        suggestions.append(
            "Never include payment card information in an AI prompt."
        )


    if "bank_account" in types:

        suggestions.append(
            "Avoid sharing bank account numbers with AI systems."
        )


    # =====================================
    # GOVERNMENT IDENTIFICATION
    # =====================================

    if "aadhaar" in types:

        suggestions.append(
            "Avoid sharing government identification numbers with AI systems."
        )


    # =====================================
    # AUTHENTICATION SECRETS
    # =====================================

    if "api_key" in types:

        suggestions.append(
            "Never expose API keys or access tokens in prompts."
        )


    if "password" in types:

        suggestions.append(
            "Never include passwords or authentication secrets."
        )


    if "jwt" in types:

        suggestions.append(
            "Never expose JWT tokens or authentication tokens in prompts."
        )


    # =====================================
    # NETWORK INFORMATION
    # =====================================

    if "ip_address" in types:

        suggestions.append(
            "Avoid exposing internal IP addresses when they are not required."
        )


    # =====================================
    # PROMPT INJECTION
    # =====================================

    if injection_detected:

        suggestions.append(
            "Potential prompt injection detected. Review the instruction before processing it."
        )


    # =====================================
    # NO ISSUES
    # =====================================

    if not suggestions:

        suggestions.append(
            "No obvious privacy or security issue was detected."
        )


    return suggestions