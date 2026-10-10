
def make_security_decision(risk):
    """Choose an action from the calculated risk scores and detections."""

    if not isinstance(risk, dict):
        raise TypeError("Risk must be a dictionary.")

    privacy_score = risk.get("privacy_score", 0)
    security_score = risk.get("security_score", 0)
    overall_score = risk.get("overall_score", 0)

    detected_details = risk.get("detected_details", [])

    # Block malformed risk details rather than silently trusting them.
    if not isinstance(detected_details, list):
        raise TypeError("detected_details must be a list.")

    # Block prompt injection and high security risk.
    if security_score >= 30:
        return {
            "action": "BLOCK",
            "reason": "Prompt injection or high security risk detected."
        }

    # Normalize labels so api_key, API Key, and api-key
    # are handled consistently.
    blocked_types = {
        "password",
        "api_key",
        "credential",
        "credentials",
        "jwt",
    }

    for item in detected_details:
        if not isinstance(item, dict):
            continue

        item_type = str(item.get("type", "")).lower()
        normalized_type = (
            item_type.replace(" ", "_").replace("-", "_")
        )

        if normalized_type in blocked_types:
            return {
                "action": "BLOCK",
                "reason": "Highly sensitive credential detected."
            }

    # Other privacy risks should be sanitized, even when
    # their score is high. A high privacy score alone does
    # not mean the prompt contains a malicious instruction.
    if overall_score > 0 or privacy_score > 0:
        return {
            "action": "SANITIZE",
            "reason": "Prompt contains privacy risk requiring sanitization."
        }

    return {
        "action": "ALLOW",
        "reason": "No significant security risk detected."
    }
