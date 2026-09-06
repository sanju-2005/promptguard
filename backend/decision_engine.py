CRITICAL_TYPES = {
    "password",
    "api_key",
    "aadhaar"
}


CRITICAL_INJECTION_CATEGORIES = {
    "Jailbreak",
    "Safety Bypass"
}


def make_security_decision(risk):

    score = risk.get(
        "overall_score",
        0
    )

    detected_details = risk.get(
        "detected_details",
        []
    )

    injection_details = risk.get(
        "injection_details",
        []
    )

    # Get detected sensitive-data types
    detected_types = {
        item.get("type")
        for item in detected_details
    }

    # Get detected injection categories
    injection_categories = {
        item.get("category")
        for item in injection_details
    }

    # ==========================================
    # RULE 1: CRITICAL SENSITIVE DATA
    # ==========================================

    if detected_types & CRITICAL_TYPES:

        return {
            "action": "BLOCK",
            "reason": (
                "Critical sensitive information detected. "
                "The prompt must not be forwarded to an AI system."
            )
        }


    # ==========================================
    # RULE 2: CRITICAL PROMPT INJECTION
    # ==========================================

    if injection_categories & CRITICAL_INJECTION_CATEGORIES:

        return {
            "action": "BLOCK",
            "reason": (
                "Critical prompt injection risk detected. "
                "The prompt must not be forwarded to an AI system."
            )
        }


    # ==========================================
    # RULE 3: NO RISK
    # ==========================================

    if score == 0:

        return {
            "action": "ALLOW",
            "reason": (
                "No significant privacy or security risk detected."
            )
        }


    # ==========================================
    # RULE 4: MODERATE RISK
    # ==========================================

    if score < 50:

        return {
            "action": "SANITIZE",
            "reason": (
                "Moderate risk detected. "
                "Sensitive information should be masked before processing."
            )
        }


    # ==========================================
    # RULE 5: HIGH RISK
    # ==========================================

    return {
        "action": "BLOCK",
        "reason": (
            "High security risk detected. "
            "The prompt should not be forwarded to an AI system."
        )
    }