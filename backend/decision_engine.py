def make_security_decision(risk):

    if not isinstance(risk, dict):
        raise TypeError("Risk must be a dictionary.")

    privacy_score = risk.get("privacy_score", 0)
    security_score = risk.get("security_score", 0)
    overall_score = risk.get("overall_score", 0)

    detected_details = risk.get("detected_details", [])

    # Block prompt injection / high security risk.
    if security_score >= 30:
        return {
            "action": "BLOCK",
            "reason": "Prompt injection or high security risk detected."
        }

    # Block passwords and credentials.
    for item in detected_details:
        item_type = str(item.get("type", "")).lower()

        if item_type in {
            "password",
            "api key",
            "apikey",
            "credential",
            "credentials"
        }:
            return {
                "action": "BLOCK",
                "reason": "Highly sensitive credential detected."
            }

    # Block very high overall risk.
    if overall_score >= 50:
        return {
            "action": "BLOCK",
            "reason": "Overall security risk is HIGH."
        }

    # Sanitize other privacy risks.
    if overall_score > 0 or privacy_score > 0:
        return {
            "action": "SANITIZE",
            "reason": "Prompt contains risk that requires sanitization."
        }

    return {
        "action": "ALLOW",
        "reason": "No significant security risk detected."
    }


if __name__ == "__main__":

    print(
        make_security_decision({
            "privacy_score": 0,
            "security_score": 0,
            "overall_score": 0
        })
    )

    print(
        make_security_decision({
            "privacy_score": 0,
            "security_score": 30,
            "overall_score": 30
        })
    )

    print(
        make_security_decision({
            "privacy_score": 30,
            "security_score": 0,
            "overall_score": 30,
            "detected_details": [
                {"type": "Password", "severity": "HIGH"}
            ]
        })
    )