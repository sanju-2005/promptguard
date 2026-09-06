PRIVACY_WEIGHTS = {
    "email": 15,
    "phone": 20,
    "credit_card": 35,
    "password": 40,
    "api_key": 40
}


def calculate_risk_level(score):

    if score == 0:
        return "LOW"

    elif score < 50:
        return "MEDIUM"

    else:
        return "HIGH"


def analyze_risk(detected, injection_detected=False):

    privacy_score = 0

    for item in detected:
        privacy_score += PRIVACY_WEIGHTS.get(
            item["type"],
            10
        )

    privacy_score = min(privacy_score, 100)

    security_score = 0

    if injection_detected:
        security_score += 30

    security_score = min(security_score, 100)

    overall_score = max(
        privacy_score,
        security_score
    )

    overall_level = calculate_risk_level(
        overall_score
    )

    return {
        "privacy_score": privacy_score,
        "privacy_level": calculate_risk_level(
            privacy_score
        ),

        "security_score": security_score,
        "security_level": calculate_risk_level(
            security_score
        ),

        "overall_score": overall_score,
        "overall_level": overall_level
    }
