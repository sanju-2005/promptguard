PRIVACY_WEIGHTS = {
    "email": 15,
    "phone": 20,
    "credit_card": 35,
    "password": 40,
    "api_key": 40,
    "jwt": 35,
    "ip_address": 10
}


INJECTION_WEIGHTS = {
    "Instruction Override": 30,
    "System Prompt Extraction": 35,
    "Safety Bypass": 45,
    "Developer Instruction Manipulation": 40,
    "Role Manipulation": 30,
    "Jailbreak": 50
}


def calculate_risk_level(score):

    if score == 0:
        return "LOW"

    elif score < 50:
        return "MEDIUM"

    else:
        return "HIGH"


def analyze_risk(
    detected,
    injection_categories=None
):

    if injection_categories is None:
        injection_categories = []


    # -------------------------
    # PRIVACY RISK
    # -------------------------

    privacy_score = 0

    for item in detected:

        privacy_score += PRIVACY_WEIGHTS.get(
            item["type"],
            10
        )

    privacy_score = min(
        privacy_score,
        100
    )


    # -------------------------
    # SECURITY RISK
    # -------------------------

    security_score = 0

    for category in injection_categories:

        security_score += INJECTION_WEIGHTS.get(
            category,
            20
        )

    security_score = min(
        security_score,
        100
    )


    # -------------------------
    # OVERALL RISK
    # -------------------------

    overall_score = max(
        privacy_score,
        security_score
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

        "overall_level": calculate_risk_level(
            overall_score
        )
    }