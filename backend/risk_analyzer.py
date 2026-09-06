PRIVACY_WEIGHTS = {

    "email": 15,

    "phone": 20,

    "credit_card": 35,

    "bank_account": 35,

    "password": 40,

    "api_key": 40,

    "jwt": 35,

    "ip_address": 10,

    "aadhaar": 40
}


PRIVACY_SEVERITY = {

    "email": "LOW",

    "phone": "MEDIUM",

    "credit_card": "HIGH",

    "bank_account": "HIGH",

    "password": "CRITICAL",

    "api_key": "CRITICAL",

    "jwt": "HIGH",

    "ip_address": "LOW",

    "aadhaar": "CRITICAL"
}


INJECTION_WEIGHTS = {

    "Instruction Override": 30,

    "System Prompt Extraction": 35,

    "Safety Bypass": 45,

    "Developer Instruction Manipulation": 40,

    "Role Manipulation": 30,

    "Jailbreak": 50
}


INJECTION_SEVERITY = {

    "Instruction Override": "MEDIUM",

    "System Prompt Extraction": "HIGH",

    "Safety Bypass": "HIGH",

    "Developer Instruction Manipulation": "HIGH",

    "Role Manipulation": "MEDIUM",

    "Jailbreak": "CRITICAL"
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


    # =====================================
    # PRIVACY RISK
    # =====================================

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


    # =====================================
    # SECURITY / INJECTION RISK
    # =====================================

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


    # =====================================
    # OVERALL RISK
    # =====================================

    overall_score = max(
        privacy_score,
        security_score
    )


    # =====================================
    # DETECTION SEVERITY
    # =====================================

    detected_details = []

    for item in detected:

        data_type = item["type"]

        detected_details.append({
            "type": data_type,
            "value": item["value"],
            "severity": PRIVACY_SEVERITY.get(
                data_type,
                "MEDIUM"
            )
        })


    # =====================================
    # INJECTION SEVERITY
    # =====================================

    injection_details = []

    for category in injection_categories:

        injection_details.append({
            "category": category,
            "severity": INJECTION_SEVERITY.get(
                category,
                "MEDIUM"
            )
        })


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
        ),

        "detected_details": detected_details,

        "injection_details": injection_details
    }