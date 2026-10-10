
PRIVACY_WEIGHTS = {
    "email": 15,
    "phone": 20,
    "credit_card": 35,
    "bank_account": 35,
    "password": 40,
    "api_key": 40,
    "jwt": 35,
    "ip_address": 10,
    "aadhaar": 40,
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
    "aadhaar": "CRITICAL",
}

INJECTION_WEIGHTS = {
    "Instruction Override": 30,
    "System Prompt Extraction": 35,
    "Safety Bypass": 45,
    "Developer Instruction Manipulation": 40,
    "Role Manipulation": 30,
    "Jailbreak": 50,
    "Prompt Injection via Untrusted Content": 35,
}

INJECTION_SEVERITY = {
    "Instruction Override": "MEDIUM",
    "System Prompt Extraction": "HIGH",
    "Safety Bypass": "HIGH",
    "Developer Instruction Manipulation": "HIGH",
    "Role Manipulation": "MEDIUM",
    "Jailbreak": "CRITICAL",
    "Prompt Injection via Untrusted Content": "HIGH",
}


def calculate_risk_level(score):
    if score == 0:
        return "LOW"
    elif score < 50:
        return "MEDIUM"
    return "HIGH"


def analyze_risk(detected, injection_categories=None):
    if not isinstance(detected, list):
        raise TypeError("detected must be a list.")

    if injection_categories is None:
        injection_categories = []

    if not isinstance(injection_categories, list):
        raise TypeError("injection_categories must be a list.")

    # Count each unique type/value pair only once.
    unique_detected = []
    seen = set()

    for item in detected:
        if not isinstance(item, dict) or "type" not in item:
            continue

        data_type = item["type"]
        value = item.get("value", "")
        key = (data_type, value)

        if key not in seen:
            seen.add(key)
            unique_detected.append(item)

    privacy_score = min(
        sum(
            PRIVACY_WEIGHTS.get(item["type"], 10)
            for item in unique_detected
        ),
        100,
    )

    # Count each injection category once.
    unique_categories = list(dict.fromkeys(injection_categories))

    security_score = min(
        sum(
            INJECTION_WEIGHTS.get(category, 20)
            for category in unique_categories
        ),
        100,
    )

    overall_score = max(privacy_score, security_score)

    detected_details = [
        {
            "type": item["type"],
            "value": item.get("value", ""),
            "severity": PRIVACY_SEVERITY.get(
                item["type"], "MEDIUM"
            ),
        }
        for item in unique_detected
    ]

    injection_details = [
        {
            "category": category,
            "severity": INJECTION_SEVERITY.get(
                category, "MEDIUM"
            ),
        }
        for category in unique_categories
    ]

    return {
        "privacy_score": privacy_score,
        "privacy_level": calculate_risk_level(privacy_score),
        "security_score": security_score,
        "security_level": calculate_risk_level(security_score),
        "overall_score": overall_score,
        "overall_level": calculate_risk_level(overall_score),
        "detected_details": detected_details,
        "injection_details": injection_details,
    }
