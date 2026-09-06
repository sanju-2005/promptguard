RISK_WEIGHTS = {
    "email": 15,
    "phone": 20,
    "credit_card": 35,
    "api_key": 40,
    "password": 40
}


def analyze_risk(detected, injection_detected=False):

    score = 0

    for item in detected:
        score += RISK_WEIGHTS.get(item["type"], 10)

    if injection_detected:
        score += 30

    score = min(score, 100)

    if score == 0:
        level = "LOW"
    elif score < 50:
        level = "MEDIUM"
    else:
        level = "HIGH"

    return {
        "score": score,
        "level": level
    }