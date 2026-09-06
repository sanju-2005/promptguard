import re


PATTERNS = {
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",

    "phone": r"\b(?:\+91[-\s]?)?[6-9]\d{9}\b",

    "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",

    "api_key": r"\b(?:sk-[A-Za-z0-9_-]{20,}|AIza[A-Za-z0-9_-]{20,})\b",

    "password": r"(?i)\b(?:password|passwd|pwd)\b\s*(?:is|:|=)\s*\S+"
}


def detect_sensitive_data(text):
    detected = []

    for data_type, pattern in PATTERNS.items():
        matches = re.findall(pattern, text)

        for match in matches:
            detected.append({
                "type": data_type,
                "value": match
            })

    return detected