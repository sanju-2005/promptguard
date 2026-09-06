import re


MASKS = {
    "email": (
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "[EMAIL_MASKED]"
    ),

    "phone": (
        r"\b(?:\+91[-\s]?)?[6-9]\d{9}\b",
        "[PHONE_MASKED]"
    ),

    "credit_card": (
        r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        "[CARD_MASKED]"
    ),

    "api_key": (
        r"\b(?:sk-[A-Za-z0-9_-]{20,}|AIza[A-Za-z0-9_-]{20,})\b",
        "[API_KEY_MASKED]"
    ),

    "password": (
    r"(?i)\b(?:password|passwd|pwd)\b\s*(?:is|:|=)\s*\S+",
    "password=[PASSWORD_MASKED]"
) 
}


def mask_data(text):
    masked = text

    for pattern, replacement in MASKS.values():
        masked = re.sub(pattern, replacement, masked)

    return masked