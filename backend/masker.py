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
        r"\b(?:"
        r"sk-[A-Za-z0-9_-]{20,}|"
        r"AIza[A-Za-z0-9_-]{20,}|"
        r"AKIA[0-9A-Z]{16}|"
        r"ghp_[A-Za-z0-9]{20,}"
        r")\b",
        "[API_KEY_MASKED]"
    ),

    "jwt": (
        r"\beyJ[A-Za-z0-9_-]+\."
        r"[A-Za-z0-9_-]+\."
        r"[A-Za-z0-9_-]+\b",
        "[JWT_MASKED]"
    ),

    "ip_address": (
        r"\b(?:"
        r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\."
        r"){3}"
        r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
        r"\b",
        "[IP_MASKED]"
    ),

    "aadhaar": (
        r"\b\d{4}[-\s]\d{4}[-\s]\d{4}\b",
        "[AADHAAR_MASKED]"
    ),

    "password": (
        r"(?i)\b(?:password|passwd|pwd)\b"
        r"\s*(?:is|:|=)\s*\S+",
        "password=[PASSWORD_MASKED]"
    ),

    "bank_account": (
        r"(?i)\b(?:"
        r"bank\s+account"
        r"|account\s+number"
        r"|account\s+no"
        r"|a/c"
        r"|ac\s+no"
        r")"
        r"\s*(?:number|no\.?)?"
        r"\s*(?:is|:|=|-)?"
        r"\s*"
        r"\d{9,18}\b",
        "[BANK_ACCOUNT_MASKED]"
    )
}


def mask_data(text):

    masked = text

    for pattern, replacement in MASKS.values():

        masked = re.sub(
            pattern,
            replacement,
            masked
        )

    return masked