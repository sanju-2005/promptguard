import re


PATTERNS = {

    "email": (
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    ),

    "phone": (
        r"\b(?:\+91[-\s]?)?[6-9]\d{9}\b"
    ),

    "credit_card": (
        r"\b(?:\d{4}[-\s]?){3}\d{4}\b"
    ),

    "password": (
        r"(?i)\b(?:password|passwd|pwd)\b"
        r"\s*(?:is|:|=)\s*\S+"
    ),

    "api_key": (
        r"\b(?:"
        r"sk-[A-Za-z0-9_-]{20,}|"
        r"AIza[A-Za-z0-9_-]{20,}|"
        r"AKIA[0-9A-Z]{16}|"
        r"ghp_[A-Za-z0-9]{20,}"
        r")\b"
    ),

    "jwt": (
        r"\beyJ[A-Za-z0-9_-]+\."
        r"[A-Za-z0-9_-]+\."
        r"[A-Za-z0-9_-]+\b"
    ),

    "ip_address": (
        r"\b(?:"
        r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\."
        r"){3}"
        r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
        r"\b"
    ),

    "aadhaar": (
        r"\b\d{4}[-\s]\d{4}[-\s]\d{4}\b"
    )
}


# ==========================================
# BANK ACCOUNT CONTEXT PATTERN
# ==========================================

BANK_ACCOUNT_PATTERN = (
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
    r"(\d{9,18})\b"
)


def detect_sensitive_data(text):

    detected = []

    # ======================================
    # STANDARD PATTERNS
    # ======================================

    for data_type, pattern in PATTERNS.items():

        matches = re.findall(
            pattern,
            text
        )

        for match in matches:

            detected.append({
                "type": data_type,
                "value": match,
                "confidence": "HIGH"
            })


    # ======================================
    # BANK ACCOUNT
    # ======================================

    bank_matches = re.findall(
        BANK_ACCOUNT_PATTERN,
        text
    )

    for match in bank_matches:

        detected.append({
            "type": "bank_account",
            "value": match,
            "confidence": "HIGH"
        })


    return detected