
import re


PATTERNS = {
    "email": (
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    ),

    # Indian mobile numbers, optionally with +91 or 0 prefix.
    "phone": (
        r"(?<!\d)(?:\+91[-\s]?|0)?[6-9]\d{9}(?!\d)"
    ),

    "credit_card": (
        r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"
    ),

    "password": (
        r"(?i)\b(?:password|passwd|pwd)\b"
        r"\s*(?:is|:|=)\s*[^\s,;]+"
    ),

    "api_key": (
        r"\b(?:"
        r"sk-[A-Za-z0-9_-]{20,}|"
        r"AIza[A-Za-z0-9_-]{20,}|"
        r"AKIA[0-9A-Z]{16}|"
        r"gh[pousr]_[A-Za-z0-9]{20,}|"
        r"xox[baprs]-[A-Za-z0-9-]{10,}"
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
        r"(?<!\d)\d{4}[- ]\d{4}[- ]\d{4}(?!\d)"
    ),
}


BANK_ACCOUNT_PATTERN = (
    r"(?i)\b(?:"
    r"bank\s+account"
    r"|account\s+(?:number|no\.?)"
    r"|a/c"
    r"|ac\s+no\.?"
    r")"
    r"\s*(?:is|:|=|-)?\s*"
    r"(\d{9,18})(?!\d)"
)


def detect_sensitive_data(text):
    """Detect supported sensitive-data patterns in a prompt."""
    if not isinstance(text, str) or not text:
        return []

    detected = []
    seen = set()

    def add_detection(data_type, value):
        key = (data_type, value)
        if key in seen:
            return

        seen.add(key)
        detected.append({
            "type": data_type,
            "value": value,
            "confidence": "HIGH",
        })

    for data_type, pattern in PATTERNS.items():
        for match in re.finditer(pattern, text):
            add_detection(data_type, match.group(0))

    for match in re.finditer(BANK_ACCOUNT_PATTERN, text):
        add_detection("bank_account", match.group(1))

    return detected
