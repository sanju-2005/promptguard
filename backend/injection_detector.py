import re


INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"ignore\s+your\s+instructions",
    r"forget\s+your\s+instructions",
    r"reveal\s+(your\s+)?system\s+prompt",
    r"show\s+(me\s+)?your\s+system\s+prompt",
    r"bypass\s+(the\s+)?safety",
    r"disable\s+(your\s+)?safety",
    r"developer\s+message"
]


def detect_prompt_injection(text):

    matches = []

    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            matches.append(pattern)

    return {
        "detected": len(matches) > 0,
        "matches": matches
    }