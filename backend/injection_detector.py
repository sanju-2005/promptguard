import re


INJECTION_PATTERNS = [

    # Instruction override
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"ignore\s+(all\s+)?prior\s+instructions",
    r"forget\s+(all\s+)?previous\s+instructions",

    # System prompt extraction
    r"reveal\s+(your\s+)?system\s+prompt",
    r"show\s+(me\s+)?(your\s+)?system\s+prompt",
    r"tell\s+me\s+your\s+system\s+instructions",

    # Safety bypass
    r"bypass\s+(the\s+)?safety",
    r"disable\s+(your\s+)?safety",
    r"bypass\s+(your\s+)?restrictions",
    r"ignore\s+(your\s+)?safety\s+rules",

    # Developer instruction manipulation
    r"ignore\s+the\s+developer\s+message",
    r"override\s+the\s+developer\s+instructions",
    r"developer\s+message",

    # Role manipulation
    r"you\s+are\s+now\s+an?\s+unrestricted",
    r"act\s+as\s+an?\s+unrestricted",
    r"pretend\s+you\s+have\s+no\s+rules",

    # Jailbreak-style requests
    r"do\s+anything\s+now",
    r"remove\s+all\s+restrictions",
    r"without\s+any\s+restrictions"
]


def detect_prompt_injection(text):

    matches = []

    for pattern in INJECTION_PATTERNS:

        if re.search(
            pattern,
            text,
            re.IGNORECASE
        ):
            matches.append(pattern)

    return {
        "detected": len(matches) > 0,
        "matches": matches
    }