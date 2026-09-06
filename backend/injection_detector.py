import re


INJECTION_PATTERNS = {

    "Instruction Override": [
        r"ignore\s+(all\s+)?previous\s+instructions",
        r"ignore\s+(all\s+)?prior\s+instructions",
        r"forget\s+(all\s+)?previous\s+instructions"
    ],

    "System Prompt Extraction": [
        r"reveal\s+(your\s+)?system\s+prompt",
        r"show\s+(me\s+)?(your\s+)?system\s+prompt",
        r"tell\s+me\s+your\s+system\s+instructions"
    ],

    "Safety Bypass": [
        r"bypass\s+(the\s+)?safety",
        r"disable\s+(your\s+)?safety",
        r"bypass\s+(your\s+)?restrictions",
        r"ignore\s+(your\s+)?safety\s+rules"
    ],

    "Developer Instruction Manipulation": [
        r"ignore\s+the\s+developer\s+message",
        r"override\s+the\s+developer\s+instructions",
        r"developer\s+message"
    ],

    "Role Manipulation": [
        r"you\s+are\s+now\s+an?\s+unrestricted",
        r"act\s+as\s+an?\s+unrestricted",
        r"pretend\s+you\s+have\s+no\s+rules"
    ],

    "Jailbreak": [
        r"do\s+anything\s+now",
        r"remove\s+all\s+restrictions",
        r"without\s+any\s+restrictions"
    ]
}


def detect_prompt_injection(text):

    detected_categories = []
    matched_patterns = []

    for category, patterns in INJECTION_PATTERNS.items():

        for pattern in patterns:

            if re.search(
                pattern,
                text,
                re.IGNORECASE
            ):
                detected_categories.append(category)
                matched_patterns.append(pattern)

                break

    return {
        "detected": len(detected_categories) > 0,
        "categories": detected_categories,
        "matches": matched_patterns
    }