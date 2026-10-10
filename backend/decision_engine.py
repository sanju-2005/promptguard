
POLICY_VERSION = "2.0"

SECURITY_BLOCK_THRESHOLD = 30

BLOCKED_SENSITIVE_TYPES = {
    "password",
    "api_key",
    "credential",
    "credentials",
    "jwt",
}


def make_security_decision(risk):
    """Return an explainable, policy-based security decision."""

    if not isinstance(risk, dict):
        raise TypeError("Risk must be a dictionary.")

    scores = {}

    for name in ("privacy_score", "security_score", "overall_score"):
        score = risk.get(name, 0)

        if (
            not isinstance(score, (int, float))
            or isinstance(score, bool)
            or not 0 <= score <= 100
        ):
            raise ValueError(
                f"{name} must be a number between 0 and 100."
            )

        scores[name] = score

    detected_details = risk.get("detected_details", [])

    if not isinstance(detected_details, list):
        raise TypeError("detected_details must be a list.")

    def decision(action, rule_id, severity, reason):
        return {
            "action": action,
            "policy_version": POLICY_VERSION,
            "rule_id": rule_id,
            "severity": severity,
            "reason": reason,
        }

    # Rule 1: Block prompts with high security risk.
    if scores["security_score"] >= SECURITY_BLOCK_THRESHOLD:
        return decision(
            action="BLOCK",
            rule_id="SEC-001",
            severity="HIGH",
            reason=(
                f"Security risk score "
                f"{scores['security_score']} meets or exceeds "
                f"the blocking threshold of "
                f"{SECURITY_BLOCK_THRESHOLD}."
            ),
        )

    # Rule 2: Block highly sensitive credential types.
    for item in detected_details:
        if not isinstance(item, dict):
            raise ValueError(
                "Each detected detail must be a dictionary."
            )

        item_type = str(item.get("type", "")).lower()
        normalized_type = item_type.replace(" ", "_").replace("-", "_")

        if normalized_type in BLOCKED_SENSITIVE_TYPES:
            return decision(
                action="BLOCK",
                rule_id="PRIV-001",
                severity="CRITICAL",
                reason=(
                    f"Highly sensitive data of type "
                    f"'{normalized_type}' was detected."
                ),
            )

    # Rule 3: Sanitize other detected privacy risks.
    if scores["overall_score"] > 0 or scores["privacy_score"] > 0:
        return decision(
            action="SANITIZE",
            rule_id="PRIV-002",
            severity="MEDIUM",
            reason=(
                "Privacy risk was detected. Sensitive values "
                "must be masked before the prompt is sent "
                "to an AI provider."
            ),
        )

    # Rule 4: Allow prompts with no detected risk.
    return decision(
        action="ALLOW",
        rule_id="BASE-001",
        severity="LOW",
        reason="No risk was detected by the configured security checks.",
    )
