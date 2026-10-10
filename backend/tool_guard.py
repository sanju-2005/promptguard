
"""Allowlist-based authorization for AI tool calls."""

from typing import Any


TOOL_REGISTRY = {
    "calculator": {
        "required_arguments": {
            "operation": str,
            "a": (int, float),
            "b": (int, float),
        },
        "permission": "tool:calculator",
        "requires_approval": False,
    },
    "export_report": {
        "required_arguments": {
            "report_id": str,
        },
        "permission": "tool:export_report",
        "requires_approval": True,
    },
}


def authorize_tool_call(
    tool_name: str,
    arguments: dict[str, Any],
    permissions: set[str] | None = None,
    approved: bool = False,
) -> dict[str, Any]:
    """Authorize a tool call without executing the tool."""

    permissions = permissions or set()

    def deny(rule_id: str, reason: str) -> dict[str, Any]:
        return {
            "action": "BLOCK",
            "rule_id": rule_id,
            "reason": reason,
            "tool_name": tool_name,
        }

    if not isinstance(tool_name, str) or tool_name not in TOOL_REGISTRY:
        return deny("TOOL-001", "Tool is not allowlisted.")

    if not isinstance(arguments, dict):
        return deny("TOOL-002", "Tool arguments must be an object.")

    spec = TOOL_REGISTRY[tool_name]
    required = spec["required_arguments"]

    missing = set(required) - set(arguments)
    unexpected = set(arguments) - set(required)

    if missing:
        return deny("TOOL-002", f"Missing arguments: {sorted(missing)}")

    if unexpected:
        return deny(
            "TOOL-002",
            f"Unexpected arguments: {sorted(unexpected)}",
        )

    for name, expected_type in required.items():
        value = arguments[name]

        if expected_type == str:
            valid = isinstance(value, str) and bool(value.strip())
        else:
            valid = (
                isinstance(value, expected_type)
                and not isinstance(value, bool)
            )

        if not valid:
            return deny("TOOL-002", f"Invalid argument: {name}")

    if tool_name == "calculator":
        if arguments["operation"] not in {
            "add", "subtract", "multiply", "divide"
        }:
            return deny("TOOL-002", "Unsupported calculator operation.")

        if (
            arguments["operation"] == "divide"
            and arguments["b"] == 0
        ):
            return deny("TOOL-002", "Division by zero is not permitted.")

    if spec["permission"] not in permissions:
        return deny("TOOL-003", "Required permission is missing.")

    if spec["requires_approval"] and not approved:
        return {
            "action": "REQUIRE_APPROVAL",
            "rule_id": "TOOL-004",
            "reason": "This sensitive action requires explicit approval.",
            "tool_name": tool_name,
        }

    return {
        "action": "ALLOW",
        "rule_id": "TOOL-ALLOW-001",
        "reason": "Tool, arguments, and permissions passed validation.",
        "tool_name": tool_name,
    }
