
from backend.tool_guard import authorize_tool_call
import pytest
import backend.app as app_module

def test_allowed_calculator():
    result = authorize_tool_call(
        "calculator",
        {"operation": "add", "a": 2, "b": 3},
        permissions={"tool:calculator"},
    )
    assert result["action"] == "ALLOW"


def test_unknown_tool_is_blocked():
    result = authorize_tool_call(
        "run_shell_command",
        {},
        permissions={"*"},
    )
    assert result["action"] == "BLOCK"
    assert result["rule_id"] == "TOOL-001"


def test_missing_permission_is_blocked():
    result = authorize_tool_call(
        "calculator",
        {"operation": "add", "a": 2, "b": 3},
    )
    assert result["action"] == "BLOCK"
    assert result["rule_id"] == "TOOL-003"


def test_export_requires_approval():
    result = authorize_tool_call(
        "export_report",
        {"report_id": "REPORT-001"},
        permissions={"tool:export_report"},
    )
    assert result["action"] == "REQUIRE_APPROVAL"


def test_approved_export_is_authorized():
    result = authorize_tool_call(
        "export_report",
        {"report_id": "REPORT-001"},
        permissions={"tool:export_report"},
        approved=True,
    )
    assert result["action"] == "ALLOW"


def test_invalid_arguments_are_blocked():
    result = authorize_tool_call(
        "calculator",
        {"operation": "execute arbitrary code", "a": 2, "b": 3},
        permissions={"tool:calculator"},
    )
    assert result["action"] == "BLOCK"


def test_boolean_is_not_accepted_as_number():
    result = authorize_tool_call(
        "calculator",
        {"operation": "add", "a": True, "b": 3},
        permissions={"tool:calculator"},
    )
    assert result["action"] == "BLOCK"

@pytest.fixture
def tool_api_client(monkeypatch):
    monkeypatch.setattr(app_module, "API_KEY", "test-api-key")
    monkeypatch.setenv(
        "PROMPTGUARD_TOOL_PERMISSIONS",
        "tool:calculator,tool:export_report",
    )
    monkeypatch.setenv(
        "PROMPTGUARD_TOOL_APPROVAL_TOKEN",
        "approval-test-token",
    )
    app_module.app.config["TESTING"] = True

    with app_module.app.test_client() as client:
        yield client


def test_tool_api_requires_authentication(tool_api_client):
    response = tool_api_client.post(
        "/api/tools/authorize",
        json={
            "tool_name": "calculator",
            "arguments": {"operation": "add", "a": 2, "b": 3},
        },
    )
    assert response.status_code == 401


def test_tool_api_allows_valid_calculator(tool_api_client):
    response = tool_api_client.post(
        "/api/tools/authorize",
        headers={"X-API-Key": "test-api-key"},
        json={
            "tool_name": "calculator",
            "arguments": {"operation": "add", "a": 2, "b": 3},
        },
    )
    assert response.status_code == 200
    assert response.get_json()["decision"]["action"] == "ALLOW"
    assert response.get_json()["executed"] is False


def test_tool_api_blocks_unknown_tool(tool_api_client):
    response = tool_api_client.post(
        "/api/tools/authorize",
        headers={"X-API-Key": "test-api-key"},
        json={"tool_name": "shell", "arguments": {}},
    )
    assert response.status_code == 403
    assert response.get_json()["decision"]["action"] == "BLOCK"


def test_tool_api_requires_export_approval(tool_api_client):
    response = tool_api_client.post(
        "/api/tools/authorize",
        headers={"X-API-Key": "test-api-key"},
        json={
            "tool_name": "export_report",
            "arguments": {"report_id": "REPORT-001"},
        },
    )
    assert response.status_code == 200
    assert response.get_json()["decision"]["action"] == "REQUIRE_APPROVAL"
    assert response.get_json()["executed"] is False


def test_tool_api_accepts_valid_approval(tool_api_client):
    response = tool_api_client.post(
        "/api/tools/authorize",
        headers={
            "X-API-Key": "test-api-key",
            "X-Tool-Approval": "approval-test-token",
        },
        json={
            "tool_name": "export_report",
            "arguments": {"report_id": "REPORT-001"},
        },
    )
    assert response.status_code == 200
    assert response.get_json()["decision"]["action"] == "ALLOW"
    assert response.get_json()["executed"] is False
