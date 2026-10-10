"""Targeted security and failure-mode tests for PromptGuard."""

import pytest
import backend.app as app_module


@pytest.fixture
def security_client(monkeypatch):
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
    app_module.app.config["RATELIMIT_ENABLED"] = False

    with app_module.app.test_client() as client:
        yield client


def auth_headers():
    return {"X-API-Key": "test-api-key"}


def test_analytics_api_returns_live_evaluation(security_client):
    response = security_client.get("/api/analytics")

    assert response.status_code == 200

    data = response.get_json()
    assert data["dataset_size"] == len(data["cases"])
    assert data["dataset_size"] >= 1
    assert "sensitive_metrics" in data
    assert "injection_metrics" in data
    assert "decision_agreement" in data
    assert "limitations" in data


def test_tool_execution_rejects_missing_authentication(security_client):
    response = security_client.post(
        "/api/tools/execute",
        json={
            "tool_name": "calculator",
            "arguments": {"operation": "add", "a": 2, "b": 3},
        },
    )

    assert response.status_code == 401


def test_tool_execution_rejects_non_json(security_client):
    response = security_client.post(
        "/api/tools/execute",
        data="not json",
        content_type="text/plain",
        headers=auth_headers(),
    )

    assert response.status_code == 400


def test_tool_execution_rejects_invalid_arguments(security_client):
    response = security_client.post(
        "/api/tools/execute",
        headers=auth_headers(),
        json={
            "tool_name": "calculator",
            "arguments": ["add", 2, 3],
        },
    )

    assert response.status_code == 400


def test_tool_execution_requires_server_permission(
    security_client, monkeypatch
):
    monkeypatch.setenv("PROMPTGUARD_TOOL_PERMISSIONS", "")

    response = security_client.post(
        "/api/tools/execute",
        headers=auth_headers(),
        json={
            "tool_name": "calculator",
            "arguments": {"operation": "add", "a": 2, "b": 3},
        },
    )

    assert response.status_code == 403

    data = response.get_json()
    assert data["decision"]["action"] == "BLOCK"
    assert data["executed"] is False


def test_export_requires_correct_approval_token(security_client):
    response = security_client.post(
        "/api/tools/execute",
        headers={
            **auth_headers(),
            "X-Tool-Approval": "incorrect-token",
        },
        json={
            "tool_name": "export_report",
            "arguments": {"report_id": "REPORT-001"},
        },
    )

    assert response.status_code == 403

    data = response.get_json()
    assert data["decision"]["action"] == "REQUIRE_APPROVAL"
    assert data["executed"] is False


def test_calculator_rejects_non_finite_result(security_client):
    response = security_client.post(
        "/api/tools/execute",
        headers=auth_headers(),
        json={
            "tool_name": "calculator",
            "arguments": {
                "operation": "multiply",
                "a": 1e308,
                "b": 1e308,
            },
        },
    )

    assert response.status_code == 422

    data = response.get_json()
    assert data["executed"] is False