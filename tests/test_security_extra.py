import pytest

import backend.app as app_module


@pytest.fixture
def client():

    app_module.app.config["TESTING"] = True

    original_api_key = app_module.API_KEY

    app_module.API_KEY = "test-api-key"

    with app_module.app.test_client() as client:

        yield client

    app_module.API_KEY = original_api_key


def test_health_endpoint(client):

    response = client.get("/health")

    assert response.status_code == 200

    data = response.get_json()

    assert data["status"] == "healthy"

    assert data["service"] == "PromptGuard AI"


def test_api_requires_authentication(client):

    response = client.post(
        "/api/analyze",
        json={
            "prompt": "Explain AI"
        }
    )

    assert response.status_code == 401


def test_api_rejects_wrong_api_key(client):

    response = client.post(
        "/api/analyze",
        headers={
            "X-API-Key": "wrong-key"
        },
        json={
            "prompt": "Explain AI"
        }
    )

    assert response.status_code == 401


def test_api_rejects_non_json(client):

    response = client.post(
        "/api/analyze",
        headers={
            "X-API-Key": "test-api-key"
        },
        data="Explain AI"
    )

    assert response.status_code == 400


def test_api_requires_prompt(client):

    response = client.post(
        "/api/analyze",
        headers={
            "X-API-Key": "test-api-key"
        },
        json={}
    )

    assert response.status_code == 400


def test_api_rejects_non_string_prompt(client):

    response = client.post(
        "/api/analyze",
        headers={
            "X-API-Key": "test-api-key"
        },
        json={
            "prompt": 12345
        }
    )

    assert response.status_code == 400


def test_api_rejects_empty_prompt(client):

    response = client.post(
        "/api/analyze",
        headers={
            "X-API-Key": "test-api-key"
        },
        json={
            "prompt": "   "
        }
    )

    assert response.status_code == 400


def test_api_rejects_oversized_prompt(client):

    huge_prompt = "A" * 10001

    response = client.post(
        "/api/analyze",
        headers={
            "X-API-Key": "test-api-key"
        },
        json={
            "prompt": huge_prompt
        }
    )

    assert response.status_code == 413


def test_security_headers(client):

    response = client.get("/health")

    assert response.headers[
        "X-Content-Type-Options"
    ] == "nosniff"

    assert response.headers[
        "X-Frame-Options"
    ] == "DENY"

    assert response.headers[
        "Referrer-Policy"
    ] == "strict-origin-when-cross-origin"


def test_api_history(client):

    response = client.get(
        "/api/history"
    )

    assert response.status_code == 200

    data = response.get_json()

    assert "count" in data

    assert "scans" in data


def test_web_history_page(client):

    response = client.get("/history")

    assert response.status_code == 200

    assert b"Scan History" in response.data


def test_api_does_not_return_original_prompt(client):

    secret = "SuperSecretPassword123"

    response = client.post(
        "/api/analyze",
        headers={
            "X-API-Key": "test-api-key"
        },
        json={
            "prompt": f"My password is {secret}"
        }
    )

    assert response.status_code == 200

    data = response.get_json()

    assert "original" not in data

    assert secret not in str(data)


def test_clean_prompt_is_allowed(client):

    response = client.post(
        "/api/analyze",
        headers={
            "X-API-Key": "test-api-key"
        },
        json={
            "prompt": "Explain neural networks."
        }
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["decision"]["action"] == "ALLOW"


def test_password_is_blocked(client):

    response = client.post(
        "/api/analyze",
        headers={
            "X-API-Key": "test-api-key"
        },
        json={
            "prompt": "My password is Secret123"
        }
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["decision"]["action"] == "BLOCK"

    assert (
        "[PASSWORD_MASKED]"
        in data["masked"]
    )