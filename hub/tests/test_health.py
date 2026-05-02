"""Health endpoint contract tests."""

from __future__ import annotations

import httpx
import respx
from fastapi.testclient import TestClient


def test_live_returns_ok(client: TestClient) -> None:
    response = client.get("/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@respx.mock
def test_ready_all_ok(client: TestClient) -> None:
    respx.get("http://arcadedb:2480/api/v1/ready").mock(return_value=httpx.Response(204))
    respx.get("http://test-keycloak:8080/realms/test-realm/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json={"issuer": "http://test-keycloak:8080"})
    )

    response = client.get("/health/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert {k: v["status"] for k, v in body["checks"].items()} == {
        "arcadedb": "ok",
        "keycloak": "ok",
    }


@respx.mock
def test_ready_503_when_any_check_fails(client: TestClient) -> None:
    respx.get("http://arcadedb:2480/api/v1/ready").mock(return_value=httpx.Response(204))
    respx.get("http://test-keycloak:8080/realms/test-realm/.well-known/openid-configuration").mock(
        side_effect=httpx.ConnectError("refused")
    )

    response = client.get("/health/ready")
    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "fail"
    assert body["checks"]["keycloak"]["status"] == "fail"
    assert body["checks"]["arcadedb"]["status"] == "ok"
    assert "ollama" not in body["checks"]
