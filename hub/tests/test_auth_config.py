"""``/auth/public-config`` integration tests — proves the endpoint serves
the active provider's discovery payload regardless of whether the Hub is
configured for Keycloak or Entra. Edge / admin SPA OIDC bootstrap depends
on this contract."""

from __future__ import annotations

import base64
import secrets as stdlib_secrets
from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _b64_32_bytes() -> str:
    return base64.urlsafe_b64encode(stdlib_secrets.token_bytes(32)).decode("ascii")


def test_keycloak_configured_hub_returns_keycloak_discovery(
    client: TestClient,
) -> None:
    response = client.get("/auth/public-config")
    assert response.status_code == 200
    body = response.json()
    assert body["provider"] == "keycloak"
    assert body["issuer"] == "http://test-keycloak:8080/realms/test-realm"
    assert body["realm"] == "test-realm"
    assert body["audience"] == "lehen-hub"
    assert body["edge_client_id"] == "lehen-edge"
    assert body["admin_ui_client_id"] == "lehen-admin-ui"


@pytest.fixture
def entra_app(monkeypatch: pytest.MonkeyPatch) -> Iterator[FastAPI]:
    """Hub configured with Entra as the active SIAM provider."""
    tenant_id = "00000000-0000-0000-0000-000000000abc"
    monkeypatch.setenv("LEHEN_ARCADEDB__PASSWORD", "test-password")
    monkeypatch.setenv("LEHEN_IDENTITY_PROVIDER", "entra")
    monkeypatch.setenv("LEHEN_ENTRA__TENANT_ID", tenant_id)
    monkeypatch.setenv(
        "LEHEN_ENTRA__AUDIENCE", f"api://{tenant_id}-client"
    )
    monkeypatch.setenv(
        "LEHEN_ENTRA__EDGE_CLIENT_ID", f"{tenant_id}-edge"
    )
    monkeypatch.setenv(
        "LEHEN_ENTRA__ADMIN_UI_CLIENT_ID", f"{tenant_id}-admin-ui"
    )
    monkeypatch.setenv("LEHEN_CRYPTO__MASTER_KEY", _b64_32_bytes())
    monkeypatch.setenv("LEHEN_CRYPTO__AUDIT_PEPPER", _b64_32_bytes())

    from lehen_hub.auth.identity_provider import (
        build_identity_provider_from_settings,
    )
    from lehen_hub.config import get_settings
    from lehen_hub.main import create_app

    get_settings.cache_clear()
    application = create_app()
    settings = get_settings()
    application.state.identity_provider = build_identity_provider_from_settings(
        keycloak=settings.keycloak,
        entra=settings.entra,
        selector=settings.identity_provider,
    )
    yield application
    get_settings.cache_clear()


def test_entra_configured_hub_returns_entra_discovery(
    entra_app: FastAPI,
) -> None:
    # Don't use TestClient as a context manager — that would run the full
    # lifespan, which needs a live ArcadeDB. The fixture has already seeded
    # app.state.identity_provider, which is all this endpoint reads.
    tenant_id = "00000000-0000-0000-0000-000000000abc"
    client = TestClient(entra_app)
    response = client.get("/auth/public-config")
    assert response.status_code == 200
    body = response.json()
    assert body["provider"] == "entra"
    assert (
        body["issuer"]
        == f"https://login.microsoftonline.com/{tenant_id}/v2.0"
    )
    # `realm` carries the tenant id for Entra deployments — clients use
    # `provider` to disambiguate when reading this field.
    assert body["realm"] == tenant_id
    assert body["audience"] == f"api://{tenant_id}-client"
    assert body["edge_client_id"] == f"{tenant_id}-edge"
    assert body["admin_ui_client_id"] == f"{tenant_id}-admin-ui"


def test_misconfigured_hub_with_no_provider_fails_at_settings_load(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Settings validator rejects ``identity_provider=entra`` with no Entra
    block. This is the contract that prevents a misconfigured Hub from
    silently starting with no IdP."""
    monkeypatch.setenv("LEHEN_ARCADEDB__PASSWORD", "test-password")
    monkeypatch.setenv("LEHEN_IDENTITY_PROVIDER", "entra")
    # No LEHEN_ENTRA__* vars set
    monkeypatch.setenv("LEHEN_CRYPTO__MASTER_KEY", _b64_32_bytes())
    monkeypatch.setenv("LEHEN_CRYPTO__AUDIT_PEPPER", _b64_32_bytes())

    from lehen_hub.config import Settings, get_settings

    get_settings.cache_clear()
    with pytest.raises(Exception, match="entra"):
        Settings()
    get_settings.cache_clear()
