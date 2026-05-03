"""Shared test fixtures.

The ``app`` fixture builds a FastAPI app **without** running the production
lifespan (which would require a live ArcadeDB and Keycloak). Instead, the
fixture seeds ``app.state`` with the minimum the per-test surface needs —
today, just ``identity_provider``. Other state (jwks_cache, services, arcade)
is provisioned by individual tests when relevant.
"""

from __future__ import annotations

import base64
import secrets as stdlib_secrets
from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _b64_32_bytes() -> str:
    return base64.urlsafe_b64encode(stdlib_secrets.token_bytes(32)).decode("ascii")


@pytest.fixture
def app(monkeypatch: pytest.MonkeyPatch) -> Iterator[FastAPI]:
    monkeypatch.setenv("LEHEN_ARCADEDB__PASSWORD", "test-password")
    monkeypatch.setenv("LEHEN_KEYCLOAK__BASE_URL", "http://test-keycloak:8080")
    monkeypatch.setenv("LEHEN_KEYCLOAK__REALM", "test-realm")
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
    # Default fixture: local-admin path is NOT configured (no signing key).
    # Tests that need it should use the ``app_with_local_admin`` fixture.
    application.state.local_admin_signing_key = None
    application.state.local_admin_service = None
    application.state.local_admin_disable_state = "no_local_admin"
    yield application
    get_settings.cache_clear()


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)
