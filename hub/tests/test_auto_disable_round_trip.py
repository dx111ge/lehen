"""Auto-disable end-to-end through the request path.

Proves DESIGN.md §10's auto-disable rule: a successful SIAM admin login
flips the ``LocalAdmin`` row to ``enabled=false`` exactly once, on the
first observation, then never again. Subsequent SIAM admin requests are
zero-DB-cost (cache short-circuits the check)."""

from __future__ import annotations

import base64
import secrets as stdlib_secrets
import time
from collections.abc import Callable, Iterator
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient
from jose import jwk as jose_jwk
from jose import jwt as jose_jwt


def _b64_32_bytes() -> str:
    return base64.urlsafe_b64encode(stdlib_secrets.token_bytes(32)).decode("ascii")


@pytest.fixture(scope="module")
def admin_keypair() -> tuple[bytes, bytes]:
    pk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return (
        pk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        pk.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )


@pytest.fixture(scope="module")
def admin_jwks(admin_keypair: tuple[bytes, bytes]) -> dict[str, Any]:
    _, public_pem = admin_keypair
    public_jwk = jose_jwk.construct(public_pem, "RS256").to_dict()
    public_jwk = {
        k: (v.decode() if isinstance(v, bytes) else v)
        for k, v in public_jwk.items()
    }
    public_jwk["kid"] = "auto-disable-kid"
    public_jwk["use"] = "sig"
    public_jwk["alg"] = "RS256"
    return {"keys": [public_jwk]}


@pytest.fixture
def issue_admin_token(admin_keypair: tuple[bytes, bytes]) -> Callable[..., str]:
    private_pem, _ = admin_keypair

    def _issue(*, username: str = "real-admin") -> str:
        now = int(time.time())
        return jose_jwt.encode(
            {
                "sub": "admin-uuid-1",
                "preferred_username": username,
                "realm_access": {"roles": ["lehen-admin"]},
                "iss": "http://test-keycloak:8080/realms/test-realm",
                "aud": "lehen-hub",
                "exp": now + 300,
                "iat": now,
            },
            private_pem.decode("utf-8"),
            algorithm="RS256",
            headers={"kid": "auto-disable-kid"},
        )

    return _issue


@pytest.fixture
def app_for_auto_disable(
    monkeypatch: pytest.MonkeyPatch, admin_jwks: dict[str, Any]
) -> Iterator[FastAPI]:
    monkeypatch.setenv("LEHEN_ARCADEDB__PASSWORD", "test-password")
    monkeypatch.setenv("LEHEN_KEYCLOAK__BASE_URL", "http://test-keycloak:8080")
    monkeypatch.setenv("LEHEN_KEYCLOAK__REALM", "test-realm")
    monkeypatch.setenv("LEHEN_CRYPTO__MASTER_KEY", _b64_32_bytes())
    monkeypatch.setenv("LEHEN_CRYPTO__AUDIT_PEPPER", _b64_32_bytes())
    monkeypatch.setenv("LEHEN_LOCAL_ADMIN__SIGNING_KEY", _b64_32_bytes())

    from lehen_hub.auth.identity_provider import (
        build_identity_provider_from_settings,
    )
    from lehen_hub.auth.jwks import JWKSCache
    from lehen_hub.config import get_settings
    from lehen_hub.main import create_app

    get_settings.cache_clear()
    application = create_app()
    settings = get_settings()
    provider = build_identity_provider_from_settings(
        keycloak=settings.keycloak,
        entra=settings.entra,
        selector=settings.identity_provider,
    )
    application.state.identity_provider = provider

    # Wire a pre-populated JWKS cache (so the verifier never needs to fetch).
    # ``app.state.http`` is required by the auth dep but unused with a warm
    # cache; a placeholder mock satisfies the not-None check without holding
    # a real connection (avoids unclosed-loop ResourceWarnings in pytest).
    application.state.http = AsyncMock(spec=httpx.AsyncClient)
    cache = JWKSCache(provider.jwks_url, ttl_seconds=600)
    cache._keys = admin_jwks  # type: ignore[attr-defined]
    cache._fetched_at = time.monotonic()  # type: ignore[attr-defined]
    application.state.jwks_cache = cache

    # Replace LocalAdminService with an AsyncMock to observe disable_on_siam_admin_login
    mock_service = AsyncMock()
    mock_service.disable_on_siam_admin_login.return_value = True
    application.state.local_admin_service = mock_service
    application.state.local_admin_signing_key = stdlib_secrets.token_bytes(32)
    application.state.local_admin_disable_state = "pending"

    yield application

    get_settings.cache_clear()


@respx.mock
def test_first_siam_admin_request_triggers_auto_disable(
    app_for_auto_disable: FastAPI,
    issue_admin_token: Callable[..., str],
) -> None:
    token = issue_admin_token()
    client = TestClient(app_for_auto_disable)
    response = client.get(
        "/admin/whoami", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200

    service = app_for_auto_disable.state.local_admin_service
    service.disable_on_siam_admin_login.assert_awaited_once_with(
        siam_username="real-admin"
    )
    # State cache flips so the second call is a no-op
    assert app_for_auto_disable.state.local_admin_disable_state == "disabled"


@respx.mock
def test_subsequent_siam_admin_requests_skip_disable_check(
    app_for_auto_disable: FastAPI,
    issue_admin_token: Callable[..., str],
) -> None:
    token = issue_admin_token()
    client = TestClient(app_for_auto_disable)
    # First request triggers the check
    client.get("/admin/whoami", headers={"Authorization": f"Bearer {token}"})
    service = app_for_auto_disable.state.local_admin_service
    assert service.disable_on_siam_admin_login.await_count == 1

    # Second + third requests must NOT call disable_on_siam_admin_login again
    client.get("/admin/whoami", headers={"Authorization": f"Bearer {token}"})
    client.get("/admin/whoami", headers={"Authorization": f"Bearer {token}"})
    assert service.disable_on_siam_admin_login.await_count == 1


@respx.mock
def test_local_token_admin_request_does_not_trigger_auto_disable(
    app_for_auto_disable: FastAPI,
) -> None:
    """A Hub-self-issued token (iss=lehen-hub-local) on the admin surface
    must NOT trigger the auto-disable hook — the local-admin path itself
    is using the path it was meant to disable. Auto-disable should only
    fire when a SIAM admin (the intended replacement authority) authenticates."""
    from lehen_hub.auth.local_jwt import issue_local_admin_token

    signing_key = app_for_auto_disable.state.local_admin_signing_key
    token = issue_local_admin_token(
        username="admin", signing_key=signing_key, ttl_seconds=300
    )
    client = TestClient(app_for_auto_disable)
    response = client.get(
        "/admin/whoami", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200

    service = app_for_auto_disable.state.local_admin_service
    service.disable_on_siam_admin_login.assert_not_called()
    # State cache stays "pending" — a future SIAM admin login should still trigger
    assert app_for_auto_disable.state.local_admin_disable_state == "pending"
