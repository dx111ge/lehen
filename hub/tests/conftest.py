"""Shared test fixtures."""

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
    monkeypatch.setenv("LEHEN_ENV", "test")
    monkeypatch.setenv("LEHEN_LOG_LEVEL", "WARNING")
    monkeypatch.setenv("LEHEN_ARCADEDB__PASSWORD", "test-password")
    monkeypatch.setenv("LEHEN_KEYCLOAK__BASE_URL", "http://test-keycloak:8080")
    monkeypatch.setenv("LEHEN_KEYCLOAK__REALM", "test-realm")
    monkeypatch.setenv("LEHEN_OLLAMA__BASE_URL", "http://test-ollama:11434")
    monkeypatch.setenv("LEHEN_CRYPTO__MASTER_KEY", _b64_32_bytes())
    monkeypatch.setenv("LEHEN_CRYPTO__AUDIT_PEPPER", _b64_32_bytes())

    from lehen_hub.config import get_settings
    from lehen_hub.main import create_app

    get_settings.cache_clear()
    yield create_app()
    get_settings.cache_clear()


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)
