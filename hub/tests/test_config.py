"""Settings validation tests — fail-closed on missing/invalid crypto keys."""

from __future__ import annotations

import base64
import secrets as stdlib_secrets

import pytest
from pydantic import ValidationError


def _b64_32_bytes() -> str:
    return base64.urlsafe_b64encode(stdlib_secrets.token_bytes(32)).decode("ascii")


@pytest.fixture(autouse=True)
def _required_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure other required settings are set so we can isolate crypto/key validation."""
    monkeypatch.setenv("LEHEN_ARCADEDB__PASSWORD", "test-password")
    monkeypatch.setenv("LEHEN_KEYCLOAK__BASE_URL", "http://test-keycloak:8080")


def _build_settings(monkeypatch: pytest.MonkeyPatch):
    from lehen_hub.config import Settings, get_settings

    get_settings.cache_clear()
    return Settings()


class TestCryptoSettings:
    def test_loads_with_valid_keys(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("LEHEN_CRYPTO__MASTER_KEY", _b64_32_bytes())
        monkeypatch.setenv("LEHEN_CRYPTO__AUDIT_PEPPER", _b64_32_bytes())
        s = _build_settings(monkeypatch)
        assert len(s.crypto.get_master_key_bytes()) == 32
        assert len(s.crypto.get_audit_pepper_bytes()) == 32

    def test_master_key_and_audit_pepper_are_distinct(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("LEHEN_CRYPTO__MASTER_KEY", _b64_32_bytes())
        monkeypatch.setenv("LEHEN_CRYPTO__AUDIT_PEPPER", _b64_32_bytes())
        s = _build_settings(monkeypatch)
        # Test data is random so this is virtually-always-true; documents the contract
        assert s.crypto.get_master_key_bytes() != s.crypto.get_audit_pepper_bytes()

    def test_missing_master_key_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("LEHEN_CRYPTO__MASTER_KEY", raising=False)
        monkeypatch.setenv("LEHEN_CRYPTO__AUDIT_PEPPER", _b64_32_bytes())
        with pytest.raises(ValidationError):
            _build_settings(monkeypatch)

    def test_missing_audit_pepper_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("LEHEN_CRYPTO__MASTER_KEY", _b64_32_bytes())
        monkeypatch.delenv("LEHEN_CRYPTO__AUDIT_PEPPER", raising=False)
        with pytest.raises(ValidationError):
            _build_settings(monkeypatch)

    def test_short_master_key_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        bad = base64.urlsafe_b64encode(b"too-short").decode("ascii")
        monkeypatch.setenv("LEHEN_CRYPTO__MASTER_KEY", bad)
        monkeypatch.setenv("LEHEN_CRYPTO__AUDIT_PEPPER", _b64_32_bytes())
        with pytest.raises(ValidationError, match="32 bytes"):
            _build_settings(monkeypatch)

    def test_short_audit_pepper_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("LEHEN_CRYPTO__MASTER_KEY", _b64_32_bytes())
        bad = base64.urlsafe_b64encode(b"too-short").decode("ascii")
        monkeypatch.setenv("LEHEN_CRYPTO__AUDIT_PEPPER", bad)
        with pytest.raises(ValidationError, match="32 bytes"):
            _build_settings(monkeypatch)


class TestKeycloakSettingsDefaults:
    def test_realm_defaults_to_lehen(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("LEHEN_CRYPTO__MASTER_KEY", _b64_32_bytes())
        monkeypatch.setenv("LEHEN_CRYPTO__AUDIT_PEPPER", _b64_32_bytes())
        monkeypatch.delenv("LEHEN_KEYCLOAK__REALM", raising=False)
        s = _build_settings(monkeypatch)
        assert s.keycloak.realm == "lehen"

    def test_audience_defaults_to_lehen_hub(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("LEHEN_CRYPTO__MASTER_KEY", _b64_32_bytes())
        monkeypatch.setenv("LEHEN_CRYPTO__AUDIT_PEPPER", _b64_32_bytes())
        s = _build_settings(monkeypatch)
        assert s.keycloak.audience == "lehen-hub"
        assert s.keycloak.admin_role == "lehen-admin"
        assert s.keycloak.edge_client_id == "lehen-edge"
        assert s.keycloak.admin_ui_client_id == "lehen-admin-ui"

    def test_jwks_url_derived(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("LEHEN_CRYPTO__MASTER_KEY", _b64_32_bytes())
        monkeypatch.setenv("LEHEN_CRYPTO__AUDIT_PEPPER", _b64_32_bytes())
        s = _build_settings(monkeypatch)
        assert (
            s.keycloak.jwks_url
            == "http://test-keycloak:8080/realms/lehen/protocol/openid-connect/certs"
        )
        assert s.keycloak.issuer == "http://test-keycloak:8080/realms/lehen"


class TestRetentionDefaults:
    def test_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("LEHEN_CRYPTO__MASTER_KEY", _b64_32_bytes())
        monkeypatch.setenv("LEHEN_CRYPTO__AUDIT_PEPPER", _b64_32_bytes())
        s = _build_settings(monkeypatch)
        assert s.retention.login_event_days == 90
        assert s.retention.consent_event_days == 2557

    def test_env_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("LEHEN_CRYPTO__MASTER_KEY", _b64_32_bytes())
        monkeypatch.setenv("LEHEN_CRYPTO__AUDIT_PEPPER", _b64_32_bytes())
        monkeypatch.setenv("LEHEN_RETENTION__LOGIN_EVENT_DAYS", "30")
        s = _build_settings(monkeypatch)
        assert s.retention.login_event_days == 30


