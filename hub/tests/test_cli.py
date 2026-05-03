"""``python -m lehen_hub.cli create-admin`` integration test.

Exercises the CLI end-to-end with mocked ArcadeDB responses. Verifies the
generated password is printed to stdout, the bootstrap row write is issued,
and the rotation audit event is emitted."""

from __future__ import annotations

import base64
import json
import secrets as stdlib_secrets

import httpx
import pytest
import respx

from lehen_hub.cli import main


def _b64_32_bytes() -> str:
    return base64.urlsafe_b64encode(stdlib_secrets.token_bytes(32)).decode("ascii")


def _set_required_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LEHEN_ARCADEDB__HOST", "test-arcade")
    monkeypatch.setenv("LEHEN_ARCADEDB__HTTP_PORT", "2480")
    monkeypatch.setenv("LEHEN_ARCADEDB__DATABASE", "lehen-test")
    monkeypatch.setenv("LEHEN_ARCADEDB__PASSWORD", "test-password")
    monkeypatch.setenv("LEHEN_KEYCLOAK__BASE_URL", "http://test-keycloak:8080")
    monkeypatch.setenv("LEHEN_KEYCLOAK__REALM", "test-realm")
    monkeypatch.setenv("LEHEN_CRYPTO__MASTER_KEY", _b64_32_bytes())
    monkeypatch.setenv("LEHEN_CRYPTO__AUDIT_PEPPER", _b64_32_bytes())
    monkeypatch.setenv("LEHEN_LOCAL_ADMIN__SIGNING_KEY", _b64_32_bytes())


@respx.mock
def test_create_admin_writes_row_and_prints_password(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _set_required_env(monkeypatch)
    from lehen_hub.config import get_settings

    get_settings.cache_clear()

    arcade_base = "http://test-arcade:2480"
    # Schema bootstrap: DB exists, all types exist, LLMConfig populated
    respx.get(f"{arcade_base}/api/v1/exists/lehen-test").mock(
        return_value=httpx.Response(200, json={"result": True})
    )
    schema_types = [
        {"name": t}
        for t in (
            "LLMConfig",
            "IntegrationInstance",
            "SIAMMapping",
            "IntegrationConnection",
            "ConsentEvent",
            "AdminAuditEvent",
            "LoginEvent",
            "LocalAdmin",
            "LocalAdminLoginEvent",
            "LocalAdminCredentialRotated",
        )
    ]
    respx.post(f"{arcade_base}/api/v1/query/lehen-test").mock(
        side_effect=[
            # ensure_admin_schema schema-types query
            httpx.Response(200, json={"result": schema_types}),
            # ensure_admin_schema _is_llm_config_empty
            httpx.Response(200, json={"result": [{"c": 1}]}),
            # bootstrap_set_password row check (absent)
            httpx.Response(200, json={"result": []}),
        ]
    )
    command_route = respx.post(f"{arcade_base}/api/v1/command/lehen-test").mock(
        return_value=httpx.Response(200, json={"result": []})
    )

    # CLI exits with sys.exit(0) on success
    with pytest.raises(SystemExit) as excinfo:
        main(["create-admin", "--username", "admin"])
    assert excinfo.value.code == 0

    captured = capsys.readouterr()
    assert "Local-admin bootstrap credential created/rotated" in captured.out
    assert "Username: admin" in captured.out
    # Password line is present and the value is non-empty
    password_line = [
        line for line in captured.out.splitlines() if "Password:" in line
    ]
    assert password_line, "expected a password line in stdout"
    password_value = password_line[0].split("Password:", 1)[1].strip()
    assert len(password_value) >= 32, "generated password must be high-entropy"

    # Two commands fire: INSERT LocalAdmin, INSERT LocalAdminCredentialRotated
    assert command_route.call_count == 2
    insert_command = json.loads(
        command_route.calls[0].request.content.decode()
    )["command"]
    assert "INSERT INTO LocalAdmin" in insert_command
    rotation_command = json.loads(
        command_route.calls[1].request.content.decode()
    )["command"]
    assert "INSERT INTO LocalAdminCredentialRotated" in rotation_command

    get_settings.cache_clear()


def test_create_admin_fails_without_signing_key(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The CLI refuses to run when LEHEN_LOCAL_ADMIN__SIGNING_KEY is unset.
    A fresh contributor running the CLI without the env file should get a
    clear error instead of writing a row that can never be authenticated."""
    monkeypatch.setenv("LEHEN_ARCADEDB__PASSWORD", "test-password")
    monkeypatch.setenv("LEHEN_KEYCLOAK__BASE_URL", "http://test-keycloak:8080")
    monkeypatch.setenv("LEHEN_CRYPTO__MASTER_KEY", _b64_32_bytes())
    monkeypatch.setenv("LEHEN_CRYPTO__AUDIT_PEPPER", _b64_32_bytes())
    monkeypatch.delenv("LEHEN_LOCAL_ADMIN__SIGNING_KEY", raising=False)

    from lehen_hub.config import get_settings

    get_settings.cache_clear()

    with pytest.raises(SystemExit) as excinfo:
        main(["create-admin", "--username", "admin"])
    assert excinfo.value.code == 1

    captured = capsys.readouterr()
    assert "local-admin path is not configured" in captured.err.lower()

    get_settings.cache_clear()
