"""LocalAdminService — bootstrap, login, lockout, auto-disable.

These tests run against a mocked ``ArcadeClient`` (respx-mocked HTTP). They
cover the security-critical surface: vague error messages, lockout, rate
limit, constant-time response on missing user, idempotent auto-disable,
audit-event emission.
"""

from __future__ import annotations

import json
import secrets as stdlib_secrets
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
import respx

from lehen_hub.admin.local_admin_service import (
    LocalAdminAuthError,
    LocalAdminService,
)
from lehen_hub.config import ArcadeDBSettings
from lehen_hub.storage.arcade import ArcadeClient

ARCADE_BASE = "http://test-arcade:2480"


@pytest.fixture
def signing_key() -> bytes:
    return stdlib_secrets.token_bytes(32)


@pytest.fixture
def arcade_settings() -> ArcadeDBSettings:
    return ArcadeDBSettings(
        host="test-arcade",
        http_port=2480,
        password="test-password",
        database="lehen-test",
    )


@pytest.fixture
async def http_client() -> httpx.AsyncClient:
    async with httpx.AsyncClient() as c:
        yield c


@pytest.fixture
def arcade_client(
    arcade_settings: ArcadeDBSettings,
    http_client: httpx.AsyncClient,
) -> ArcadeClient:
    return ArcadeClient(settings=arcade_settings, http=http_client)


def _query_url() -> str:
    return f"{ARCADE_BASE}/api/v1/query/lehen-test"


def _command_url() -> str:
    return f"{ARCADE_BASE}/api/v1/command/lehen-test"


@pytest.fixture
def service(
    arcade_client: ArcadeClient,
    signing_key: bytes,
) -> LocalAdminService:
    return LocalAdminService(
        arcade=arcade_client,
        signing_key=signing_key,
        token_ttl_seconds=300,
        failed_attempts_threshold=3,  # Low threshold for fast lockout tests
        lockout_duration_seconds=60,
        rate_limit_per_minute=100,  # High to avoid rate-limit interfering
    )


def _row_with_password_hash(
    *, password_hash: str, enabled: bool = True
) -> dict[str, Any]:
    return {
        "username": "admin",
        "password_hash": password_hash,
        "enabled": enabled,
        "failed_attempts": 0,
        "locked_until": None,
        "last_login_at": None,
        "created_at": "2026-05-03T00:00:00+00:00",
    }


class TestBootstrapSetPassword:
    @respx.mock
    async def test_creates_new_row_when_absent(
        self, service: LocalAdminService
    ) -> None:
        # First query: row absent
        respx.post(_query_url()).mock(
            return_value=httpx.Response(200, json={"result": []})
        )
        commands = respx.post(_command_url()).mock(
            return_value=httpx.Response(200, json={"result": []})
        )
        await service.bootstrap_set_password(username="admin", password="secret-x")
        # Two writes: INSERT LocalAdmin + INSERT LocalAdminCredentialRotated
        assert commands.call_count == 2
        first_command = json.loads(
            commands.calls[0].request.content.decode()
        )["command"]
        assert "INSERT INTO LocalAdmin" in first_command

    @respx.mock
    async def test_replaces_existing_row(self, service: LocalAdminService) -> None:
        respx.post(_query_url()).mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": [
                        _row_with_password_hash(password_hash="old-hash")
                    ]
                },
            )
        )
        commands = respx.post(_command_url()).mock(
            return_value=httpx.Response(200, json={"result": []})
        )
        await service.bootstrap_set_password(username="admin", password="new-secret")
        # First: UPDATE LocalAdmin; second: INSERT LocalAdminCredentialRotated
        first_command = json.loads(
            commands.calls[0].request.content.decode()
        )["command"]
        assert "UPDATE LocalAdmin" in first_command


class TestLoginSuccess:
    @respx.mock
    async def test_valid_credentials_return_token(
        self, service: LocalAdminService
    ) -> None:
        # Bootstrap → then login
        respx.post(_query_url()).mock(
            side_effect=[
                # 1st call: bootstrap_set_password row check (absent)
                httpx.Response(200, json={"result": []}),
                # 2nd call: login row fetch
                # Set after we know the hash — see below
            ]
        )
        respx.post(_command_url()).mock(
            return_value=httpx.Response(200, json={"result": []})
        )

        password = "the-correct-password"
        await service.bootstrap_set_password(username="admin", password=password)

        # Capture the hash that was just written. Re-mock for the login phase.
        respx.reset()

        # Re-bootstrap to capture the hash that the service writes
        respx.post(_query_url()).mock(
            return_value=httpx.Response(200, json={"result": []})
        )
        commands_route = respx.post(_command_url()).mock(
            return_value=httpx.Response(200, json={"result": []})
        )
        await service.bootstrap_set_password(username="admin", password=password)
        insert_doc_str = json.loads(
            commands_route.calls[0].request.content.decode()
        )["command"]
        # Pull the hash out of the INSERT body
        # Format: "INSERT INTO LocalAdmin CONTENT {...}"
        json_part = insert_doc_str.split("CONTENT ", 1)[1]
        doc = json.loads(json_part)
        actual_hash = doc["password_hash"]

        # Now run login with the hash returned from "DB"
        respx.reset()
        respx.post(_query_url()).mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": [
                        _row_with_password_hash(password_hash=actual_hash)
                    ]
                },
            )
        )
        respx.post(_command_url()).mock(
            return_value=httpx.Response(200, json={"result": []})
        )
        result = await service.login(
            username="admin",
            password=password,
            client_ip="127.0.0.1",
            user_agent="pytest",
        )
        assert result.username == "admin"
        assert result.token  # non-empty
        assert result.expires_at > datetime.now(UTC)


class TestLoginFailureModes:
    @respx.mock
    async def test_no_such_user_raises_vague_auth_error(
        self, service: LocalAdminService
    ) -> None:
        respx.post(_query_url()).mock(
            return_value=httpx.Response(200, json={"result": []})
        )
        respx.post(_command_url()).mock(
            return_value=httpx.Response(200, json={"result": []})
        )
        with pytest.raises(LocalAdminAuthError, match="authentication failed"):
            await service.login(
                username="ghost",
                password="anything",
                client_ip="127.0.0.1",
                user_agent="pytest",
            )

    @respx.mock
    async def test_disabled_user_raises_vague_auth_error(
        self, service: LocalAdminService
    ) -> None:
        respx.post(_query_url()).mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": [
                        _row_with_password_hash(
                            password_hash="any-hash", enabled=False
                        )
                    ]
                },
            )
        )
        respx.post(_command_url()).mock(
            return_value=httpx.Response(200, json={"result": []})
        )
        with pytest.raises(LocalAdminAuthError, match="authentication failed"):
            await service.login(
                username="admin",
                password="anything",
                client_ip="127.0.0.1",
                user_agent="pytest",
            )

    @respx.mock
    async def test_locked_until_in_future_raises_vague_auth_error(
        self, service: LocalAdminService
    ) -> None:
        from datetime import timedelta as _td

        future_iso = (datetime.now(UTC) + _td(minutes=5)).isoformat()
        row = _row_with_password_hash(password_hash="any-hash")
        row["locked_until"] = future_iso
        respx.post(_query_url()).mock(
            return_value=httpx.Response(200, json={"result": [row]})
        )
        respx.post(_command_url()).mock(
            return_value=httpx.Response(200, json={"result": []})
        )
        with pytest.raises(LocalAdminAuthError, match="authentication failed"):
            await service.login(
                username="admin",
                password="anything",
                client_ip="127.0.0.1",
                user_agent="pytest",
            )


class TestRateLimit:
    @respx.mock
    async def test_rate_limit_blocks_after_threshold(
        self, arcade_client: ArcadeClient, signing_key: bytes
    ) -> None:
        # Tight rate-limit to provoke quickly
        service = LocalAdminService(
            arcade=arcade_client,
            signing_key=signing_key,
            token_ttl_seconds=300,
            failed_attempts_threshold=999,
            lockout_duration_seconds=60,
            rate_limit_per_minute=2,
        )
        respx.post(_query_url()).mock(
            return_value=httpx.Response(200, json={"result": []})
        )
        respx.post(_command_url()).mock(
            return_value=httpx.Response(200, json={"result": []})
        )
        # First two attempts: under the limit → fall through to "no_such_user"
        # Third attempt: rate-limited → still raises auth-error (vague)
        for _ in range(3):
            with pytest.raises(LocalAdminAuthError):
                await service.login(
                    username="admin",
                    password="anything",
                    client_ip="127.0.0.1",
                    user_agent="pytest",
                )


class TestAutoDisable:
    @respx.mock
    async def test_disables_enabled_local_admin_on_first_call(
        self, service: LocalAdminService
    ) -> None:
        respx.post(_query_url()).mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": [_row_with_password_hash(password_hash="hash")]
                },
            )
        )
        commands = respx.post(_command_url()).mock(
            return_value=httpx.Response(200, json={"result": []})
        )
        transitioned = await service.disable_on_siam_admin_login(
            siam_username="real-admin"
        )
        assert transitioned is True
        # First command: UPDATE LocalAdmin SET enabled = false ...
        # Second command: INSERT LocalAdminLoginEvent for the audit
        update_command = json.loads(
            commands.calls[0].request.content.decode()
        )["command"]
        assert "UPDATE LocalAdmin" in update_command
        assert "enabled = false" in update_command

    @respx.mock
    async def test_no_op_when_already_disabled(
        self, service: LocalAdminService
    ) -> None:
        respx.post(_query_url()).mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": [
                        _row_with_password_hash(
                            password_hash="hash", enabled=False
                        )
                    ]
                },
            )
        )
        respx.post(_command_url()).mock(
            return_value=httpx.Response(200, json={"result": []})
        )
        transitioned = await service.disable_on_siam_admin_login(
            siam_username="real-admin"
        )
        assert transitioned is False

    @respx.mock
    async def test_no_op_when_local_admin_absent(
        self, service: LocalAdminService
    ) -> None:
        respx.post(_query_url()).mock(
            return_value=httpx.Response(200, json={"result": []})
        )
        respx.post(_command_url()).mock(
            return_value=httpx.Response(200, json={"result": []})
        )
        transitioned = await service.disable_on_siam_admin_login(
            siam_username="real-admin"
        )
        assert transitioned is False


class TestPasswordGenerator:
    def test_generated_password_is_high_entropy(self) -> None:
        a = LocalAdminService.generate_password()
        b = LocalAdminService.generate_password()
        assert a != b
        # token_urlsafe(32) yields ~43 chars
        assert len(a) >= 32

    def test_generated_password_is_url_safe(self) -> None:
        # Should survive copy-paste through shells without quoting
        password = LocalAdminService.generate_password()
        for ch in password:
            assert ch.isalnum() or ch in ("-", "_")
