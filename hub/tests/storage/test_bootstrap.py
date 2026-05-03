"""Bootstrap idempotency + LLMConfig seeding tests (no real ArcadeDB)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
import respx

from lehen_hub.config import ArcadeDBSettings
from lehen_hub.storage.arcade import ArcadeClient
from lehen_hub.storage.bootstrap import ensure_admin_schema

ARCADE_BASE = "http://test-arcade:2480"


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


def _expected_query_url() -> str:
    return f"{ARCADE_BASE}/api/v1/query/lehen-test"


def _expected_command_url() -> str:
    return f"{ARCADE_BASE}/api/v1/command/lehen-test"


def _expected_exists_url() -> str:
    return f"{ARCADE_BASE}/api/v1/exists/lehen-test"


def _mock_db_exists(exists: bool = True) -> None:
    """Mock the database_exists() preflight call all bootstraps now do first."""
    respx.get(_expected_exists_url()).mock(
        return_value=httpx.Response(200, json={"result": exists})
    )


@respx.mock
async def test_first_boot_creates_all_types_and_seeds_llm(
    arcade_client: ArcadeClient,
) -> None:
    # DB exists (skip CREATE DATABASE branch); empty schema; empty LLMConfig
    _mock_db_exists(True)
    schema_route = respx.post(_expected_query_url()).mock(
        side_effect=[
            httpx.Response(200, json={"result": []}),  # SELECT name FROM schema:types
            httpx.Response(200, json={"result": [{"c": 0}]}),  # SELECT count(*) FROM LLMConfig
        ]
    )
    command_route = respx.post(_expected_command_url()).mock(
        return_value=httpx.Response(200, json={"result": [{"created": 1}]})
    )

    created = await ensure_admin_schema(
        arcade_client, now=datetime(2026, 5, 2, tzinfo=UTC)
    )

    assert created == [
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
    ]
    assert schema_route.call_count == 2  # one schema list + one LLMConfig count
    # 10 type creates + 1 LLMConfig seed = 11 commands
    assert command_route.call_count == 11


@respx.mock
async def test_second_boot_creates_nothing(
    arcade_client: ArcadeClient,
) -> None:
    _mock_db_exists(True)
    existing_types: list[dict[str, Any]] = [
        {"name": "LLMConfig"},
        {"name": "IntegrationInstance"},
        {"name": "SIAMMapping"},
        {"name": "IntegrationConnection"},
        {"name": "ConsentEvent"},
        {"name": "AdminAuditEvent"},
        {"name": "LoginEvent"},
        {"name": "LocalAdmin"},
        {"name": "LocalAdminLoginEvent"},
        {"name": "LocalAdminCredentialRotated"},
    ]
    respx.post(_expected_query_url()).mock(
        side_effect=[
            httpx.Response(200, json={"result": existing_types}),
            httpx.Response(200, json={"result": [{"c": 1}]}),  # LLMConfig already populated
        ]
    )
    command_route = respx.post(_expected_command_url()).mock(
        return_value=httpx.Response(200, json={"result": []})
    )

    created = await ensure_admin_schema(arcade_client)

    assert created == []
    assert command_route.call_count == 0


@respx.mock
async def test_partial_bootstrap_only_creates_missing(
    arcade_client: ArcadeClient,
) -> None:
    _mock_db_exists(True)
    # Schema has some types, missing ConsentEvent, LoginEvent, and the
    # local-admin trio
    existing_types = [
        {"name": "LLMConfig"},
        {"name": "IntegrationInstance"},
        {"name": "SIAMMapping"},
        {"name": "IntegrationConnection"},
        {"name": "AdminAuditEvent"},
    ]
    respx.post(_expected_query_url()).mock(
        side_effect=[
            httpx.Response(200, json={"result": existing_types}),
            httpx.Response(200, json={"result": [{"c": 1}]}),
        ]
    )
    command_route = respx.post(_expected_command_url()).mock(
        return_value=httpx.Response(200, json={"result": []})
    )

    created = await ensure_admin_schema(arcade_client)

    assert created == [
        "ConsentEvent",
        "LoginEvent",
        "LocalAdmin",
        "LocalAdminLoginEvent",
        "LocalAdminCredentialRotated",
    ]
    assert command_route.call_count == 5


@respx.mock
async def test_seed_uses_hardcoded_defaults(
    arcade_client: ArcadeClient,
) -> None:
    """First-run seed uses the hardcoded model + base-url defaults from
    bootstrap.py; no env-based override path exists by design."""
    _mock_db_exists(True)
    respx.post(_expected_query_url()).mock(
        side_effect=[
            httpx.Response(
                200,
                json={
                    "result": [
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
                },
            ),
            httpx.Response(200, json={"result": [{"c": 0}]}),  # empty LLMConfig
        ]
    )
    command_route = respx.post(_expected_command_url()).mock(
        return_value=httpx.Response(200, json={"result": []})
    )

    await ensure_admin_schema(arcade_client)

    # Only one command should fire — the LLMConfig seed
    assert command_route.call_count == 1
    seed_call_body = json.loads(command_route.calls[0].request.content.decode())
    assert "INSERT INTO LLMConfig" in seed_call_body["command"]
    assert "gemma4:e4b" in seed_call_body["command"]
    assert "nomic-embed-text" in seed_call_body["command"]
    assert "host.docker.internal:11434" in seed_call_body["command"]
    assert "system-bootstrap" in seed_call_body["command"]


@respx.mock
async def test_arcade_query_error_raises(
    arcade_client: ArcadeClient,
) -> None:
    from lehen_hub.storage.arcade import ArcadeQueryError

    _mock_db_exists(True)
    respx.post(_expected_query_url()).mock(
        return_value=httpx.Response(500, text="ArcadeDB unavailable")
    )

    with pytest.raises(ArcadeQueryError, match="500"):
        await ensure_admin_schema(arcade_client)
