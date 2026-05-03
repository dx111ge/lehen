"""IntegrationsService — encrypt-on-write of secret fields, no plaintext leak in reads."""

from __future__ import annotations

import json
import secrets as stdlib_secrets

import httpx
import pytest
import respx

from lehen_hub.admin.audit_service import AdminAuditService
from lehen_hub.admin.integrations_service import (
    IntegrationConfigError,
    IntegrationInstanceConflictError,
    IntegrationInstanceNotFoundError,
    IntegrationsService,
)
from lehen_hub.auth.dependencies import CurrentUser
from lehen_hub.config import ArcadeDBSettings
from lehen_hub.crypto import decrypt
from lehen_hub.storage.arcade import ArcadeClient

ARCADE_QUERY_URL = "http://test-arcade:2480/api/v1/query/lehen-test"
ARCADE_COMMAND_URL = "http://test-arcade:2480/api/v1/command/lehen-test"


@pytest.fixture
def master_key() -> bytes:
    return stdlib_secrets.token_bytes(32)


@pytest.fixture
def pepper() -> bytes:
    return stdlib_secrets.token_bytes(32)


@pytest.fixture
async def http_client() -> httpx.AsyncClient:
    async with httpx.AsyncClient() as c:
        yield c


@pytest.fixture
def arcade(http_client: httpx.AsyncClient) -> ArcadeClient:
    return ArcadeClient(
        settings=ArcadeDBSettings(
            host="test-arcade",
            password="test",
            database="lehen-test",
        ),
        http=http_client,
    )


@pytest.fixture
def audit_service(arcade: ArcadeClient, pepper: bytes) -> AdminAuditService:
    return AdminAuditService(arcade=arcade, audit_pepper=pepper)


@pytest.fixture
def service(
    arcade: ArcadeClient,
    audit_service: AdminAuditService,
    master_key: bytes,
) -> IntegrationsService:
    return IntegrationsService(arcade=arcade, audit=audit_service, master_key=master_key)


@pytest.fixture
def admin_user() -> CurrentUser:
    return CurrentUser(
        sub="admin-1",
        username="dx-admin",
        realm_roles=["lehen-admin"],
        identity_source="http://test-keycloak/realms/lehen",
        raw_claims={"sub": "admin-1"},
    )


def _command_body_for_call(route: respx.Route, call_index: int) -> dict:
    return json.loads(route.calls[call_index].request.content.decode())


def _content_doc_from_command(cmd: str) -> dict:
    json_start = cmd.index("CONTENT ") + len("CONTENT ")
    # The command may end with " WHERE id = :id" etc; cut at the first non-json char
    # We'll just attempt to json.loads from start to end of {...}
    end = cmd.rindex("}") + 1
    return json.loads(cmd[json_start:end])


@respx.mock
async def test_create_encrypts_secret_fields_at_rest(
    service: IntegrationsService,
    admin_user: CurrentUser,
    master_key: bytes,
) -> None:
    # First query: existence check returns empty
    respx.post(ARCADE_QUERY_URL).mock(return_value=httpx.Response(200, json={"result": []}))
    cmd_route = respx.post(ARCADE_COMMAND_URL).mock(
        return_value=httpx.Response(200, json={"result": [{"created": 1}]})
    )

    result = await service.create(
        actor=admin_user,
        instance_id="teams-prod",
        type_id="teams-graph",
        display_name="Teams (Production)",
        config={
            "tenant_id": "ten-001",
            "client_id": "cli-001",
            "client_secret": "secret-plaintext-value",
        },
    )

    assert "config_secrets_encrypted" not in result, "secrets must not appear in API response"
    assert result["secret_fields_set"] == ["client_secret"]
    assert result["config_public"] == {"tenant_id": "ten-001", "client_id": "cli-001"}

    # First command call is the INSERT — confirm what hits ArcadeDB.
    insert_body = _command_body_for_call(cmd_route, 0)
    insert_cmd = insert_body["command"]
    assert "INSERT INTO IntegrationInstance" in insert_cmd
    stored_doc = _content_doc_from_command(insert_cmd)
    encrypted = stored_doc["config_secrets_encrypted"]["client_secret"]
    # Must be the encrypted envelope, not plaintext
    assert encrypted != "secret-plaintext-value"
    # And must round-trip with the master key
    assert decrypt(encrypted, key=master_key) == "secret-plaintext-value"


@respx.mock
async def test_create_rejects_unknown_type(
    service: IntegrationsService,
    admin_user: CurrentUser,
) -> None:
    with pytest.raises(IntegrationConfigError, match="unknown integration type"):
        await service.create(
            actor=admin_user,
            instance_id="x",
            type_id="not-a-real-type",
            display_name="X",
            config={},
        )


@respx.mock
async def test_create_rejects_missing_required_field(
    service: IntegrationsService,
    admin_user: CurrentUser,
) -> None:
    respx.post(ARCADE_QUERY_URL).mock(return_value=httpx.Response(200, json={"result": []}))
    with pytest.raises(IntegrationConfigError, match="required field missing"):
        await service.create(
            actor=admin_user,
            instance_id="teams-prod",
            type_id="teams-graph",
            display_name="Teams Prod",
            config={"tenant_id": "abc"},  # missing client_id, client_secret
        )


@respx.mock
async def test_create_rejects_unknown_config_keys(
    service: IntegrationsService,
    admin_user: CurrentUser,
) -> None:
    respx.post(ARCADE_QUERY_URL).mock(return_value=httpx.Response(200, json={"result": []}))
    with pytest.raises(IntegrationConfigError, match="unknown config fields"):
        await service.create(
            actor=admin_user,
            instance_id="teams-prod",
            type_id="teams-graph",
            display_name="Teams Prod",
            config={
                "tenant_id": "abc",
                "client_id": "def",
                "client_secret": "x",
                "rogue_field": "whatever",
            },
        )


@respx.mock
async def test_create_409_on_existing_id(
    service: IntegrationsService,
    admin_user: CurrentUser,
) -> None:
    # Existence check returns a row → conflict
    respx.post(ARCADE_QUERY_URL).mock(
        return_value=httpx.Response(200, json={"result": [{"id": "teams-prod"}]})
    )
    with pytest.raises(IntegrationInstanceConflictError):
        await service.create(
            actor=admin_user,
            instance_id="teams-prod",
            type_id="teams-graph",
            display_name="Teams",
            config={
                "tenant_id": "a",
                "client_id": "b",
                "client_secret": "c",
            },
        )


@respx.mock
async def test_create_rejects_multi_on_single_cardinality_type(
    service: IntegrationsService,
    admin_user: CurrentUser,
) -> None:
    """``teams-graph`` has connection_cardinality='single'; admin cannot
    enable multi_connection_allowed on it. Sprint 2 §3.3 invariant."""
    with pytest.raises(IntegrationConfigError, match="connection_cardinality='single'"):
        await service.create(
            actor=admin_user,
            instance_id="teams-prod",
            type_id="teams-graph",
            display_name="Teams Prod",
            config={
                "tenant_id": "a",
                "client_id": "b",
                "client_secret": "c",
            },
            multi_connection_allowed=True,
        )


@respx.mock
async def test_create_allows_multi_on_multi_cardinality_type(
    service: IntegrationsService,
    admin_user: CurrentUser,
) -> None:
    """``outlook-graph`` has connection_cardinality='multi'; admin may set
    multi_connection_allowed freely."""
    respx.post(ARCADE_QUERY_URL).mock(return_value=httpx.Response(200, json={"result": []}))
    respx.post(ARCADE_COMMAND_URL).mock(
        return_value=httpx.Response(200, json={"result": [{"created": 1}]})
    )

    result = await service.create(
        actor=admin_user,
        instance_id="outlook-graph-prod",
        type_id="outlook-graph",
        display_name="Outlook (Graph)",
        config={
            "tenant_id": "ten-001",
            "client_id": "cli-001",
            "client_secret": "secret",
        },
        multi_connection_allowed=True,
    )
    assert result["multi_connection_allowed"] is True


@respx.mock
async def test_update_rejects_multi_on_single_cardinality_type(
    service: IntegrationsService,
    admin_user: CurrentUser,
) -> None:
    """An existing single-cardinality instance cannot be flipped to multi
    via update. Same invariant as create."""
    existing_doc = {
        "id": "teams-prod",
        "type": "teams-graph",
        "display_name": "Teams",
        "config_public": {"tenant_id": "a", "client_id": "b"},
        "config_secrets_encrypted": {"client_secret": "<encrypted>"},
        "enabled": True,
        "multi_connection_allowed": False,
    }
    respx.post(ARCADE_QUERY_URL).mock(
        return_value=httpx.Response(200, json={"result": [existing_doc]})
    )
    with pytest.raises(IntegrationConfigError, match="connection_cardinality='single'"):
        await service.update(
            actor=admin_user,
            instance_id="teams-prod",
            multi_connection_allowed=True,
        )


@respx.mock
async def test_get_returns_no_plaintext_secrets(
    service: IntegrationsService,
) -> None:
    stored = {
        "id": "teams-prod",
        "type": "teams-graph",
        "display_name": "Teams",
        "config_public": {"tenant_id": "a", "client_id": "b"},
        "config_secrets_encrypted": {"client_secret": "<encrypted-blob>"},
        "enabled": True,
        "multi_connection_allowed": False,
        "@rid": "#10:0",
    }
    respx.post(ARCADE_QUERY_URL).mock(
        return_value=httpx.Response(200, json={"result": [stored]})
    )
    result = await service.get("teams-prod")
    assert "config_secrets_encrypted" not in result
    assert "@rid" not in result
    assert result["secret_fields_set"] == ["client_secret"]
    assert result["config_public"] == {"tenant_id": "a", "client_id": "b"}


@respx.mock
async def test_get_404_when_missing(service: IntegrationsService) -> None:
    respx.post(ARCADE_QUERY_URL).mock(return_value=httpx.Response(200, json={"result": []}))
    with pytest.raises(IntegrationInstanceNotFoundError):
        await service.get("no-such-id")
