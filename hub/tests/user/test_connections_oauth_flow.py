"""End-to-end OAuth flow + admin-cascade revoke through ``UserConnectionsService``.

Exercises Sprint 2 Phase 2:

* ``initiate_grant`` builds an auth URL and signed state.
* ``complete_grant`` validates state, exchanges code via the token endpoint,
  fetches identity from the source (Graph ``/me``), persists a real
  ``IntegrationConnection`` with encrypted tokens.
* Admin-action revoke cascade (``revoke_all_for_instance``) wipes credentials
  and emits a per-user ``ConsentEvent``.
* SIAM-cascade revoke (``revoke_for_users_no_longer_authorized``) revokes
  connections whose backing instance is no longer reachable under the new
  mapping.
"""

from __future__ import annotations

import json
import secrets as stdlib_secrets
from typing import Any
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx

from lehen_hub.auth.dependencies import CurrentUser
from lehen_hub.auth.oauth import OAuthStateError, decode_state
from lehen_hub.config import ArcadeDBSettings
from lehen_hub.crypto import decrypt
from lehen_hub.storage.arcade import ArcadeClient
from lehen_hub.user.connections_service import (
    OAuthFlowConfigError,
    RedirectUriNotAllowedError,
    UserConnectionsService,
)

ARCADE_QUERY_URL = "http://test-arcade:2480/api/v1/query/lehen-test"
ARCADE_COMMAND_URL = "http://test-arcade:2480/api/v1/command/lehen-test"
TOKEN_URL = "https://login.microsoftonline.com/tenant-abc/oauth2/v2.0/token"
GRAPH_ME_URL = "https://graph.microsoft.com/v1.0/me"


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
def master_key() -> bytes:
    return stdlib_secrets.token_bytes(32)


@pytest.fixture
def siam_mock() -> AsyncMock:
    mock = AsyncMock()
    mock.get.return_value = {
        "change-manager": ["outlook-graph-prod"],
    }
    return mock


@pytest.fixture
def service(
    arcade: ArcadeClient, siam_mock: AsyncMock, master_key: bytes
) -> UserConnectionsService:
    return UserConnectionsService(
        arcade=arcade,
        siam=siam_mock,
        consent_retention_days=30,
        master_key=master_key,
        allowed_redirect_uris=("lehen://oauth/callback",),
    )


@pytest.fixture
def user() -> CurrentUser:
    return CurrentUser(
        sub="user-1",
        username="alice",
        realm_roles=["change-manager"],
        identity_source="http://test-keycloak/realms/lehen",
        raw_claims={},
    )


def _outlook_instance_doc(client_secret_envelope: str) -> dict[str, Any]:
    return {
        "id": "outlook-graph-prod",
        "type": "outlook-graph",
        "display_name": "Outlook (Graph)",
        "enabled": True,
        "multi_connection_allowed": True,
        "config_public": {"tenant_id": "tenant-abc", "client_id": "cli-001"},
        "config_secrets_encrypted": {"client_secret": client_secret_envelope},
    }


# ----------------------------------------------------------------------
# initiate_grant
# ----------------------------------------------------------------------

class TestInitiateGrant:
    @respx.mock
    async def test_returns_auth_url_and_state(
        self,
        service: UserConnectionsService,
        user: CurrentUser,
        master_key: bytes,
    ) -> None:
        from lehen_hub.crypto import encrypt as enc

        instance = _outlook_instance_doc(enc("dummy-secret", key=master_key))
        respx.post(ARCADE_QUERY_URL).mock(
            return_value=httpx.Response(200, json={"result": [instance]})
        )

        result = await service.initiate_grant(
            user=user,
            integration_instance_id="outlook-graph-prod",
            redirect_uri="lehen://oauth/callback",
        )

        # Auth URL points to Microsoft and carries our params
        parsed = urlparse(result["auth_url"])
        assert parsed.netloc == "login.microsoftonline.com"
        assert "/tenant-abc/oauth2/v2.0/authorize" in parsed.path
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        assert params["client_id"] == "cli-001"
        assert params["redirect_uri"] == "lehen://oauth/callback"
        assert params["state"] == result["state"]
        # State decodes back with the right context
        flow = decode_state(result["state"], key=master_key)
        assert flow.user_sub == "user-1"
        assert flow.instance_id == "outlook-graph-prod"
        assert flow.redirect_uri == "lehen://oauth/callback"

    @respx.mock
    async def test_rejects_unallowed_redirect_uri(
        self,
        service: UserConnectionsService,
        user: CurrentUser,
        master_key: bytes,
    ) -> None:
        from lehen_hub.crypto import encrypt as enc

        instance = _outlook_instance_doc(enc("dummy", key=master_key))
        respx.post(ARCADE_QUERY_URL).mock(
            return_value=httpx.Response(200, json={"result": [instance]})
        )
        with pytest.raises(RedirectUriNotAllowedError):
            await service.initiate_grant(
                user=user,
                integration_instance_id="outlook-graph-prod",
                redirect_uri="https://attacker.example/steal",
            )

    @respx.mock
    async def test_missing_client_id_raises_config_error(
        self,
        service: UserConnectionsService,
        user: CurrentUser,
        master_key: bytes,
    ) -> None:
        from lehen_hub.crypto import encrypt as enc

        instance = _outlook_instance_doc(enc("dummy", key=master_key))
        instance["config_public"] = {"tenant_id": "tenant-abc"}  # no client_id
        respx.post(ARCADE_QUERY_URL).mock(
            return_value=httpx.Response(200, json={"result": [instance]})
        )
        with pytest.raises(OAuthFlowConfigError, match="client_id"):
            await service.initiate_grant(
                user=user,
                integration_instance_id="outlook-graph-prod",
                redirect_uri="lehen://oauth/callback",
            )


# ----------------------------------------------------------------------
# complete_grant
# ----------------------------------------------------------------------

class TestCompleteGrant:
    @respx.mock
    async def test_full_oauth_round_trip(
        self,
        service: UserConnectionsService,
        user: CurrentUser,
        http_client: httpx.AsyncClient,
        master_key: bytes,
    ) -> None:
        """initiate → mock IdP → complete. Verifies token exchange happens,
        Graph /me is called, encrypted_credentials persisted, status=connected."""
        from lehen_hub.crypto import encrypt as enc

        instance = _outlook_instance_doc(enc("the-client-secret", key=master_key))

        # Phase 1 — initiate. The instance fetch returns our outlook-graph doc.
        respx.post(ARCADE_QUERY_URL).mock(
            return_value=httpx.Response(200, json={"result": [instance]})
        )
        initiate_result = await service.initiate_grant(
            user=user,
            integration_instance_id="outlook-graph-prod",
            redirect_uri="lehen://oauth/callback",
        )
        state = initiate_result["state"]

        # Phase 2 — complete. Re-mock the routes. Order:
        # 1. _fetch_instance → instance doc
        # 2. uniqueness check → no existing
        # 3. _next_seq → max(seq)=null (first connection)
        respx.reset()
        respx.post(ARCADE_QUERY_URL).mock(
            side_effect=[
                httpx.Response(200, json={"result": [instance]}),
                httpx.Response(200, json={"result": []}),
                httpx.Response(200, json={"result": [{"m": None}]}),
            ]
        )
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": "graph-at-1",
                    "refresh_token": "graph-rt-1",
                    "expires_in": 3600,
                    "scope": "openid Mail.Read User.Read offline_access",
                    "token_type": "Bearer",
                },
            )
        )
        respx.get(GRAPH_ME_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "mail": "alice@company.example",
                    "userPrincipalName": "alice@company.onmicrosoft.com",
                    "displayName": "Alice Adams",
                },
            )
        )
        commands = respx.post(ARCADE_COMMAND_URL).mock(
            return_value=httpx.Response(200, json={"result": []})
        )

        result = await service.complete_grant(
            user=user,
            integration_instance_id="outlook-graph-prod",
            code="auth-code-from-microsoft",
            state=state,
            http_client=http_client,
        )

        # Result reflects real state — no encrypted_credentials in API response
        assert result["status"] == "connected"
        assert result["external_subject"] == "alice@company.example"
        assert result["display_label"] == "Alice Adams"
        assert result["last_health_status"] == "ok"
        assert "encrypted_credentials" not in result

        # Two writes: INSERT IntegrationConnection + INSERT ConsentEvent
        assert commands.call_count == 2
        insert_cmd = json.loads(commands.calls[0].request.content.decode())[
            "command"
        ]
        assert "INSERT INTO IntegrationConnection" in insert_cmd
        # The persisted token blob is encrypted; verify roundtrip with master_key
        json_part = insert_cmd.split("CONTENT ", 1)[1]
        end = json_part.rindex("}") + 1
        doc = json.loads(json_part[:end])
        decrypted_blob = decrypt(doc["encrypted_credentials"], key=master_key)
        token_data = json.loads(decrypted_blob)
        assert token_data["access_token"] == "graph-at-1"
        assert token_data["refresh_token"] == "graph-rt-1"

    @respx.mock
    async def test_rejects_state_for_different_user(
        self,
        service: UserConnectionsService,
        user: CurrentUser,
        http_client: httpx.AsyncClient,
        master_key: bytes,
    ) -> None:
        """A state minted for user A cannot be used by user B even with a
        valid bearer token. The HMAC checks signature; this assertion is
        the application-layer ``state.user_sub == caller.sub`` check."""
        from lehen_hub.crypto import encrypt as enc

        instance = _outlook_instance_doc(enc("secret", key=master_key))

        # User A initiates
        respx.post(ARCADE_QUERY_URL).mock(
            return_value=httpx.Response(200, json={"result": [instance]})
        )
        result = await service.initiate_grant(
            user=user,
            integration_instance_id="outlook-graph-prod",
            redirect_uri="lehen://oauth/callback",
        )
        state = result["state"]

        # User B tries to complete
        user_b = CurrentUser(
            sub="user-2",
            username="bob",
            realm_roles=["change-manager"],
            identity_source="http://test-keycloak/realms/lehen",
            raw_claims={},
        )
        respx.reset()
        with pytest.raises(OAuthStateError, match="user_sub"):
            await service.complete_grant(
                user=user_b,
                integration_instance_id="outlook-graph-prod",
                code="any-code",
                state=state,
                http_client=http_client,
            )


# ----------------------------------------------------------------------
# Admin cascade
# ----------------------------------------------------------------------

class TestRevokeAllForInstance:
    @respx.mock
    async def test_revokes_active_connections_and_wipes_credentials(
        self, service: UserConnectionsService
    ) -> None:
        respx.post(ARCADE_QUERY_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": [
                        {
                            "id": "user-1:outlook-graph-prod:0",
                            "user_sub": "user-1",
                            "username": "alice",
                            "integration_instance_id": "outlook-graph-prod",
                            "connection_seq": 0,
                            "external_subject": "alice@example.com",
                            "privacy_class": "company",
                        },
                        {
                            "id": "user-2:outlook-graph-prod:0",
                            "user_sub": "user-2",
                            "username": "bob",
                            "integration_instance_id": "outlook-graph-prod",
                            "connection_seq": 0,
                            "external_subject": "bob@example.com",
                            "privacy_class": "company",
                        },
                    ]
                },
            )
        )
        commands = respx.post(ARCADE_COMMAND_URL).mock(
            return_value=httpx.Response(200, json={"result": []})
        )

        revoked = await service.revoke_all_for_instance(
            "outlook-graph-prod",
            "revoked-by-admin-disable",
            "req-1",
        )
        assert revoked == 2
        # Each connection: 1 UPDATE + 1 INSERT (ConsentEvent) = 4 commands
        assert commands.call_count == 4
        update_cmd = json.loads(
            commands.calls[0].request.content.decode()
        )["command"]
        assert "UPDATE IntegrationConnection" in update_cmd
        assert "encrypted_credentials = null" in update_cmd
        consent_cmd = json.loads(
            commands.calls[1].request.content.decode()
        )["command"]
        assert "INSERT INTO ConsentEvent" in consent_cmd
        assert "revoked-by-admin-disable" in consent_cmd

    @respx.mock
    async def test_no_op_when_no_active_connections(
        self, service: UserConnectionsService
    ) -> None:
        respx.post(ARCADE_QUERY_URL).mock(
            return_value=httpx.Response(200, json={"result": []})
        )
        revoked = await service.revoke_all_for_instance(
            "outlook-graph-prod", "revoked-by-admin-disable", None
        )
        assert revoked == 0


class TestSIAMCascade:
    @respx.mock
    async def test_revokes_orphaned_instance_connections(
        self, service: UserConnectionsService
    ) -> None:
        """Admin removes ``outlook-graph-prod`` from every role mapping. Any
        active connection on that instance must revoke."""
        respx.post(ARCADE_QUERY_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": [
                        {
                            "id": "user-1:outlook-graph-prod:0",
                            "user_sub": "user-1",
                            "username": "alice",
                            "integration_instance_id": "outlook-graph-prod",
                            "connection_seq": 0,
                            "external_subject": "a@x",
                            "privacy_class": "company",
                        }
                    ]
                },
            )
        )
        commands = respx.post(ARCADE_COMMAND_URL).mock(
            return_value=httpx.Response(200, json={"result": []})
        )
        revoked = await service.revoke_for_users_no_longer_authorized(
            {"change-manager": ["outlook-graph-prod"]},
            {"change-manager": []},  # newly orphaned
            "req-1",
        )
        assert revoked == 1
        consent_cmd = json.loads(
            commands.calls[1].request.content.decode()
        )["command"]
        assert "revoked-by-siam-change" in consent_cmd

    @respx.mock
    async def test_no_op_when_instance_still_mapped_to_some_role(
        self, service: UserConnectionsService
    ) -> None:
        """If at least one role still maps to the instance, connections stay.
        Conservative behavior — see service docstring on why."""
        respx.post(ARCADE_QUERY_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": [
                        {
                            "id": "user-1:outlook-graph-prod:0",
                            "user_sub": "user-1",
                            "username": "alice",
                            "integration_instance_id": "outlook-graph-prod",
                            "connection_seq": 0,
                            "external_subject": "a@x",
                            "privacy_class": "company",
                        }
                    ]
                },
            )
        )
        respx.post(ARCADE_COMMAND_URL).mock(
            return_value=httpx.Response(200, json={"result": []})
        )
        # Removed from change-manager but still on lehen-admin
        revoked = await service.revoke_for_users_no_longer_authorized(
            {
                "change-manager": ["outlook-graph-prod"],
                "lehen-admin": ["outlook-graph-prod"],
            },
            {
                "change-manager": [],
                "lehen-admin": ["outlook-graph-prod"],
            },
            None,
        )
        assert revoked == 0
