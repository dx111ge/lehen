"""``UserConnectionsService`` — gates, ID monotonicity, multi-mailbox.

Covers Sprint 2 Phase 1 invariants:

* SIAM gate 2 enforcement (403 for instances not in user's role-mapped set).
* Always-monotonic ``connection_seq`` so re-grant after revoke does not
  collide on the connection id.
* ``external_subject`` + ``display_label`` propagation for multi-mailbox.
* Per-(user, instance, external_subject) uniqueness — same external_subject
  → conflict, different external_subject → independent active connection.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
import respx

from lehen_hub.auth.dependencies import CurrentUser
from lehen_hub.config import ArcadeDBSettings
from lehen_hub.storage.arcade import ArcadeClient
from lehen_hub.user.connections_service import (
    ConnectionAlreadyExistsError,
    ConnectionNotFoundError,
    IntegrationDisabledError,
    IntegrationNotAuthorizedForRoleError,
    UserConnectionsService,
)

ARCADE_QUERY_URL = "http://test-arcade:2480/api/v1/query/lehen-test"
ARCADE_COMMAND_URL = "http://test-arcade:2480/api/v1/command/lehen-test"


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
def siam_mock() -> AsyncMock:
    """SIAMService mock — by default authorizes the user for all instances."""
    mock = AsyncMock()
    mock.get.return_value = {
        "lehen-admin": ["outlook-graph-prod", "teams-prod", "itsm-prod"],
        "change-manager": ["outlook-graph-prod", "itsm-prod"],
    }
    return mock


@pytest.fixture
def service(arcade: ArcadeClient, siam_mock: AsyncMock) -> UserConnectionsService:
    return UserConnectionsService(
        arcade=arcade, siam=siam_mock, consent_retention_days=30
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


def _enabled_instance_doc(instance_id: str = "outlook-graph-prod") -> dict[str, Any]:
    return {
        "id": instance_id,
        "type": "outlook-graph",
        "display_name": "Outlook (Graph)",
        "enabled": True,
        "multi_connection_allowed": True,
    }


def _command_for_call(call_index: int, route: respx.Route) -> str:
    return json.loads(route.calls[call_index].request.content.decode())["command"]


# ----------------------------------------------------------------------
# Existence + enablement gates
# ----------------------------------------------------------------------

class TestInstanceGates:
    @respx.mock
    async def test_grant_404_when_instance_missing(
        self, service: UserConnectionsService, user: CurrentUser
    ) -> None:
        # Instance fetch returns empty
        respx.post(ARCADE_QUERY_URL).mock(
            return_value=httpx.Response(200, json={"result": []})
        )
        with pytest.raises(ConnectionNotFoundError):
            await service.grant(
                user=user,
                integration_instance_id="missing-id",
            )

    @respx.mock
    async def test_grant_409_when_instance_disabled(
        self, service: UserConnectionsService, user: CurrentUser
    ) -> None:
        disabled_doc = _enabled_instance_doc()
        disabled_doc["enabled"] = False
        respx.post(ARCADE_QUERY_URL).mock(
            return_value=httpx.Response(200, json={"result": [disabled_doc]})
        )
        with pytest.raises(IntegrationDisabledError):
            await service.grant(
                user=user,
                integration_instance_id="outlook-graph-prod",
            )


# ----------------------------------------------------------------------
# SIAM gate 2 — the security gap fixed in Sprint 2 Phase 1
# ----------------------------------------------------------------------

class TestSIAMGate:
    @respx.mock
    async def test_grant_403_when_user_role_not_mapped(
        self,
        arcade: ArcadeClient,
        user: CurrentUser,
    ) -> None:
        """User has role 'change-manager' but SIAM mapping does not authorize
        that role for the requested instance. Must reject with
        IntegrationNotAuthorizedForRoleError, no DB write."""
        siam = AsyncMock()
        siam.get.return_value = {
            "lehen-admin": ["outlook-graph-prod"],
            # change-manager is NOT mapped to outlook-graph-prod
        }
        service = UserConnectionsService(
            arcade=arcade, siam=siam, consent_retention_days=30
        )
        # Instance fetch will return enabled, but SIAM gate fires first
        respx.post(ARCADE_QUERY_URL).mock(
            return_value=httpx.Response(
                200, json={"result": [_enabled_instance_doc()]}
            )
        )
        command_route = respx.post(ARCADE_COMMAND_URL).mock(
            return_value=httpx.Response(200, json={"result": []})
        )
        with pytest.raises(IntegrationNotAuthorizedForRoleError):
            await service.grant(
                user=user,
                integration_instance_id="outlook-graph-prod",
            )
        # No INSERT must have been issued — the gate fires before any write
        assert command_route.call_count == 0

    @respx.mock
    async def test_grant_403_for_user_with_no_roles(
        self, arcade: ArcadeClient
    ) -> None:
        """A user with empty realm_roles can't be SIAM-authorized for anything."""
        siam = AsyncMock()
        siam.get.return_value = {"lehen-admin": ["outlook-graph-prod"]}
        service = UserConnectionsService(
            arcade=arcade, siam=siam, consent_retention_days=30
        )
        no_roles_user = CurrentUser(
            sub="user-2",
            username="ghost",
            realm_roles=[],  # no roles
            identity_source="http://test-keycloak/realms/lehen",
            raw_claims={},
        )
        respx.post(ARCADE_QUERY_URL).mock(
            return_value=httpx.Response(
                200, json={"result": [_enabled_instance_doc()]}
            )
        )
        with pytest.raises(IntegrationNotAuthorizedForRoleError):
            await service.grant(
                user=no_roles_user,
                integration_instance_id="outlook-graph-prod",
            )


# ----------------------------------------------------------------------
# Multi-mailbox Layer 1 — external_subject + display_label
# ----------------------------------------------------------------------

class TestExternalSubject:
    @respx.mock
    async def test_grant_persists_external_subject_and_display_label(
        self, service: UserConnectionsService, user: CurrentUser
    ) -> None:
        respx.post(ARCADE_QUERY_URL).mock(
            side_effect=[
                # _fetch_instance
                httpx.Response(
                    200, json={"result": [_enabled_instance_doc()]}
                ),
                # uniqueness check (no existing active row)
                httpx.Response(200, json={"result": []}),
                # _next_seq
                httpx.Response(200, json={"result": [{"m": None}]}),
            ]
        )
        commands = respx.post(ARCADE_COMMAND_URL).mock(
            return_value=httpx.Response(200, json={"result": []})
        )

        result = await service.grant(
            user=user,
            integration_instance_id="outlook-graph-prod",
            external_subject="alice@company.example",
            display_label="Alice's Mailbox",
        )

        assert result["external_subject"] == "alice@company.example"
        assert result["display_label"] == "Alice's Mailbox"
        # First command: INSERT IntegrationConnection
        insert_cmd = _command_for_call(0, commands)
        assert "INSERT INTO IntegrationConnection" in insert_cmd
        assert "alice@company.example" in insert_cmd
        # Consent event also persists external_subject for audit completeness
        consent_cmd = _command_for_call(1, commands)
        assert "INSERT INTO ConsentEvent" in consent_cmd
        assert "alice@company.example" in consent_cmd

    @respx.mock
    async def test_grant_409_when_same_external_subject_already_active(
        self, service: UserConnectionsService, user: CurrentUser
    ) -> None:
        respx.post(ARCADE_QUERY_URL).mock(
            side_effect=[
                httpx.Response(
                    200, json={"result": [_enabled_instance_doc()]}
                ),
                # uniqueness check — existing active row for same external_subject
                httpx.Response(
                    200,
                    json={
                        "result": [
                            {
                                "id": "user-1:outlook-graph-prod:0",
                                "external_subject": "alice@company.example",
                            }
                        ]
                    },
                ),
            ]
        )
        with pytest.raises(ConnectionAlreadyExistsError):
            await service.grant(
                user=user,
                integration_instance_id="outlook-graph-prod",
                external_subject="alice@company.example",
            )

    @respx.mock
    async def test_grant_succeeds_for_different_external_subject(
        self, service: UserConnectionsService, user: CurrentUser
    ) -> None:
        """Multi-mailbox: alice already has a connection for her primary mailbox.
        She can also connect a shared mailbox — different external_subject,
        independent active connection."""
        respx.post(ARCADE_QUERY_URL).mock(
            side_effect=[
                httpx.Response(
                    200, json={"result": [_enabled_instance_doc()]}
                ),
                # uniqueness check for shared@team.example — no existing row
                httpx.Response(200, json={"result": []}),
                # _next_seq — primary mailbox is at seq=0, so next is 1
                httpx.Response(200, json={"result": [{"m": 0}]}),
            ]
        )
        commands = respx.post(ARCADE_COMMAND_URL).mock(
            return_value=httpx.Response(200, json={"result": []})
        )

        result = await service.grant(
            user=user,
            integration_instance_id="outlook-graph-prod",
            external_subject="shared@team.example",
            display_label="Team Inbox",
        )
        _ = commands  # writes are persisted; this test asserts on the result, not commands

        assert result["connection_seq"] == 1
        assert result["external_subject"] == "shared@team.example"


# ----------------------------------------------------------------------
# Connection-id collision fix — always-monotonic seq
# ----------------------------------------------------------------------

class TestMonotonicSeq:
    @respx.mock
    async def test_regrant_after_revoke_uses_next_seq(
        self, service: UserConnectionsService, user: CurrentUser
    ) -> None:
        """Sprint 1's bug: after revoke, the disconnected row at seq=0 was left
        in place; re-grant tried to insert seq=0 again → primary key collision.
        Sprint 2 fix: always-monotonic seq. Re-grant gets seq=1."""
        respx.post(ARCADE_QUERY_URL).mock(
            side_effect=[
                # _fetch_instance
                httpx.Response(
                    200, json={"result": [_enabled_instance_doc()]}
                ),
                # uniqueness check — empty (the previous row is disconnected)
                httpx.Response(200, json={"result": []}),
                # _next_seq — max(seq)=0 from the disconnected row → next = 1
                httpx.Response(200, json={"result": [{"m": 0}]}),
            ]
        )
        commands = respx.post(ARCADE_COMMAND_URL).mock(
            return_value=httpx.Response(200, json={"result": []})
        )

        result = await service.grant(
            user=user,
            integration_instance_id="outlook-graph-prod",
            external_subject="",
        )
        _ = commands
        assert result["connection_seq"] == 1
        assert result["id"] == "user-1:outlook-graph-prod:1"


# ----------------------------------------------------------------------
# Revoke
# ----------------------------------------------------------------------

class TestRevoke:
    @respx.mock
    async def test_revoke_404_when_no_active_connection(
        self, service: UserConnectionsService, user: CurrentUser
    ) -> None:
        respx.post(ARCADE_QUERY_URL).mock(
            return_value=httpx.Response(200, json={"result": []})
        )
        with pytest.raises(ConnectionNotFoundError):
            await service.revoke(
                user=user, integration_instance_id="outlook-graph-prod"
            )

    @respx.mock
    async def test_revoke_targets_specific_external_subject(
        self, service: UserConnectionsService, user: CurrentUser
    ) -> None:
        """When external_subject is given, only the matching active row revokes;
        other mailbox connections under the same instance stay active."""
        respx.post(ARCADE_QUERY_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": [
                        {
                            "id": "user-1:outlook-graph-prod:1",
                            "connection_seq": 1,
                            "privacy_class": "company",
                            "external_subject": "shared@team.example",
                        }
                    ]
                },
            )
        )
        commands = respx.post(ARCADE_COMMAND_URL).mock(
            return_value=httpx.Response(200, json={"result": []})
        )

        await service.revoke(
            user=user,
            integration_instance_id="outlook-graph-prod",
            external_subject="shared@team.example",
        )

        update_cmd = _command_for_call(0, commands)
        assert "UPDATE IntegrationConnection SET status = 'disconnected'" in update_cmd
