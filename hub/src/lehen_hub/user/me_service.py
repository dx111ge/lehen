"""``MeService`` — composes the GET /me payload and writes a ``LoginEvent``.

The payload is the union of integrations allowed by the SIAM mapping for
each of the user's matching realm roles (D3), with per-integration
connection status pulled from ``IntegrationConnection`` (D4).

All lists are alphabetically sorted before return (A10).
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from lehen_hub.admin.integrations_service import IntegrationsService
from lehen_hub.admin.siam_service import SIAMService
from lehen_hub.auth.dependencies import CurrentUser
from lehen_hub.storage.arcade import ArcadeClient
from lehen_hub.user.connections_service import UserConnectionsService

_NEEDS_CONNECT = "needs_connect"
_CONNECTED = "connected"
_STALE = "stale"


class MeService:
    def __init__(
        self,
        *,
        arcade: ArcadeClient,
        siam: SIAMService,
        integrations: IntegrationsService,
        connections: UserConnectionsService,
        login_retention_days: int,
    ) -> None:
        self._arcade = arcade
        self._siam = siam
        self._integrations = integrations
        self._connections = connections
        self._login_retention_days = login_retention_days

    async def me(
        self,
        user: CurrentUser,
        *,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        siam_mapping = await self._siam.get()
        matching_roles = sorted(r for r in user.realm_roles if r in siam_mapping)

        allowed_instance_ids: set[str] = set()
        for role in matching_roles:
            allowed_instance_ids.update(siam_mapping.get(role, []))

        all_instances = await self._integrations.list()
        instance_by_id = {i["id"]: i for i in all_instances}

        user_connections = await self._connections.list_for_user(user.sub)
        connections_by_instance = {
            c["integration_instance_id"]: c for c in user_connections
        }

        integrations_payload: list[dict[str, Any]] = []
        for instance_id in sorted(allowed_instance_ids):  # A10
            instance = instance_by_id.get(instance_id)
            if instance is None or not instance.get("enabled", False):
                continue
            connection = connections_by_instance.get(instance_id)
            integrations_payload.append(
                {
                    "instance_id": instance_id,
                    "type": instance["type"],
                    "display_name": instance["display_name"],
                    "status": _status_for(connection),
                    "connection_id": connection["id"] if connection else None,
                }
            )

        await self._record_login_event(
            user=user,
            roles=matching_roles,
            integration_ids=[i["instance_id"] for i in integrations_payload],
            request_id=request_id,
        )

        return {
            "identity": {"sub": user.sub, "username": user.username},
            "roles": matching_roles,
            "integrations": integrations_payload,
        }

    async def _record_login_event(
        self,
        *,
        user: CurrentUser,
        roles: list[str],
        integration_ids: list[str],
        request_id: str | None,
    ) -> None:
        now = datetime.now(UTC)
        retain_until = now + timedelta(days=self._login_retention_days)
        doc = {
            "id": str(uuid.uuid4()),
            "ts": now.isoformat(),
            "user_sub": user.sub,
            "username": user.username,
            "roles": roles,
            "integrations_resolved": integration_ids,
            "request_id": request_id or str(uuid.uuid4()),
            "retain_until": retain_until.isoformat(),
        }
        # doc dict is fully validated above; JSON literal embed is safe.
        await self._arcade.command(
            f"INSERT INTO LoginEvent CONTENT {json.dumps(doc)}"
        )


def _status_for(connection: dict[str, Any] | None) -> str:
    if connection is None:
        return _NEEDS_CONNECT
    raw = str(connection.get("status", ""))
    if raw == "stale":
        return _STALE
    if raw in {"stub-connected", "connected"}:
        return _CONNECTED
    return _NEEDS_CONNECT
