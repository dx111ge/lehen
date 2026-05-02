"""Per-user IntegrationConnection CRUD + ConsentEvent emission.

In v1 the Connect action creates a stub connection (no real OAuth; no
``encrypted_credentials`` populated). Real adapters land in a later journey;
the contract is set so the wiring doesn't change when they do.

Single-connection mode (default): one row per (user, instance). Multi-connection
mode (per ``IntegrationInstance.multi_connection_allowed``) allows multiple
seq values — v1 UI does not surface this; the data model is ready.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from lehen_hub.auth.dependencies import CurrentUser
from lehen_hub.storage.arcade import ArcadeClient


class ConnectionAlreadyExistsError(ValueError):
    """User already has an active connection for this single-connection instance."""


class ConnectionNotFoundError(LookupError):
    """No active connection for the given (user, instance) pair."""


class IntegrationDisabledError(ValueError):
    """The integration instance exists but is disabled — cannot connect."""


_DEFAULT_SEQ = 0
_DEFAULT_PRIVACY_CLASS = "company"


def _connection_id(user_sub: str, instance_id: str, seq: int) -> str:
    return f"{user_sub}:{instance_id}:{seq}"


class UserConnectionsService:
    def __init__(
        self,
        *,
        arcade: ArcadeClient,
        consent_retention_days: int,
    ) -> None:
        self._arcade = arcade
        self._consent_retention_days = consent_retention_days

    async def list_for_user(self, user_sub: str) -> list[dict[str, Any]]:
        rows = await self._arcade.query(
            "SELECT FROM IntegrationConnection "
            "WHERE user_sub = :sub AND disconnected_at IS NULL",
            {"sub": user_sub},
        )
        return [_strip_internals(r) for r in rows]

    async def grant(
        self,
        *,
        user: CurrentUser,
        integration_instance_id: str,
        privacy_class: str = _DEFAULT_PRIVACY_CLASS,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        instance = await self._fetch_instance(integration_instance_id)
        if instance is None:
            raise ConnectionNotFoundError(
                f"integration instance not found: {integration_instance_id}"
            )
        if not instance.get("enabled", False):
            raise IntegrationDisabledError(
                f"integration instance is disabled: {integration_instance_id}"
            )

        multi = bool(instance.get("multi_connection_allowed", False))
        if not multi:
            existing = await self._arcade.query(
                "SELECT FROM IntegrationConnection "
                "WHERE user_sub = :sub AND integration_instance_id = :id "
                "AND disconnected_at IS NULL",
                {"sub": user.sub, "id": integration_instance_id},
            )
            if existing:
                raise ConnectionAlreadyExistsError(
                    f"user already has an active connection to {integration_instance_id}; "
                    "disconnect first or enable multi_connection_allowed on the instance"
                )
            seq = _DEFAULT_SEQ
        else:
            seq = await self._next_seq(user.sub, integration_instance_id)

        now = datetime.now(UTC)
        conn_id = _connection_id(user.sub, integration_instance_id, seq)
        connection_doc = {
            "id": conn_id,
            "user_sub": user.sub,
            "username": user.username,
            "integration_instance_id": integration_instance_id,
            "connection_seq": seq,
            "privacy_class": privacy_class,
            "encrypted_credentials": None,
            "status": "stub-connected",
            "connected_at": now.isoformat(),
            "disconnected_at": None,
            "last_health_status": None,
            "last_health_check_at": None,
        }
        # connection_doc is fully validated above — JSON literal embed is safe.
        await self._arcade.command(
            f"INSERT INTO IntegrationConnection CONTENT {json.dumps(connection_doc)}"
        )

        await self._record_consent(
            user=user,
            action="granted",
            integration_instance_id=integration_instance_id,
            connection_seq=seq,
            privacy_class=privacy_class,
            request_id=request_id,
            now=now,
        )
        return _strip_internals(connection_doc)

    async def revoke(
        self,
        *,
        user: CurrentUser,
        integration_instance_id: str,
        request_id: str | None = None,
    ) -> None:
        active = await self._arcade.query(
            "SELECT FROM IntegrationConnection "
            "WHERE user_sub = :sub AND integration_instance_id = :id "
            "AND disconnected_at IS NULL",
            {"sub": user.sub, "id": integration_instance_id},
        )
        if not active:
            raise ConnectionNotFoundError(
                f"no active connection for ({user.sub}, {integration_instance_id})"
            )

        now = datetime.now(UTC)
        for row in active:
            await self._arcade.command(
                "UPDATE IntegrationConnection SET status = 'disconnected', "
                "disconnected_at = :ts WHERE id = :id",
                {"ts": now.isoformat(), "id": row["id"]},
            )
            await self._record_consent(
                user=user,
                action="revoked",
                integration_instance_id=integration_instance_id,
                connection_seq=int(row.get("connection_seq", 0)),
                privacy_class=str(row.get("privacy_class", _DEFAULT_PRIVACY_CLASS)),
                request_id=request_id,
                now=now,
            )

    async def _fetch_instance(self, instance_id: str) -> dict[str, Any] | None:
        rows = await self._arcade.query(
            "SELECT FROM IntegrationInstance WHERE id = :id",
            {"id": instance_id},
        )
        return rows[0] if rows else None

    async def _next_seq(self, user_sub: str, instance_id: str) -> int:
        rows = await self._arcade.query(
            "SELECT max(connection_seq) AS m FROM IntegrationConnection "
            "WHERE user_sub = :sub AND integration_instance_id = :id",
            {"sub": user_sub, "id": instance_id},
        )
        if not rows or rows[0].get("m") is None:
            return _DEFAULT_SEQ
        return int(rows[0]["m"]) + 1

    async def _record_consent(
        self,
        *,
        user: CurrentUser,
        action: str,
        integration_instance_id: str,
        connection_seq: int,
        privacy_class: str,
        request_id: str | None,
        now: datetime,
    ) -> None:
        retain_until = now + timedelta(days=self._consent_retention_days)
        doc = {
            "id": str(uuid.uuid4()),
            "ts": now.isoformat(),
            "user_sub": user.sub,
            "username": user.username,
            "action": action,
            "integration_instance_id": integration_instance_id,
            "connection_seq": connection_seq,
            "privacy_class": privacy_class,
            "request_id": request_id or str(uuid.uuid4()),
            "retain_until": retain_until.isoformat(),
        }
        # doc dict is fully validated above; JSON literal embed is safe.
        await self._arcade.command(
            f"INSERT INTO ConsentEvent CONTENT {json.dumps(doc)}"
        )


def _strip_internals(doc: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in doc.items() if not k.startswith("@")}
