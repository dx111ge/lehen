"""SIAM mapping service — singleton role→integrations allowlist.

On ``replace``, runs the SIAM-cascade revoke hook (Sprint 2 Phase 2.5):
when a role's instance allowlist shrinks (or an instance becomes unmapped
entirely), every active connection that's no longer authorized by the new
mapping is revoked, credentials wiped, ``ConsentEvent`` recorded with
``action="revoked-by-siam-change"``."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from lehen_hub.admin.audit_service import AdminAuditService, AuditEvent
from lehen_hub.auth.dependencies import CurrentUser
from lehen_hub.storage.arcade import ArcadeClient

_SIAM_ID = "default"

# Callback shape for the SIAM cascade hook. Called with the previous and new
# mappings and the request id. Returns the number of connections revoked.
SIAMCascadeHook = Callable[
    [dict[str, list[str]], dict[str, list[str]], str | None], Awaitable[int]
]


class SIAMService:
    def __init__(
        self,
        *,
        arcade: ArcadeClient,
        audit: AdminAuditService,
        cascade: SIAMCascadeHook | None = None,
    ) -> None:
        self._arcade = arcade
        self._audit = audit
        self._cascade = cascade

    def set_cascade(self, cascade: SIAMCascadeHook) -> None:
        """Late-binding setter; ``main.lifespan`` wires this to
        ``UserConnectionsService.revoke_for_users_no_longer_authorized``."""
        self._cascade = cascade

    async def get(self) -> dict[str, list[str]]:
        """Return the role→[instance_id, ...] mapping. Empty dict if not yet set."""
        rows = await self._arcade.query(
            f"SELECT FROM SIAMMapping WHERE id = '{_SIAM_ID}'"
        )
        if not rows:
            return {}
        mapping = rows[0].get("mapping") or {}
        return _normalize(mapping)

    async def replace(
        self,
        *,
        actor: CurrentUser,
        mapping: dict[str, list[str]],
        request_id: str | None = None,
    ) -> dict[str, list[str]]:
        before = await self.get()
        normalized = _normalize(mapping)
        now_iso = datetime.now(UTC).isoformat()
        doc = {
            "id": _SIAM_ID,
            "mapping": normalized,
            "updated_by": actor.username,
            "updated_at": now_iso,
        }
        existing = await self._arcade.query(
            "SELECT id FROM SIAMMapping WHERE id = :id",
            {"id": _SIAM_ID},
        )
        if existing:
            # doc is fully validated above; treat JSON as a constant SQL embed.
            await self._arcade.command(
                f"UPDATE SIAMMapping CONTENT {json.dumps(doc)} WHERE id = :id",
                {"id": _SIAM_ID},
            )
        else:
            await self._arcade.command(
                f"INSERT INTO SIAMMapping CONTENT {json.dumps(doc)}"
            )

        after = await self.get()
        await self._audit.record(
            AuditEvent(
                actor_sub=actor.sub,
                actor_username=actor.username,
                action="siam.update",
                target_id=_SIAM_ID,
                before={"mapping": before},
                after={"mapping": after},
                request_id=request_id,
            )
        )
        if self._cascade is not None and before != after:
            await self._cascade(before, after, request_id)
        return after


def _normalize(mapping: Any) -> dict[str, list[str]]:
    """Coerce + alphabetically sort the lists for deterministic output (A10)."""
    if not isinstance(mapping, dict):
        return {}
    out: dict[str, list[str]] = {}
    for role, ids in mapping.items():
        if not isinstance(ids, list):
            continue
        clean = sorted({str(x) for x in ids if isinstance(x, str)})
        out[str(role)] = clean
    return dict(sorted(out.items()))
