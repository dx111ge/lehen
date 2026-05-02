"""SIAM mapping service — singleton role→integrations allowlist."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from lehen_hub.admin.audit_service import AdminAuditService, AuditEvent
from lehen_hub.auth.dependencies import CurrentUser
from lehen_hub.storage.arcade import ArcadeClient

_SIAM_ID = "default"


class SIAMService:
    def __init__(self, *, arcade: ArcadeClient, audit: AdminAuditService) -> None:
        self._arcade = arcade
        self._audit = audit

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
