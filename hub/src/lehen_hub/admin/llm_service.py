"""LLMConfig service — singleton row read/update with audit."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from lehen_hub.admin.audit_service import AdminAuditService, AuditEvent
from lehen_hub.auth.dependencies import CurrentUser
from lehen_hub.storage.arcade import ArcadeClient

_LLM_CONFIG_ID = "default"

_UPDATABLE_FIELDS: frozenset[str] = frozenset(
    {
        "inference_provider",
        "inference_model",
        "inference_base_url",
        "embedding_provider",
        "embedding_model",
        "embedding_base_url",
    }
)


class LLMConfigNotFoundError(LookupError):
    """LLMConfig singleton is missing — bootstrap probably hasn't run."""


class LLMService:
    def __init__(self, *, arcade: ArcadeClient, audit: AdminAuditService) -> None:
        self._arcade = arcade
        self._audit = audit

    async def get(self) -> dict[str, Any]:
        rows = await self._arcade.query(
            f"SELECT FROM LLMConfig WHERE id = '{_LLM_CONFIG_ID}'"
        )
        if not rows:
            raise LLMConfigNotFoundError("LLMConfig singleton missing — has bootstrap run?")
        return _strip_arcade_internals(rows[0])

    async def update(
        self,
        *,
        actor: CurrentUser,
        new_values: dict[str, Any],
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """Replace the updatable fields of the singleton. Unknown keys are rejected."""
        unknown = set(new_values) - _UPDATABLE_FIELDS
        if unknown:
            raise ValueError(f"unknown LLMConfig fields: {sorted(unknown)}")

        before = await self.get()

        merged = {**before, **new_values}
        merged["updated_by"] = actor.username
        merged["updated_at"] = datetime.now(UTC).isoformat()
        merged["id"] = _LLM_CONFIG_ID

        # merged is fully validated above; treat JSON as a constant SQL embed.
        await self._arcade.command(
            f"UPDATE LLMConfig CONTENT {json.dumps(merged)} WHERE id = :id",
            {"id": _LLM_CONFIG_ID},
        )

        after = await self.get()
        await self._audit.record(
            AuditEvent(
                actor_sub=actor.sub,
                actor_username=actor.username,
                action="llm.update",
                target_id=_LLM_CONFIG_ID,
                before=before,
                after=after,
                request_id=request_id,
            )
        )
        return after


def _strip_arcade_internals(row: dict[str, Any]) -> dict[str, Any]:
    """ArcadeDB returns @rid, @type etc. Strip those for public response shape."""
    return {k: v for k, v in row.items() if not k.startswith("@")}
