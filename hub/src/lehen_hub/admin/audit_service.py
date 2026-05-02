"""Admin audit service.

Append-only writer + paginated reader for ``AdminAuditEvent``. Renders any
``before/after`` fields that are flagged as secrets via HMAC fingerprint
keyed by the audit pepper (A12) — never plaintext, never the same as the
encryption key.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from lehen_hub.crypto import fingerprint
from lehen_hub.storage.arcade import ArcadeClient


@dataclass(frozen=True)
class AuditEvent:
    """An admin-side mutation worth recording."""

    actor_sub: str
    actor_username: str
    action: str  # e.g. "llm.update", "integration.create", "siam.update"
    target_id: str | None
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    secret_fields: tuple[str, ...] = ()
    request_id: str | None = None


class AdminAuditService:
    """One instance per app, held on ``app.state.admin_audit``."""

    def __init__(self, *, arcade: ArcadeClient, audit_pepper: bytes) -> None:
        self._arcade = arcade
        self._pepper = audit_pepper

    async def record(self, event: AuditEvent) -> None:
        doc = {
            "id": str(uuid.uuid4()),
            "ts": datetime.now(UTC).isoformat(),
            "actor_sub": event.actor_sub,
            "actor_username": event.actor_username,
            "action": event.action,
            "target_id": event.target_id,
            "before": self._mask_secrets(event.before, event.secret_fields),
            "after": self._mask_secrets(event.after, event.secret_fields),
            "request_id": event.request_id or str(uuid.uuid4()),
        }
        await self._arcade.command(f"INSERT INTO AdminAuditEvent CONTENT {json.dumps(doc)}")

    async def list_recent(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        # int() coercion already in place; values are bound + bounded by the
        # router via Query(..., ge/le). Adding noqa for ArcadeDB SQL where
        # parameter bindings for SKIP/LIMIT aren't reliably supported.
        return await self._arcade.query(
            f"SELECT FROM AdminAuditEvent ORDER BY ts DESC SKIP {int(offset)} LIMIT {int(limit)}"
        )

    def _mask_secrets(
        self,
        doc: dict[str, Any] | None,
        secret_fields: tuple[str, ...],
    ) -> dict[str, Any] | None:
        if doc is None:
            return None
        if not secret_fields:
            return dict(doc)
        out: dict[str, Any] = {}
        for k, v in doc.items():
            if k in secret_fields:
                out[k] = self._mark_secret(v)
            else:
                out[k] = v
        return out

    def _mark_secret(self, value: Any) -> dict[str, Any]:
        if value is None or value == "":
            return {"is_set": False, "hmac": None}
        return {
            "is_set": True,
            "hmac": fingerprint(str(value), pepper=self._pepper),
        }
