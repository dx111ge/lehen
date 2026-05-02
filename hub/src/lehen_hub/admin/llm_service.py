"""LLMConfig service.

Singleton row read/update with audit. Inference and embedding sides are
configured independently; each side picks a provider from the LLM provider
registry and supplies the fields that provider declares.

API keys (the only ``secret=True`` field type today) are encrypted with
the master key at write, never returned in plaintext on read, and rendered
as HMAC fingerprints in the audit log (A12).

The DB document keeps a flat shape for backward compatibility with the
existing seed. Service GET returns a structured shape that the admin UI
renders directly:

    {
      "inference": {"provider": "...", "model": "...", "base_url": "...",
                    "api_key_set": bool},
      "embedding": {... same shape},
      "updated_by": "...",
      "updated_at": "..."
    }
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from lehen_hub.admin.audit_service import AdminAuditService, AuditEvent
from lehen_hub.auth.dependencies import CurrentUser
from lehen_hub.crypto import encrypt
from lehen_hub.llm.providers import (
    LLMProvider,
    UnknownLLMProviderError,
    get_provider,
)
from lehen_hub.storage.arcade import ArcadeClient

_LLM_CONFIG_ID = "default"

_SIDES = ("inference", "embedding")


class LLMConfigNotFoundError(LookupError):
    """LLMConfig singleton is missing — bootstrap probably hasn't run."""


class LLMConfigError(ValueError):
    """Validation error against the provider registry."""


class LLMService:
    def __init__(
        self,
        *,
        arcade: ArcadeClient,
        audit: AdminAuditService,
        master_key: bytes,
    ) -> None:
        self._arcade = arcade
        self._audit = audit
        self._key = master_key

    async def get(self) -> dict[str, Any]:
        rows = await self._arcade.query(
            f"SELECT FROM LLMConfig WHERE id = '{_LLM_CONFIG_ID}'"
        )
        if not rows:
            raise LLMConfigNotFoundError("LLMConfig singleton missing — has bootstrap run?")
        raw = rows[0]
        return _render_for_read(raw)

    async def update(
        self,
        *,
        actor: CurrentUser,
        inference: dict[str, Any] | None,
        embedding: dict[str, Any] | None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """Replace inference and/or embedding configuration. Either side
        is optional; if absent, the existing values for that side are kept.

        Each side payload is shaped: {provider, ...provider-fields...}.
        Public fields go to inference_*/embedding_*; secret fields are
        AES-256-GCM-encrypted into ``*_secrets_encrypted`` and never echoed
        back. To unset an api key, send ``api_key=""``.
        """
        if inference is None and embedding is None:
            raise LLMConfigError("nothing to update")

        before_raw = await self._raw_get()
        # Strip ArcadeDB-internal fields (@rid, @type, ...) — they cannot
        # be part of an UPDATE ... CONTENT body.
        merged = {k: v for k, v in before_raw.items() if not k.startswith("@")}
        merged["id"] = _LLM_CONFIG_ID

        before_audit: dict[str, Any] = _audit_view(before_raw)
        after_audit: dict[str, Any] = dict(before_audit)
        secret_audit_fields: list[str] = []

        if inference is not None:
            self._apply_side(
                merged=merged,
                after_audit=after_audit,
                secret_audit_fields=secret_audit_fields,
                side="inference",
                payload=inference,
            )
        if embedding is not None:
            self._apply_side(
                merged=merged,
                after_audit=after_audit,
                secret_audit_fields=secret_audit_fields,
                side="embedding",
                payload=embedding,
            )

        merged["updated_by"] = actor.username
        merged["updated_at"] = datetime.now(UTC).isoformat()

        await self._arcade.command(
            f"UPDATE LLMConfig CONTENT {json.dumps(merged)} WHERE id = :id",
            {"id": _LLM_CONFIG_ID},
        )

        await self._audit.record(
            AuditEvent(
                actor_sub=actor.sub,
                actor_username=actor.username,
                action="llm.update",
                target_id=_LLM_CONFIG_ID,
                before=before_audit,
                after=after_audit,
                secret_fields=tuple(secret_audit_fields),
                request_id=request_id,
            )
        )
        return _render_for_read(await self._raw_get())

    async def _raw_get(self) -> dict[str, Any]:
        rows = await self._arcade.query(
            f"SELECT FROM LLMConfig WHERE id = '{_LLM_CONFIG_ID}'"
        )
        if not rows:
            raise LLMConfigNotFoundError("LLMConfig singleton missing")
        return rows[0]

    def _apply_side(
        self,
        *,
        merged: dict[str, Any],
        after_audit: dict[str, Any],
        secret_audit_fields: list[str],
        side: str,
        payload: dict[str, Any],
    ) -> None:
        provider = self._resolve_provider(side, payload)
        self._validate_payload_keys(side, provider, payload)
        self._validate_required_fields(side, provider, payload, merged)
        self._apply_fields(
            merged=merged,
            after_audit=after_audit,
            secret_audit_fields=secret_audit_fields,
            side=side,
            provider=provider,
            payload=payload,
        )

    @staticmethod
    def _resolve_provider(side: str, payload: dict[str, Any]) -> LLMProvider:
        provider_id = payload.get("provider")
        if not provider_id:
            raise LLMConfigError(f"{side}.provider is required")
        try:
            return get_provider(str(provider_id))
        except UnknownLLMProviderError as exc:
            raise LLMConfigError(str(exc)) from exc

    @staticmethod
    def _validate_payload_keys(
        side: str, provider: LLMProvider, payload: dict[str, Any]
    ) -> None:
        known = {f.name for f in provider.fields} | {"provider"}
        unknown = set(payload) - known
        if unknown:
            raise LLMConfigError(
                f"{side}: unknown fields for provider={provider.id}: {sorted(unknown)}"
            )

    @staticmethod
    def _validate_required_fields(
        side: str,
        provider: LLMProvider,
        payload: dict[str, Any],
        merged: dict[str, Any],
    ) -> None:
        for field in provider.fields:
            if not field.required:
                continue
            value = payload.get(field.name)
            if value not in (None, ""):
                continue
            # api_key counts as required only if no value is already stored
            if field.secret and merged.get(f"{side}_{field.name}_encrypted"):
                continue
            raise LLMConfigError(
                f"{side}: required field '{field.name}' is missing "
                f"for provider={provider.id}"
            )

    def _apply_fields(
        self,
        *,
        merged: dict[str, Any],
        after_audit: dict[str, Any],
        secret_audit_fields: list[str],
        side: str,
        provider: LLMProvider,
        payload: dict[str, Any],
    ) -> None:
        merged[f"{side}_provider"] = provider.id
        after_audit[f"{side}_provider"] = provider.id
        for field in provider.fields:
            value = payload.get(field.name)
            if field.secret:
                self._apply_secret_field(
                    merged=merged,
                    after_audit=after_audit,
                    secret_audit_fields=secret_audit_fields,
                    side=side,
                    field_name=field.name,
                    value=value,
                )
            else:
                cleaned = "" if value is None or value == "" else value
                merged[f"{side}_{field.name}"] = cleaned
                after_audit[f"{side}_{field.name}"] = cleaned

    def _apply_secret_field(
        self,
        *,
        merged: dict[str, Any],
        after_audit: dict[str, Any],
        secret_audit_fields: list[str],
        side: str,
        field_name: str,
        value: Any,
    ) -> None:
        # value=="" → explicit clear. value is None → not provided, keep existing.
        if value is None:
            return
        if value == "":
            merged[f"{side}_{field_name}_encrypted"] = None
            after_audit[f"{side}_{field_name}"] = ""
        else:
            merged[f"{side}_{field_name}_encrypted"] = encrypt(str(value), key=self._key)
            after_audit[f"{side}_{field_name}"] = str(value)
        secret_audit_fields.append(f"{side}_{field_name}")


def _render_for_read(raw: dict[str, Any]) -> dict[str, Any]:
    """Build the structured admin-API view from a flat DB row."""
    out: dict[str, Any] = {
        "inference": _render_side(raw, "inference"),
        "embedding": _render_side(raw, "embedding"),
        "updated_by": raw.get("updated_by"),
        "updated_at": raw.get("updated_at"),
    }
    return out


def _render_side(raw: dict[str, Any], side: str) -> dict[str, Any]:
    side_obj: dict[str, Any] = {"provider": raw.get(f"{side}_provider")}
    # Carry through every public field for whichever provider is set, so the
    # UI can pick what's relevant. Secrets are reported as a presence bool only.
    provider_id = raw.get(f"{side}_provider")
    if provider_id:
        try:
            provider = get_provider(str(provider_id))
        except UnknownLLMProviderError:
            provider = None
        if provider:
            for field in provider.fields:
                if field.secret:
                    encrypted = raw.get(f"{side}_{field.name}_encrypted")
                    side_obj[f"{field.name}_set"] = bool(encrypted)
                else:
                    side_obj[field.name] = raw.get(f"{side}_{field.name}", "")
            return side_obj

    # Fallback for unknown / legacy rows: surface what we have, no secrets.
    side_obj["model"] = raw.get(f"{side}_model", "")
    side_obj["base_url"] = raw.get(f"{side}_base_url", "")
    return side_obj


def _audit_view(raw: dict[str, Any]) -> dict[str, Any]:
    """Audit `before` view of the row — no secrets, just public fields."""
    out: dict[str, Any] = {
        "inference_provider": raw.get("inference_provider"),
        "embedding_provider": raw.get("embedding_provider"),
    }
    for side in _SIDES:
        provider_id = raw.get(f"{side}_provider")
        if not provider_id:
            continue
        try:
            provider = get_provider(str(provider_id))
        except UnknownLLMProviderError:
            continue
        for field in provider.fields:
            if field.secret:
                # Marker that something is/was set; the audit-service will
                # render this as the HMAC-fingerprint of "<existing>".
                if raw.get(f"{side}_{field.name}_encrypted"):
                    out[f"{side}_{field.name}"] = "<existing>"
            else:
                out[f"{side}_{field.name}"] = raw.get(f"{side}_{field.name}", "")
    return out
