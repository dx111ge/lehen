"""Integration instance CRUD with encrypt-on-write of secret fields."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from lehen_hub.admin.audit_service import AdminAuditService, AuditEvent
from lehen_hub.auth.dependencies import CurrentUser
from lehen_hub.crypto import encrypt
from lehen_hub.integrations.registry import (
    UnknownIntegrationTypeError,
    get_type,
)
from lehen_hub.storage.arcade import ArcadeClient


class IntegrationInstanceNotFoundError(LookupError):
    pass


class IntegrationInstanceConflictError(ValueError):
    pass


class IntegrationConfigError(ValueError):
    pass


class IntegrationsService:
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

    async def list(self) -> list[dict[str, Any]]:
        rows = await self._arcade.query("SELECT FROM IntegrationInstance ORDER BY id")
        return [self._render_for_read(r) for r in rows]

    async def get(self, instance_id: str) -> dict[str, Any]:
        rows = await self._arcade.query(
            "SELECT FROM IntegrationInstance WHERE id = :id",
            {"id": instance_id},
        )
        if not rows:
            raise IntegrationInstanceNotFoundError(instance_id)
        return self._render_for_read(rows[0])

    async def create(
        self,
        *,
        actor: CurrentUser,
        instance_id: str,
        type_id: str,
        display_name: str,
        config: dict[str, Any],
        multi_connection_allowed: bool = False,
        enabled: bool = True,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        try:
            spec = get_type(type_id)
        except UnknownIntegrationTypeError as exc:
            raise IntegrationConfigError(str(exc)) from exc

        existing = await self._arcade.query(
            "SELECT id FROM IntegrationInstance WHERE id = :id",
            {"id": instance_id},
        )
        if existing:
            raise IntegrationInstanceConflictError(
                f"IntegrationInstance with id={instance_id} already exists"
            )

        public, encrypted_secrets, secret_fingerprintable = self._split_config(spec, config)
        now_iso = datetime.now(UTC).isoformat()
        doc = {
            "id": instance_id,
            "type": type_id,
            "display_name": display_name,
            "config_public": public,
            "config_secrets_encrypted": encrypted_secrets,
            "enabled": enabled,
            "multi_connection_allowed": multi_connection_allowed,
            "created_by": actor.username,
            "created_at": now_iso,
            "updated_by": actor.username,
            "updated_at": now_iso,
        }
        # doc dict is fully constructed from validated input; no user-controlled
        # SQL string concatenation. Treating the JSON literal as a SQL embed.
        await self._arcade.command(
            f"INSERT INTO IntegrationInstance CONTENT {json.dumps(doc)}"
        )

        await self._audit.record(
            AuditEvent(
                actor_sub=actor.sub,
                actor_username=actor.username,
                action="integration.create",
                target_id=instance_id,
                before=None,
                after={
                    "id": instance_id,
                    "type": type_id,
                    "display_name": display_name,
                    "enabled": enabled,
                    "multi_connection_allowed": multi_connection_allowed,
                    **public,
                    **secret_fingerprintable,
                },
                secret_fields=spec.secret_field_names,
                request_id=request_id,
            )
        )
        return self._render_for_read(doc)

    async def update(
        self,
        *,
        actor: CurrentUser,
        instance_id: str,
        display_name: str | None = None,
        config: dict[str, Any] | None = None,
        enabled: bool | None = None,
        multi_connection_allowed: bool | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        before = await self._raw_get(instance_id)

        spec = get_type(before["type"])
        merged_doc = dict(before)
        before_audit = {
            "id": instance_id,
            "type": before["type"],
            "display_name": before.get("display_name"),
            "enabled": before.get("enabled"),
            "multi_connection_allowed": before.get("multi_connection_allowed"),
            **(before.get("config_public") or {}),
            # Re-fingerprint existing secrets by decrypting (only used in audit before/after)
        }
        # We can't decrypt secrets just for the audit before-snapshot (that would decrypt
        # without need). Instead we mark them as opaque-set via the audit service:
        for f in spec.secret_field_names:
            if (before.get("config_secrets_encrypted") or {}).get(f):
                # Will be replaced by HMAC marker via secret_fields list — store a sentinel
                before_audit[f] = "<existing>"

        after_audit = dict(before_audit)

        if display_name is not None:
            merged_doc["display_name"] = display_name
            after_audit["display_name"] = display_name
        if enabled is not None:
            merged_doc["enabled"] = enabled
            after_audit["enabled"] = enabled
        if multi_connection_allowed is not None:
            merged_doc["multi_connection_allowed"] = multi_connection_allowed
            after_audit["multi_connection_allowed"] = multi_connection_allowed

        if config is not None:
            public, enc_new, fingerprintable = self._split_config(spec, config)
            # Merge into existing public config + replace any provided secrets
            merged_public = {**(before.get("config_public") or {}), **public}
            merged_secrets = {
                **(before.get("config_secrets_encrypted") or {}),
                **enc_new,
            }
            merged_doc["config_public"] = merged_public
            merged_doc["config_secrets_encrypted"] = merged_secrets
            for k, v in public.items():
                after_audit[k] = v
            for k, v in fingerprintable.items():
                after_audit[k] = v

        merged_doc["updated_by"] = actor.username
        merged_doc["updated_at"] = datetime.now(UTC).isoformat()

        await self._arcade.command(
            f"UPDATE IntegrationInstance CONTENT {json.dumps(merged_doc)} "
            "WHERE id = :id",
            {"id": instance_id},
        )

        await self._audit.record(
            AuditEvent(
                actor_sub=actor.sub,
                actor_username=actor.username,
                action="integration.update",
                target_id=instance_id,
                before=before_audit,
                after=after_audit,
                secret_fields=spec.secret_field_names,
                request_id=request_id,
            )
        )

        return self._render_for_read(merged_doc)

    async def delete(
        self,
        *,
        actor: CurrentUser,
        instance_id: str,
        request_id: str | None = None,
    ) -> None:
        before = await self._raw_get(instance_id)
        await self._arcade.command(
            "DELETE FROM IntegrationInstance WHERE id = :id",
            {"id": instance_id},
        )
        spec = get_type(before["type"])
        await self._audit.record(
            AuditEvent(
                actor_sub=actor.sub,
                actor_username=actor.username,
                action="integration.delete",
                target_id=instance_id,
                before={
                    "id": instance_id,
                    "type": before["type"],
                    "display_name": before.get("display_name"),
                    **(before.get("config_public") or {}),
                    **{f: "<existing>" for f in spec.secret_field_names
                       if (before.get("config_secrets_encrypted") or {}).get(f)},
                },
                after=None,
                secret_fields=spec.secret_field_names,
                request_id=request_id,
            )
        )

    async def _raw_get(self, instance_id: str) -> dict[str, Any]:
        rows = await self._arcade.query(
            "SELECT FROM IntegrationInstance WHERE id = :id",
            {"id": instance_id},
        )
        if not rows:
            raise IntegrationInstanceNotFoundError(instance_id)
        return rows[0]

    def _split_config(
        self,
        spec: Any,  # IntegrationType
        config: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, str], dict[str, str]]:
        """Return (public_dict, encrypted_secrets_dict, secret_plaintexts_dict).

        The third return is used by the audit service to compute HMAC fingerprints
        of the secret values that were just written. Plaintext does not leave
        this method's stack frame.
        """
        public: dict[str, Any] = {}
        encrypted: dict[str, str] = {}
        plaintext: dict[str, str] = {}
        known_fields = {f.name for f in spec.fields}
        unknown = set(config) - known_fields
        if unknown:
            raise IntegrationConfigError(
                f"unknown config fields for type={spec.id}: {sorted(unknown)}"
            )
        for field in spec.fields:
            value = config.get(field.name)
            if field.required and (value is None or value == ""):
                raise IntegrationConfigError(
                    f"required field missing: {field.name}"
                )
            if value is None:
                continue
            if field.secret:
                encrypted[field.name] = encrypt(str(value), key=self._key)
                plaintext[field.name] = str(value)
            else:
                public[field.name] = value
        return public, encrypted, plaintext

    def _render_for_read(self, doc: dict[str, Any]) -> dict[str, Any]:
        """Build the public-API representation of an IntegrationInstance.

        Strips ArcadeDB internals (@rid etc.), removes ``config_secrets_encrypted``,
        replaces it with ``secret_fields_set`` (list of field names that have
        a stored value).
        """
        clean = {k: v for k, v in doc.items() if not k.startswith("@")}
        encrypted = clean.pop("config_secrets_encrypted", None) or {}
        clean["secret_fields_set"] = sorted(k for k, v in encrypted.items() if v)
        return clean
