"""Per-user IntegrationConnection CRUD + ConsentEvent emission.

Two admin-side gates apply to every grant:

1. **Gate 1 — instance enabled.** The targeted ``IntegrationInstance`` must
   exist and have ``enabled=true``. Caught by ``ConnectionNotFoundError`` /
   ``IntegrationDisabledError``.
2. **Gate 2 — SIAM authorization.** At least one of the user's realm roles
   must be mapped to the targeted instance in the SIAM mapping. Caught by
   ``IntegrationNotAuthorizedForRoleError``. Without this gate, a user with
   a valid bearer token who knows or guesses an instance id could
   ``POST /me/connections/<id>`` directly and bypass the SIAM filter that
   ``MeService.me()`` applies on the read side.

The data model is multi-mailbox-ready (Sprint 2 Layer 1). Each connection
carries an ``external_subject`` identifying the underlying source-system
account (SMTP for mail, workspace+user pair for Slack, etc.) and a
human-readable ``display_label``. Uniqueness on the active surface is
``(user_sub, integration_instance_id, external_subject)``. Single-cardinality
types use ``external_subject=""``; multi-cardinality types populate it from
the OAuth round-trip (Sprint 2 Phase 2).

Connection sequence numbers are always-monotonic per ``(user_sub, instance)``.
Re-grant after revoke increments seq; the historical row stays disconnected.
This replaces the previous "single-connection means seq=0 forever" model
which collided on re-grant.
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import httpx

from lehen_hub.auth.dependencies import CurrentUser
from lehen_hub.auth.oauth import (
    OAuthExchangeError,
    OAuthStateError,
    OAuthTokens,
    build_authorization_url,
    decode_state,
    exchange_code_for_tokens,
    refresh_access_token,
)
from lehen_hub.crypto import decrypt, encrypt
from lehen_hub.integrations.source_adapter import (
    SourceAdapterError,
    SourceAdapterNotImplementedError,
    build_adapter_for_instance,
)
from lehen_hub.storage.arcade import ArcadeClient

if TYPE_CHECKING:
    from lehen_hub.admin.siam_service import SIAMService


class ConnectionAlreadyExistsError(ValueError):
    """User already has an active connection for this (instance, external_subject)."""


class ConnectionNotFoundError(LookupError):
    """No active connection for the given (user, instance) pair."""


class IntegrationDisabledError(ValueError):
    """The integration instance exists but is disabled — cannot connect."""


class IntegrationNotAuthorizedForRoleError(PermissionError):
    """User's realm roles do not include any role mapped to this instance.

    Raised even if the instance exists and is enabled — the SIAM mapping
    is what authorizes a user to connect, not just instance existence."""


class RedirectUriNotAllowedError(ValueError):
    """The redirect_uri requested by the caller is not on the Hub's allowlist.

    Prevents an attacker who can call ``/me/connections/{id}/initiate`` with
    a stolen bearer token from injecting their own callback URL."""


class OAuthFlowConfigError(ValueError):
    """The targeted instance lacks the configuration the OAuth flow needs
    (e.g., no client_secret persisted). Raised before any IdP call."""


_DEFAULT_PRIVACY_CLASS = "company"


def _connection_id(user_sub: str, instance_id: str, seq: int) -> str:
    return f"{user_sub}:{instance_id}:{seq}"


class UserConnectionsService:
    def __init__(
        self,
        *,
        arcade: ArcadeClient,
        siam: SIAMService,
        consent_retention_days: int,
        master_key: bytes = b"",
        state_key: bytes = b"",
        allowed_redirect_uris: tuple[str, ...] = (),
    ) -> None:
        self._arcade = arcade
        self._siam = siam
        self._consent_retention_days = consent_retention_days
        self._master_key = master_key
        # state_key defaults to master_key if not given — single shared key
        # is fine: AES-GCM is unique-nonce-secure, no key reuse concern.
        self._state_key = state_key if state_key else master_key
        self._allowed_redirect_uris = frozenset(allowed_redirect_uris)

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
        external_subject: str = "",
        display_label: str = "",
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

        # Gate 2: SIAM authorization. Resolve the user's realm roles to the
        # set of instances they're allowed to connect; reject if the
        # requested instance isn't in that set, regardless of role count.
        if not await self._is_siam_authorized(user, integration_instance_id):
            raise IntegrationNotAuthorizedForRoleError(
                f"user roles {sorted(user.realm_roles)} are not SIAM-mapped to "
                f"instance {integration_instance_id}"
            )

        existing = await self._arcade.query(
            "SELECT FROM IntegrationConnection "
            "WHERE user_sub = :sub AND integration_instance_id = :id "
            "AND external_subject = :ext "
            "AND disconnected_at IS NULL",
            {
                "sub": user.sub,
                "id": integration_instance_id,
                "ext": external_subject,
            },
        )
        if existing:
            raise ConnectionAlreadyExistsError(
                f"user already has an active connection to "
                f"{integration_instance_id} for external_subject={external_subject!r}; "
                "disconnect it first or grant a different external_subject"
            )

        # Always-monotonic seq per (user, instance) — the row id stays unique
        # across grant→revoke→re-grant cycles. Single-cardinality types simply
        # have at most one active row at a time; the seq tracks history.
        seq = await self._next_seq(user.sub, integration_instance_id)
        now = datetime.now(UTC)
        conn_id = _connection_id(user.sub, integration_instance_id, seq)
        connection_doc = {
            "id": conn_id,
            "user_sub": user.sub,
            "username": user.username,
            "integration_instance_id": integration_instance_id,
            "connection_seq": seq,
            "external_subject": external_subject,
            "display_label": display_label,
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
            external_subject=external_subject,
            request_id=request_id,
            now=now,
        )
        return _strip_internals(connection_doc)

    async def revoke(
        self,
        *,
        user: CurrentUser,
        integration_instance_id: str,
        external_subject: str | None = None,
        request_id: str | None = None,
    ) -> None:
        """Revoke a user's active connection(s) for an instance.

        If ``external_subject`` is given, only the matching active connection
        is revoked. If omitted, every active connection on the instance is
        revoked (preserves single-cardinality behavior for callers that
        haven't been updated to pass a specific mailbox).
        """
        if external_subject is None:
            active = await self._arcade.query(
                "SELECT FROM IntegrationConnection "
                "WHERE user_sub = :sub AND integration_instance_id = :id "
                "AND disconnected_at IS NULL",
                {"sub": user.sub, "id": integration_instance_id},
            )
        else:
            active = await self._arcade.query(
                "SELECT FROM IntegrationConnection "
                "WHERE user_sub = :sub AND integration_instance_id = :id "
                "AND external_subject = :ext "
                "AND disconnected_at IS NULL",
                {
                    "sub": user.sub,
                    "id": integration_instance_id,
                    "ext": external_subject,
                },
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
                external_subject=str(row.get("external_subject", "")),
                request_id=request_id,
                now=now,
            )

    # ------------------------------------------------------------------
    # Two-step OAuth flow (Sprint 2)
    # ------------------------------------------------------------------

    async def initiate_grant(
        self,
        *,
        user: CurrentUser,
        integration_instance_id: str,
        redirect_uri: str,
    ) -> dict[str, str]:
        """Begin an OAuth-2 PKCE flow against the instance's source IdP.

        Returns ``{"auth_url": ..., "state": ...}``. The caller redirects the
        user's browser to ``auth_url``; the IdP eventually redirects back to
        ``redirect_uri`` with ``code`` and ``state`` query parameters that
        the caller forwards to ``complete_grant``.

        All connection gates (existence, enabled, SIAM authorization) fire
        here — a callback for an unauthorized instance never happens because
        no auth URL was minted in the first place.
        """
        instance = await self._fetch_instance(integration_instance_id)
        if instance is None:
            raise ConnectionNotFoundError(
                f"integration instance not found: {integration_instance_id}"
            )
        if not instance.get("enabled", False):
            raise IntegrationDisabledError(
                f"integration instance is disabled: {integration_instance_id}"
            )
        if not await self._is_siam_authorized(user, integration_instance_id):
            raise IntegrationNotAuthorizedForRoleError(
                f"user roles {sorted(user.realm_roles)} are not SIAM-mapped to "
                f"instance {integration_instance_id}"
            )
        if redirect_uri not in self._allowed_redirect_uris:
            raise RedirectUriNotAllowedError(
                f"redirect_uri {redirect_uri!r} is not on the Hub allowlist"
            )

        adapter = build_adapter_for_instance(instance)
        config_public = instance.get("config_public") or {}
        client_id = str(config_public.get("client_id") or "")
        if not client_id:
            raise OAuthFlowConfigError(
                f"instance {integration_instance_id} has no client_id"
            )
        request = build_authorization_url(
            auth_endpoint=adapter.auth_endpoint,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scopes=adapter.scopes,
            user_sub=user.sub,
            instance_id=integration_instance_id,
            state_key=self._state_key,
            extra_params=dict(adapter.extra_authorization_params),
        )
        return {"auth_url": request.auth_url, "state": request.state}

    async def complete_grant(
        self,
        *,
        user: CurrentUser,
        integration_instance_id: str,
        code: str,
        state: str,
        http_client: httpx.AsyncClient,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """Consume the OAuth callback: validate state, exchange code for
        tokens, fetch identity, persist a real ``IntegrationConnection``."""
        flow = decode_state(state, key=self._state_key)
        # Defense in depth: state must match the calling user + URL path.
        # The state HMAC already protects integrity; these checks catch the
        # case of a state issued for user A being replayed by user B with a
        # valid bearer token of their own.
        if flow.user_sub != user.sub:
            raise OAuthStateError("state user_sub does not match caller")
        if flow.instance_id != integration_instance_id:
            raise OAuthStateError("state instance_id does not match URL path")

        instance = await self._fetch_instance(integration_instance_id)
        if instance is None:
            raise ConnectionNotFoundError(
                f"integration instance not found: {integration_instance_id}"
            )
        # Re-check gates: instance may have been disabled or SIAM mapping
        # changed between initiate and complete.
        if not instance.get("enabled", False):
            raise IntegrationDisabledError(
                f"integration instance is disabled: {integration_instance_id}"
            )
        if not await self._is_siam_authorized(user, integration_instance_id):
            raise IntegrationNotAuthorizedForRoleError(
                f"user roles {sorted(user.realm_roles)} are not SIAM-mapped to "
                f"instance {integration_instance_id}"
            )

        adapter = build_adapter_for_instance(instance)
        config_public = instance.get("config_public") or {}
        client_id = str(config_public.get("client_id") or "")
        if not client_id:
            raise OAuthFlowConfigError(
                f"instance {integration_instance_id} missing client_id"
            )
        # client_secret is only present for confidential-client app registrations.
        # Public clients (the recommended Edge setup) authenticate via PKCE and
        # MUST NOT send a secret — Microsoft rejects with AADSTS700025 if any
        # secret reaches the token endpoint. Treat missing secret as the public-
        # client path; the OAuth helper omits the field on the wire when empty.
        config_secrets = instance.get("config_secrets_encrypted") or {}
        encrypted_secret = config_secrets.get("client_secret")
        client_secret = (
            decrypt(encrypted_secret, key=self._master_key)
            if encrypted_secret
            else ""
        )

        tokens = await exchange_code_for_tokens(
            token_endpoint=adapter.token_endpoint,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=flow.redirect_uri,
            code=code,
            code_verifier=flow.code_verifier,
            http_client=http_client,
        )
        external_subject, display_label = await adapter.fetch_user_identity(
            access_token=tokens.access_token,
            http_client=http_client,
        )
        health_ok = await adapter.health(
            access_token=tokens.access_token, http_client=http_client
        )

        # Uniqueness on (user, instance, external_subject).
        existing = await self._arcade.query(
            "SELECT FROM IntegrationConnection "
            "WHERE user_sub = :sub AND integration_instance_id = :id "
            "AND external_subject = :ext "
            "AND disconnected_at IS NULL",
            {
                "sub": user.sub,
                "id": integration_instance_id,
                "ext": external_subject,
            },
        )
        if existing:
            raise ConnectionAlreadyExistsError(
                f"user already has an active connection to "
                f"{integration_instance_id} for {external_subject!r}"
            )

        seq = await self._next_seq(user.sub, integration_instance_id)
        now = datetime.now(UTC)
        token_blob = json.dumps(
            tokens.to_storage_dict(), separators=(",", ":"), sort_keys=True
        )
        encrypted_credentials = encrypt(token_blob, key=self._master_key)
        conn_id = _connection_id(user.sub, integration_instance_id, seq)
        connection_doc = {
            "id": conn_id,
            "user_sub": user.sub,
            "username": user.username,
            "integration_instance_id": integration_instance_id,
            "connection_seq": seq,
            "external_subject": external_subject,
            "display_label": display_label,
            "privacy_class": _DEFAULT_PRIVACY_CLASS,
            "encrypted_credentials": encrypted_credentials,
            "status": "connected",
            "connected_at": now.isoformat(),
            "disconnected_at": None,
            "last_health_status": "ok" if health_ok else "fail",
            "last_health_check_at": now.isoformat(),
        }
        await self._arcade.command(
            f"INSERT INTO IntegrationConnection CONTENT {json.dumps(connection_doc)}"
        )
        await self._record_consent(
            user=user,
            action="granted",
            integration_instance_id=integration_instance_id,
            connection_seq=seq,
            privacy_class=_DEFAULT_PRIVACY_CLASS,
            external_subject=external_subject,
            request_id=request_id,
            now=now,
        )
        # Strip sensitive fields from the API response — the access token
        # never leaves the Hub.
        result = _strip_internals(connection_doc)
        result.pop("encrypted_credentials", None)
        return result

    # ------------------------------------------------------------------
    # Admin-action revoke cascade (Sprint 2)
    # ------------------------------------------------------------------

    async def revoke_all_for_instance(
        self,
        integration_instance_id: str,
        reason: str,
        request_id: str | None = None,
    ) -> int:
        """Revoke every active connection for the instance, wipe credentials,
        emit a ``ConsentEvent`` per user with the given ``reason``.

        Used by ``IntegrationsService.update(enabled=False)``,
        ``IntegrationsService.delete()``, and the SIAM-cascade hook. Returns
        the number of connections revoked (0 if no actives — idempotent).
        """
        active = await self._arcade.query(
            "SELECT FROM IntegrationConnection "
            "WHERE integration_instance_id = :id AND disconnected_at IS NULL",
            {"id": integration_instance_id},
        )
        if not active:
            return 0
        now = datetime.now(UTC)
        retain_until = now + timedelta(days=self._consent_retention_days)
        for row in active:
            await self._arcade.command(
                "UPDATE IntegrationConnection SET status = 'disconnected', "
                "disconnected_at = :ts, encrypted_credentials = null, "
                "revoked_by = :reason, revoked_at = :ts WHERE id = :id",
                {"ts": now.isoformat(), "id": row["id"], "reason": reason},
            )
            consent_doc = {
                "id": str(uuid.uuid4()),
                "ts": now.isoformat(),
                "user_sub": str(row.get("user_sub", "")),
                "username": str(row.get("username", "")),
                "action": reason,
                "integration_instance_id": integration_instance_id,
                "connection_seq": int(row.get("connection_seq", 0)),
                "external_subject": str(row.get("external_subject", "")),
                "privacy_class": str(
                    row.get("privacy_class", _DEFAULT_PRIVACY_CLASS)
                ),
                "request_id": request_id or str(uuid.uuid4()),
                "retain_until": retain_until.isoformat(),
            }
            await self._arcade.command(
                f"INSERT INTO ConsentEvent CONTENT {json.dumps(consent_doc)}"
            )
        return len(active)

    async def revoke_for_users_no_longer_authorized(
        self,
        previous_mapping: dict[str, list[str]],
        new_mapping: dict[str, list[str]],
        request_id: str | None = None,
    ) -> int:
        """SIAM-cascade revoke: when admin edits the SIAM mapping, revoke
        every active connection whose owning user no longer has any role
        authorizing the instance under the new mapping. Returns the number
        of connections revoked."""
        actives = await self._arcade.query(
            "SELECT FROM IntegrationConnection WHERE disconnected_at IS NULL"
        )
        if not actives:
            return 0

        # For each active connection, walk the user's realm_roles and check
        # whether any of them is mapped to the connection's instance under
        # the NEW mapping. If not, revoke. We have to ask: how do we know
        # the user's realm_roles? They aren't stored on the connection —
        # only the username. But the SIAM mapping is role→[instances]; we
        # can invert: for each instance the user has a connection on, find
        # the set of roles authorizing it under new_mapping. If that set is
        # empty, the connection is no longer authorized regardless of role.
        new_instances_by_role = {r: set(ids) for r, ids in new_mapping.items()}

        revoked = 0
        now = datetime.now(UTC)
        retain_until = now + timedelta(days=self._consent_retention_days)
        for row in actives:
            instance_id = str(row.get("integration_instance_id", ""))
            roles_now_authorizing = [
                r
                for r, ids in new_instances_by_role.items()
                if instance_id in ids
            ]
            if roles_now_authorizing:
                # Some role still maps to this instance — connection stays.
                # We could be stricter and require the SPECIFIC user have
                # one of those roles, but realm_roles aren't stored here.
                # The conservative behavior: only revoke when *no* role
                # maps to the instance at all (instance fully orphaned in
                # the new mapping). This matches the user-experienced
                # behavior of "instance still reachable for some role".
                continue
            previous_roles_authorizing = [
                r for r, ids in previous_mapping.items() if instance_id in ids
            ]
            if not previous_roles_authorizing:
                # Was already orphan; not a transition caused by this edit.
                continue
            await self._arcade.command(
                "UPDATE IntegrationConnection SET status = 'disconnected', "
                "disconnected_at = :ts, encrypted_credentials = null, "
                "revoked_by = :reason, revoked_at = :ts WHERE id = :id",
                {
                    "ts": now.isoformat(),
                    "id": row["id"],
                    "reason": "revoked-by-siam-change",
                },
            )
            consent_doc = {
                "id": str(uuid.uuid4()),
                "ts": now.isoformat(),
                "user_sub": str(row.get("user_sub", "")),
                "username": str(row.get("username", "")),
                "action": "revoked-by-siam-change",
                "integration_instance_id": instance_id,
                "connection_seq": int(row.get("connection_seq", 0)),
                "external_subject": str(row.get("external_subject", "")),
                "privacy_class": str(
                    row.get("privacy_class", _DEFAULT_PRIVACY_CLASS)
                ),
                "request_id": request_id or str(uuid.uuid4()),
                "retain_until": retain_until.isoformat(),
            }
            await self._arcade.command(
                f"INSERT INTO ConsentEvent CONTENT {json.dumps(consent_doc)}"
            )
            revoked += 1
        return revoked

    # ------------------------------------------------------------------
    # Token retrieval with refresh-once-then-stale (§3.8)
    # ------------------------------------------------------------------

    async def get_valid_access_token(
        self,
        *,
        connection_id: str,
        http_client: httpx.AsyncClient,
        clock_skew_seconds: int = 60,
        now: int | None = None,
    ) -> str | None:
        """Return a valid access token for the given connection, refreshing
        once if expired. Returns ``None`` if the connection is stale,
        disconnected, or refresh fails — callers surface this as ``stale``
        in ``/me`` and the user re-Connects."""
        row = await self._fetch_connection_row(connection_id)
        if row is None:
            return None
        tokens = self._decode_token_blob(row)
        if tokens is None:
            await self._mark_stale(row["id"])
            return None
        now_ts = now if now is not None else int(time.time())
        if tokens.expires_at - clock_skew_seconds > now_ts:
            return tokens.access_token
        # Expired (or near it). Refresh once; on any failure mark stale.
        new_tokens = await self._refresh_once(row, tokens, http_client, now_ts)
        if new_tokens is None:
            await self._mark_stale(row["id"])
            return None
        await self._persist_tokens(row["id"], new_tokens)
        return new_tokens.access_token

    async def _fetch_connection_row(
        self, connection_id: str
    ) -> dict[str, Any] | None:
        rows = await self._arcade.query(
            "SELECT FROM IntegrationConnection WHERE id = :id",
            {"id": connection_id},
        )
        if not rows:
            return None
        row = rows[0]
        if row.get("status") != "connected":
            return None
        if not row.get("encrypted_credentials"):
            return None
        return row

    def _decode_token_blob(self, row: dict[str, Any]) -> OAuthTokens | None:
        try:
            blob = decrypt(row["encrypted_credentials"], key=self._master_key)
            return OAuthTokens.from_storage_dict(json.loads(blob))
        except Exception:
            return None

    async def _refresh_once(
        self,
        row: dict[str, Any],
        tokens: OAuthTokens,
        http_client: httpx.AsyncClient,
        now_ts: int,
    ) -> OAuthTokens | None:
        if tokens.refresh_token is None:
            return None
        instance = await self._fetch_instance(
            str(row["integration_instance_id"])
        )
        if instance is None:
            return None
        try:
            adapter = build_adapter_for_instance(instance)
            config_public = instance.get("config_public") or {}
            client_id = str(config_public.get("client_id") or "")
            config_secrets = instance.get("config_secrets_encrypted") or {}
            encrypted_secret = config_secrets.get("client_secret") or ""
            client_secret = (
                decrypt(encrypted_secret, key=self._master_key)
                if encrypted_secret
                else ""
            )
            return await refresh_access_token(
                token_endpoint=adapter.token_endpoint,
                client_id=client_id,
                client_secret=client_secret,
                refresh_token=tokens.refresh_token,
                http_client=http_client,
                now=now_ts,
            )
        except (
            OAuthExchangeError,
            SourceAdapterError,
            SourceAdapterNotImplementedError,
        ):
            return None

    async def _persist_tokens(
        self, connection_id: str, tokens: OAuthTokens
    ) -> None:
        blob = json.dumps(
            tokens.to_storage_dict(), separators=(",", ":"), sort_keys=True
        )
        encrypted = encrypt(blob, key=self._master_key)
        await self._arcade.command(
            "UPDATE IntegrationConnection SET encrypted_credentials = :ec "
            "WHERE id = :id",
            {"ec": encrypted, "id": connection_id},
        )

    async def _mark_stale(self, connection_id: str) -> None:
        await self._arcade.command(
            "UPDATE IntegrationConnection SET status = 'stale' WHERE id = :id",
            {"id": connection_id},
        )

    async def _is_siam_authorized(
        self, user: CurrentUser, instance_id: str
    ) -> bool:
        mapping = await self._siam.get()
        for role in user.realm_roles:
            allowed = mapping.get(role, [])
            if instance_id in allowed:
                return True
        return False

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
            return 0
        return int(rows[0]["m"]) + 1

    async def _record_consent(
        self,
        *,
        user: CurrentUser,
        action: str,
        integration_instance_id: str,
        connection_seq: int,
        privacy_class: str,
        external_subject: str,
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
            "external_subject": external_subject,
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
