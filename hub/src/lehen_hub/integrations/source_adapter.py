"""``SourceAdapter`` Protocol + concrete implementations.

DESIGN.md §6 declares ``SourceAdapter`` as one of the five plugin interfaces.
This module formalizes the contract in code and ships the first concrete
implementation: ``OutlookGraphAdapter`` for ``outlook-graph``.

Each adapter knows three things its instance does not:

* The OIDC/OAuth-2 endpoints to drive the authorization flow against.
* The scopes the Hub requests during user consent.
* How to extract the source-system identity (``external_subject``,
  ``display_label``) and run a ``health()`` round-trip from a freshly
  exchanged access token.

Everything else (token storage, refresh, per-user state) lives in the
generic ``auth.oauth`` helper and ``user.connections_service``. Adapters
deliberately do NOT carry token state — they are stateless dispatchers.
"""

from __future__ import annotations

from typing import Any, ClassVar, Protocol, runtime_checkable

import httpx

from lehen_hub.integrations.registry import (
    UnknownIntegrationTypeError,
    get_type,
)

_HTTP_OK = 200


class SourceAdapterError(RuntimeError):
    """The adapter could not complete the requested round-trip against the
    source system. Used by both health() and identity-fetch failures."""


class SourceAdapterNotImplementedError(NotImplementedError):
    """A SourceAdapter for the requested type_id is not yet shipped.

    Sprint 2 ships ``outlook-graph``. Other types in the registry
    (``outlook-edge-com``, ``teams-graph``, ``itsm-rest-generic``) declare
    their config schema and cardinality but raise this error if a connection
    flow tries to drive them — they land in later sprints.
    """


@runtime_checkable
class SourceAdapter(Protocol):
    """Provider-specific behavior backing the SourceAdapter contract.

    Stateless. One instance per ``IntegrationInstance`` config; held by
    ``connections_service`` for the duration of an OAuth flow or health check.
    """

    @property
    def type_id(self) -> str:
        """Matches ``IntegrationType.id`` from the registry."""

    @property
    def auth_endpoint(self) -> str:
        """OAuth-2 authorization endpoint (where the user consents)."""

    @property
    def token_endpoint(self) -> str:
        """OAuth-2 token endpoint (code-exchange + refresh)."""

    @property
    def scopes(self) -> list[str]:
        """Scopes the Hub requests during user consent."""

    @property
    def extra_authorization_params(self) -> dict[str, str]:
        """Adapter-specific extra params for the authorization URL.

        Examples: Microsoft requires ``prompt=consent`` to force re-consent
        when scopes change; Google uses ``access_type=offline`` to receive
        a refresh token. Default empty.
        """

    async def fetch_user_identity(
        self,
        *,
        access_token: str,
        http_client: httpx.AsyncClient,
    ) -> tuple[str, str]:
        """Return ``(external_subject, display_label)`` for the just-consented user.

        ``external_subject`` is the stable source-system identifier (SMTP
        address for mail, workspace+user pair for chat, user GUID for ITSM).
        ``display_label`` is a human-readable label for the Edge UI.
        """

    async def health(
        self,
        *,
        access_token: str,
        http_client: httpx.AsyncClient,
    ) -> bool:
        """Return True if the access token authenticates a basic source-system
        round-trip. Used to populate ``IntegrationConnection.last_health_status``."""


class OutlookGraphAdapter:
    """``SourceAdapter`` for Microsoft Outlook via Graph (Sprint 2).

    Reads identity from ``GET https://graph.microsoft.com/v1.0/me``. Health
    is the same call — a 200 response means the access token is good for
    the user's profile, which is the floor of what every Graph mail call
    needs.
    """

    type_id = "outlook-graph"
    extra_authorization_params: ClassVar[dict[str, str]] = {"prompt": "consent"}

    def __init__(self, *, tenant_id: str) -> None:
        self._tenant_id = tenant_id

    @property
    def auth_endpoint(self) -> str:
        return (
            f"https://login.microsoftonline.com/{self._tenant_id}/oauth2/v2.0/authorize"
        )

    @property
    def token_endpoint(self) -> str:
        return f"https://login.microsoftonline.com/{self._tenant_id}/oauth2/v2.0/token"

    @property
    def scopes(self) -> list[str]:
        # offline_access is required for refresh_token issuance; openid +
        # profile + email are standard. Mail.Read is the actual capture
        # surface; User.Read backs fetch_user_identity. Mail.Read.Shared
        # ships in Sprint 3 with the picker UX.
        return [
            "openid",
            "profile",
            "email",
            "offline_access",
            "User.Read",
            "Mail.Read",
        ]

    async def fetch_user_identity(
        self,
        *,
        access_token: str,
        http_client: httpx.AsyncClient,
    ) -> tuple[str, str]:
        try:
            resp = await http_client.get(
                "https://graph.microsoft.com/v1.0/me",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=10.0,
            )
        except httpx.HTTPError as exc:
            raise SourceAdapterError(f"Graph /me unreachable: {exc}") from exc
        if resp.status_code != _HTTP_OK:
            raise SourceAdapterError(
                f"Graph /me returned {resp.status_code}: {resp.text[:200]}"
            )
        data = resp.json()
        # Per Graph: ``mail`` is the SMTP address (may be null on personal
        # accounts); ``userPrincipalName`` is always present and is a
        # workable fallback. Display name is always present.
        external_subject = str(
            data.get("mail") or data.get("userPrincipalName") or ""
        )
        if not external_subject:
            raise SourceAdapterError(
                "Graph /me returned no mail or userPrincipalName"
            )
        display_label = str(data.get("displayName") or external_subject)
        return external_subject, display_label

    async def health(
        self,
        *,
        access_token: str,
        http_client: httpx.AsyncClient,
    ) -> bool:
        try:
            resp = await http_client.get(
                "https://graph.microsoft.com/v1.0/me",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=10.0,
            )
        except httpx.HTTPError:
            return False
        return resp.status_code == _HTTP_OK


def build_adapter_for_instance(instance: dict[str, Any]) -> SourceAdapter:
    """Construct the adapter for an ``IntegrationInstance`` document.

    Reads the instance's ``type`` and ``config_public`` to instantiate the
    right adapter. Raises ``SourceAdapterNotImplementedError`` for types
    whose adapters land in later sprints.
    """
    type_id = str(instance.get("type", ""))
    try:
        get_type(type_id)
    except UnknownIntegrationTypeError as exc:
        raise SourceAdapterNotImplementedError(
            f"unknown integration type: {type_id}"
        ) from exc
    config_public = instance.get("config_public") or {}
    if type_id == "outlook-graph":
        tenant_id = str(config_public.get("tenant_id", ""))
        if not tenant_id:
            raise SourceAdapterError(
                "outlook-graph instance missing tenant_id in config_public"
            )
        return OutlookGraphAdapter(tenant_id=tenant_id)
    raise SourceAdapterNotImplementedError(
        f"SourceAdapter for type={type_id!r} not implemented in this sprint"
    )
