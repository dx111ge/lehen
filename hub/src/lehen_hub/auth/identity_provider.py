"""IdentityProvider abstraction for SIAM authentication.

Two first-class implementations ship with the Hub: ``KeycloakIdentityProvider``
(default for OSS-shop deployments) and ``EntraIdentityProvider`` (default for
M365-shop deployments). Either can be the configured SIAM IdP for a given Hub
deployment. The active provider is held on ``app.state.identity_provider`` and
consumed by:

* ``auth.dependencies._verify_request_token`` — for issuer/audience and role
  extraction from the JWT claims.
* ``api.auth_config`` — to expose discovery info to the Edge and admin SPAs
  via ``GET /auth/public-config``.
* ``api.health`` — to liveness-check the active IdP's well-known endpoint.

The Hub-self-issued JWTs used for the local-admin bootstrap path (Sprint 1.5,
phase 4) live on a separate code path and do **not** implement this Protocol —
they are validated locally without JWKS fetch and are explicitly scoped to
the admin surface only.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from lehen_hub.config import EntraSettings, KeycloakSettings


@runtime_checkable
class IdentityProvider(Protocol):
    """Read-only view of the active SIAM identity provider.

    Implementations expose the OIDC topology (issuer, audience, JWKS URL) plus
    the provider-specific knowledge of how to extract realm-equivalent roles
    from a verified JWT's claims.
    """

    @property
    def provider_id(self) -> str:
        """Stable id, e.g. ``"keycloak"`` or ``"entra"``. Used in audit logs
        and admin diagnostics; never user-facing."""

    @property
    def issuer(self) -> str:
        """Expected ``iss`` claim. Used by ``decode_and_verify``."""

    @property
    def audience(self) -> str:
        """Expected ``aud`` claim. Used by ``decode_and_verify``."""

    @property
    def jwks_url(self) -> str:
        """JWKS document URL. Held by ``JWKSCache``."""

    @property
    def well_known_url(self) -> str:
        """OIDC discovery URL. Used by health checks and the SPA bootstrap."""

    @property
    def admin_role(self) -> str:
        """The realm/app role name that gates ``/admin/*`` endpoints."""

    @property
    def jwks_ttl_seconds(self) -> int:
        """How long the JWKS cache should hold keys before re-fetching."""

    def extract_realm_roles(self, claims: dict[str, Any]) -> list[str]:
        """Return the user's roles from verified JWT claims.

        Keycloak puts roles in ``realm_access.roles``; Entra puts them in the
        top-level ``roles`` claim when the app manifest defines app roles.
        Implementations encapsulate that difference so callers can treat
        ``user.realm_roles`` as a flat list of role names regardless of IdP.
        """

    def discovery_config(self) -> dict[str, Any]:
        """Return the public, unauthenticated discovery payload for SPAs.

        Shape consumed by ``GET /auth/public-config``. Includes provider
        identity, issuer, well-known URL, audience, and the public client ids
        the Edge and admin SPAs use for OIDC PKCE.
        """


class KeycloakIdentityProvider:
    """``IdentityProvider`` backed by a Keycloak realm.

    Reads role claims from the Keycloak-shaped ``realm_access.roles`` array.
    Discovery values are derived from ``KeycloakSettings``.
    """

    provider_id = "keycloak"

    def __init__(self, settings: KeycloakSettings) -> None:
        self._settings = settings

    @property
    def issuer(self) -> str:
        return self._settings.issuer

    @property
    def audience(self) -> str:
        return self._settings.audience

    @property
    def jwks_url(self) -> str:
        return self._settings.jwks_url

    @property
    def well_known_url(self) -> str:
        return self._settings.well_known_url

    @property
    def admin_role(self) -> str:
        return self._settings.admin_role

    @property
    def jwks_ttl_seconds(self) -> int:
        return self._settings.jwks_ttl_seconds

    def extract_realm_roles(self, claims: dict[str, Any]) -> list[str]:
        realm_access = claims.get("realm_access") or {}
        if not isinstance(realm_access, dict):
            return []
        roles = realm_access.get("roles") or []
        if not isinstance(roles, list):
            return []
        return [str(r) for r in roles]

    def discovery_config(self) -> dict[str, Any]:
        return {
            "provider": self.provider_id,
            "issuer": self.issuer,
            "well_known_url": self.well_known_url,
            "realm": self._settings.realm,
            "edge_client_id": self._settings.edge_client_id,
            "admin_ui_client_id": self._settings.admin_ui_client_id,
            "audience": self.audience,
        }


class EntraIdentityProvider:
    """``IdentityProvider`` backed by Microsoft Entra ID (Azure AD).

    Reads role claims from the top-level ``roles`` claim — Entra emits this
    when app roles are assigned. Issuer and JWKS URL are derived from the
    configured tenant id; audience comes from the operator's app registration
    (typically ``api://{client_id}``).

    The ``realm`` field of the discovery config is populated with the tenant
    id so the response shape stays stable across providers; consumers should
    treat ``realm`` as provider-specific (Keycloak realm name vs. Entra
    tenant id) and use ``provider`` to disambiguate.
    """

    provider_id = "entra"

    def __init__(self, settings: EntraSettings) -> None:
        self._settings = settings

    @property
    def issuer(self) -> str:
        return self._settings.issuer

    @property
    def audience(self) -> str:
        return self._settings.audience

    @property
    def jwks_url(self) -> str:
        return self._settings.jwks_url

    @property
    def well_known_url(self) -> str:
        return self._settings.well_known_url

    @property
    def admin_role(self) -> str:
        return self._settings.admin_role

    @property
    def jwks_ttl_seconds(self) -> int:
        return self._settings.jwks_ttl_seconds

    def extract_realm_roles(self, claims: dict[str, Any]) -> list[str]:
        roles = claims.get("roles") or []
        if not isinstance(roles, list):
            return []
        return [str(r) for r in roles]

    def discovery_config(self) -> dict[str, Any]:
        return {
            "provider": self.provider_id,
            "issuer": self.issuer,
            "well_known_url": self.well_known_url,
            "realm": self._settings.tenant_id,
            "edge_client_id": self._settings.edge_client_id,
            "admin_ui_client_id": self._settings.admin_ui_client_id,
            "audience": self.audience,
        }


def build_identity_provider_from_settings(
    *,
    keycloak: KeycloakSettings | None,
    entra: EntraSettings | None,
    selector: str,
) -> IdentityProvider:
    """Build the active ``IdentityProvider`` from the validated Settings.

    Raises ``RuntimeError`` if the selected provider's settings block is not
    populated — this is a defensive check; ``Settings._selected_provider_is_configured``
    already enforces it at config-load time.
    """
    if selector == "keycloak":
        if keycloak is None:
            raise RuntimeError("identity_provider=keycloak but keycloak settings are not set")
        return KeycloakIdentityProvider(keycloak)
    if selector == "entra":
        if entra is None:
            raise RuntimeError("identity_provider=entra but entra settings are not set")
        return EntraIdentityProvider(entra)
    raise RuntimeError(f"unknown identity_provider selector: {selector!r}")
