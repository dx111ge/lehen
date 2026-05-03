"""Public auth-config endpoint consumed by the SPAs and the Edge to bootstrap
OIDC PKCE.

Returns just enough for the browser/Edge to discover the active SIAM IdP's
OIDC endpoints and pick the right public client. No secrets — readable without
authentication. The local-admin path is **never** exposed via this endpoint;
the Edge has no awareness that local admin exists.

The response shape is provider-agnostic enough that the same endpoint serves
both Keycloak and Entra deployments — clients should treat ``provider`` as
authoritative and ``realm`` as provider-specific (it carries the Keycloak
realm name; Entra deployments populate it with the tenant id).
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel

from lehen_hub.auth.identity_provider import IdentityProvider

router = APIRouter(tags=["auth"])


class AuthPublicConfig(BaseModel):
    provider: str
    issuer: str
    well_known_url: str
    realm: str
    edge_client_id: str
    admin_ui_client_id: str
    audience: str


@router.get("/auth/public-config", response_model=AuthPublicConfig)
async def public_config(request: Request) -> AuthPublicConfig:
    provider: IdentityProvider | None = getattr(
        request.app.state, "identity_provider", None
    )
    if provider is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="identity provider not initialized",
        )
    return AuthPublicConfig(**provider.discovery_config())
