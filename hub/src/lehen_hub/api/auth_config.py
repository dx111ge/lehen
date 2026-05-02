"""Public auth-config endpoint consumed by the SPAs to bootstrap OIDC PKCE.

Returns just enough for the browser to discover Keycloak's OIDC endpoints and
pick the right public client. No secrets — readable without authentication.
"""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from lehen_hub.config import Settings, get_settings

router = APIRouter(tags=["auth"])


class AuthPublicConfig(BaseModel):
    issuer: str
    well_known_url: str
    realm: str
    edge_client_id: str
    admin_ui_client_id: str
    audience: str


@router.get("/auth/public-config", response_model=AuthPublicConfig)
async def public_config() -> AuthPublicConfig:
    settings: Settings = get_settings()
    return AuthPublicConfig(
        issuer=settings.keycloak.issuer,
        well_known_url=settings.keycloak.well_known_url,
        realm=settings.keycloak.realm,
        edge_client_id=settings.keycloak.edge_client_id,
        admin_ui_client_id=settings.keycloak.admin_ui_client_id,
        audience=settings.keycloak.audience,
    )
