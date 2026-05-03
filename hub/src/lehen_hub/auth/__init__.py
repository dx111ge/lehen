"""Hub auth: JWKS cache, JWT verification, FastAPI dependencies."""

from lehen_hub.auth.dependencies import (
    AdminUserDep,
    CurrentUser,
    CurrentUserDep,
    require_admin,
    require_realm_role,
)
from lehen_hub.auth.identity_provider import (
    EntraIdentityProvider,
    IdentityProvider,
    KeycloakIdentityProvider,
    build_identity_provider_from_settings,
)
from lehen_hub.auth.jwks import JWKSCache, JWKSFetchError
from lehen_hub.auth.jwt import InvalidTokenError, decode_and_verify
from lehen_hub.auth.local_jwt import (
    LOCAL_ISSUER,
    LocalTokenError,
    decode_local_admin_token,
    issue_local_admin_token,
)

__all__ = [
    "LOCAL_ISSUER",
    "AdminUserDep",
    "CurrentUser",
    "CurrentUserDep",
    "EntraIdentityProvider",
    "IdentityProvider",
    "InvalidTokenError",
    "JWKSCache",
    "JWKSFetchError",
    "KeycloakIdentityProvider",
    "LocalTokenError",
    "build_identity_provider_from_settings",
    "decode_and_verify",
    "decode_local_admin_token",
    "issue_local_admin_token",
    "require_admin",
    "require_realm_role",
]
