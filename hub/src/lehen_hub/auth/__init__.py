"""Hub auth: JWKS cache, JWT verification, FastAPI dependencies."""

from lehen_hub.auth.dependencies import (
    CurrentUser,
    CurrentUserDep,
    require_admin,
    require_realm_role,
)
from lehen_hub.auth.jwks import JWKSCache, JWKSFetchError
from lehen_hub.auth.jwt import InvalidTokenError, decode_and_verify

__all__ = [
    "CurrentUser",
    "CurrentUserDep",
    "InvalidTokenError",
    "JWKSCache",
    "JWKSFetchError",
    "decode_and_verify",
    "require_admin",
    "require_realm_role",
]
