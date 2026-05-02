"""FastAPI auth dependencies.

``CurrentUserDep`` — extracts and verifies the bearer token; the request fails
401 on any token problem.

``require_realm_role(role)`` — factory that adds a 403 gate on top of
``CurrentUserDep``. Use ``require_admin`` for the canonical admin gate.
"""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from typing import Annotated, Any

import httpx
import structlog
from fastapi import Depends, HTTPException, Request, status
from pydantic import BaseModel

from lehen_hub.auth.jwks import JWKSCache
from lehen_hub.auth.jwt import InvalidTokenError, decode_and_verify
from lehen_hub.config import Settings, get_settings


class CurrentUser(BaseModel):
    """Verified caller identity. Built from the JWT claims."""

    sub: str
    username: str
    realm_roles: list[str]
    raw_claims: dict[str, Any]


def _get_jwks_cache(request: Request) -> JWKSCache:
    cache: JWKSCache | None = getattr(request.app.state, "jwks_cache", None)
    if cache is None:
        # Misconfiguration; fail-closed at request time rather than at startup
        # (some test setups skip lifespan).
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="auth not initialized",
        )
    return cache


def _get_http_client(request: Request) -> httpx.AsyncClient:
    client: httpx.AsyncClient | None = getattr(request.app.state, "http", None)
    if client is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="http client not initialized",
        )
    return client


async def _verify_request_token(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> CurrentUser:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing bearer token",
            headers={"WWW-Authenticate": 'Bearer realm="lehen"'},
        )
    token = auth_header[len("Bearer ") :].strip()

    jwks_cache = _get_jwks_cache(request)
    http_client = _get_http_client(request)

    try:
        claims = await decode_and_verify(
            token,
            jwks_cache=jwks_cache,
            http_client=http_client,
            expected_audience=settings.keycloak.audience,
            expected_issuer=settings.keycloak.issuer,
        )
    except InvalidTokenError as exc:
        structlog.get_logger(__name__).info("hub.auth.token_rejected", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"invalid token: {exc}",
            headers={"WWW-Authenticate": 'Bearer realm="lehen"'},
        ) from exc

    realm_roles = list(claims.get("realm_access", {}).get("roles", []))
    return CurrentUser(
        sub=str(claims.get("sub", "")),
        username=str(claims.get("preferred_username", "")),
        realm_roles=realm_roles,
        raw_claims=claims,
    )


CurrentUserDep = Annotated[CurrentUser, Depends(_verify_request_token)]


_RoleDep = Callable[[CurrentUser], Coroutine[Any, Any, CurrentUser]]


def require_realm_role(role: str) -> _RoleDep:
    """Build a FastAPI dependency that 403s when the caller's realm roles
    do not include ``role``. Use as ``Depends(require_realm_role("foo"))``.
    """

    async def _dep(user: CurrentUserDep) -> CurrentUser:
        if role not in user.realm_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"missing required realm role: {role}",
            )
        return user

    return _dep


async def require_admin(
    user: CurrentUserDep,
    settings: Annotated[Settings, Depends(get_settings)],
) -> CurrentUser:
    """Convenience: gate by the admin role configured in settings (default ``lehen-admin``)."""
    if settings.keycloak.admin_role not in user.realm_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"missing required realm role: {settings.keycloak.admin_role}",
        )
    return user
