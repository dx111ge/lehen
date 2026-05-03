"""FastAPI auth dependencies.

``CurrentUserDep`` — extracts and verifies the bearer token. Two validation
paths exist, selected by the unverified ``iss`` claim of the token:

* SIAM-issued tokens (Keycloak, Entra) — verified via JWKS through the
  active ``IdentityProvider`` on ``app.state.identity_provider``.
* Hub-self-issued tokens (``iss=lehen-hub-local``) — verified via HS256
  with the local-admin signing key. **Only valid on the admin surface.**

The user-surface auth dependency (``CurrentUserDep`` for ``/me/*``) rejects
local-issued tokens by issuer claim. The admin gate (``require_admin``)
accepts both. The strict separation is the architectural rule from
DESIGN.md §10: confused-deputy risks die at the issuer check.

``require_admin`` also runs the auto-disable hook on first SIAM admin
login: if a local-admin row exists with ``enabled=true`` and the current
JWT was SIAM-issued, the local-admin row flips to ``enabled=false`` and an
audit event is recorded.
"""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from typing import Annotated, Any

import httpx
import structlog
from fastapi import Depends, HTTPException, Request, status
from pydantic import BaseModel

from lehen_hub.auth.identity_provider import IdentityProvider
from lehen_hub.auth.jwks import JWKSCache
from lehen_hub.auth.jwt import InvalidTokenError, decode_and_verify
from lehen_hub.auth.local_jwt import (
    LOCAL_ISSUER,
    LocalTokenError,
    decode_local_admin_token,
    peek_unverified_issuer,
)


class CurrentUser(BaseModel):
    """Verified caller identity. Built from the JWT claims.

    ``identity_source`` is the issuer string of the verified token — either
    a SIAM IdP issuer URL or the literal ``lehen-hub-local``. Authorization
    code uses this to enforce surface-specific rules (``/me/*`` rejects
    ``lehen-hub-local``; auto-disable triggers on SIAM admin login)."""

    sub: str
    username: str
    realm_roles: list[str]
    identity_source: str
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


def _get_identity_provider(request: Request) -> IdentityProvider:
    provider: IdentityProvider | None = getattr(
        request.app.state, "identity_provider", None
    )
    if provider is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="identity provider not initialized",
        )
    return provider


def _get_local_admin_signing_key(request: Request) -> bytes | None:
    return getattr(request.app.state, "local_admin_signing_key", None)


async def _verify_local_token(token: str, signing_key: bytes) -> CurrentUser:
    try:
        claims = decode_local_admin_token(token, signing_key=signing_key)
    except LocalTokenError as exc:
        structlog.get_logger(__name__).info(
            "hub.auth.local_token_rejected", error=str(exc)
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"invalid token: {exc}",
            headers={"WWW-Authenticate": 'Bearer realm="lehen"'},
        ) from exc
    # Local tokens grant the admin role implicitly through their scope claim;
    # downstream code reads ``identity_source`` to enforce surface restrictions.
    return CurrentUser(
        sub=str(claims.get("sub", "")),
        username=str(claims.get("preferred_username", "")),
        realm_roles=[],
        identity_source=LOCAL_ISSUER,
        raw_claims=claims,
    )


async def _verify_siam_token(
    token: str,
    *,
    request: Request,
    provider: IdentityProvider,
) -> CurrentUser:
    jwks_cache = _get_jwks_cache(request)
    http_client = _get_http_client(request)
    try:
        claims = await decode_and_verify(
            token,
            jwks_cache=jwks_cache,
            http_client=http_client,
            expected_audience=provider.audience,
            expected_issuer=provider.issuer,
        )
    except InvalidTokenError as exc:
        structlog.get_logger(__name__).info("hub.auth.token_rejected", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"invalid token: {exc}",
            headers={"WWW-Authenticate": 'Bearer realm="lehen"'},
        ) from exc

    return CurrentUser(
        sub=str(claims.get("sub", "")),
        username=str(claims.get("preferred_username", "")),
        realm_roles=provider.extract_realm_roles(claims),
        identity_source=provider.issuer,
        raw_claims=claims,
    )


def _extract_bearer_token(request: Request) -> str:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing bearer token",
            headers={"WWW-Authenticate": 'Bearer realm="lehen"'},
        )
    return auth_header[len("Bearer ") :].strip()


async def _verify_user_surface_token(request: Request) -> CurrentUser:
    """User-surface auth (``/me/*``). SIAM-issued tokens only.

    Tokens with ``iss=lehen-hub-local`` are rejected with 401 — the local
    admin path is structurally invisible on the user surface.
    """
    token = _extract_bearer_token(request)
    issuer = peek_unverified_issuer(token)
    if issuer == LOCAL_ISSUER:
        structlog.get_logger(__name__).info(
            "hub.auth.local_token_on_user_surface",
            path=request.url.path,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid token for this surface",
            headers={"WWW-Authenticate": 'Bearer realm="lehen"'},
        )
    provider = _get_identity_provider(request)
    return await _verify_siam_token(token, request=request, provider=provider)


async def _verify_admin_surface_token(request: Request) -> CurrentUser:
    """Admin-surface auth. Accepts both SIAM-issued (with admin role)
    and Hub-self-issued (``iss=lehen-hub-local``) tokens. Role check happens
    in ``require_admin`` after the issuer-specific verifier returns."""
    token = _extract_bearer_token(request)
    issuer = peek_unverified_issuer(token)
    if issuer == LOCAL_ISSUER:
        signing_key = _get_local_admin_signing_key(request)
        if signing_key is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="local-admin path is not configured on this Hub",
                headers={"WWW-Authenticate": 'Bearer realm="lehen"'},
            )
        return await _verify_local_token(token, signing_key)
    provider = _get_identity_provider(request)
    return await _verify_siam_token(token, request=request, provider=provider)


CurrentUserDep = Annotated[CurrentUser, Depends(_verify_user_surface_token)]
"""User-surface auth (``/me/*``). Rejects Hub-self-issued JWTs.

Do **not** use this on admin endpoints — local-admin tokens carry
``iss=lehen-hub-local`` and will be rejected. Use ``AdminUserDep`` instead."""


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
    request: Request,
) -> CurrentUser:
    """Admin-surface gate.

    Accepts either a SIAM-issued JWT carrying the admin role declared on the
    active ``IdentityProvider``, or a Hub-self-issued JWT (``iss=lehen-hub-local``)
    whose scope is implicitly admin. On a SIAM admin login, runs the local-admin
    auto-disable hook (idempotent and cached on first observation).
    """
    user = await _verify_admin_surface_token(request)
    if user.identity_source != LOCAL_ISSUER:
        provider = _get_identity_provider(request)
        if provider.admin_role not in user.realm_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"missing required realm role: {provider.admin_role}",
            )
        # Successful SIAM admin login → run auto-disable check (idempotent).
        await _maybe_auto_disable_local_admin(request, siam_username=user.username)
    return user


AdminUserDep = Annotated[CurrentUser, Depends(require_admin)]
"""Admin-surface auth. Accepts SIAM-issued JWTs (with admin role claim) or
Hub-self-issued JWTs (``iss=lehen-hub-local``, ``scope=admin``).

Use this on every endpoint under ``/admin/*`` that needs the verified actor.
``CurrentUserDep`` is for ``/me/*`` only and rejects local tokens by issuer
claim — using it on admin endpoints fails 401 for local admins."""


async def _maybe_auto_disable_local_admin(
    request: Request, *, siam_username: str
) -> None:
    """Idempotent: trigger ``LocalAdminService.disable_on_siam_admin_login``
    on the first SIAM admin login seen by this process. After the first
    observation the cached state on ``app.state`` short-circuits the DB read.
    """
    cache_state: str = getattr(
        request.app.state, "local_admin_disable_state", "pending"
    )
    if cache_state != "pending":
        return
    service = getattr(request.app.state, "local_admin_service", None)
    if service is None:
        # Local-admin path not configured — nothing to disable.
        request.app.state.local_admin_disable_state = "no_local_admin"
        return
    transitioned = await service.disable_on_siam_admin_login(
        siam_username=siam_username
    )
    request.app.state.local_admin_disable_state = (
        "disabled" if transitioned else "already_disabled_or_absent"
    )
