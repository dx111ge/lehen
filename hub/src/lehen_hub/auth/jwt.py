"""JWT verification against cached JWKS.

Validates: signature (RS256), expiry, issuer, audience. Returns claims dict on
success; raises ``InvalidTokenError`` on any failure.
"""

from __future__ import annotations

from typing import Any

import httpx
from jose import jwt as jose_jwt
from jose.exceptions import (
    ExpiredSignatureError,
    JWKError,
    JWTClaimsError,
    JWTError,
)

from lehen_hub.auth.jwks import JWKSCache, JWKSFetchError


class InvalidTokenError(ValueError):
    """Token failed any verification step (signature, expiry, iss, aud, kid)."""


_ALG = "RS256"


async def decode_and_verify(
    token: str,
    *,
    jwks_cache: JWKSCache,
    http_client: httpx.AsyncClient,
    expected_audience: str,
    expected_issuer: str,
) -> dict[str, Any]:
    """Verify ``token`` and return its claims.

    Raises ``InvalidTokenError`` if anything is wrong: malformed header, missing kid,
    no matching JWKS key, signature failure, expired, wrong issuer, or wrong
    audience.
    """
    if not token:
        raise InvalidTokenError("empty token")

    try:
        header = jose_jwt.get_unverified_header(token)
    except (JWTError, JWKError) as exc:
        raise InvalidTokenError(f"malformed token header: {exc}") from exc

    kid = header.get("kid")
    if not kid:
        raise InvalidTokenError("token has no 'kid' in header")

    try:
        jwks = await jwks_cache.get_keys(http_client)
    except JWKSFetchError as exc:
        raise InvalidTokenError(f"cannot validate token: {exc}") from exc

    key = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
    if key is None:
        # Try one cache invalidation in case Keycloak rotated keys.
        jwks_cache.invalidate()
        try:
            jwks = await jwks_cache.get_keys(http_client)
        except JWKSFetchError as exc:
            raise InvalidTokenError(f"cannot validate token: {exc}") from exc
        key = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
        if key is None:
            raise InvalidTokenError(f"no JWKS key matches kid={kid}")

    try:
        claims: dict[str, Any] = jose_jwt.decode(
            token,
            key,
            algorithms=[_ALG],
            audience=expected_audience,
            issuer=expected_issuer,
        )
    except ExpiredSignatureError as exc:
        raise InvalidTokenError("token expired") from exc
    except JWTClaimsError as exc:
        raise InvalidTokenError(f"claim verification failed: {exc}") from exc
    except (JWTError, JWKError) as exc:
        raise InvalidTokenError(f"signature verification failed: {exc}") from exc

    return claims
