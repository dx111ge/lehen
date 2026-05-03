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
    expected_issuer: str | list[str],
) -> dict[str, Any]:
    """Verify ``token`` and return its claims.

    ``expected_issuer`` may be a single string or a list — a single string is
    the typical case (Keycloak); a list is needed for IdPs whose tokens can
    legitimately carry one of several issuer values (Entra v1 vs. v2 access
    tokens). When a list is given, the issuer is verified manually after
    signature/audience/expiry pass.

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

    issuers = (
        [expected_issuer]
        if isinstance(expected_issuer, str)
        else list(expected_issuer)
    )
    try:
        # When multiple issuers are accepted, decode without jose's iss check
        # and validate the iss claim manually below. jose only accepts a single
        # issuer string; the manual path keeps the contract uniform.
        claims: dict[str, Any] = jose_jwt.decode(
            token,
            key,
            algorithms=[_ALG],
            audience=expected_audience,
            issuer=issuers[0] if len(issuers) == 1 else None,
            options={"verify_iss": len(issuers) == 1},
        )
    except ExpiredSignatureError as exc:
        raise InvalidTokenError("token expired") from exc
    except JWTClaimsError as exc:
        raise InvalidTokenError(f"claim verification failed: {exc}") from exc
    except (JWTError, JWKError) as exc:
        raise InvalidTokenError(f"signature verification failed: {exc}") from exc

    if len(issuers) > 1:
        actual_iss = str(claims.get("iss", ""))
        if actual_iss not in issuers:
            raise InvalidTokenError(
                f"claim verification failed: issuer {actual_iss!r} not in "
                f"accepted set"
            )

    return claims
