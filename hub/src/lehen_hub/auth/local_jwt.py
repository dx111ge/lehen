"""Hub-self-issued JWTs for the local-admin bootstrap path.

These tokens are signed by the Hub itself with a shared HS256 secret. They
are validated only on the admin surface; the user-facing auth dependency
rejects any token bearing this issuer outright. Issuer claim:
``lehen-hub-local``. Scope claim: ``admin``. There are no other valid scopes.

This is deliberately separate from ``auth.jwt.decode_and_verify``, which
handles JWKS-based IdP-issued tokens (Keycloak, Entra). Mixing the two
would couple the trust boundaries and is exactly the confused-deputy risk
DESIGN.md §10's "strict separation of admin and user surfaces" decision
guards against.
"""

from __future__ import annotations

import time
from typing import Any

from jose import jwt as jose_jwt
from jose.exceptions import (
    ExpiredSignatureError,
    JWTClaimsError,
    JWTError,
)

LOCAL_ISSUER = "lehen-hub-local"
LOCAL_SCOPE_ADMIN = "admin"
_ALG = "HS256"


class LocalTokenError(ValueError):
    """The local-issued token failed verification (signature, expiry, iss, scope)."""


def issue_local_admin_token(
    *,
    username: str,
    signing_key: bytes,
    ttl_seconds: int,
    audience: str = "lehen-hub-admin",
) -> str:
    """Sign a Hub-self-issued JWT for the given local admin username.

    Always carries ``iss=lehen-hub-local`` and ``scope=admin``. The audience
    defaults to ``lehen-hub-admin`` to make wrong-surface use even less
    accidental — a SIAM-issued token has audience ``lehen-hub`` (or the
    Entra api://... form), so a local-issued token won't ever pass an
    audience check intended for SIAM tokens.
    """
    now = int(time.time())
    claims: dict[str, Any] = {
        "sub": username,
        "preferred_username": username,
        "iss": LOCAL_ISSUER,
        "aud": audience,
        "scope": LOCAL_SCOPE_ADMIN,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    encoded: str = jose_jwt.encode(claims, signing_key, algorithm=_ALG)
    return encoded


def decode_local_admin_token(
    token: str,
    *,
    signing_key: bytes,
    audience: str = "lehen-hub-admin",
) -> dict[str, Any]:
    """Verify a Hub-self-issued JWT and return its claims.

    Raises ``LocalTokenError`` on any verification failure. Validates
    signature, expiry, issuer, audience, and scope.
    """
    if not token:
        raise LocalTokenError("empty token")
    try:
        claims: dict[str, Any] = jose_jwt.decode(
            token,
            signing_key,
            algorithms=[_ALG],
            audience=audience,
            issuer=LOCAL_ISSUER,
        )
    except ExpiredSignatureError as exc:
        raise LocalTokenError("token expired") from exc
    except JWTClaimsError as exc:
        raise LocalTokenError(f"claim verification failed: {exc}") from exc
    except JWTError as exc:
        raise LocalTokenError(f"signature verification failed: {exc}") from exc

    scope = claims.get("scope")
    if scope != LOCAL_SCOPE_ADMIN:
        raise LocalTokenError(f"unexpected scope: {scope!r}")
    return claims


def peek_unverified_issuer(token: str) -> str | None:
    """Read the ``iss`` claim from a JWT *without* verifying the signature.

    Used by the auth dependency to route tokens to the right validator
    (JWKS-based for IdP tokens; HS256 for local). Never trust the result
    for authorization — it must be confirmed by the matching verifier.
    """
    if not token:
        return None
    try:
        unverified = jose_jwt.get_unverified_claims(token)
    except JWTError:
        return None
    iss = unverified.get("iss")
    if iss is None:
        return None
    return str(iss)
