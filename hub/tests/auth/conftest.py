"""Auth test fixtures: a session-scoped RSA keypair, a JWKS-dict factory, and
a token-issue helper. RSA generation is expensive — one keypair per session."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwk as jose_jwk
from jose import jwt as jose_jwt

TEST_KID = "test-kid-1"
TEST_ISSUER = "http://test-keycloak/realms/lehen"
TEST_AUDIENCE = "lehen-hub"


@pytest.fixture(scope="session")
def rsa_keypair() -> tuple[bytes, bytes]:
    pk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = pk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = pk.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


@pytest.fixture(scope="session")
def jwks_dict(rsa_keypair: tuple[bytes, bytes]) -> dict[str, Any]:
    _, public_pem = rsa_keypair
    public_jwk = jose_jwk.construct(public_pem, "RS256").to_dict()
    # python-jose returns JWK fields as bytes for some keys; coerce to str for JSON serialization.
    public_jwk = {k: (v.decode() if isinstance(v, bytes) else v) for k, v in public_jwk.items()}
    public_jwk["kid"] = TEST_KID
    public_jwk["use"] = "sig"
    public_jwk["alg"] = "RS256"
    return {"keys": [public_jwk]}


@pytest.fixture
def issue_token(rsa_keypair: tuple[bytes, bytes]) -> Callable[..., str]:
    private_pem, _ = rsa_keypair

    def _issue(
        *,
        sub: str = "user-1",
        username: str = "test-user",
        roles: list[str] | None = None,
        issuer: str = TEST_ISSUER,
        audience: str | list[str] = TEST_AUDIENCE,
        expires_in: int = 300,
        kid: str = TEST_KID,
        extra_claims: dict[str, Any] | None = None,
    ) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "sub": sub,
            "preferred_username": username,
            "realm_access": {"roles": roles or []},
            "iss": issuer,
            "aud": audience,
            "exp": now + expires_in,
            "iat": now,
        }
        if extra_claims:
            claims.update(extra_claims)
        return jose_jwt.encode(
            claims,
            private_pem.decode("utf-8"),
            algorithm="RS256",
            headers={"kid": kid},
        )

    return _issue
