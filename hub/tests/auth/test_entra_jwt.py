"""End-to-end JWT validation through ``decode_and_verify`` for Entra-shaped
tokens. Independent keypair from the Keycloak fixture so cross-issuer
forgery (Keycloak-issued token claiming an Entra issuer or vice versa)
cannot succeed even if both providers were configured side-by-side."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import httpx
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwk as jose_jwk
from jose import jwt as jose_jwt

from lehen_hub.auth.identity_provider import EntraIdentityProvider
from lehen_hub.auth.jwks import JWKSCache
from lehen_hub.auth.jwt import InvalidTokenError, decode_and_verify
from lehen_hub.config import EntraSettings

ENTRA_TID = "00000000-0000-0000-0000-000000000abc"
ENTRA_KID = "test-entra-kid"
ENTRA_AUDIENCE = f"api://{ENTRA_TID}-client"


@pytest.fixture(scope="session")
def entra_keypair() -> tuple[bytes, bytes]:
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
def entra_jwks_dict(entra_keypair: tuple[bytes, bytes]) -> dict[str, Any]:
    _, public_pem = entra_keypair
    public_jwk = jose_jwk.construct(public_pem, "RS256").to_dict()
    public_jwk = {
        k: (v.decode() if isinstance(v, bytes) else v)
        for k, v in public_jwk.items()
    }
    public_jwk["kid"] = ENTRA_KID
    public_jwk["use"] = "sig"
    public_jwk["alg"] = "RS256"
    return {"keys": [public_jwk]}


@pytest.fixture
def entra_provider() -> EntraIdentityProvider:
    return EntraIdentityProvider(
        EntraSettings(
            tenant_id=ENTRA_TID,
            audience=ENTRA_AUDIENCE,
            edge_client_id=f"{ENTRA_TID}-edge",
            admin_ui_client_id=f"{ENTRA_TID}-admin-ui",
        )
    )


@pytest.fixture
def issue_entra_token(entra_keypair: tuple[bytes, bytes]) -> Callable[..., str]:
    private_pem, _ = entra_keypair

    def _issue(
        *,
        sub: str = "user-1",
        username: str = "test-user@example.onmicrosoft.com",
        roles: list[str] | None = None,
        issuer: str | None = None,
        audience: str | list[str] = ENTRA_AUDIENCE,
        tid: str = ENTRA_TID,
        expires_in: int = 300,
        kid: str = ENTRA_KID,
    ) -> str:
        now = int(time.time())
        # Entra-shaped: roles at the top level, no realm_access, includes tid.
        claims: dict[str, Any] = {
            "sub": sub,
            "preferred_username": username,
            "roles": roles or [],
            "tid": tid,
            "iss": issuer or f"https://login.microsoftonline.com/{tid}/v2.0",
            "aud": audience,
            "exp": now + expires_in,
            "iat": now,
        }
        return jose_jwt.encode(
            claims,
            private_pem.decode("utf-8"),
            algorithm="RS256",
            headers={"kid": kid},
        )

    return _issue


@pytest.fixture
async def http_client() -> httpx.AsyncClient:
    async with httpx.AsyncClient() as client:
        yield client


@pytest.fixture
def entra_jwks_cache(entra_provider: EntraIdentityProvider) -> JWKSCache:
    return JWKSCache(entra_provider.jwks_url, ttl_seconds=600)


class TestEntraEndToEnd:
    @respx.mock
    async def test_valid_entra_token_decodes(
        self,
        entra_jwks_cache: JWKSCache,
        entra_jwks_dict: dict[str, Any],
        entra_provider: EntraIdentityProvider,
        http_client: httpx.AsyncClient,
        issue_entra_token: Callable[..., str],
    ) -> None:
        respx.get(entra_provider.jwks_url).mock(
            return_value=httpx.Response(200, json=entra_jwks_dict)
        )
        token = issue_entra_token(roles=["lehen-admin", "change-manager"])
        claims = await decode_and_verify(
            token,
            jwks_cache=entra_jwks_cache,
            http_client=http_client,
            expected_audience=entra_provider.audience,
            expected_issuer=entra_provider.issuer,
        )
        assert claims["sub"] == "user-1"
        assert claims["roles"] == ["lehen-admin", "change-manager"]
        assert claims["tid"] == ENTRA_TID
        # Entra adapter extracts roles cleanly from the verified claims
        assert entra_provider.extract_realm_roles(claims) == [
            "lehen-admin",
            "change-manager",
        ]

    @respx.mock
    async def test_token_from_different_tenant_rejected_by_issuer_check(
        self,
        entra_jwks_cache: JWKSCache,
        entra_jwks_dict: dict[str, Any],
        entra_provider: EntraIdentityProvider,
        http_client: httpx.AsyncClient,
        issue_entra_token: Callable[..., str],
    ) -> None:
        # Mock our configured tenant's JWKS with our keypair. Issue a token
        # claiming a different tenant's issuer — even though signed with the
        # right key (mock simulates a misconfigured app trusting a wrong
        # JWKS), the issuer claim mismatch must reject it.
        respx.get(entra_provider.jwks_url).mock(
            return_value=httpx.Response(200, json=entra_jwks_dict)
        )
        token = issue_entra_token(
            issuer="https://login.microsoftonline.com/some-other-tenant/v2.0"
        )
        with pytest.raises(InvalidTokenError, match="claim verification"):
            await decode_and_verify(
                token,
                jwks_cache=entra_jwks_cache,
                http_client=http_client,
                expected_audience=entra_provider.audience,
                expected_issuer=entra_provider.issuer,
            )

    @respx.mock
    async def test_wrong_audience_rejected(
        self,
        entra_jwks_cache: JWKSCache,
        entra_jwks_dict: dict[str, Any],
        entra_provider: EntraIdentityProvider,
        http_client: httpx.AsyncClient,
        issue_entra_token: Callable[..., str],
    ) -> None:
        respx.get(entra_provider.jwks_url).mock(
            return_value=httpx.Response(200, json=entra_jwks_dict)
        )
        token = issue_entra_token(audience="https://graph.microsoft.com")
        with pytest.raises(InvalidTokenError, match="claim verification"):
            await decode_and_verify(
                token,
                jwks_cache=entra_jwks_cache,
                http_client=http_client,
                expected_audience=entra_provider.audience,
                expected_issuer=entra_provider.issuer,
            )
