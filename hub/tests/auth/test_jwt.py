"""Tests for JWKS cache + JWT verification."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from typing import Any

import httpx
import pytest
import respx

from lehen_hub.auth.jwks import JWKSCache, JWKSFetchError
from lehen_hub.auth.jwt import InvalidTokenError, decode_and_verify

from .conftest import TEST_AUDIENCE, TEST_ISSUER

JWKS_URL = "http://test-keycloak/realms/lehen/protocol/openid-connect/certs"


@pytest.fixture
async def http_client() -> httpx.AsyncClient:
    async with httpx.AsyncClient() as client:
        yield client


@pytest.fixture
def jwks_cache() -> JWKSCache:
    return JWKSCache(JWKS_URL, ttl_seconds=600, negative_ttl_seconds=2.0)


class TestJWKSCache:
    @respx.mock
    async def test_first_fetch_populates_cache(
        self,
        jwks_cache: JWKSCache,
        jwks_dict: dict[str, Any],
        http_client: httpx.AsyncClient,
    ) -> None:
        route = respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=jwks_dict))
        result = await jwks_cache.get_keys(http_client)
        assert result == jwks_dict
        assert route.call_count == 1

    @respx.mock
    async def test_second_call_within_ttl_uses_cache(
        self,
        jwks_cache: JWKSCache,
        jwks_dict: dict[str, Any],
        http_client: httpx.AsyncClient,
    ) -> None:
        route = respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=jwks_dict))
        await jwks_cache.get_keys(http_client)
        await jwks_cache.get_keys(http_client)
        assert route.call_count == 1

    @respx.mock
    async def test_invalidate_forces_refetch(
        self,
        jwks_cache: JWKSCache,
        jwks_dict: dict[str, Any],
        http_client: httpx.AsyncClient,
    ) -> None:
        route = respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=jwks_dict))
        await jwks_cache.get_keys(http_client)
        jwks_cache.invalidate()
        await jwks_cache.get_keys(http_client)
        assert route.call_count == 2

    @respx.mock
    async def test_failure_enters_negative_cache(
        self,
        jwks_cache: JWKSCache,
        http_client: httpx.AsyncClient,
    ) -> None:
        route = respx.get(JWKS_URL).mock(return_value=httpx.Response(500))
        with pytest.raises(JWKSFetchError):
            await jwks_cache.get_keys(http_client)
        # Second call should NOT trigger a fetch — it sits in negative cache.
        with pytest.raises(JWKSFetchError, match="negative-cache"):
            await jwks_cache.get_keys(http_client)
        assert route.call_count == 1

    @respx.mock
    async def test_negative_cache_expires(
        self,
        jwks_dict: dict[str, Any],
        http_client: httpx.AsyncClient,
    ) -> None:
        cache = JWKSCache(JWKS_URL, ttl_seconds=600, negative_ttl_seconds=0.05)
        respx.get(JWKS_URL).mock(
            side_effect=[httpx.Response(500), httpx.Response(200, json=jwks_dict)]
        )
        with pytest.raises(JWKSFetchError):
            await cache.get_keys(http_client)
        await asyncio.sleep(0.1)
        result = await cache.get_keys(http_client)
        assert result == jwks_dict

    @respx.mock
    async def test_malformed_payload_treated_as_failure(
        self,
        jwks_cache: JWKSCache,
        http_client: httpx.AsyncClient,
    ) -> None:
        respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json={"not_keys": "wrong"}))
        with pytest.raises(JWKSFetchError, match="malformed"):
            await jwks_cache.get_keys(http_client)


class TestDecodeAndVerify:
    @respx.mock
    async def test_valid_token_decodes(
        self,
        jwks_cache: JWKSCache,
        jwks_dict: dict[str, Any],
        http_client: httpx.AsyncClient,
        issue_token: Callable[..., str],
    ) -> None:
        respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=jwks_dict))
        token = issue_token(sub="alice", username="alice", roles=["change-manager"])
        claims = await decode_and_verify(
            token,
            jwks_cache=jwks_cache,
            http_client=http_client,
            expected_audience=TEST_AUDIENCE,
            expected_issuer=TEST_ISSUER,
        )
        assert claims["sub"] == "alice"
        assert claims["preferred_username"] == "alice"
        assert claims["realm_access"]["roles"] == ["change-manager"]

    @respx.mock
    async def test_expired_token_rejected(
        self,
        jwks_cache: JWKSCache,
        jwks_dict: dict[str, Any],
        http_client: httpx.AsyncClient,
        issue_token: Callable[..., str],
    ) -> None:
        respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=jwks_dict))
        token = issue_token(expires_in=-60)
        with pytest.raises(InvalidTokenError, match="expired"):
            await decode_and_verify(
                token,
                jwks_cache=jwks_cache,
                http_client=http_client,
                expected_audience=TEST_AUDIENCE,
                expected_issuer=TEST_ISSUER,
            )

    @respx.mock
    async def test_wrong_audience_rejected(
        self,
        jwks_cache: JWKSCache,
        jwks_dict: dict[str, Any],
        http_client: httpx.AsyncClient,
        issue_token: Callable[..., str],
    ) -> None:
        respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=jwks_dict))
        token = issue_token(audience="some-other-api")
        with pytest.raises(InvalidTokenError, match="claim verification"):
            await decode_and_verify(
                token,
                jwks_cache=jwks_cache,
                http_client=http_client,
                expected_audience=TEST_AUDIENCE,
                expected_issuer=TEST_ISSUER,
            )

    @respx.mock
    async def test_wrong_issuer_rejected(
        self,
        jwks_cache: JWKSCache,
        jwks_dict: dict[str, Any],
        http_client: httpx.AsyncClient,
        issue_token: Callable[..., str],
    ) -> None:
        respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=jwks_dict))
        token = issue_token(issuer="http://attacker/realms/evil")
        with pytest.raises(InvalidTokenError, match="claim verification"):
            await decode_and_verify(
                token,
                jwks_cache=jwks_cache,
                http_client=http_client,
                expected_audience=TEST_AUDIENCE,
                expected_issuer=TEST_ISSUER,
            )

    @respx.mock
    async def test_missing_kid_rejected(
        self,
        jwks_cache: JWKSCache,
        jwks_dict: dict[str, Any],
        http_client: httpx.AsyncClient,
        rsa_keypair: tuple[bytes, bytes],
    ) -> None:
        from jose import jwt as jose_jwt

        respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=jwks_dict))
        private_pem, _ = rsa_keypair
        # Forge a token without kid in header
        token = jose_jwt.encode(
            {"sub": "x", "iss": TEST_ISSUER, "aud": TEST_AUDIENCE, "exp": int(time.time()) + 60},
            private_pem.decode(),
            algorithm="RS256",
            # no 'kid' header
        )
        with pytest.raises(InvalidTokenError, match="no 'kid'"):
            await decode_and_verify(
                token,
                jwks_cache=jwks_cache,
                http_client=http_client,
                expected_audience=TEST_AUDIENCE,
                expected_issuer=TEST_ISSUER,
            )

    @respx.mock
    async def test_unknown_kid_rejected(
        self,
        jwks_cache: JWKSCache,
        jwks_dict: dict[str, Any],
        http_client: httpx.AsyncClient,
        issue_token: Callable[..., str],
    ) -> None:
        respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=jwks_dict))
        token = issue_token(kid="kid-not-in-jwks")
        with pytest.raises(InvalidTokenError, match="no JWKS key matches"):
            await decode_and_verify(
                token,
                jwks_cache=jwks_cache,
                http_client=http_client,
                expected_audience=TEST_AUDIENCE,
                expected_issuer=TEST_ISSUER,
            )

    @respx.mock
    async def test_garbage_token_rejected(
        self,
        jwks_cache: JWKSCache,
        http_client: httpx.AsyncClient,
    ) -> None:
        with pytest.raises(InvalidTokenError, match="malformed"):
            await decode_and_verify(
                "not.a.token",
                jwks_cache=jwks_cache,
                http_client=http_client,
                expected_audience=TEST_AUDIENCE,
                expected_issuer=TEST_ISSUER,
            )

    async def test_empty_token_rejected(
        self,
        jwks_cache: JWKSCache,
        http_client: httpx.AsyncClient,
    ) -> None:
        with pytest.raises(InvalidTokenError, match="empty token"):
            await decode_and_verify(
                "",
                jwks_cache=jwks_cache,
                http_client=http_client,
                expected_audience=TEST_AUDIENCE,
                expected_issuer=TEST_ISSUER,
            )
