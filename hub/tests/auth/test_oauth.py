"""OAuth-2 PKCE helper — state encode/decode, PKCE generation, code exchange."""

from __future__ import annotations

import base64
import hashlib
import secrets as stdlib_secrets
import time
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx

from lehen_hub.auth.oauth import (
    OAuthExchangeError,
    OAuthFlowState,
    OAuthStateError,
    OAuthTokens,
    build_authorization_url,
    decode_state,
    encode_state,
    exchange_code_for_tokens,
    generate_pkce,
    refresh_access_token,
)


@pytest.fixture
def state_key() -> bytes:
    return stdlib_secrets.token_bytes(32)


@pytest.fixture
async def http_client() -> httpx.AsyncClient:
    async with httpx.AsyncClient() as c:
        yield c


class TestPKCE:
    def test_generates_43_plus_chars(self) -> None:
        verifier, challenge = generate_pkce()
        # 32 random bytes b64url-no-pad → 43 chars
        assert len(verifier) >= 43
        assert len(challenge) >= 43

    def test_challenge_is_sha256_of_verifier(self) -> None:
        verifier, challenge = generate_pkce()
        expected = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode("ascii")).digest()
        ).rstrip(b"=").decode("ascii")
        assert challenge == expected

    def test_two_calls_produce_distinct_pairs(self) -> None:
        a = generate_pkce()
        b = generate_pkce()
        assert a != b


class TestStateRoundtrip:
    def test_roundtrip(self, state_key: bytes) -> None:
        original = OAuthFlowState(
            user_sub="user-1",
            instance_id="outlook-graph-prod",
            nonce="nonce-x",
            issued_at=1_700_000_000,
            code_verifier="verifier-x",
            redirect_uri="lehen://oauth/callback",
        )
        encoded = encode_state(original, key=state_key)
        decoded = decode_state(
            encoded,
            key=state_key,
            now=1_700_000_100,  # 100s after issue, well within window
        )
        assert decoded == original

    def test_state_is_url_safe(self, state_key: bytes) -> None:
        encoded = encode_state(
            OAuthFlowState(
                user_sub="u",
                instance_id="i",
                nonce="n",
                issued_at=int(time.time()),
                code_verifier="v",
                redirect_uri="r",
            ),
            key=state_key,
        )
        # urllib.parse.urlencode handles ``=`` padding correctly; what would
        # actually break is ``+`` (space) or ``/`` (path) in the unencoded
        # body. crypto.encrypt uses url-safe-base64, so neither appears.
        assert "+" not in encoded
        assert "/" not in encoded


class TestStateRejection:
    def test_empty_state_rejected(self, state_key: bytes) -> None:
        with pytest.raises(OAuthStateError, match="missing"):
            decode_state("", key=state_key)

    def test_wrong_key_rejected(self, state_key: bytes) -> None:
        encoded = encode_state(
            OAuthFlowState(
                user_sub="u",
                instance_id="i",
                nonce="n",
                issued_at=int(time.time()),
                code_verifier="v",
                redirect_uri="r",
            ),
            key=state_key,
        )
        wrong = stdlib_secrets.token_bytes(32)
        with pytest.raises(OAuthStateError, match="decryption"):
            decode_state(encoded, key=wrong)

    def test_garbage_state_rejected(self, state_key: bytes) -> None:
        with pytest.raises(OAuthStateError):
            decode_state("not-real-base64!@#", key=state_key)

    def test_expired_state_rejected(self, state_key: bytes) -> None:
        encoded = encode_state(
            OAuthFlowState(
                user_sub="u",
                instance_id="i",
                nonce="n",
                issued_at=1_700_000_000,
                code_verifier="v",
                redirect_uri="r",
            ),
            key=state_key,
        )
        # Pretend we're 2 hours later — beyond default 10-minute window
        with pytest.raises(OAuthStateError, match="expired"):
            decode_state(
                encoded, key=state_key, now=1_700_000_000 + 2 * 3600
            )

    def test_future_issued_at_rejected(self, state_key: bytes) -> None:
        # issued_at far in the future — clock skew exceeds tolerance
        encoded = encode_state(
            OAuthFlowState(
                user_sub="u",
                instance_id="i",
                nonce="n",
                issued_at=1_700_001_000,
                code_verifier="v",
                redirect_uri="r",
            ),
            key=state_key,
        )
        with pytest.raises(OAuthStateError, match="future"):
            decode_state(encoded, key=state_key, now=1_700_000_000)


class TestAuthorizationURL:
    def test_url_carries_required_oauth_params(self, state_key: bytes) -> None:
        result = build_authorization_url(
            auth_endpoint="https://idp.example/auth",
            client_id="abc",
            redirect_uri="lehen://oauth/callback",
            scopes=["openid", "Mail.Read"],
            user_sub="user-1",
            instance_id="instance-1",
            state_key=state_key,
        )
        parsed = urlparse(result.auth_url)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        assert parsed.scheme == "https"
        assert parsed.netloc == "idp.example"
        assert params["client_id"] == "abc"
        assert params["response_type"] == "code"
        assert params["redirect_uri"] == "lehen://oauth/callback"
        assert params["scope"] == "openid Mail.Read"
        assert params["code_challenge_method"] == "S256"
        assert "code_challenge" in params
        assert params["state"] == result.state

    def test_state_decodes_back_to_input(self, state_key: bytes) -> None:
        result = build_authorization_url(
            auth_endpoint="https://idp.example/auth",
            client_id="abc",
            redirect_uri="lehen://oauth/callback",
            scopes=["openid"],
            user_sub="user-1",
            instance_id="instance-1",
            state_key=state_key,
        )
        decoded = decode_state(result.state, key=state_key)
        assert decoded.user_sub == "user-1"
        assert decoded.instance_id == "instance-1"
        assert decoded.redirect_uri == "lehen://oauth/callback"
        # code_verifier is embedded in the state, NOT exposed in the URL
        params = parse_qs(urlparse(result.auth_url).query)
        assert decoded.code_verifier not in params.get("code_challenge", [""])

    def test_extra_params_merged_into_url(self, state_key: bytes) -> None:
        result = build_authorization_url(
            auth_endpoint="https://idp.example/auth",
            client_id="abc",
            redirect_uri="lehen://oauth/callback",
            scopes=["openid"],
            user_sub="user-1",
            instance_id="instance-1",
            state_key=state_key,
            extra_params={"prompt": "consent"},
        )
        params = parse_qs(urlparse(result.auth_url).query)
        assert params["prompt"][0] == "consent"


class TestCodeExchange:
    @respx.mock
    async def test_successful_exchange(
        self, http_client: httpx.AsyncClient
    ) -> None:
        respx.post("https://idp.example/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": "at-1",
                    "refresh_token": "rt-1",
                    "expires_in": 3600,
                    "scope": "openid Mail.Read",
                    "token_type": "Bearer",
                },
            )
        )
        tokens = await exchange_code_for_tokens(
            token_endpoint="https://idp.example/token",
            client_id="abc",
            client_secret="def",
            redirect_uri="lehen://oauth/callback",
            code="the-code",
            code_verifier="the-verifier",
            http_client=http_client,
            now=1_700_000_000,
        )
        assert tokens.access_token == "at-1"
        assert tokens.refresh_token == "rt-1"
        assert tokens.expires_at == 1_700_003_600
        assert tokens.scope == "openid Mail.Read"

    @respx.mock
    async def test_exchange_rejects_4xx(
        self, http_client: httpx.AsyncClient
    ) -> None:
        respx.post("https://idp.example/token").mock(
            return_value=httpx.Response(
                400, json={"error": "invalid_grant"}
            )
        )
        with pytest.raises(OAuthExchangeError, match="returned 400"):
            await exchange_code_for_tokens(
                token_endpoint="https://idp.example/token",
                client_id="abc",
                client_secret="def",
                redirect_uri="lehen://oauth/callback",
                code="bad",
                code_verifier="v",
                http_client=http_client,
            )

    @respx.mock
    async def test_exchange_rejects_missing_access_token(
        self, http_client: httpx.AsyncClient
    ) -> None:
        respx.post("https://idp.example/token").mock(
            return_value=httpx.Response(
                200, json={"refresh_token": "rt", "expires_in": 3600}
            )
        )
        with pytest.raises(OAuthExchangeError, match="missing access_token"):
            await exchange_code_for_tokens(
                token_endpoint="https://idp.example/token",
                client_id="abc",
                client_secret="def",
                redirect_uri="lehen://oauth/callback",
                code="c",
                code_verifier="v",
                http_client=http_client,
            )

    @respx.mock
    async def test_refresh_works(
        self, http_client: httpx.AsyncClient
    ) -> None:
        respx.post("https://idp.example/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": "at-2",
                    "refresh_token": "rt-2",
                    "expires_in": 3600,
                    "scope": "openid Mail.Read",
                },
            )
        )
        tokens = await refresh_access_token(
            token_endpoint="https://idp.example/token",
            client_id="abc",
            client_secret="def",
            refresh_token="rt-1",
            http_client=http_client,
            now=1_700_000_000,
        )
        assert tokens.access_token == "at-2"
        assert tokens.expires_at == 1_700_003_600


class TestTokenStorage:
    def test_roundtrip_through_dict(self) -> None:
        original = OAuthTokens(
            access_token="at",
            refresh_token="rt",
            expires_at=1_700_003_600,
            scope="openid Mail.Read",
        )
        roundtripped = OAuthTokens.from_storage_dict(original.to_storage_dict())
        assert roundtripped == original

    def test_handles_null_refresh_token(self) -> None:
        # IdPs that don't issue refresh tokens (no offline_access scope etc.)
        original = OAuthTokens(
            access_token="at",
            refresh_token=None,
            expires_at=1_700_003_600,
            scope="openid",
        )
        roundtripped = OAuthTokens.from_storage_dict(original.to_storage_dict())
        assert roundtripped.refresh_token is None
