"""Hub-self-issued JWT (HS256) — issue, decode, edge cases."""

from __future__ import annotations

import secrets as stdlib_secrets
import time
from typing import Any

import pytest
from jose import jwt as jose_jwt

from lehen_hub.auth.local_jwt import (
    LOCAL_ISSUER,
    LOCAL_SCOPE_ADMIN,
    LocalTokenError,
    decode_local_admin_token,
    issue_local_admin_token,
    peek_unverified_issuer,
)


@pytest.fixture
def signing_key() -> bytes:
    return stdlib_secrets.token_bytes(32)


class TestRoundTrip:
    def test_valid_token_roundtrips(self, signing_key: bytes) -> None:
        token = issue_local_admin_token(
            username="admin", signing_key=signing_key, ttl_seconds=300
        )
        claims = decode_local_admin_token(token, signing_key=signing_key)
        assert claims["sub"] == "admin"
        assert claims["preferred_username"] == "admin"
        assert claims["iss"] == LOCAL_ISSUER
        assert claims["scope"] == LOCAL_SCOPE_ADMIN

    def test_issuer_claim_is_lehen_hub_local(self, signing_key: bytes) -> None:
        token = issue_local_admin_token(
            username="admin", signing_key=signing_key, ttl_seconds=300
        )
        # Decode without verification to confirm the literal string
        unverified = jose_jwt.get_unverified_claims(token)
        assert unverified["iss"] == "lehen-hub-local"


class TestRejection:
    def test_wrong_signing_key_rejected(self, signing_key: bytes) -> None:
        token = issue_local_admin_token(
            username="admin", signing_key=signing_key, ttl_seconds=300
        )
        wrong_key = stdlib_secrets.token_bytes(32)
        with pytest.raises(LocalTokenError, match="signature"):
            decode_local_admin_token(token, signing_key=wrong_key)

    def test_expired_token_rejected(self, signing_key: bytes) -> None:
        # Manually craft a token with an expiry in the past
        now = int(time.time())
        claims: dict[str, Any] = {
            "sub": "admin",
            "preferred_username": "admin",
            "iss": LOCAL_ISSUER,
            "aud": "lehen-hub-admin",
            "scope": LOCAL_SCOPE_ADMIN,
            "iat": now - 7200,
            "exp": now - 3600,
        }
        token = jose_jwt.encode(claims, signing_key, algorithm="HS256")
        with pytest.raises(LocalTokenError, match="expired"):
            decode_local_admin_token(token, signing_key=signing_key)

    def test_wrong_issuer_rejected(self, signing_key: bytes) -> None:
        # A token signed with our key but claiming a different issuer must
        # not pass — protects against accidental cross-issuance bugs.
        now = int(time.time())
        claims: dict[str, Any] = {
            "sub": "admin",
            "iss": "http://attacker/realms/evil",
            "aud": "lehen-hub-admin",
            "scope": LOCAL_SCOPE_ADMIN,
            "iat": now,
            "exp": now + 300,
        }
        token = jose_jwt.encode(claims, signing_key, algorithm="HS256")
        with pytest.raises(LocalTokenError, match="claim verification"):
            decode_local_admin_token(token, signing_key=signing_key)

    def test_wrong_audience_rejected(self, signing_key: bytes) -> None:
        # A SIAM-shaped audience must not pass — the local-admin audience
        # is namespace-distinct so SIAM-token-shaped audiences fail closed.
        now = int(time.time())
        claims: dict[str, Any] = {
            "sub": "admin",
            "iss": LOCAL_ISSUER,
            "aud": "lehen-hub",  # SIAM audience, not local-admin audience
            "scope": LOCAL_SCOPE_ADMIN,
            "iat": now,
            "exp": now + 300,
        }
        token = jose_jwt.encode(claims, signing_key, algorithm="HS256")
        with pytest.raises(LocalTokenError, match="claim verification"):
            decode_local_admin_token(token, signing_key=signing_key)

    def test_wrong_scope_rejected(self, signing_key: bytes) -> None:
        now = int(time.time())
        claims: dict[str, Any] = {
            "sub": "admin",
            "iss": LOCAL_ISSUER,
            "aud": "lehen-hub-admin",
            "scope": "user",  # not "admin"
            "iat": now,
            "exp": now + 300,
        }
        token = jose_jwt.encode(claims, signing_key, algorithm="HS256")
        with pytest.raises(LocalTokenError, match="unexpected scope"):
            decode_local_admin_token(token, signing_key=signing_key)

    def test_empty_token_rejected(self, signing_key: bytes) -> None:
        with pytest.raises(LocalTokenError, match="empty"):
            decode_local_admin_token("", signing_key=signing_key)


class TestPeekUnverifiedIssuer:
    def test_reads_issuer_from_local_token(self, signing_key: bytes) -> None:
        token = issue_local_admin_token(
            username="admin", signing_key=signing_key, ttl_seconds=300
        )
        assert peek_unverified_issuer(token) == LOCAL_ISSUER

    def test_reads_issuer_from_siam_shaped_token(self) -> None:
        # No verification — just unverified claim peek
        siam_token = jose_jwt.encode(
            {
                "iss": "http://test-keycloak/realms/lehen",
                "aud": "lehen-hub",
                "exp": int(time.time()) + 300,
            },
            "any-secret",
            algorithm="HS256",
        )
        assert (
            peek_unverified_issuer(siam_token)
            == "http://test-keycloak/realms/lehen"
        )

    def test_garbage_token_returns_none(self) -> None:
        assert peek_unverified_issuer("not.a.token") is None

    def test_empty_token_returns_none(self) -> None:
        assert peek_unverified_issuer("") is None
