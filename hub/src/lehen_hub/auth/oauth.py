"""Generic OAuth-2 authorization-code-with-PKCE helper.

Provider-agnostic. The Hub uses this helper to drive every Sprint-2-and-later
``SourceAdapter`` OAuth flow against external IdPs (Microsoft Graph, Slack,
ServiceNow, ...). It also issues the OAuth ``state`` parameter as an
AES-256-GCM encrypted envelope of ``(user_sub, instance_id, nonce, issued_at,
code_verifier, redirect_uri)`` so the Hub callback handler can validate
everything statelessly without a per-flow DB record.

Choice of authenticated encryption over the originally-planned HMAC (Sprint 2
§3.7) is strictly stronger: GCM provides both integrity and confidentiality,
which means the embedded PKCE ``code_verifier`` is hidden even from a passive
network observer who captures the URL. Verification (HMAC-only) would have
required either a separate DB-backed flow record or an ad-hoc encryption
layer for the verifier; AES-GCM eliminates both.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
import urllib.parse
from dataclasses import asdict, dataclass
from typing import Any

import httpx

from lehen_hub.crypto import decrypt, encrypt

DEFAULT_STATE_MAX_AGE_SECONDS = 600  # 10 minutes between initiate and complete
_HTTP_OK = 200


class OAuthStateError(ValueError):
    """The OAuth ``state`` parameter is missing, malformed, expired, or tampered."""


class OAuthExchangeError(RuntimeError):
    """The token endpoint returned a non-success response or an unexpected body."""


@dataclass(frozen=True)
class OAuthFlowState:
    """The opaque-to-the-IdP context the Hub embeds in ``state``.

    On callback, the Hub decrypts this back out and uses it to:

    * Confirm the calling user matches ``user_sub`` (defense in depth — the
      bearer-token user must equal the user who initiated the flow).
    * Confirm the path-bound ``instance_id`` matches.
    * Reject expired flows via ``issued_at``.
    * Provide the original ``redirect_uri`` to the token exchange — must
      match what was sent in the auth request, per RFC 6749 §4.1.3.
    * Provide the PKCE ``code_verifier`` for code-exchange.
    """

    user_sub: str
    instance_id: str
    nonce: str
    issued_at: int
    code_verifier: str
    redirect_uri: str


def _b64url_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def generate_pkce() -> tuple[str, str]:
    """Generate a PKCE pair.

    Returns ``(code_verifier, code_challenge)``. The verifier is ~43 chars of
    url-safe-base64-without-padding (~256 bits of entropy); the challenge is
    its SHA-256 digest, also url-safe-base64-without-padding, per RFC 7636.
    """
    verifier = _b64url_no_pad(secrets.token_bytes(32))
    challenge = _b64url_no_pad(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def encode_state(flow: OAuthFlowState, *, key: bytes) -> str:
    """AES-GCM encrypt the flow state. Output is url-safe-base64 envelope
    consumable by ``decode_state`` and safe to put into a query string."""
    payload = json.dumps(asdict(flow), separators=(",", ":"), sort_keys=True)
    return encrypt(payload, key=key)


def decode_state(
    encoded: str,
    *,
    key: bytes,
    max_age_seconds: int = DEFAULT_STATE_MAX_AGE_SECONDS,
    now: int | None = None,
) -> OAuthFlowState:
    """Decrypt + validate the state envelope.

    Raises ``OAuthStateError`` on:

    * Missing/empty input.
    * Decryption failure (tampering or wrong key).
    * Malformed JSON / missing fields.
    * Age exceeding ``max_age_seconds`` (default 10 minutes).
    """
    if not encoded:
        raise OAuthStateError("missing state")
    try:
        payload = decrypt(encoded, key=key)
    except Exception as exc:
        raise OAuthStateError(f"state decryption failed: {exc}") from exc
    try:
        data = json.loads(payload)
    except (TypeError, ValueError) as exc:
        raise OAuthStateError(f"state payload malformed: {exc}") from exc
    try:
        flow = OAuthFlowState(
            user_sub=str(data["user_sub"]),
            instance_id=str(data["instance_id"]),
            nonce=str(data["nonce"]),
            issued_at=int(data["issued_at"]),
            code_verifier=str(data["code_verifier"]),
            redirect_uri=str(data["redirect_uri"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise OAuthStateError(f"state missing required field: {exc}") from exc
    now_ts = now if now is not None else int(time.time())
    if now_ts - flow.issued_at > max_age_seconds:
        raise OAuthStateError(
            f"state expired (age {now_ts - flow.issued_at}s > {max_age_seconds}s)"
        )
    if flow.issued_at > now_ts + 60:
        raise OAuthStateError("state issued_at is in the future")
    return flow


@dataclass(frozen=True)
class OAuthAuthorizationRequest:
    """The result of building an authorization request: the URL to redirect
    the user to, plus the encrypted state to round-trip back through the IdP."""

    auth_url: str
    state: str


def build_authorization_url(
    *,
    auth_endpoint: str,
    client_id: str,
    redirect_uri: str,
    scopes: list[str],
    user_sub: str,
    instance_id: str,
    state_key: bytes,
    extra_params: dict[str, str] | None = None,
    nonce: str | None = None,
    issued_at: int | None = None,
) -> OAuthAuthorizationRequest:
    """Construct the authorization URL and encrypted state for an OAuth flow.

    The caller redirects the user's browser to ``auth_url``. After consent,
    the IdP redirects to ``redirect_uri`` with ``code`` and ``state`` query
    parameters; the Hub callback decodes the state and exchanges the code.
    """
    code_verifier, code_challenge = generate_pkce()
    flow = OAuthFlowState(
        user_sub=user_sub,
        instance_id=instance_id,
        nonce=nonce or _b64url_no_pad(secrets.token_bytes(16)),
        issued_at=issued_at if issued_at is not None else int(time.time()),
        code_verifier=code_verifier,
        redirect_uri=redirect_uri,
    )
    state = encode_state(flow, key=state_key)
    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": " ".join(scopes),
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    if extra_params:
        params.update(extra_params)
    auth_url = f"{auth_endpoint}?{urllib.parse.urlencode(params)}"
    return OAuthAuthorizationRequest(auth_url=auth_url, state=state)


@dataclass(frozen=True)
class OAuthTokens:
    """The result of a successful code-exchange or refresh."""

    access_token: str
    refresh_token: str | None
    expires_at: int  # unix timestamp
    scope: str
    token_type: str = "Bearer"  # noqa: S105 — RFC 6749 token type label, not a credential

    def to_storage_dict(self) -> dict[str, Any]:
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "expires_at": self.expires_at,
            "scope": self.scope,
            "token_type": self.token_type,
        }

    @classmethod
    def from_storage_dict(cls, data: dict[str, Any]) -> OAuthTokens:
        return cls(
            access_token=str(data["access_token"]),
            refresh_token=(
                str(data["refresh_token"])
                if data.get("refresh_token") is not None
                else None
            ),
            expires_at=int(data["expires_at"]),
            scope=str(data.get("scope", "")),
            token_type=str(data.get("token_type", "Bearer")),
        )


async def exchange_code_for_tokens(
    *,
    token_endpoint: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    code: str,
    code_verifier: str,
    http_client: httpx.AsyncClient,
    now: int | None = None,
) -> OAuthTokens:
    """Exchange an authorization code for an access + refresh token pair."""
    body = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }
    return await _post_token_endpoint(
        url=token_endpoint, body=body, http_client=http_client, now=now
    )


async def refresh_access_token(
    *,
    token_endpoint: str,
    client_id: str,
    client_secret: str,
    refresh_token: str,
    http_client: httpx.AsyncClient,
    now: int | None = None,
) -> OAuthTokens:
    """Use a refresh token to obtain a fresh access token."""
    body = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token,
    }
    return await _post_token_endpoint(
        url=token_endpoint, body=body, http_client=http_client, now=now
    )


async def _post_token_endpoint(
    *,
    url: str,
    body: dict[str, str],
    http_client: httpx.AsyncClient,
    now: int | None,
) -> OAuthTokens:
    try:
        resp = await http_client.post(
            url,
            data=body,
            headers={"Accept": "application/json"},
            timeout=10.0,
        )
    except httpx.HTTPError as exc:
        raise OAuthExchangeError(f"token endpoint unreachable: {exc}") from exc
    if resp.status_code != _HTTP_OK:
        raise OAuthExchangeError(
            f"token endpoint returned {resp.status_code}: {resp.text[:200]}"
        )
    try:
        data = resp.json()
    except ValueError as exc:
        raise OAuthExchangeError(f"token endpoint returned non-JSON: {exc}") from exc
    if "access_token" not in data:
        raise OAuthExchangeError(
            f"token endpoint response missing access_token: keys={list(data.keys())}"
        )
    issued_at = now if now is not None else int(time.time())
    expires_in = int(data.get("expires_in", 3600))
    return OAuthTokens(
        access_token=str(data["access_token"]),
        refresh_token=(
            str(data["refresh_token"])
            if data.get("refresh_token") is not None
            else None
        ),
        expires_at=issued_at + expires_in,
        scope=str(data.get("scope", "")),
        token_type=str(data.get("token_type", "Bearer")),
    )
