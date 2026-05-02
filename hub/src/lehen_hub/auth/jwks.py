"""Cached JWKS fetch.

The cache holds the parsed JWKS dict for ``ttl_seconds`` (default 600 = 10min).
On fetch failure it enters a short negative-cache window (~30s) so a flapping
Keycloak does not produce one upstream call per inbound request.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx
import structlog


class JWKSFetchError(RuntimeError):
    """Could not fetch the JWKS from Keycloak."""


class JWKSCache:
    """Async-safe TTL+negative cache around a single JWKS endpoint.

    Designed to be held on ``app.state.jwks_cache`` for the lifetime of the app.
    """

    def __init__(
        self,
        jwks_url: str,
        *,
        ttl_seconds: int,
        negative_ttl_seconds: float = 30.0,
        request_timeout_seconds: float = 5.0,
    ) -> None:
        self._url = jwks_url
        self._ttl = ttl_seconds
        self._negative_ttl = negative_ttl_seconds
        self._timeout = request_timeout_seconds
        self._keys: dict[str, Any] | None = None
        self._fetched_at: float = 0.0
        self._negative_until: float = 0.0
        self._lock = asyncio.Lock()
        self._log = structlog.get_logger(__name__)

    async def get_keys(self, client: httpx.AsyncClient) -> dict[str, Any]:
        now = time.monotonic()
        if self._keys is not None and now - self._fetched_at < self._ttl:
            return self._keys
        if now < self._negative_until:
            raise JWKSFetchError("recent JWKS fetch failed; in negative-cache window")

        async with self._lock:
            now = time.monotonic()
            if self._keys is not None and now - self._fetched_at < self._ttl:
                return self._keys
            try:
                response = await client.get(self._url, timeout=self._timeout)
                response.raise_for_status()
                payload = response.json()
            except (httpx.HTTPError, ValueError) as exc:
                self._negative_until = now + self._negative_ttl
                self._log.warning("hub.auth.jwks_fetch_failed", url=self._url, error=str(exc))
                raise JWKSFetchError(f"failed to fetch JWKS from {self._url}: {exc}") from exc

            if not isinstance(payload, dict) or "keys" not in payload:
                self._negative_until = now + self._negative_ttl
                raise JWKSFetchError(f"JWKS response from {self._url} is malformed")

            self._keys = payload
            self._fetched_at = now
            self._log.info(
                "hub.auth.jwks_fetched",
                url=self._url,
                key_count=len(payload.get("keys", [])),
            )
            return self._keys

    async def warm(self, client: httpx.AsyncClient) -> None:
        """Fetch once at startup so the first protected request doesn't pay the latency."""
        try:
            await self.get_keys(client)
        except JWKSFetchError as exc:
            # Don't fail startup — mark negative-cached and let runtime retry.
            self._log.warning("hub.auth.jwks_warm_failed", error=str(exc))

    def invalidate(self) -> None:
        """Force the next ``get_keys`` to re-fetch. Useful in tests."""
        self._keys = None
        self._fetched_at = 0.0
        self._negative_until = 0.0
