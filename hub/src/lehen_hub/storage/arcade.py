"""Async ArcadeDB HTTP/JSON client.

Two endpoints:
- ``/api/v1/query/{db}``   — read-only SELECT
- ``/api/v1/command/{db}`` — write/DDL/general SQL

Auth: HTTP Basic with the configured ``root`` user. Both endpoints accept
``{"language": "sql", "command": "..."}`` and return ``{"result": [...]}``.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from lehen_hub.config import ArcadeDBSettings

_HTTP_ERROR_FLOOR = 400
_HTTP_OK = 200
_HTTP_NOT_FOUND = 404


class ArcadeError(RuntimeError):
    """Base class for ArcadeDB client errors."""


class ArcadeQueryError(ArcadeError):
    """A SQL command/query against ArcadeDB returned an error response."""


class ArcadeClient:
    """Thin async wrapper around ArcadeDB's HTTP/JSON API.

    One ``ArcadeClient`` instance per app, held on ``app.state.arcade``.
    Backed by a single shared ``httpx.AsyncClient`` (also app-state).
    """

    def __init__(self, *, settings: ArcadeDBSettings, http: httpx.AsyncClient) -> None:
        self._settings = settings
        self._http = http
        self._base = f"{settings.http_url}/api/v1"
        self._auth = (settings.user, settings.password)
        self._db = settings.database
        self._log = structlog.get_logger(__name__)

    @property
    def database(self) -> str:
        return self._db

    async def query(
        self,
        sql: str,
        params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Execute a read-only SELECT. Returns the ``result`` array."""
        return await self._post("query", sql, params)

    async def command(
        self,
        sql: str,
        params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Execute a write/DDL/CREATE/INSERT/UPDATE/DELETE/etc."""
        return await self._post("command", sql, params)

    async def server_command(self, sql: str) -> list[dict[str, Any]]:
        """Execute a server-level command (CREATE DATABASE, etc.) at /api/v1/server.

        Server commands require authentication as a server-admin user (``root``
        in the dev stack).
        """
        url = f"{self._settings.http_url}/api/v1/server"
        body = {"language": "sql", "command": sql}
        try:
            response = await self._http.post(url, auth=self._auth, json=body, timeout=15.0)
        except httpx.HTTPError as exc:
            raise ArcadeError(f"ArcadeDB HTTP request to {url} failed: {exc}") from exc
        if response.status_code >= _HTTP_ERROR_FLOOR:
            self._log.warning(
                "hub.arcade.server_command_error",
                status=response.status_code,
                body=response.text[:500],
            )
            raise ArcadeQueryError(
                f"ArcadeDB server-command {response.status_code}: {response.text[:500]}"
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise ArcadeQueryError(f"ArcadeDB server-command returned non-JSON: {exc}") from exc
        result = payload.get("result")
        if not isinstance(result, list):
            # Some server commands return a dict instead of a list — wrap it.
            return [payload] if isinstance(payload, dict) else []
        return result

    async def database_exists(self) -> bool:
        """Return True if the configured database exists on the server."""
        url = f"{self._settings.http_url}/api/v1/exists/{self._db}"
        try:
            response = await self._http.get(url, auth=self._auth, timeout=10.0)
        except httpx.HTTPError as exc:
            raise ArcadeError(f"ArcadeDB HTTP request to {url} failed: {exc}") from exc
        if response.status_code == _HTTP_OK:
            try:
                return bool(response.json().get("result", False))
            except ValueError:
                return False
        if response.status_code == _HTTP_NOT_FOUND:
            return False
        raise ArcadeQueryError(
            f"ArcadeDB exists-check {response.status_code}: {response.text[:500]}"
        )

    async def _post(
        self,
        endpoint: str,
        sql: str,
        params: dict[str, Any] | None,
    ) -> list[dict[str, Any]]:
        body: dict[str, Any] = {"language": "sql", "command": sql}
        if params:
            body["params"] = params
        url = f"{self._base}/{endpoint}/{self._db}"
        try:
            response = await self._http.post(url, auth=self._auth, json=body, timeout=15.0)
        except httpx.HTTPError as exc:
            raise ArcadeError(f"ArcadeDB HTTP request to {url} failed: {exc}") from exc

        if response.status_code >= _HTTP_ERROR_FLOOR:
            self._log.warning(
                "hub.arcade.query_error",
                status=response.status_code,
                url=url,
                body=response.text[:500],
            )
            raise ArcadeQueryError(
                f"ArcadeDB {endpoint} {response.status_code}: {response.text[:500]}"
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise ArcadeQueryError(f"ArcadeDB {endpoint} returned non-JSON: {exc}") from exc

        result = payload.get("result")
        if not isinstance(result, list):
            raise ArcadeQueryError(
                f"ArcadeDB {endpoint} response missing 'result' array: {payload}"
            )
        return result
