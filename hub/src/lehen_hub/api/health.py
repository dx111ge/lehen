"""Liveness + readiness probes.

``/health/live``  — process is up. No deps. Cheap and always succeeds.
``/health/ready`` — pings the bootstrap dependencies (ArcadeDB + Keycloak)
                   in parallel; 503 if any fails.

LLM provider health is not in this probe because the LLM provider is
admin-configured in the DB-backed ``LLMConfig`` and is not a bootstrap
dependency. A separate ``/admin/llm/health`` endpoint can ship later if
operators want it surfaced.
"""

from __future__ import annotations

import asyncio
from typing import Annotated, Literal, TypedDict

import httpx
from fastapi import APIRouter, Depends, Response, status

from lehen_hub.config import Settings, get_settings

router = APIRouter(prefix="/health", tags=["health"])

_PROBE_TIMEOUT_SECONDS = 2.0


class CheckResult(TypedDict):
    status: Literal["ok", "fail"]
    detail: str | None


async def _check_http(
    client: httpx.AsyncClient,
    url: str,
    accept_codes: tuple[int, ...],
) -> CheckResult:
    try:
        response = await client.get(url, timeout=_PROBE_TIMEOUT_SECONDS)
    except httpx.HTTPError as exc:
        return {"status": "fail", "detail": f"{type(exc).__name__}: {exc}"}

    if response.status_code in accept_codes:
        return {"status": "ok", "detail": None}
    return {"status": "fail", "detail": f"unexpected HTTP {response.status_code}"}


@router.get("/live")
async def live() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/ready")
async def ready(
    response: Response,
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, object]:
    async with httpx.AsyncClient() as client:
        arcadedb, keycloak = await asyncio.gather(
            _check_http(client, f"{settings.arcadedb.http_url}/api/v1/ready", (200, 204)),
            _check_http(client, settings.keycloak.well_known_url, (200,)),
        )

    checks: dict[str, CheckResult] = {
        "arcadedb": arcadedb,
        "keycloak": keycloak,
    }
    all_ok = all(c["status"] == "ok" for c in checks.values())
    if not all_ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {"status": "ok" if all_ok else "fail", "checks": checks}
