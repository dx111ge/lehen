"""GET /me — user identity + active roles + allowed integrations + statuses."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from lehen_hub.api.deps import MeServiceDep, RequestIdDep
from lehen_hub.auth.dependencies import CurrentUserDep

router = APIRouter(tags=["me"])


@router.get("/me")
async def me(
    user: CurrentUserDep,
    request_id: RequestIdDep,
    me_service: MeServiceDep,
) -> dict[str, Any]:
    return await me_service.me(user, request_id=request_id)
