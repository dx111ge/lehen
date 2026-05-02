"""GET / PUT /admin/siam — role → integration-instance allowance map.

Auth is enforced at the parent admin router.
"""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from lehen_hub.api.deps import RequestIdDep, SIAMServiceDep
from lehen_hub.auth.dependencies import CurrentUserDep

router = APIRouter()


class SIAMMappingResponse(BaseModel):
    mapping: dict[str, list[str]]


class SIAMMappingUpdate(BaseModel):
    mapping: dict[str, list[str]] = Field(default_factory=dict)


@router.get("/siam", response_model=SIAMMappingResponse)
async def get_siam(siam: SIAMServiceDep) -> dict[str, dict[str, list[str]]]:
    return {"mapping": await siam.get()}


@router.put("/siam", response_model=SIAMMappingResponse)
async def replace_siam(
    payload: SIAMMappingUpdate,
    siam: SIAMServiceDep,
    request_id: RequestIdDep,
    user: CurrentUserDep,
) -> dict[str, dict[str, list[str]]]:
    return {
        "mapping": await siam.replace(
            actor=user, mapping=payload.mapping, request_id=request_id
        )
    }
