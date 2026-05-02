"""GET / PUT /admin/llm — current LLMConfig singleton.

Auth is enforced at the parent admin router.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from lehen_hub.admin.llm_service import LLMConfigNotFoundError
from lehen_hub.api.deps import LLMServiceDep, RequestIdDep
from lehen_hub.auth.dependencies import CurrentUserDep

router = APIRouter()


class LLMConfigResponse(BaseModel):
    inference_provider: str
    inference_model: str
    inference_base_url: str
    embedding_provider: str
    embedding_model: str
    embedding_base_url: str
    updated_by: str | None = None
    updated_at: str | None = None


class LLMConfigUpdate(BaseModel):
    """Partial update — any subset of the updatable fields is accepted."""

    inference_provider: str | None = None
    inference_model: str | None = None
    inference_base_url: str | None = None
    embedding_provider: str | None = None
    embedding_model: str | None = None
    embedding_base_url: str | None = None


@router.get("/llm", response_model=LLMConfigResponse)
async def get_llm(llm_service: LLMServiceDep) -> dict[str, Any]:
    try:
        return await llm_service.get()
    except LLMConfigNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc


@router.put("/llm", response_model=LLMConfigResponse)
async def update_llm(
    payload: LLMConfigUpdate,
    llm_service: LLMServiceDep,
    request_id: RequestIdDep,
    user: CurrentUserDep,
) -> dict[str, Any]:
    new_values = {k: v for k, v in payload.model_dump().items() if v is not None}
    if not new_values:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="no fields to update",
        )
    try:
        return await llm_service.update(
            actor=user, new_values=new_values, request_id=request_id
        )
    except (ValueError, LLMConfigNotFoundError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
