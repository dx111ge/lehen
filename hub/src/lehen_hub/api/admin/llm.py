"""GET /admin/llm/providers — registry for the admin UI dropdown.
GET / PUT /admin/llm — current LLMConfig (structured shape).

Auth is enforced at the parent admin router.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from lehen_hub.admin.llm_service import LLMConfigError, LLMConfigNotFoundError
from lehen_hub.api.deps import LLMServiceDep, RequestIdDep
from lehen_hub.auth.dependencies import CurrentUserDep
from lehen_hub.llm.providers import LLM_PROVIDERS

router = APIRouter()


class LLMProviderFieldDescriptor(BaseModel):
    name: str
    label: str
    field_type: str
    required: bool
    secret: bool
    placeholder: str | None
    description: str | None


class LLMProviderDescriptor(BaseModel):
    id: str
    display_name: str
    description: str
    fields: list[LLMProviderFieldDescriptor]


class LLMSidePayload(BaseModel):
    """Provider-driven payload for one side (inference or embedding).

    The ``provider`` key picks which provider's field-spec applies; the rest
    of the keys are validated against that provider's field list. ``api_key``
    is optional on update — only send it to set/change/clear it. Empty string
    explicitly clears a previously-set api_key.
    """

    model_config = {"extra": "allow"}

    provider: str = Field(min_length=1)


class LLMConfigUpdate(BaseModel):
    inference: LLMSidePayload | None = None
    embedding: LLMSidePayload | None = None


@router.get("/llm/providers", response_model=list[LLMProviderDescriptor])
async def list_providers() -> list[dict[str, Any]]:
    return [
        {
            "id": p.id,
            "display_name": p.display_name,
            "description": p.description,
            "fields": [
                {
                    "name": f.name,
                    "label": f.label,
                    "field_type": f.field_type,
                    "required": f.required,
                    "secret": f.secret,
                    "placeholder": f.placeholder,
                    "description": f.description,
                }
                for f in p.fields
            ],
        }
        for p in LLM_PROVIDERS
    ]


@router.get("/llm")
async def get_llm(llm_service: LLMServiceDep) -> dict[str, Any]:
    try:
        return await llm_service.get()
    except LLMConfigNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc


@router.put("/llm")
async def update_llm(
    payload: LLMConfigUpdate,
    llm_service: LLMServiceDep,
    request_id: RequestIdDep,
    user: CurrentUserDep,
) -> dict[str, Any]:
    if payload.inference is None and payload.embedding is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="at least one of 'inference' or 'embedding' must be provided",
        )
    try:
        return await llm_service.update(
            actor=user,
            inference=payload.inference.model_dump() if payload.inference else None,
            embedding=payload.embedding.model_dump() if payload.embedding else None,
            request_id=request_id,
        )
    except (LLMConfigError, LLMConfigNotFoundError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
