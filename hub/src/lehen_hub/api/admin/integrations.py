"""CRUD for IntegrationInstance + read-only registry of integration types.

Auth is enforced at the parent admin router.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from lehen_hub.admin.integrations_service import (
    IntegrationConfigError,
    IntegrationInstanceConflictError,
    IntegrationInstanceNotFoundError,
)
from lehen_hub.api.deps import IntegrationsServiceDep, RequestIdDep
from lehen_hub.auth.dependencies import CurrentUserDep
from lehen_hub.integrations.registry import INTEGRATION_TYPES

router = APIRouter()


class IntegrationFieldDescriptor(BaseModel):
    name: str
    label: str
    field_type: str
    required: bool
    secret: bool
    placeholder: str | None
    description: str | None


class IntegrationTypeDescriptor(BaseModel):
    id: str
    display_name: str
    description: str
    fields: list[IntegrationFieldDescriptor]


class IntegrationInstanceCreate(BaseModel):
    id: str = Field(min_length=1, max_length=128)
    type: str
    display_name: str = Field(min_length=1, max_length=200)
    config: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    multi_connection_allowed: bool = False


class IntegrationInstanceUpdate(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=200)
    config: dict[str, Any] | None = None
    enabled: bool | None = None
    multi_connection_allowed: bool | None = None


@router.get("/integrations/types", response_model=list[IntegrationTypeDescriptor])
async def list_types() -> list[dict[str, Any]]:
    return [
        {
            "id": t.id,
            "display_name": t.display_name,
            "description": t.description,
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
                for f in t.fields
            ],
        }
        for t in INTEGRATION_TYPES
    ]


@router.get("/integrations")
async def list_instances(integrations: IntegrationsServiceDep) -> list[dict[str, Any]]:
    return await integrations.list()


@router.post("/integrations", status_code=status.HTTP_201_CREATED)
async def create_instance(
    payload: IntegrationInstanceCreate,
    integrations: IntegrationsServiceDep,
    request_id: RequestIdDep,
    user: CurrentUserDep,
) -> dict[str, Any]:
    try:
        return await integrations.create(
            actor=user,
            instance_id=payload.id,
            type_id=payload.type,
            display_name=payload.display_name,
            config=payload.config,
            multi_connection_allowed=payload.multi_connection_allowed,
            enabled=payload.enabled,
            request_id=request_id,
        )
    except IntegrationInstanceConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except IntegrationConfigError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.put("/integrations/{instance_id}")
async def update_instance(
    instance_id: str,
    payload: IntegrationInstanceUpdate,
    integrations: IntegrationsServiceDep,
    request_id: RequestIdDep,
    user: CurrentUserDep,
) -> dict[str, Any]:
    if not any(
        v is not None
        for v in (
            payload.display_name,
            payload.config,
            payload.enabled,
            payload.multi_connection_allowed,
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="no fields to update",
        )
    try:
        return await integrations.update(
            actor=user,
            instance_id=instance_id,
            display_name=payload.display_name,
            config=payload.config,
            enabled=payload.enabled,
            multi_connection_allowed=payload.multi_connection_allowed,
            request_id=request_id,
        )
    except IntegrationInstanceNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"integration instance not found: {exc}",
        ) from exc
    except IntegrationConfigError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.delete("/integrations/{instance_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_instance(
    instance_id: str,
    integrations: IntegrationsServiceDep,
    request_id: RequestIdDep,
    user: CurrentUserDep,
) -> None:
    try:
        await integrations.delete(actor=user, instance_id=instance_id, request_id=request_id)
    except IntegrationInstanceNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"integration instance not found: {exc}",
        ) from exc
