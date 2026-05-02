"""User-facing /me/connections endpoints.

In v1 the Connect button creates a stub IntegrationConnection (no real OAuth)
and records a ConsentEvent. Disconnect marks the row disconnected_at and
records a ConsentEvent. The ``access-token`` endpoint is reserved for the
future SourceAdapters and returns 501 in v1.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from lehen_hub.api.deps import ConnectionsServiceDep, RequestIdDep
from lehen_hub.auth.dependencies import CurrentUserDep
from lehen_hub.user.connections_service import (
    ConnectionAlreadyExistsError,
    ConnectionNotFoundError,
    IntegrationDisabledError,
)

router = APIRouter(prefix="/me", tags=["me"])


class ConnectionGrantBody(BaseModel):
    privacy_class: str = Field(default="company", pattern=r"^(company|excluded)$")


@router.get("/connections")
async def list_my_connections(
    user: CurrentUserDep,
    connections: ConnectionsServiceDep,
) -> list[dict[str, Any]]:
    rows = await connections.list_for_user(user.sub)
    rows.sort(key=lambda r: r["integration_instance_id"])  # A10
    return rows


@router.post("/connections/{integration_instance_id}", status_code=status.HTTP_201_CREATED)
async def grant_my_connection(
    integration_instance_id: str,
    payload: ConnectionGrantBody,
    user: CurrentUserDep,
    request_id: RequestIdDep,
    connections: ConnectionsServiceDep,
) -> dict[str, Any]:
    try:
        return await connections.grant(
            user=user,
            integration_instance_id=integration_instance_id,
            privacy_class=payload.privacy_class,
            request_id=request_id,
        )
    except ConnectionNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except IntegrationDisabledError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ConnectionAlreadyExistsError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.delete("/connections/{integration_instance_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_my_connection(
    integration_instance_id: str,
    user: CurrentUserDep,
    request_id: RequestIdDep,
    connections: ConnectionsServiceDep,
) -> None:
    try:
        await connections.revoke(
            user=user,
            integration_instance_id=integration_instance_id,
            request_id=request_id,
        )
    except ConnectionNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.post(
    "/connections/{integration_instance_id}/access-token",
    status_code=status.HTTP_501_NOT_IMPLEMENTED,
)
async def issue_access_token(
    integration_instance_id: str,
    user: CurrentUserDep,
) -> dict[str, str]:
    """Reserved for future SourceAdapters. v1 returns 501."""
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=(
            f"access-token issuance not implemented in v1 (asked for {integration_instance_id}); "
            "reserved for future SourceAdapter integration."
        ),
    )
