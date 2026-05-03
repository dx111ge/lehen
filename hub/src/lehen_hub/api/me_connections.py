"""User-facing /me/connections endpoints.

Sprint 2 adds the two-step OAuth flow against ``SourceAdapter`` IdPs:

* ``POST /me/connections/{id}/initiate`` — Hub builds an authorization URL
  and returns it plus an encrypted state. The Edge redirects the user's
  browser there.
* ``POST /me/connections/{id}/complete`` — Edge forwards the IdP callback's
  ``code`` and ``state``; the Hub exchanges, fetches identity, persists the
  ``IntegrationConnection`` with real ``encrypted_credentials``.

The Sprint 1 single-shot ``POST /me/connections/{id}`` stays for stub flows
(types whose adapters don't ship in this sprint, e.g., ``outlook-edge-com``).
"""

from __future__ import annotations

from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

from lehen_hub.api.deps import ConnectionsServiceDep, RequestIdDep
from lehen_hub.auth.dependencies import CurrentUserDep
from lehen_hub.auth.oauth import OAuthExchangeError, OAuthStateError
from lehen_hub.integrations.source_adapter import (
    SourceAdapterError,
    SourceAdapterNotImplementedError,
)
from lehen_hub.user.connections_service import (
    ConnectionAlreadyExistsError,
    ConnectionNotFoundError,
    IntegrationDisabledError,
    IntegrationNotAuthorizedForRoleError,
    OAuthFlowConfigError,
    RedirectUriNotAllowedError,
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
    except IntegrationNotAuthorizedForRoleError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
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


class InitiateGrantBody(BaseModel):
    redirect_uri: str = Field(min_length=1, max_length=512)


class InitiateGrantResponse(BaseModel):
    auth_url: str
    state: str


class CompleteGrantBody(BaseModel):
    code: str = Field(min_length=1, max_length=4096)
    state: str = Field(min_length=1, max_length=8192)


@router.post(
    "/connections/{integration_instance_id}/initiate",
    response_model=InitiateGrantResponse,
    status_code=status.HTTP_200_OK,
)
async def initiate_grant_my_connection(
    integration_instance_id: str,
    payload: InitiateGrantBody,
    user: CurrentUserDep,
    connections: ConnectionsServiceDep,
) -> InitiateGrantResponse:
    """Begin an OAuth-2 PKCE flow against the instance's source IdP."""
    try:
        result = await connections.initiate_grant(
            user=user,
            integration_instance_id=integration_instance_id,
            redirect_uri=payload.redirect_uri,
        )
    except ConnectionNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except IntegrationNotAuthorizedForRoleError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except IntegrationDisabledError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except RedirectUriNotAllowedError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except OAuthFlowConfigError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except SourceAdapterNotImplementedError as exc:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED, detail=str(exc)
        ) from exc
    return InitiateGrantResponse(**result)


@router.post(
    "/connections/{integration_instance_id}/complete",
    status_code=status.HTTP_201_CREATED,
)
async def complete_grant_my_connection(
    integration_instance_id: str,
    payload: CompleteGrantBody,
    request: Request,
    user: CurrentUserDep,
    request_id: RequestIdDep,
    connections: ConnectionsServiceDep,
) -> dict[str, Any]:
    """Consume the OAuth callback's ``code`` + ``state`` and persist the
    real ``IntegrationConnection``."""
    http_client: httpx.AsyncClient | None = getattr(
        request.app.state, "http", None
    )
    if http_client is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="http client not initialized",
        )
    try:
        return await connections.complete_grant(
            user=user,
            integration_instance_id=integration_instance_id,
            code=payload.code,
            state=payload.state,
            http_client=http_client,
            request_id=request_id,
        )
    except OAuthStateError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except ConnectionNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except IntegrationNotAuthorizedForRoleError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except IntegrationDisabledError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ConnectionAlreadyExistsError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except OAuthFlowConfigError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except OAuthExchangeError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    except SourceAdapterError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    except SourceAdapterNotImplementedError as exc:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED, detail=str(exc)
        ) from exc
