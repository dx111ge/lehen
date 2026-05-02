"""Shared FastAPI dependencies wiring app-state into request handlers.

The actual instances live on ``app.state.*`` (set up by ``main.lifespan``).
These dependencies just look them up so handlers can declare them as
``Annotated[X, Depends(get_x)]``.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status

from lehen_hub.admin import (
    AdminAuditService,
    IntegrationsService,
    LLMService,
    SIAMService,
)
from lehen_hub.storage.arcade import ArcadeClient
from lehen_hub.user import MeService, UserConnectionsService


def _state(request: Request, attr: str) -> object:
    value = getattr(request.app.state, attr, None)
    if value is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"app.state.{attr} not initialized",
        )
    return value


def get_arcade(request: Request) -> ArcadeClient:
    return _state(request, "arcade")  # type: ignore[return-value]


def get_admin_audit(request: Request) -> AdminAuditService:
    return _state(request, "admin_audit")  # type: ignore[return-value]


def get_llm_service(request: Request) -> LLMService:
    return _state(request, "llm_service")  # type: ignore[return-value]


def get_integrations_service(request: Request) -> IntegrationsService:
    return _state(request, "integrations_service")  # type: ignore[return-value]


def get_siam_service(request: Request) -> SIAMService:
    return _state(request, "siam_service")  # type: ignore[return-value]


def get_connections_service(request: Request) -> UserConnectionsService:
    return _state(request, "connections_service")  # type: ignore[return-value]


def get_me_service(request: Request) -> MeService:
    return _state(request, "me_service")  # type: ignore[return-value]


def get_request_id(request: Request) -> str:
    """Fetch a per-request id. Set by the request-id middleware in main.py;
    if missing (e.g., direct test client without middleware), generate a fresh uuid."""
    return getattr(request.state, "request_id", None) or str(uuid.uuid4())


ArcadeDep = Annotated[ArcadeClient, Depends(get_arcade)]
AdminAuditDep = Annotated[AdminAuditService, Depends(get_admin_audit)]
LLMServiceDep = Annotated[LLMService, Depends(get_llm_service)]
IntegrationsServiceDep = Annotated[IntegrationsService, Depends(get_integrations_service)]
SIAMServiceDep = Annotated[SIAMService, Depends(get_siam_service)]
ConnectionsServiceDep = Annotated[UserConnectionsService, Depends(get_connections_service)]
MeServiceDep = Annotated[MeService, Depends(get_me_service)]
RequestIdDep = Annotated[str, Depends(get_request_id)]
