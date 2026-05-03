"""``POST /admin/local-login`` — emergency-only password authentication.

This endpoint is registered on its own router with **no auth dependency**.
It is the one path on the entire admin surface that accepts unauthenticated
POST. It is rate-limited, audited heavily, and disabled by default in
deployments that have completed the SIAM bootstrap (the auto-disable rule
in ``LocalAdminService.disable_on_siam_admin_login``).

Successful authentication returns a Hub-self-issued JWT scoped to the
admin surface only. The same JWT will be rejected by user-facing
endpoints by issuer claim.
"""

from __future__ import annotations

import time

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

from lehen_hub.admin.local_admin_service import (
    LocalAdminAuthError,
    LocalAdminService,
)

router = APIRouter(tags=["admin"])


class LocalLoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=512)


class LocalLoginResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"  # noqa: S105 — RFC 6750 token type, not a credential
    expires_in: int


def _get_local_admin_service(request: Request) -> LocalAdminService:
    service: LocalAdminService | None = getattr(
        request.app.state, "local_admin_service", None
    )
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="local-admin path is not configured on this Hub",
        )
    return service


@router.post(
    "/admin/local-login",
    response_model=LocalLoginResponse,
    status_code=status.HTTP_200_OK,
)
async def local_login(
    body: LocalLoginRequest,
    request: Request,
) -> LocalLoginResponse:
    service = _get_local_admin_service(request)
    client_ip = request.client.host if request.client else "-"
    user_agent = request.headers.get("user-agent", "-")
    request_id: str = getattr(request.state, "request_id", "")
    try:
        result = await service.login(
            username=body.username,
            password=body.password,
            client_ip=client_ip,
            user_agent=user_agent,
            request_id=request_id or None,
        )
    except LocalAdminAuthError as exc:
        # Single vague reply for every failure mode — no leakage of whether
        # the username exists, whether the account is locked, or whether
        # rate-limiting fired. Audit trail records the actual reason.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authentication failed",
        ) from exc

    expires_in = max(0, int(result.expires_at.timestamp() - time.time()))
    return LocalLoginResponse(
        access_token=result.token,
        expires_in=expires_in,
    )
