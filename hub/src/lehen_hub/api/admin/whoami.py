"""Admin self-check: returns the caller's identity and admin role membership.

Auth is enforced at the parent admin router via ``dependencies=[Depends(require_admin)]``.
This endpoint also injects ``require_admin`` to receive the resolved
``CurrentUser`` — FastAPI caches dependency results within a request, so the
admin gate runs once. ``CurrentUserDep`` (user surface) cannot be used here:
it rejects Hub-self-issued JWTs by issuer claim per the surface-separation rule.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from lehen_hub.auth.dependencies import CurrentUser, require_admin

router = APIRouter()


@router.get("/whoami")
async def whoami(
    user: Annotated[CurrentUser, Depends(require_admin)],
) -> dict[str, object]:
    return {
        "ok": True,
        "sub": user.sub,
        "username": user.username,
        "realm_roles": sorted(user.realm_roles),
        "identity_source": user.identity_source,
    }
