"""Admin self-check: returns the caller's identity and admin role membership.

Auth is enforced at the parent admin router via ``dependencies=[Depends(require_admin)]``.
"""

from __future__ import annotations

from fastapi import APIRouter

from lehen_hub.auth.dependencies import CurrentUserDep

router = APIRouter()


@router.get("/whoami")
async def whoami(user: CurrentUserDep) -> dict[str, object]:
    return {
        "ok": True,
        "sub": user.sub,
        "username": user.username,
        "realm_roles": sorted(user.realm_roles),
    }
