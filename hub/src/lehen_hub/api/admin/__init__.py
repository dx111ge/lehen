"""Admin sub-app: aggregates the four panes' routers under ``/admin``.

Authorization is applied at this aggregator level: ``Depends(require_admin)``
gates every child route, so individual handlers don't need to repeat the gate.
Handlers that need the verified user object inject ``CurrentUserDep``; the
result is cached per-request by FastAPI, so the auth flow runs once.
"""

from fastapi import APIRouter, Depends

from lehen_hub.api.admin.audit import router as audit_router
from lehen_hub.api.admin.integrations import router as integrations_router
from lehen_hub.api.admin.llm import router as llm_router
from lehen_hub.api.admin.siam import router as siam_router
from lehen_hub.api.admin.whoami import router as whoami_router
from lehen_hub.auth.dependencies import require_admin

router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(require_admin)],
)
router.include_router(whoami_router)
router.include_router(llm_router)
router.include_router(integrations_router)
router.include_router(siam_router)
router.include_router(audit_router)
