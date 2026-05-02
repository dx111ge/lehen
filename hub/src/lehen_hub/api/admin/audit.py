"""GET /admin/audit — paginated read of admin audit events.

Auth is enforced at the parent admin router.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

from lehen_hub.api.deps import AdminAuditDep

router = APIRouter()


@router.get("/audit")
async def list_audit(
    audit: AdminAuditDep,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    rows = await audit.list_recent(limit=limit, offset=offset)
    return {"items": rows, "limit": limit, "offset": offset}
