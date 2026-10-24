"""Operational visibility for retention and graph size.

The endpoint is read-only and admin-only: it reports how far the retention job
is behind, without exposing event content.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from ..auth.rbac import Principal
from ..db.retention import retention_status
from .deps import require

router = APIRouter(tags=["operations"])


@router.get("/retention")
def retention(principal: Principal = Depends(require("audit:read"))) -> dict[str, Any]:
    return retention_status()
