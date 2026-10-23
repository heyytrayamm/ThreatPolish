"""Audit trail read endpoint."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import text

from ..auth.rbac import Principal
from ..core.audit import parse_detail
from ..db.database import connection
from .deps import require

router = APIRouter(tags=["audit"])


@router.get("/audit")
def audit_entries(
    limit: int = Query(default=100, ge=1, le=500),
    action: str | None = Query(default=None, max_length=80),
    principal: Principal = Depends(require("audit:read")),
) -> dict[str, Any]:
    clauses = ["1 = 1"]
    params: dict[str, Any] = {"limit": limit}
    if action:
        clauses.append("action LIKE :action")
        params["action"] = f"{action}%"
    with connection() as conn:
        rows = conn.execute(
            text(
                "SELECT id, ts, actor_id, actor_role, action, object_type, object_id, "
                "outcome, detail, request_ip FROM audit_log WHERE "
                + " AND ".join(clauses)
                + " ORDER BY ts DESC LIMIT :limit"
            ),
            params,
        ).fetchall()
    return {
        "items": [
            {
                "id": row[0],
                "ts": row[1],
                "actor_id": row[2],
                "actor_role": row[3],
                "action": row[4],
                "object_type": row[5],
                "object_id": row[6],
                "outcome": row[7],
                "detail": parse_detail(row[8]),
                "request_ip": row[9],
            }
            for row in rows
        ]
    }
