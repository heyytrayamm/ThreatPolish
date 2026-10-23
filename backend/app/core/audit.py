"""Append-only audit trail.

Audit writes are part of the caller's transaction where one exists, so an action
and its audit record commit together or not at all.
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy.engine import Connection

from ..db.database import connection, dumps
from ..db.schema import audit_log
from .security import iso, new_id, utcnow


def record_audit(
    conn: Connection,
    *,
    action: str,
    outcome: str = "success",
    actor_id: str | None = None,
    actor_role: str | None = None,
    object_type: str | None = None,
    object_id: str | None = None,
    detail: dict[str, Any] | None = None,
    request_ip: str | None = None,
) -> str:
    audit_id = new_id("aud")
    conn.execute(
        audit_log.insert().values(
            id=audit_id,
            ts=iso(utcnow()),
            actor_id=actor_id,
            actor_role=actor_role,
            action=action,
            object_type=object_type,
            object_id=object_id,
            outcome=outcome,
            detail=dumps(detail or {}),
            request_ip=request_ip,
        )
    )
    return audit_id


def audit_standalone(**kwargs: Any) -> str:
    """Record an audit entry when no transaction is already open."""
    with connection() as conn:
        return record_audit(conn, **kwargs)


def parse_detail(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}
