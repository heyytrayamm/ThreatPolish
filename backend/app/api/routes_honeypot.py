"""Decoy profile and honeypot session read models."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import text

from ..auth.rbac import Principal
from ..core.security import iso, utcnow
from ..db.database import connection
from ..deception.profiles import list_profiles
from .deps import require

router = APIRouter(tags=["honeypot"])


@router.get("/honeypot/profiles")
def profiles(principal: Principal = Depends(require("honeypot:read"))) -> dict[str, Any]:
    return {
        "items": list_profiles(),
        "note": (
            "Profiles are declarative data. Only enabled HTTP profiles may be "
            "selected by adaptive investigations."
        ),
    }


@router.get("/honeypot/sessions")
def sessions(
    hours: int = Query(default=24, ge=1, le=720),
    limit: int = Query(default=50, ge=1, le=200),
    principal: Principal = Depends(require("honeypot:read")),
) -> dict[str, Any]:
    since = iso(utcnow() - timedelta(hours=hours))
    with connection() as conn:
        rows = conn.execute(
            text(
                "SELECT session_id, MIN(occurred_at) AS first_seen, MAX(occurred_at) AS last_seen, "
                "COUNT(*) AS events, COUNT(DISTINCT source_ip) AS ips, MAX(CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) AS severity_rank, "
                "MAX(target_id) AS target FROM events "
                "WHERE source_module = 'honeypot' AND occurred_at >= :since "
                "AND session_id IS NOT NULL "
                "GROUP BY session_id ORDER BY last_seen DESC LIMIT :limit"
            ),
            {"since": since, "limit": limit},
        ).fetchall()
        session_ids = [row[0] for row in rows]
        ip_rows = []
        if session_ids:
            placeholders = ", ".join(f":s{index}" for index in range(len(session_ids)))
            ip_params = {
                f"s{index}": session_id for index, session_id in enumerate(session_ids)
            }
            ip_params["since"] = since
            ip_rows = conn.execute(
                text(
                    "SELECT session_id, source_ip FROM events "
                    "WHERE source_module = 'honeypot' AND occurred_at >= :since "
                    f"AND session_id IN ({placeholders}) AND source_ip IS NOT NULL"
                ),
                ip_params,
            ).fetchall()
    by_session: dict[str, set[str]] = {}
    for session_id, ip in ip_rows:
        by_session.setdefault(session_id, set()).add(ip)
    return {
        "window_hours": hours,
        "items": [
            {
                "session_id": row[0],
                "first_seen": row[1],
                "last_seen": row[2],
                "events": int(row[3]),
                "source_ips": sorted(by_session.get(row[0], set())),
                "severity": ["info", "low", "medium", "high", "critical"][int(row[5] or 0)],
                "target": row[6],
            }
            for row in rows
        ],
        "note": "Sessions are observed interactions with decoy services.",
    }
