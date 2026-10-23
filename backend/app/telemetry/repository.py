"""Read paths for the event store."""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import text

from ..core.errors import ValidationFailure
from ..db.database import connection, loads, query_one
from ..schemas.event import SEVERITY_ORDER

EVENT_COLUMNS = (
    "id, schema_version, occurred_at, received_at, source_module, event_type, source_ip, "
    "session_id, target_id, severity, provenance, features, evidence_refs, raw, status, "
    "correlation_state, synthetic"
)


def row_to_event(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "schema_version": row["schema_version"],
        "occurred_at": row["occurred_at"],
        "received_at": row["received_at"],
        "source_module": row["source_module"],
        "event_type": row["event_type"],
        "source_ip": row["source_ip"],
        "session_id": row["session_id"],
        "target_id": row["target_id"],
        "severity": row["severity"],
        "provenance": loads(row["provenance"], {}),
        "features": loads(row["features"], {}),
        "evidence_refs": loads(row["evidence_refs"], []),
        "raw": loads(row["raw"], {}),
        "status": row["status"],
        "correlation_state": row["correlation_state"],
        "synthetic": bool(row["synthetic"]),
    }


def _filters(
    *,
    source_module: str | None,
    severity: str | None,
    min_severity: str | None,
    source_ip: str | None,
    session_id: str | None,
    event_type: str | None,
    since: str | None,
    until: str | None,
    q: str | None,
) -> tuple[list[str], dict[str, Any]]:
    clauses: list[str] = []
    params: dict[str, Any] = {}
    if source_module:
        clauses.append("source_module = :module")
        params["module"] = source_module
    if severity:
        clauses.append("severity = :severity")
        params["severity"] = severity
    if min_severity:
        if min_severity not in SEVERITY_ORDER:
            raise ValidationFailure(
                "min_severity must be one of info, low, medium, high or critical"
            )
        allowed = [name for name, rank in SEVERITY_ORDER.items() if rank >= SEVERITY_ORDER[min_severity]]
        placeholders = ", ".join(f":sev_{index}" for index in range(len(allowed)))
        clauses.append(f"severity IN ({placeholders})")
        for index, name in enumerate(allowed):
            params[f"sev_{index}"] = name
    if source_ip:
        clauses.append("source_ip = :source_ip")
        params["source_ip"] = source_ip
    if session_id:
        clauses.append("session_id = :session_id")
        params["session_id"] = session_id
    if event_type:
        clauses.append("event_type LIKE :event_type")
        params["event_type"] = f"{event_type}%"
    if since:
        clauses.append("occurred_at >= :since")
        params["since"] = since
    if until:
        clauses.append("occurred_at <= :until")
        params["until"] = until
    if q:
        clauses.append("(target_id LIKE :q OR session_id LIKE :q OR source_ip LIKE :q)")
        params["q"] = f"%{q}%"
    return clauses, params


def list_events(
    *,
    limit: int = 50,
    offset: int = 0,
    source_module: str | None = None,
    severity: str | None = None,
    min_severity: str | None = None,
    source_ip: str | None = None,
    session_id: str | None = None,
    event_type: str | None = None,
    since: str | None = None,
    until: str | None = None,
    q: str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    clauses, params = _filters(
        source_module=source_module,
        severity=severity,
        min_severity=min_severity,
        source_ip=source_ip,
        session_id=session_id,
        event_type=event_type,
        since=since,
        until=until,
        q=q,
    )
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with connection() as conn:
        total = conn.execute(
            text(f"SELECT COUNT(*) FROM events {where}"), params
        ).scalar_one()
        rows = conn.execute(
            text(
                f"SELECT {EVENT_COLUMNS} FROM events {where} "
                "ORDER BY occurred_at DESC, id DESC LIMIT :limit OFFSET :offset"
            ),
            {**params, "limit": limit, "offset": offset},
        ).fetchall()
    return [row_to_event(dict(row._mapping)) for row in rows], int(total)


def get_event(event_id: str) -> dict[str, Any] | None:
    with connection() as conn:
        row = query_one(conn, f"SELECT {EVENT_COLUMNS} FROM events WHERE id = :id", {"id": event_id})
    return row_to_event(row) if row else None


def events_in_window(start: str, end: str, *, limit: int = 50_000) -> list[dict[str, Any]]:
    with connection() as conn:
        rows = conn.execute(
            text(
                f"SELECT {EVENT_COLUMNS} FROM events "
                "WHERE occurred_at >= :start AND occurred_at <= :end "
                "ORDER BY occurred_at ASC LIMIT :limit"
            ),
            {"start": start, "end": end, "limit": limit},
        ).fetchall()
    return [row_to_event(dict(row._mapping)) for row in rows]


def event_summary(*, since: str) -> dict[str, Any]:
    with connection() as conn:
        total = conn.execute(
            text("SELECT COUNT(*) FROM events WHERE occurred_at >= :since"),
            {"since": since},
        ).scalar_one()
        by_module = conn.execute(
            text(
                "SELECT source_module, COUNT(*) AS n FROM events WHERE occurred_at >= :since "
                "GROUP BY source_module"
            ),
            {"since": since},
        ).fetchall()
        by_severity = conn.execute(
            text(
                "SELECT severity, COUNT(*) AS n FROM events WHERE occurred_at >= :since "
                "GROUP BY severity"
            ),
            {"since": since},
        ).fetchall()
        sources = conn.execute(
            text(
                "SELECT source_ip, COUNT(*) AS n FROM events "
                "WHERE occurred_at >= :since AND source_ip IS NOT NULL "
                "GROUP BY source_ip ORDER BY n DESC LIMIT 10"
            ),
            {"since": since},
        ).fetchall()
        timeline = conn.execute(
            text(
                "SELECT substr(occurred_at, 1, 13) AS hour, COUNT(*) AS n FROM events "
                "WHERE occurred_at >= :since GROUP BY hour ORDER BY hour"
            ),
            {"since": since},
        ).fetchall()
    return {
        "since": since,
        "total": int(total),
        "by_module": {row[0]: int(row[1]) for row in by_module},
        "by_severity": {row[0]: int(row[1]) for row in by_severity},
        "top_sources": [{"source_ip": row[0], "count": int(row[1])} for row in sources],
        "hourly": [{"hour": row[0], "count": int(row[1])} for row in timeline],
    }


def quarantine_list(limit: int = 50) -> list[dict[str, Any]]:
    with connection() as conn:
        rows = conn.execute(
            text(
                "SELECT id, received_at, source_module, actor, reason_code, reason, "
                "payload_bytes, status FROM event_quarantine "
                "ORDER BY received_at DESC LIMIT :limit"
            ),
            {"limit": limit},
        ).fetchall()
    return [dict(row._mapping) for row in rows]


def purge_expired(now_iso: str) -> int:
    with connection() as conn:
        result = conn.execute(
            text(
                "DELETE FROM events WHERE retention_until IS NOT NULL AND retention_until < :now"
            ),
            {"now": now_iso},
        )
        return int(result.rowcount or 0)


def parse_payload(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value
