"""Event ingestion and inspection."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Request

from ..auth.rbac import Principal
from ..core.errors import RateLimited, ValidationFailure
from ..core.security import iso, utcnow
from ..telemetry.ingest import Ingestor, source_health
from ..telemetry.repository import event_summary, get_event, list_events, quarantine_list
from .deps import client_ip, ingest_limiter, require

router = APIRouter(tags=["events"])
MAX_BATCH = 500


@router.post("/ingest/events", status_code=202)
async def ingest_events(
    request: Request, principal: Principal = Depends(require("ingest:write"))
) -> dict[str, Any]:
    allowed, retry_after = ingest_limiter().allow(principal.user_id, cost=1)
    if not allowed:
        raise RateLimited(
            "ingestion rate limit exceeded", details={"retry_after_seconds": retry_after}
        )
    try:
        body = await request.json()
    except Exception as exc:  # noqa: BLE001
        raise ValidationFailure("request body must be valid JSON") from exc

    if isinstance(body, dict) and "events" in body:
        payloads = body["events"]
    elif isinstance(body, list):
        payloads = body
    elif isinstance(body, dict):
        payloads = [body]
    else:
        raise ValidationFailure("expected an event object, an array, or {'events': [...]}")

    if not isinstance(payloads, list) or not payloads:
        raise ValidationFailure("events must be a non-empty array")
    if len(payloads) > MAX_BATCH:
        raise ValidationFailure(
            f"batch size {len(payloads)} exceeds the maximum of {MAX_BATCH}",
            details={"max_batch": MAX_BATCH},
        )

    report = Ingestor().ingest(payloads, actor=f"{principal.via}:{principal.name}")
    from ..core.audit import audit_standalone

    audit_standalone(
        action="events.ingest",
        actor_id=principal.user_id,
        actor_role=principal.role,
        object_type="batch",
        detail={
            "received": report.received,
            "accepted": report.accepted,
            "duplicates": report.duplicates,
            "rejected": report.rejected,
        },
        request_ip=client_ip(request),
    )
    return report.model_dump()


@router.get("/events")
def events(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    module: str | None = Query(default=None, max_length=32),
    severity: str | None = Query(default=None, max_length=16),
    min_severity: str | None = Query(default=None, max_length=16),
    source_ip: str | None = Query(default=None, max_length=64),
    session_id: str | None = Query(default=None, max_length=120),
    event_type: str | None = Query(default=None, max_length=64),
    since: str | None = Query(default=None, max_length=40),
    until: str | None = Query(default=None, max_length=40),
    q: str | None = Query(default=None, max_length=120),
    principal: Principal = Depends(require("events:read")),
) -> dict[str, Any]:
    items, total = list_events(
        limit=limit,
        offset=offset,
        source_module=module,
        severity=severity,
        min_severity=min_severity,
        source_ip=source_ip,
        session_id=session_id,
        event_type=event_type,
        since=since,
        until=until,
        q=q,
    )
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/events/summary")
def summary(
    hours: int = Query(default=24, ge=1, le=720),
    principal: Principal = Depends(require("events:read")),
) -> dict[str, Any]:
    start = utcnow()
    from datetime import timedelta

    return event_summary(since=iso(start - timedelta(hours=hours)))


@router.get("/events/{event_id}")
def event_detail(event_id: str, principal: Principal = Depends(require("events:read"))) -> dict[str, Any]:
    from ..core.errors import NotFound

    event = get_event(event_id)
    if not event:
        raise NotFound("event not found")
    return event


@router.get("/quarantine")
def quarantined(
    limit: int = Query(default=50, ge=1, le=200),
    principal: Principal = Depends(require("findings:read")),
) -> dict[str, Any]:
    return {"items": quarantine_list(limit=limit)}


@router.get("/sources")
def sources(principal: Principal = Depends(require("sources:read"))) -> dict[str, Any]:
    return {"sources": source_health()}
