"""Event ingestion and inspection."""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, Query, Request

from ..auth.rbac import Principal
from ..core.config import get_settings
from ..core.errors import PayloadTooLarge, RateLimited, ValidationFailure
from ..core.security import iso, parse_iso, utcnow
from ..telemetry.ingest import Ingestor, source_health
from ..schemas.event import Severity
from ..telemetry.repository import event_summary, get_event, list_events, quarantine_list
from .deps import client_ip, ingest_limiter, require

router = APIRouter(tags=["events"])
MAX_BATCH = 500


async def _read_json_body(request: Request) -> Any:
    """Read the request body with a hard size bound.

    The event contract already bounds a single event, but a batch is multiplied
    by ``MAX_BATCH``.  Enforcing the product here stops an authenticated sensor
    from making the API buffer an arbitrarily large request before validation
    ever runs.
    """
    limit = MAX_BATCH * get_settings().max_event_bytes
    declared = request.headers.get("content-length", "").strip()
    if declared.isdigit() and int(declared) > limit:
        raise PayloadTooLarge(
            f"request body exceeds the {limit}-byte ingestion limit",
            details={"max_bytes": limit},
        )
    buffer = bytearray()
    async for chunk in request.stream():
        buffer.extend(chunk)
        if len(buffer) > limit:
            raise PayloadTooLarge(
                f"request body exceeds the {limit}-byte ingestion limit",
                details={"max_bytes": limit},
            )
    try:
        return json.loads(bytes(buffer))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValidationFailure("request body must be valid JSON") from exc


@router.post("/ingest/events", status_code=202)
async def ingest_events(
    request: Request, principal: Principal = Depends(require("ingest:write"))
) -> dict[str, Any]:
    body = await _read_json_body(request)

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

    # Charge one token per record, not per HTTP request: a single 500-record
    # batch must not consume the same budget as a single event.
    allowed, retry_after = ingest_limiter().allow(principal.user_id, cost=len(payloads))
    if not allowed:
        raise RateLimited(
            "ingestion rate limit exceeded", details={"retry_after_seconds": retry_after}
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
    severity: Severity | None = Query(default=None),
    min_severity: Severity | None = Query(default=None),
    source_ip: str | None = Query(default=None, max_length=64),
    session_id: str | None = Query(default=None, max_length=120),
    event_type: str | None = Query(default=None, max_length=64),
    since: str | None = Query(default=None, max_length=40),
    until: str | None = Query(default=None, max_length=40),
    q: str | None = Query(default=None, max_length=120),
    principal: Principal = Depends(require("events:read")),
) -> dict[str, Any]:
    since_value = _timestamp_filter("since", since)
    until_value = _timestamp_filter("until", until)
    if since_value and until_value and since_value > until_value:
        raise ValidationFailure("since must not be later than until")
    items, total = list_events(
        limit=limit,
        offset=offset,
        source_module=module,
        severity=severity,
        min_severity=min_severity,
        source_ip=source_ip,
        session_id=session_id,
        event_type=event_type,
        since=since_value,
        until=until_value,
        q=q,
    )
    return {"items": items, "total": total, "limit": limit, "offset": offset}


def _timestamp_filter(name: str, value: str | None) -> str | None:
    if not value:
        return None
    try:
        return iso(parse_iso(value))
    except (TypeError, ValueError) as exc:
        raise ValidationFailure(f"{name} must be an ISO-8601 timestamp") from exc


@router.get("/events/summary")
def summary(
    hours: int = Query(default=24, ge=1, le=720),
    principal: Principal = Depends(require("events:read")),
) -> dict[str, Any]:
    start = utcnow()
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
