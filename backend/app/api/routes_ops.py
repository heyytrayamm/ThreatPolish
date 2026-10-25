"""Operational visibility for retention and graph size.

Status and history are readable by analysts and administrators without
exposing event content; only an administrator can run retention immediately.
"""

from __future__ import annotations

import csv
import io
from datetime import date, datetime, time, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, Response

from ..auth.rbac import Principal
from ..core.errors import ValidationFailure
from ..core.security import iso, parse_iso
from ..db.retention import retention_history, retention_status, run_retention
from .deps import require

router = APIRouter(tags=["operations"])


def _metric(name: str, value: float | int, help_text: str) -> list[str]:
    return [f"# HELP {name} {help_text}", f"# TYPE {name} gauge", f"{name} {value}"]


def render_metrics(status: dict[str, Any]) -> str:
    """Prometheus text exposition; deliberately no labels and no event content."""
    events = status["events"]
    graph = status["graph"]
    lines: list[str] = []
    lines += _metric(
        "threatpolish_retention_overdue",
        1 if status["overdue"] else 0,
        "1 when retention work has waited past the grace window.",
    )
    lines += _metric(
        "threatpolish_retention_grace_days",
        status["grace_days"],
        "Days backlog may wait before it is reported overdue.",
    )
    lines += _metric("threatpolish_events_total", events["total"], "Stored events.")
    lines += _metric(
        "threatpolish_events_expired",
        events["expired"],
        "Stored events past their retention date.",
    )
    lines += _metric("threatpolish_graph_nodes", graph["nodes"], "Evidence graph nodes.")
    lines += _metric("threatpolish_graph_edges", graph["edges"], "Evidence graph edges.")
    lines += _metric(
        "threatpolish_graph_retired_edges",
        graph["retired_edges"],
        "Retired edges past the graph horizon.",
    )
    lines += _metric(
        "threatpolish_graph_stale_observations",
        graph["stale_observations"],
        "Observation records of stale sessions past the graph horizon.",
    )
    lines += _metric(
        "threatpolish_graph_orphan_nodes",
        graph["orphan_nodes"],
        "Nodes no edge references.",
    )
    history = status["history"]
    if history:
        last = history[0]
        try:
            ran_at = datetime.fromisoformat(last["ran_at"]).timestamp()
        except ValueError:
            ran_at = 0
        lines += _metric(
            "threatpolish_retention_last_run_timestamp_seconds",
            round(ran_at, 3),
            "Unix time of the last recorded retention run.",
        )
        lines += _metric(
            "threatpolish_retention_last_run_overdue",
            1 if last["overdue"] else 0,
            "1 when the last retention run found an overdue backlog.",
        )
        lines += _metric(
            "threatpolish_retention_last_run_duration_milliseconds",
            last["duration_ms"],
            "Duration of the last recorded retention run.",
        )
        lines += _metric(
            "threatpolish_retention_last_run_events_removed",
            last["events_removed"],
            "Events removed by the last retention run.",
        )
        lines += _metric(
            "threatpolish_retention_last_run_edges_removed",
            last["edges_removed"],
            "Graph edges removed by the last retention run.",
        )
        lines += _metric(
            "threatpolish_retention_last_run_nodes_removed",
            last["nodes_removed"],
            "Graph nodes removed by the last retention run.",
        )
    return "\n".join(lines) + "\n"


def _history_window(since: str | None, until: str | None) -> tuple[str | None, str | None]:
    """Turn an inclusive date or datetime range into UTC boundaries.

    A bare ``YYYY-MM-DD`` describes a whole UTC day; a full timestamp is used
    as supplied.  Retention history is stored in UTC, so the dashboard labels
    the filter accordingly.
    """

    def boundary(value: str | None, end_of_day: bool) -> datetime | None:
        if not value:
            return None
        raw = value.strip()
        try:
            if len(raw) == 10:
                day = date.fromisoformat(raw)
                return datetime.combine(
                    day,
                    time.max if end_of_day else time.min,
                    tzinfo=timezone.utc,
                )
            return parse_iso(raw)
        except ValueError as exc:
            raise ValidationFailure(
                "history_since and history_until must be ISO dates or datetimes"
            ) from exc

    start = boundary(since, False)
    finish = boundary(until, True)
    if start is not None and finish is not None and start > finish:
        raise ValidationFailure("history_since must not be after history_until")
    return (iso(start) if start else None, iso(finish) if finish else None)


@router.get("/retention")
def retention(
    history_limit: int = Query(default=14, ge=1, le=100),
    history_since: str | None = Query(default=None, max_length=40),
    history_until: str | None = Query(default=None, max_length=40),
    history_trigger: Literal["manual", "scheduled"] | None = Query(default=None),
    principal: Principal = Depends(require("retention:read")),
) -> dict[str, Any]:
    since, until = _history_window(history_since, history_until)
    return retention_status(
        history_limit=history_limit,
        history_since=since,
        history_until=until,
        history_trigger=history_trigger,
    )


@router.get("/metrics")
def metrics(principal: Principal = Depends(require("graph:read"))) -> Response:
    body = render_metrics(retention_status())
    return Response(
        content=body, media_type="text/plain; version=0.0.4; charset=utf-8"
    )


@router.get("/retention/history.csv")
def retention_history_csv(
    limit: int = Query(default=1000, ge=1, le=1000),
    history_since: str | None = Query(default=None, max_length=40),
    history_until: str | None = Query(default=None, max_length=40),
    history_trigger: Literal["manual", "scheduled"] | None = Query(default=None),
    principal: Principal = Depends(require("retention:read")),
) -> Response:
    """Export recorded runs oldest first; the same fields as ``/retention``."""
    since, until = _history_window(history_since, history_until)
    runs = list(
        reversed(
            retention_history(
                limit=limit, since=since, until=until, trigger=history_trigger
            )
        )
    )
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(
        [
            "run_id",
            "ran_at",
            "trigger",
            "duration_ms",
            "backlog",
            "events_expired",
            "retired_edges",
            "stale_observations",
            "events_removed",
            "edges_removed",
            "observations_removed",
            "nodes_removed",
            "graph_nodes_before",
            "graph_edges_before",
            "overdue",
        ]
    )
    for run in runs:
        writer.writerow(
            [
                run["id"],
                run["ran_at"],
                run["trigger"],
                run["duration_ms"],
                run["events_expired"]
                + run["retired_edges"]
                + run["stale_observations"],
                run["events_expired"],
                run["retired_edges"],
                run["stale_observations"],
                run["events_removed"],
                run["edges_removed"],
                run["observations_removed"],
                run["nodes_removed"],
                run["graph_nodes"],
                run["graph_edges"],
                "true" if run["overdue"] else "false",
            ]
        )
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    return Response(
        content=buffer.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": (
                f'attachment; filename="threatpolish-retention-{stamp}.csv"'
            )
        },
    )


@router.post("/retention/run")
def run_retention_now(
    principal: Principal = Depends(require("audit:read")),
) -> dict[str, Any]:
    """Run both retention horizons now; the run is recorded and audited."""
    return run_retention(trigger="manual")
