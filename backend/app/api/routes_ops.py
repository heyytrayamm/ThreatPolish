"""Operational visibility for retention and graph size.

The endpoints are admin-only: they report how far the retention job is behind
without exposing event content, and allow an operator to run it immediately.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Response

from ..auth.rbac import Principal
from ..db.retention import retention_status, run_retention
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


@router.get("/retention")
def retention(principal: Principal = Depends(require("audit:read"))) -> dict[str, Any]:
    return retention_status()


@router.get("/metrics")
def metrics(principal: Principal = Depends(require("graph:read"))) -> Response:
    body = render_metrics(retention_status())
    return Response(
        content=body, media_type="text/plain; version=0.0.4; charset=utf-8"
    )


@router.post("/retention/run")
def run_retention_now(
    principal: Principal = Depends(require("audit:read")),
) -> dict[str, Any]:
    """Run both retention horizons now; the run is recorded and audited."""
    return run_retention(trigger="manual")
