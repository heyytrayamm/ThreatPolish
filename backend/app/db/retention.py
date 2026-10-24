"""Retention maintenance shared by the CLI and the operational endpoint.

Events and graph evidence have separate horizons.  Events carry their own
``retention_until``; graph edges are retired by correlation, so their retention
is about removing evidence that is no longer live rather than expiring links
that still hold.
"""

from __future__ import annotations

import time
from datetime import timedelta
from typing import Any

from sqlalchemy import select, text

from ..core.audit import record_audit
from ..core.config import get_settings
from ..core.security import iso, new_id, utcnow
from .database import connection
from .schema import events, retention_runs

# Observation edges are permanent while their session is in play.  They are
# retained only as long as the session can still be reached from live evidence.
_OBSERVATION_KINDS = "('observed_from', 'targeted_asset', 'matched_indicator')"
_LIVE_LINK_KINDS = "('session_similarity', 'campaign_contains')"

_RETIRED_EDGES = "status = 'expired' AND updated_at < :cutoff"
_STALE_OBSERVATIONS = (
    f"kind IN {_OBSERVATION_KINDS} AND src_id IN ("
    "SELECT n.id FROM graph_nodes n "
    "WHERE n.kind = 'session' AND n.last_seen < :cutoff "
    "AND NOT EXISTS ("
    "SELECT 1 FROM graph_edges e "
    f"WHERE e.kind IN {_LIVE_LINK_KINDS} "
    "AND e.status IN ('active', 'hypothesis') "
    "AND (e.src_id = n.id OR e.dst_id = n.id)))"
)
_ORPHAN_NODES = (
    "last_seen < :cutoff AND NOT EXISTS ("
    "SELECT 1 FROM graph_edges e "
    "WHERE e.src_id = graph_nodes.id OR e.dst_id = graph_nodes.id)"
)


def purge_events() -> dict[str, Any]:
    """Delete events past ``TP_RETENTION_DAYS``."""
    settings = get_settings()
    cutoff = utcnow()
    with connection() as conn:
        removed = conn.execute(
            events.delete().where(events.c.retention_until < iso(cutoff))
        ).rowcount
    return {
        "days": settings.retention_days,
        "cutoff": iso(cutoff),
        "events": int(removed or 0),
    }


def purge_graph(*, days: int | None = None) -> dict[str, Any]:
    """Delete graph evidence past ``TP_GRAPH_RETENTION_DAYS``.

    Correlation retires stale edges when it runs, but a deployment that stops
    correlating would otherwise keep every edge forever.  Only edges already
    retired are removed: hypotheses are open leads, and campaign membership
    edges belong to a review that is deleted with its campaign.

    Observation edges are permanent while their session is in play, so they are
    removed with the session once it is past the horizon and no live similarity
    or campaign edge still uses it.  Nodes are then removed only when they are
    older than the window *and* no edge still references them, so a recent
    session keeps the old addresses it touched.  Archived campaign rows are
    never touched; they are the record of an analyst's decision.
    """
    retention = get_settings().graph_retention_days if days is None else int(days)
    if retention < 1:
        raise ValueError("graph retention must be at least one day")
    cutoff = iso(utcnow() - timedelta(days=retention))
    params = {"cutoff": cutoff}
    with connection() as conn:
        edges = conn.execute(
            text(f"DELETE FROM graph_edges WHERE {_RETIRED_EDGES}"), params
        ).rowcount
        observations = conn.execute(
            text(f"DELETE FROM graph_edges WHERE {_STALE_OBSERVATIONS}"), params
        ).rowcount
        nodes = conn.execute(
            text(f"DELETE FROM graph_nodes WHERE {_ORPHAN_NODES}"), params
        ).rowcount
    return {
        "days": retention,
        "cutoff": cutoff,
        "edges": int(edges or 0),
        "observations": int(observations or 0),
        "nodes": int(nodes or 0),
    }


def purge_all() -> dict[str, Any]:
    """Run both retention horizons; used by ``app.cli retention``."""
    return {"events": purge_events(), "graph": purge_graph()}


def retention_status() -> dict[str, Any]:
    """Report how much evidence currently sits past each horizon.

    Counts are taken before any deletion.  ``expired`` and the graph pending
    counts include work the next scheduled run will clear, so they are backlog
    rather than an alarm.  ``overdue`` is true only when work has waited past
    ``TP_RETENTION_GRACE_DAYS``, which is what a missed schedule looks like.
    ``orphan_nodes`` counts nodes that no edge references now; purging stale
    observations can orphan more, which the next report shows.
    """
    settings = get_settings()
    now = utcnow()
    grace = timedelta(days=settings.retention_grace_days)
    event_cutoff = iso(now)
    graph_cutoff = iso(now - timedelta(days=settings.graph_retention_days))
    event_alert_cutoff = iso(now - grace)
    graph_alert_cutoff = iso(
        now - timedelta(days=settings.graph_retention_days + settings.retention_grace_days)
    )
    params = {"now": event_cutoff, "cutoff": graph_cutoff}
    alert_params = {"now": event_alert_cutoff, "cutoff": graph_alert_cutoff}
    with connection() as conn:
        event_totals = conn.execute(
            text("SELECT COUNT(*), MIN(occurred_at), MIN(retention_until) FROM events")
        ).fetchone()
        event_expired = conn.execute(
            text("SELECT COUNT(*) FROM events WHERE retention_until < :now"), params
        ).scalar_one()
        event_overdue = conn.execute(
            text("SELECT COUNT(*) FROM events WHERE retention_until < :now"),
            alert_params,
        ).scalar_one()
        node_total = conn.execute(text("SELECT COUNT(*) FROM graph_nodes")).scalar_one()
        edge_total = conn.execute(text("SELECT COUNT(*) FROM graph_edges")).scalar_one()
        retired_edges = conn.execute(
            text(f"SELECT COUNT(*) FROM graph_edges WHERE {_RETIRED_EDGES}"), params
        ).scalar_one()
        retired_overdue = conn.execute(
            text(f"SELECT COUNT(*) FROM graph_edges WHERE {_RETIRED_EDGES}"),
            alert_params,
        ).scalar_one()
        stale_observations = conn.execute(
            text(f"SELECT COUNT(*) FROM graph_edges WHERE {_STALE_OBSERVATIONS}"), params
        ).scalar_one()
        observations_overdue = conn.execute(
            text(f"SELECT COUNT(*) FROM graph_edges WHERE {_STALE_OBSERVATIONS}"),
            alert_params,
        ).scalar_one()
        orphan_nodes = conn.execute(
            text(f"SELECT COUNT(*) FROM graph_nodes WHERE {_ORPHAN_NODES}"), params
        ).scalar_one()

    overdue = bool(event_overdue or retired_overdue or observations_overdue)
    return {
        "generated_at": event_cutoff,
        "overdue": overdue,
        "grace_days": settings.retention_grace_days,
        "history": retention_history(),
        "events": {
            "retention_days": settings.retention_days,
            "total": int(event_totals[0] or 0),
            "expired": int(event_expired or 0),
            "oldest_occurred_at": event_totals[1],
            "oldest_retention_until": event_totals[2],
        },
        "graph": {
            "retention_days": settings.graph_retention_days,
            "cutoff": graph_cutoff,
            "nodes": int(node_total or 0),
            "edges": int(edge_total or 0),
            "retired_edges": int(retired_edges or 0),
            "stale_observations": int(stale_observations or 0),
            "orphan_nodes": int(orphan_nodes or 0),
        },
    }


def retention_history(limit: int = 14) -> list[dict[str, Any]]:
    """Most recent retention runs, newest first, for the dashboard trend."""
    bounded = max(1, min(int(limit), 100))
    with connection() as conn:
        rows = conn.execute(
            select(retention_runs)
            .order_by(retention_runs.c.ran_at.desc())
            .limit(bounded)
        ).fetchall()
    return [
        {
            "id": row._mapping["id"],
            "ran_at": row._mapping["ran_at"],
            "trigger": row._mapping["trigger"],
            "duration_ms": row._mapping["duration_ms"],
            "events_removed": row._mapping["events_removed"],
            "edges_removed": row._mapping["edges_removed"],
            "observations_removed": row._mapping["observations_removed"],
            "nodes_removed": row._mapping["nodes_removed"],
            "events_expired": row._mapping["events_expired"],
            "retired_edges": row._mapping["retired_edges"],
            "stale_observations": row._mapping["stale_observations"],
            "graph_nodes": row._mapping["graph_nodes"],
            "graph_edges": row._mapping["graph_edges"],
            "overdue": bool(row._mapping["overdue"]),
        }
        for row in rows
    ]


def run_retention(*, trigger: str = "manual") -> dict[str, Any]:
    """Run both horizons, record the pre-run backlog and audit the run.

    ``purge_all`` stays side-effect free so callers can enforce retention
    without creating history; this wrapper is what the CLI and the scheduled
    Compose service use.
    """
    if trigger not in {"manual", "scheduled"}:
        raise ValueError("retention trigger must be 'manual' or 'scheduled'")
    started = time.perf_counter()
    before = retention_status()
    purged = purge_all()
    duration_ms = int(round((time.perf_counter() - started) * 1000))
    run_id = new_id("rtn")
    events_result = purged["events"]
    graph_result = purged["graph"]
    detail = {
        "trigger": trigger,
        "duration_ms": duration_ms,
        "events_removed": events_result["events"],
        "edges_removed": graph_result["edges"],
        "observations_removed": graph_result["observations"],
        "nodes_removed": graph_result["nodes"],
        "events_expired": before["events"]["expired"],
        "retired_edges": before["graph"]["retired_edges"],
        "stale_observations": before["graph"]["stale_observations"],
        "graph_nodes": before["graph"]["nodes"],
        "graph_edges": before["graph"]["edges"],
        "overdue": before["overdue"],
    }
    with connection() as conn:
        conn.execute(
            retention_runs.insert().values(
                id=run_id,
                ran_at=before["generated_at"],
                trigger=trigger,
                duration_ms=duration_ms,
                events_removed=detail["events_removed"],
                edges_removed=detail["edges_removed"],
                observations_removed=detail["observations_removed"],
                nodes_removed=detail["nodes_removed"],
                events_expired=detail["events_expired"],
                retired_edges=detail["retired_edges"],
                stale_observations=detail["stale_observations"],
                graph_nodes=detail["graph_nodes"],
                graph_edges=detail["graph_edges"],
                overdue=1 if detail["overdue"] else 0,
            )
        )
        record_audit(
            conn,
            action="retention.run",
            actor_role="system",
            object_type="retention_run",
            object_id=run_id,
            detail=detail,
        )
    return {
        "run_id": run_id,
        "trigger": trigger,
        "duration_ms": duration_ms,
        "overdue": before["overdue"],
        "events": events_result,
        "graph": graph_result,
    }
