"""Read models for the evidence graph and campaign candidates."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import select, text

from ..core.errors import NotFound
from ..core.security import iso, new_id, utcnow
from ..db.database import connection, loads, query_one
from ..db.schema import campaigns, feedback, findings, graph_edges
from ..risk.scoring import explain_finding, score_risk
from .scoring import ALGORITHM_VERSION, LINK_CONFIDENCE


def graph_view(
    *,
    hours: int = 24,
    min_confidence: float = 0.0,
    kinds: list[str] | None = None,
    limit: int = 1500,
) -> dict[str, Any]:
    since = iso(utcnow() - timedelta(hours=hours))
    clauses = ["last_seen >= :since"]
    params: dict[str, Any] = {"since": since, "limit": limit}
    if kinds:
        placeholders = ", ".join(f":kind_{index}" for index in range(len(kinds)))
        clauses.append(f"kind IN ({placeholders})")
        for index, kind in enumerate(kinds):
            params[f"kind_{index}"] = kind
    node_rows = []
    with connection() as conn:
        node_rows = conn.execute(
            text(
                f"SELECT id, kind, label, props, first_seen, last_seen FROM graph_nodes "
                f"WHERE {' AND '.join(clauses)} ORDER BY last_seen DESC LIMIT :limit"
            ),
            params,
        ).fetchall()
        node_ids = [row[0] for row in node_rows]
        edge_rows: list[Any] = []
        if node_ids:
            placeholders = ", ".join(f":n{index}" for index in range(len(node_ids)))
            edge_params: dict[str, Any] = {f"n{index}": value for index, value in enumerate(node_ids)}
            edge_params["min_confidence"] = min_confidence
            edge_params["statuses"] = ("active", "hypothesis")
            edge_rows = conn.execute(
                text(
                    "SELECT id, kind, src_id, dst_id, confidence, score, status, campaign_id, "
                    "updated_at, evidence FROM graph_edges "
                    f"WHERE src_id IN ({placeholders}) AND dst_id IN ({placeholders}) "
                    "AND confidence >= :min_confidence "
                    "AND status IN ('active', 'hypothesis') "
                    f"ORDER BY confidence DESC LIMIT {int(limit)}"
                ),
                edge_params,
            ).fetchall()

    nodes = [
        {
            "id": row[0],
            "kind": row[1],
            "label": row[2],
            "props": loads(row[3], {}),
            "first_seen": row[4],
            "last_seen": row[5],
        }
        for row in node_rows
    ]
    node_id_set = {node["id"] for node in nodes}
    edges = []
    for row in edge_rows:
        if row[2] not in node_id_set or row[3] not in node_id_set:
            continue
        evidence = loads(row[9], {})
        edges.append(
            {
                "id": row[0],
                "kind": row[1],
                "source": row[2],
                "target": row[3],
                "confidence": row[4],
                "score": row[5],
                "status": row[6],
                "campaign_id": row[7],
                "updated_at": row[8],
                "explanation": evidence.get("explanation", ""),
                "contradictions": evidence.get("contradictions", []),
            }
        )
    return {
        "window_hours": hours,
        "nodes": nodes,
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "algorithm_version": ALGORITHM_VERSION,
        "note": (
            "Edges marked 'hypothesis' are unconfirmed relationships. "
            "An IP node is an observation, never an identity."
        ),
    }


def list_campaigns(
    *, limit: int = 50, status: str | None = None, include_archived: bool = False
) -> list[dict[str, Any]]:
    # Build the optional predicate instead of passing an untyped NULL: on
    # PostgreSQL ``:status IS NULL`` fails with "could not determine data type
    # of parameter" because the driver cannot infer the parameter type.
    clauses = ["1 = 1"]
    params: dict[str, Any] = {"limit": limit}
    if not include_archived:
        clauses.append("archived_at IS NULL")
    if status:
        clauses.append("status = :status")
        params["status"] = status
    with connection() as conn:
        rows = conn.execute(
            text(
                "SELECT id, name, status, confidence, summary, created_at, updated_at, "
                "member_count, ip_count, algorithm_version, status_updated_at, "
                "superseded_by, archived_at FROM campaigns "
                f"WHERE {' AND '.join(clauses)} "
                "ORDER BY confidence DESC, updated_at DESC LIMIT :limit"
            ),
            params,
        ).fetchall()
    return [
        {
            "id": row[0],
            "name": row[1],
            "status": row[2],
            "confidence": row[3],
            "summary": row[4],
            "created_at": row[5],
            "updated_at": row[6],
            "member_count": row[7],
            "ip_count": row[8],
            "algorithm_version": row[9],
            "status_updated_at": row[10],
            "superseded_by": row[11],
            "archived_at": row[12],
        }
        for row in rows
    ]


# What observing a family would buy the analyst. The wording is deliberately
# operational: a plan entry is a collection task, not a promise that the
# confidence will rise by the stated amount.
_FAMILY_GUIDANCE = {
    "behavior": "Capture more of the command sequence so behavioural overlap is measurable.",
    "targeting": "Record the assets, URLs and ports the session actually touched.",
    "timing": "Ingest UTC timestamps for each step so cadence can be compared.",
    "identity": "Capture TLS/JA3 fingerprints, client certificates or credential pairs.",
    "intel": "Enrich the source address with reputation, ASN and hosting data.",
    "toolchain": "Retain user-agent and SSH client banners on every session.",
}


def _evidence_plan(edges: list[dict[str, Any]]) -> dict[str, Any]:
    """Rank the evidence the campaign is missing.

    A component that is unavailable contributes zero weight today. Summing that
    weight per family gives an upper bound on what new telemetry could unlock,
    and counting the edges affected says how much of the campaign the gap
    weakens. It is an upper bound: an observation that is present can still
    score low for a specific pair.
    """
    families: dict[str, dict[str, Any]] = {}
    totals = {name: {"available": 0.0, "total": 0.0} for name in _FAMILY_GUIDANCE}
    for edge in edges:
        missing_families: set[str] = set()
        for component in edge["evidence"].get("components", []) or []:
            family = component.get("family")
            if family not in _FAMILY_GUIDANCE:
                continue
            weight = float(component.get("weight") or 0.0)
            entry = families.setdefault(
                family,
                {
                    "family": family,
                    "missing_on_edges": 0,
                    "weight_at_stake": 0.0,
                    "components": set(),
                },
            )
            totals[family]["total"] += weight
            if component.get("available"):
                totals[family]["available"] += weight
                continue
            entry["weight_at_stake"] += weight
            entry["components"].add(str(component.get("name")))
            missing_families.add(family)
        for family in missing_families:
            families[family]["missing_on_edges"] += 1

    plan = [
        {
            "family": entry["family"],
            "missing_on_edges": entry["missing_on_edges"],
            "weight_at_stake": round(entry["weight_at_stake"], 3),
            "components": sorted(entry["components"]),
            "guidance": _FAMILY_GUIDANCE[entry["family"]],
        }
        for entry in families.values()
        if entry["missing_on_edges"] or entry["weight_at_stake"]
    ]
    plan.sort(key=lambda item: (-item["missing_on_edges"], -item["weight_at_stake"], item["family"]))
    coverage = {
        name: round(values["available"] / values["total"], 3) if values["total"] else 0.0
        for name, values in totals.items()
    }
    # A family with only unavailable components is a ranked gap above; a family
    # no edge recorded at all is a collection gap the campaign never had.
    absent = [name for name, values in totals.items() if values["total"] == 0.0]
    return {
        "items": plan,
        "family_coverage": coverage,
        "absent_families": absent,
        "note": (
            "Weight at stake is an upper bound on the family's contribution, not a "
            "forecast of the confidence the pair would reach."
        ),
    }


def _observation_efficiency(sessions: list[dict[str, Any]], linked_pairs: int) -> dict[str, Any]:
    """How much raw observation each confirmed relationship cost.

    Analysts do not read events, they read relationships. Reporting the events
    observed per linked pair makes the cost of a campaign explicit and lets two
    campaigns of equal confidence be compared by how cheaply they were earned.
    """
    events = sum(int(session.get("event_count") or 0) for session in sessions)
    ips = {ip for session in sessions for ip in session.get("source_ips", []) or []}
    return {
        "observations": events,
        "sessions": len(sessions),
        "source_ips": len(ips),
        "linked_pairs": linked_pairs,
        "observations_per_link": round(events / linked_pairs, 2) if linked_pairs else None,
        "observations_per_session": round(events / len(sessions), 2) if sessions else None,
        "compression": round(events / linked_pairs, 2) if linked_pairs else None,
        "note": (
            "Lower observations per link means the campaign was assembled from "
            "concentrated evidence rather than volume."
        ),
    }


def get_campaign(campaign_id: str) -> dict[str, Any]:
    with connection() as conn:
        row = query_one(conn, "SELECT * FROM campaigns WHERE id = :id", {"id": campaign_id})
        if not row:
            raise NotFound("campaign not found")
        edge_rows = conn.execute(
            text(
                "SELECT id, src_id, dst_id, confidence, score, status, evidence, contradictions, "
                "updated_at FROM graph_edges WHERE campaign_id = :id AND kind = 'session_similarity' "
                "AND status = 'active' ORDER BY confidence DESC"
            ),
            {"id": campaign_id},
        ).fetchall()
        evidence = loads(row["evidence"], {})
        member_ids = set(evidence.get("sessions", []))
        session_rows = []
        if member_ids:
            placeholders = ", ".join(f":m{index}" for index in range(len(member_ids)))
            session_params = {
                f"m{index}": f"session:{session_id}"
                for index, session_id in enumerate(sorted(member_ids))
            }
            # Do not apply a time cutoff here: a campaign remains readable even
            # when its member sessions predate the graph view window.
            session_rows = conn.execute(
                text(
                    "SELECT id, label, props, first_seen, last_seen FROM graph_nodes "
                    f"WHERE id IN ({placeholders})"
                ),
                session_params,
            ).fetchall()

    evidence = loads(row["evidence"], {})
    member_ids = set(evidence.get("sessions", []))
    sessions = []
    for node in session_rows:
        session_id = node[0].removeprefix("session:")
        if session_id in member_ids:
            props = loads(node[2], {})
            sessions.append(
                {
                    "id": session_id,
                    "label": node[1],
                    "first_seen": node[3],
                    "last_seen": node[4],
                    "source_ips": props.get("source_ips", []),
                    "event_count": props.get("event_count", 0),
                    "categories": props.get("categories", {}),
                    "severity_max": props.get("severity_max", "info"),
                    "auth": props.get("auth", {}),
                }
            )
    sessions.sort(key=lambda item: item["first_seen"] or "")

    edges = [
        {
            "id": edge[0],
            "source": edge[1],
            "target": edge[2],
            "confidence": edge[3],
            "score": edge[4],
            "status": edge[5],
            "evidence": loads(edge[6], {}),
            "contradictions": loads(edge[7], []),
            "updated_at": edge[8],
        }
        for edge in edge_rows
    ]

    severity = _max_severity([session["severity_max"] for session in sessions] or ["info"])
    targets_by_session = _targets_for_sessions([session["id"] for session in sessions])
    targets = sorted({target for values in targets_by_session.values() for target in values})
    criticality = _asset_criticality(targets)
    timeline = [
        {"at": session["first_seen"], "session": session["id"], "event": "session started"}
        for session in sessions
    ] + [
        {"at": session["last_seen"], "session": session["id"], "event": "session ended"}
        for session in sessions
        if session["last_seen"]
    ]
    timeline.sort(key=lambda item: item["at"] or "")

    explanation = explain_finding(
        what_happened=row["summary"],
        assets=targets,
        why_flagged=(
            f"{len(sessions)} sessions across {len(evidence.get('ips', []))} IP(s) were linked "
            f"by {len(edges)} evidence-bearing relationship edge(s). Membership requires "
            f"confidence >= {LINK_CONFIDENCE:.2f} and at least two independent evidence families."
        ),
        evidence=[
            {
                "edge_id": edge["id"],
                "confidence": edge["confidence"],
                "score": edge["score"],
                "explanation": edge["evidence"].get("explanation", ""),
                "components": edge["evidence"].get("components", []),
                "contradictions": edge["contradictions"],
            }
            for edge in edges
        ],
        timeline=timeline,
        severity=severity,
        confidence=float(row["confidence"]),
        asset_criticality=criticality,
    )
    explanation["severity_rationale"] = (
        f"Highest observed event severity in the campaign is '{severity}'."
    )
    explanation["campaign_id"] = campaign_id
    explanation["algorithm_version"] = row["algorithm_version"]

    return {
        "campaign": {
            "id": row["id"],
            "name": row["name"],
            "status": row["status"],
            "confidence": row["confidence"],
            "summary": row["summary"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "member_count": row["member_count"],
            "ip_count": row["ip_count"],
            "algorithm_version": row["algorithm_version"],
            "status_updated_at": row["status_updated_at"],
            "superseded_by": row["superseded_by"],
            "archived_at": row["archived_at"],
            "archived": bool(row["archived_at"]),
        },
        "sessions": sessions,
        "edges": edges,
        "ips": evidence.get("ips", []),
        "categories": evidence.get("categories", {}),
        "evidence": evidence,
        "explanation": explanation,
        "evidence_plan": _evidence_plan(edges),
        "observation": _observation_efficiency(sessions, len(edges)),
    }


def get_edge(edge_id: str) -> dict[str, Any]:
    with connection() as conn:
        row = query_one(conn, "SELECT * FROM graph_edges WHERE id = :id", {"id": edge_id})
    if not row:
        raise NotFound("relationship edge not found")
    evidence = loads(row["evidence"], {})
    sessions = evidence.get("sessions", {})
    left = sessions.get("left", {})
    right = sessions.get("right", {})
    severity = _max_severity(
        [left.get("severity_max", "info"), right.get("severity_max", "info")]
    )
    risk = score_risk(
        severity=severity,
        confidence=float(row["confidence"]),
        asset_criticality=_asset_criticality(sorted(set(left.get("targets", [])) | set(right.get("targets", [])))),
        reasons=[evidence.get("explanation", "")],
    )
    return {
        "id": row["id"],
        "kind": row["kind"],
        "source": row["src_id"],
        "target": row["dst_id"],
        "confidence": row["confidence"],
        "score": row["score"],
        "status": row["status"],
        "campaign_id": row["campaign_id"],
        "algorithm_version": row["algorithm_version"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "expires_at": row["expires_at"],
        "evidence": evidence,
        "contradictions": loads(row["contradictions"], []),
        "risk": risk,
        "sessions": {"left": left, "right": right},
    }


def add_feedback(
    *, actor_id: str, object_type: str, object_id: str, label: str, note: str
) -> dict[str, Any]:
    _assert_feedback_target(object_type, object_id)
    # Feedback follows a merged campaign instead of pointing at the absorbed
    # row.  The review was about this relationship, and the relationship now
    # lives under the surviving identifier.
    resolved_id = (
        _resolve_campaign_alias(object_id) if object_type == "campaign" else object_id
    )
    now = utcnow()
    feedback_id = new_id("fbk")
    with connection() as conn:
        conn.execute(
            feedback.insert().values(
                id=feedback_id,
                ts=iso(now),
                actor_id=actor_id,
                object_type=object_type,
                object_id=resolved_id,
                label=label,
                note=note,
                algorithm_version=ALGORITHM_VERSION,
            )
        )
        if object_type == "campaign":
            status = {"supported": "confirmed", "rejected": "rejected", "uncertain": "uncertain"}[label]
            conn.execute(
                campaigns.update()
                .where(campaigns.c.id == resolved_id)
                .values(status=status, status_updated_at=iso(now))
            )
    result = {"id": feedback_id, "status": "recorded", "label": label, "object_id": resolved_id}
    if resolved_id != object_id:
        result["redirected_from"] = object_id
    return result


def _resolve_campaign_alias(campaign_id: str) -> str:
    """Follow merge pointers to the campaign that currently holds the cluster."""
    current = campaign_id
    with connection() as conn:
        for _ in range(8):
            row = conn.execute(
                select(campaigns.c.superseded_by).where(campaigns.c.id == current)
            ).fetchone()
            if not row or not row[0]:
                return current
            current = row[0]
    return current


def _assert_feedback_target(object_type: str, object_id: str) -> None:
    """Reject feedback that points at an object this platform does not store."""
    tables = {
        "campaign": campaigns,
        "edge": graph_edges,
        "finding": findings,
    }
    table = tables.get(object_type)
    if table is None:
        return
    with connection() as conn:
        found = conn.execute(select(table.c.id).where(table.c.id == object_id)).fetchone()
    if not found:
        raise NotFound(f"{object_type} not found")


def feedback_summary() -> dict[str, Any]:
    with connection() as conn:
        rows = conn.execute(
            text(
                "SELECT object_type, label, COUNT(*) FROM feedback "
                "GROUP BY object_type, label ORDER BY object_type, label"
            )
        ).fetchall()
        recent = conn.execute(
            text(
                "SELECT id, ts, actor_id, object_type, object_id, label, note "
                "FROM feedback ORDER BY ts DESC LIMIT 50"
            )
        ).fetchall()
    counts: dict[str, dict[str, int]] = {}
    for object_type, label, count in rows:
        counts.setdefault(object_type, {})[label] = int(count)
    return {
        "counts": counts,
        "recent": [
            {
                "id": row[0],
                "ts": row[1],
                "actor_id": row[2],
                "object_type": row[3],
                "object_id": row[4],
                "label": row[5],
                "note": row[6],
            }
            for row in recent
        ],
        "note": (
            "Feedback is recorded for evaluation and threshold review. It never "
            "retrains or changes production scoring automatically."
        ),
    }


def _targets_for_sessions(session_ids: list[str]) -> dict[str, list[str]]:
    """Load all targeted assets in one query instead of one query per session."""
    if not session_ids:
        return {}
    placeholders = ", ".join(f":s{index}" for index in range(len(session_ids)))
    params = {f"s{index}": f"session:{session_id}" for index, session_id in enumerate(session_ids)}
    with connection() as conn:
        rows = conn.execute(
            text(
                "SELECT src_id, dst_id FROM graph_edges "
                f"WHERE kind = 'targeted_asset' AND src_id IN ({placeholders})"
            ),
            params,
        ).fetchall()
    targets: dict[str, list[str]] = {}
    for source, target in rows:
        session_id = str(source).removeprefix("session:")
        targets.setdefault(session_id, []).append(str(target).removeprefix("asset:"))
    return targets


def _asset_criticality(targets: list[str]) -> str:
    if not targets:
        return "medium"
    placeholders = ", ".join(f":t{index}" for index in range(len(targets)))
    params = {f"t{index}": target for index, target in enumerate(targets)}
    with connection() as conn:
        row = conn.execute(
            text(
                f"SELECT criticality FROM assets WHERE name IN ({placeholders}) "
                "ORDER BY CASE criticality WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
                "WHEN 'medium' THEN 2 ELSE 1 END DESC LIMIT 1"
            ),
            params,
        ).fetchone()
    return row[0] if row else "medium"


def _max_severity(values: list[str]) -> str:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return max(values or ["info"], key=lambda value: order.get(value, 0))
