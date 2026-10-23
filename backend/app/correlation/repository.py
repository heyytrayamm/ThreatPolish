"""Read models for the evidence graph and campaign candidates."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import text

from ..core.errors import NotFound
from ..core.security import iso, new_id, utcnow
from ..db.database import connection, loads, query_one
from ..db.schema import campaigns, feedback
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


def list_campaigns(*, limit: int = 50, status: str | None = None) -> list[dict[str, Any]]:
    # Build the optional predicate instead of passing an untyped NULL: on
    # PostgreSQL ``:status IS NULL`` fails with "could not determine data type
    # of parameter" because the driver cannot infer the parameter type.
    clauses = ["1 = 1"]
    params: dict[str, Any] = {"limit": limit}
    if status:
        clauses.append("status = :status")
        params["status"] = status
    with connection() as conn:
        rows = conn.execute(
            text(
                "SELECT id, name, status, confidence, summary, created_at, updated_at, "
                "member_count, ip_count, algorithm_version FROM campaigns "
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
        }
        for row in rows
    ]


def get_campaign(campaign_id: str) -> dict[str, Any]:
    with connection() as conn:
        row = query_one(conn, "SELECT * FROM campaigns WHERE id = :id", {"id": campaign_id})
        if not row:
            raise NotFound("campaign not found")
        edge_rows = conn.execute(
            text(
                "SELECT id, src_id, dst_id, confidence, score, status, evidence, contradictions, "
                "updated_at FROM graph_edges WHERE campaign_id = :id AND kind = 'session_similarity' "
                "ORDER BY confidence DESC"
            ),
            {"id": campaign_id},
        ).fetchall()
        session_rows = conn.execute(
            text(
                "SELECT id, label, props, first_seen, last_seen FROM graph_nodes "
                "WHERE id LIKE 'session:%' AND last_seen >= :since"
            ),
            {"since": iso(utcnow() - timedelta(days=14))},
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
    targets = sorted({target for session in sessions for target in _targets_for(session["id"])})
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
        },
        "sessions": sessions,
        "edges": edges,
        "ips": evidence.get("ips", []),
        "categories": evidence.get("categories", {}),
        "explanation": explanation,
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
    feedback_id = new_id("fbk")
    with connection() as conn:
        conn.execute(
            feedback.insert().values(
                id=feedback_id,
                ts=iso(utcnow()),
                actor_id=actor_id,
                object_type=object_type,
                object_id=object_id,
                label=label,
                note=note,
                algorithm_version=ALGORITHM_VERSION,
            )
        )
        if object_type == "campaign":
            status = {"supported": "confirmed", "rejected": "rejected", "uncertain": "uncertain"}[label]
            conn.execute(
                campaigns.update().where(campaigns.c.id == object_id).values(status=status)
            )
    return {"id": feedback_id, "status": "recorded", "label": label}


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


def _targets_for(session_id: str) -> list[str]:
    with connection() as conn:
        rows = conn.execute(
            text(
                "SELECT dst_id FROM graph_edges WHERE kind = 'targeted_asset' AND src_id = :src"
            ),
            {"src": f"session:{session_id}"},
        ).fetchall()
    return [row[0].removeprefix("asset:") for row in rows]


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
