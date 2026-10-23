"""Correlation engine: sessions -> evidence edges -> campaign candidates."""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.engine import Connection

from ..core.config import get_settings
from ..core.logging import get_logger
from ..core.security import iso, new_id, utcnow
from ..db.database import connection, dumps, loads
from ..db.schema import campaigns, correlation_runs, graph_edges, graph_nodes
from ..telemetry.repository import events_in_window
from .features import CorrelationContext, Session, build_sessions
from .scoring import ALGORITHM_VERSION, MIN_SCORE_TO_STORE, PAIR_SEPARATOR, compare, pair_key

log = get_logger(__name__)
MAX_SESSIONS_PER_RUN = 400
MAX_EDGES_PER_RUN = 2_000


class UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, item: str) -> str:
        self.parent.setdefault(item, item)
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, left: str, right: str) -> None:
        self.parent[self.find(left)] = self.find(right)

    def components(self) -> dict[str, list[str]]:
        grouped: dict[str, list[str]] = defaultdict(list)
        for item in list(self.parent):
            grouped[self.find(item)].append(item)
        return grouped


def correlate(
    *, window_hours: int | None = None, trigger: str = "manual", actor: str = "system"
) -> dict[str, Any]:
    settings = get_settings()
    hours = window_hours or settings.correlation_window_hours
    started_at = utcnow()
    window_start = started_at - timedelta(hours=hours)
    started = time.perf_counter()
    run_id = new_id("run")

    events = events_in_window(iso(window_start), iso(started_at))
    sessions = build_sessions(events)
    truncated = False
    if len(sessions) > MAX_SESSIONS_PER_RUN:
        ordered = sorted(
            sessions.values(),
            key=lambda session: session.last_seen or window_start,
            reverse=True,
        )[:MAX_SESSIONS_PER_RUN]
        sessions = {session.id: session for session in ordered}
        truncated = True

    context = CorrelationContext.from_sessions(sessions.values())
    created = updated = expired = 0
    campaign_ids: list[str] = []
    scored_pairs: dict[str, dict[str, Any]] = {}

    with connection() as conn:
        existing_edge_ids = {
            row[0]
            for row in conn.execute(
                select(graph_edges.c.id).where(graph_edges.c.kind == "session_similarity")
            ).fetchall()
        }

        for session in sessions.values():
            _upsert_session_node(conn, session, started_at)

        ordered_sessions = list(sessions.values())
        for left_index in range(len(ordered_sessions)):
            left = ordered_sessions[left_index]
            for right_index in range(left_index + 1, len(ordered_sessions)):
                right = ordered_sessions[right_index]
                if left.id == right.id:
                    continue
                result = compare(left, right, context=context)
                key = pair_key(left.id, right.id)
                scored_pairs[key] = {"left": left, "right": right, "result": result}

        # Only persist the strongest relationships; a busy sensor must not be
        # able to inflate the graph without bound.
        persistable = [
            (key, item)
            for key, item in scored_pairs.items()
            if item["result"]["score"] >= MIN_SCORE_TO_STORE
        ]
        persistable.sort(key=lambda entry: entry[1]["result"]["score"], reverse=True)
        dropped = max(0, len(persistable) - MAX_EDGES_PER_RUN)
        persistable = persistable[:MAX_EDGES_PER_RUN]
        persisted_keys = {key for key, _ in persistable}

        for _, item in persistable:
            was_created = _upsert_edge(
                conn, item["left"], item["right"], item["result"], hours, started_at
            )
            created += 1 if was_created else 0
            updated += 0 if was_created else 1

        for key in scored_pairs:
            if key in persisted_keys:
                continue
            existing_id = f"edg_{_digest(key)}"
            if existing_id in existing_edge_ids:
                _expire_pair(conn, key, started_at)
                expired += 1

        # ---- campaign candidates over linked pairs ---------------------- #
        union = UnionFind()
        edge_confidence: dict[str, float] = {}
        for key, item in persistable:
            if item["result"]["decision"] != "linked":
                continue
            union.union(item["left"].id, item["right"].id)
            edge_confidence[key] = item["result"]["confidence"]

        for members in union.components().values():
            if len(members) < 2:
                continue
            member_set = set(members)
            internal = [
                (key, confidence)
                for key, confidence in edge_confidence.items()
                if set(key.split(PAIR_SEPARATOR)) <= member_set
            ]
            if not internal:
                continue
            ips = {
                ip
                for session_id in member_set
                for ip in sessions[session_id].source_ips
            }
            campaign_id, name = _upsert_campaign(
                conn, members, sessions, internal, ips, started_at
            )
            campaign_ids.append(campaign_id)
            for key, _ in internal:
                first, second = key.split(PAIR_SEPARATOR)
                conn.execute(
                    text(
                        "UPDATE graph_edges SET campaign_id = :campaign "
                        "WHERE kind = 'session_similarity' AND "
                        "((src_id = :a AND dst_id = :b) OR (src_id = :b AND dst_id = :a))"
                    ),
                    {
                        "campaign": campaign_id,
                        "a": f"session:{first}",
                        "b": f"session:{second}",
                    },
                )
            _upsert_campaign_node(conn, campaign_id, name, started_at, members)

        expired += _expire_stale(conn, started_at)
        _cleanup_stale_campaigns(conn, started_at)

        duplicate_pairs = max(0, len(scored_pairs) - len(persistable))
        conn.execute(
            correlation_runs.insert().values(
                id=run_id,
                started_at=iso(started_at),
                finished_at=iso(utcnow()),
                window_start=iso(window_start),
                window_end=iso(started_at),
                sessions=len(sessions),
                edges_created=created,
                edges_updated=updated,
                edges_expired=expired,
                campaigns=len(campaign_ids),
                algorithm_version=ALGORITHM_VERSION,
                status="completed",
                metrics=dumps(
                    {
                        "events": len(events),
                        "pairs_scored": len(scored_pairs),
                        "pairs_persisted": len(persistable),
                        "pairs_dropped_by_cap": dropped,
                        "pairs_below_threshold": duplicate_pairs,
                        "session_cap_applied": truncated,
                        "evidence_context": context.summary(),
                        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                    }
                ),
                trigger=trigger,
            )
        )

    result = {
        "run_id": run_id,
        "window_hours": hours,
        "events": len(events),
        "sessions": len(sessions),
        "pairs_scored": len(scored_pairs),
        "edges_created": created,
        "edges_updated": updated,
        "edges_expired": expired,
        "campaigns": len(campaign_ids),
        "campaign_ids": campaign_ids,
        "truncated": truncated or dropped > 0,
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        "algorithm_version": ALGORITHM_VERSION,
        "trigger": trigger,
        "actor": actor,
    }
    log.info("correlation run completed", extra=result)
    return result


def _upsert_session_node(conn: Connection, session: Session, now: datetime) -> None:
    node_id = f"session:{session.id}"
    summary = session.to_summary()
    summary.pop("event_ids", None)
    summary["event_sample"] = session.event_ids[:20]
    props = dumps(summary)
    existing = conn.execute(
        select(graph_nodes.c.id).where(graph_nodes.c.id == node_id)
    ).fetchone()
    if existing:
        conn.execute(
            graph_nodes.update()
            .where(graph_nodes.c.id == node_id)
            .values(label=session.id[:255], props=props, last_seen=iso(session.last_seen or now))
        )
    else:
        conn.execute(
            graph_nodes.insert().values(
                id=node_id,
                kind="session",
                label=session.id[:255],
                props=props,
                first_seen=iso(session.first_seen or now),
                last_seen=iso(session.last_seen or now),
            )
        )
    for ip in session.source_ips:
        _upsert_observation_node(conn, f"ip:{ip}", "ip", ip, {}, session, now)
        _upsert_edge_row(
            conn,
            edge_id=f"edg_{_digest(f'session:{session.id}|ip:{ip}')}",
            kind="observed_from",
            src=f"session:{session.id}",
            dst=f"ip:{ip}",
            confidence=1.0,
            score=1.0,
            evidence={"type": "observation", "note": "IP is observed, not an identity"},
            contradictions=[],
            now=now,
            expires_at=None,
            status="active",
        )
    for target in session.targets:
        _upsert_observation_node(conn, f"asset:{target}", "asset", target, {}, session, now)
        _upsert_edge_row(
            conn,
            edge_id=f"edg_{_digest(f'session:{session.id}|asset:{target}')}",
            kind="targeted_asset",
            src=f"session:{session.id}",
            dst=f"asset:{target}",
            confidence=1.0,
            score=1.0,
            evidence={"type": "observation"},
            contradictions=[],
            now=now,
            expires_at=None,
            status="active",
        )
    for indicator in session.indicators:
        _upsert_observation_node(
            conn, f"indicator:{indicator}", "indicator", indicator, {}, session, now
        )
        _upsert_edge_row(
            conn,
            edge_id=f"edg_{_digest(f'session:{session.id}|indicator:{indicator}')}",
            kind="matched_indicator",
            src=f"session:{session.id}",
            dst=f"indicator:{indicator}",
            confidence=1.0,
            score=1.0,
            evidence={"type": "observation"},
            contradictions=[],
            now=now,
            expires_at=None,
            status="active",
        )


def _upsert_observation_node(
    conn: Connection, node_id: str, kind: str, label: str, props: dict[str, Any], session: Session, now: datetime
) -> None:
    existing = conn.execute(
        select(graph_nodes.c.id).where(graph_nodes.c.id == node_id)
    ).fetchone()
    if existing:
        conn.execute(
            graph_nodes.update()
            .where(graph_nodes.c.id == node_id)
            .values(last_seen=iso(session.last_seen or now))
        )
    else:
        conn.execute(
            graph_nodes.insert().values(
                id=node_id,
                kind=kind,
                label=label[:255],
                props=dumps(props),
                first_seen=iso(session.first_seen or now),
                last_seen=iso(session.last_seen or now),
            )
        )


def _upsert_edge(
    conn: Connection, left: Session, right: Session, result: dict[str, Any], hours: int, now: datetime
) -> bool:
    key = pair_key(left.id, right.id)
    edge_id = f"edg_{_digest(key)}"
    latest = max(session.last_seen or now for session in (left, right))
    expires = latest + timedelta(hours=max(hours, 1))
    evidence = {
        "algorithm_version": result["algorithm_version"],
        "context": result.get("context"),
        "components": result["components"],
        "families": result["families"],
        "family_scores": result["family_scores"],
        "support": result["support"],
        "coverage": result["coverage"],
        "penalty": result["penalty"],
        "independent_families": result["independent_families"],
        "missing_evidence": result["missing_evidence"],
        "explanation": result["explanation"],
        "thresholds": result["thresholds"],
        "pair": result["pair"],
        "sessions": {
            "left": left.to_summary(),
            "right": right.to_summary(),
        },
    }
    status = "active" if result["decision"] == "linked" else "hypothesis"
    return _upsert_edge_row(
        conn,
        edge_id=edge_id,
        kind="session_similarity",
        src=f"session:{left.id}",
        dst=f"session:{right.id}",
        confidence=result["confidence"],
        score=result["score"],
        evidence=evidence,
        contradictions=result["contradictions"],
        now=now,
        expires_at=expires,
        status=status,
    )


def _upsert_edge_row(
    conn: Connection,
    *,
    edge_id: str,
    kind: str,
    src: str,
    dst: str,
    confidence: float,
    score: float,
    evidence: dict[str, Any],
    contradictions: list[dict[str, Any]],
    now: datetime,
    expires_at: datetime | None,
    status: str,
) -> bool:
    existing = conn.execute(
        select(graph_edges.c.id).where(graph_edges.c.id == edge_id)
    ).fetchone()
    if existing:
        conn.execute(
            graph_edges.update()
            .where(graph_edges.c.id == edge_id)
            .values(
                confidence=confidence,
                score=score,
                evidence=dumps(evidence),
                contradictions=dumps(contradictions),
                algorithm_version=ALGORITHM_VERSION,
                updated_at=iso(now),
                expires_at=iso(expires_at) if expires_at else None,
                status=status,
            )
        )
        return False
    conn.execute(
        graph_edges.insert().values(
            id=edge_id,
            kind=kind,
            src_id=src,
            dst_id=dst,
            confidence=confidence,
            score=score,
            evidence=dumps(evidence),
            contradictions=dumps(contradictions),
            algorithm_version=ALGORITHM_VERSION,
            created_at=iso(now),
            updated_at=iso(now),
            expires_at=iso(expires_at) if expires_at else None,
            status=status,
            campaign_id=None,
        )
    )
    return True


def _expire_pair(conn: Connection, key: str, now: datetime) -> None:
    edge_id = f"edg_{_digest(key)}"
    conn.execute(
        graph_edges.update()
        .where(graph_edges.c.id == edge_id)
        .values(
            status="expired",
            campaign_id=None,
            updated_at=iso(now),
            evidence=dumps(
                {
                    "explanation": "relationship no longer supported by current evidence",
                    "expired_at": iso(now),
                }
            ),
        )
    )


def _expire_stale(conn: Connection, now: datetime) -> int:
    result = conn.execute(
        text(
            "UPDATE graph_edges SET status = 'expired' "
            "WHERE status IN ('active', 'hypothesis') AND expires_at IS NOT NULL "
            "AND expires_at < :now"
        ),
        {"now": iso(now)},
    )
    return int(result.rowcount or 0)


def _cleanup_stale_campaigns(conn: Connection, now: datetime) -> None:
    live = {
        row[0]
        for row in conn.execute(
            text(
                "SELECT DISTINCT campaign_id FROM graph_edges "
                "WHERE kind = 'session_similarity' AND status = 'active' "
                "AND campaign_id IS NOT NULL"
            )
        ).fetchall()
    }
    stored = [row[0] for row in conn.execute(select(campaigns.c.id)).fetchall()]
    for campaign_id in stored:
        if campaign_id in live:
            continue
        conn.execute(text("DELETE FROM graph_edges WHERE campaign_id = :id"), {"id": campaign_id})
        conn.execute(
            text("DELETE FROM graph_edges WHERE src_id = :node"),
            {"node": f"campaign:{campaign_id}"},
        )
        conn.execute(text("DELETE FROM graph_nodes WHERE id = :node"), {"node": f"campaign:{campaign_id}"})
        conn.execute(campaigns.delete().where(campaigns.c.id == campaign_id))


def _upsert_campaign(
    conn: Connection,
    members: list[str],
    sessions: dict[str, Session],
    internal: list[tuple[str, float]],
    ips: set[str],
    now: datetime,
) -> tuple[str, str]:
    signature = "\x1f".join(sorted(members))
    campaign_id = f"cmp_{_digest(signature)}"
    confidence = min(value for _, value in internal)
    categories: dict[str, int] = defaultdict(int)
    for member in members:
        for category, count in sessions[member].categories.items():
            categories[category] += count
    dominant = sorted(categories.items(), key=lambda item: item[1], reverse=True)[:3]
    cross_ip = len(ips) > 1
    kind = "cross-IP campaign candidate" if cross_ip else "same-IP activity cluster"
    name = f"{kind} {campaign_id[4:10]}"
    summary = (
        f"{len(members)} sessions from {len(ips)} source IP(s) share behavioral evidence "
        f"(minimum edge confidence {confidence:.2f}). Dominant activity: "
        + ", ".join(f"{category} ({count})" for category, count in dominant)
        + ". This is a hypothesis, not an attribution."
    )
    evidence = {
        "sessions": sorted(members),
        "ips": sorted(ips),
        "edges": [{"pair": key, "confidence": value} for key, value in internal],
        "categories": dict(categories),
        "cross_ip": cross_ip,
        "algorithm_version": ALGORITHM_VERSION,
        "note": (
            "Campaign membership is derived from linked session pairs. It is a "
            "relationship hypothesis, not an attribution to a named actor."
        ),
    }
    existing = conn.execute(
        select(campaigns.c.id).where(campaigns.c.id == campaign_id)
    ).fetchone()
    if existing:
        conn.execute(
            campaigns.update()
            .where(campaigns.c.id == campaign_id)
            .values(
                confidence=confidence,
                summary=summary,
                evidence=dumps(evidence),
                updated_at=iso(now),
                member_count=len(members),
                ip_count=len(ips),
            )
        )
    else:
        conn.execute(
            campaigns.insert().values(
                id=campaign_id,
                name=name,
                status="candidate",
                confidence=confidence,
                summary=summary,
                evidence=dumps(evidence),
                created_at=iso(now),
                updated_at=iso(now),
                algorithm_version=ALGORITHM_VERSION,
                member_count=len(members),
                ip_count=len(ips),
            )
        )
    return campaign_id, name


def _upsert_campaign_node(
    conn: Connection, campaign_id: str, name: str, now: datetime, members: list[str]
) -> None:
    node_id = f"campaign:{campaign_id}"
    existing = conn.execute(
        select(graph_nodes.c.id).where(graph_nodes.c.id == node_id)
    ).fetchone()
    props = dumps({"members": len(members)})
    if existing:
        conn.execute(
            graph_nodes.update()
            .where(graph_nodes.c.id == node_id)
            .values(label=name[:255], props=props, last_seen=iso(now))
        )
    else:
        conn.execute(
            graph_nodes.insert().values(
                id=node_id,
                kind="campaign",
                label=name[:255],
                props=props,
                first_seen=iso(now),
                last_seen=iso(now),
            )
        )
    for member in members:
        _upsert_edge_row(
            conn,
            edge_id=f"edg_{_digest(f'{campaign_id}|session:{member}')}",
            kind="campaign_contains",
            src=node_id,
            dst=f"session:{member}",
            confidence=1.0,
            score=1.0,
            evidence={"type": "membership", "campaign_id": campaign_id},
            contradictions=[],
            now=now,
            expires_at=None,
            status="active",
        )


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]


def latest_run() -> dict[str, Any] | None:
    with connection() as conn:
        row = conn.execute(
            select(correlation_runs).order_by(correlation_runs.c.finished_at.desc()).limit(1)
        ).fetchone()
    if not row:
        return None
    data = dict(row._mapping)
    data["metrics"] = loads(data.get("metrics"), {})
    return data
