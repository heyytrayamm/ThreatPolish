"""Correlation engine: sessions -> evidence edges -> campaign candidates."""

from __future__ import annotations

import hashlib
import heapq
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
# Sized from `scripts/benchmark_correlation.py` and recorded in
# `docs/research/correlation-runtime.md`: at 788 sessions the run scores 310,078
# pairs in about 28 s and the 8,000-edge cap retains every linked pair.  At 982
# sessions the same edge cap starts dropping links, so 800 is the largest
# measured window that keeps all of them.
MAX_SESSIONS_PER_RUN = 800
MAX_EDGES_PER_RUN = 8_000
# A campaign keeps its identifier while at least half of its membership survives,
# measured as Jaccard overlap with the previous member set.  Growth, shrinkage
# and the merge of two comparable campaigns therefore keep the reviewed
# identity; a mostly new set of sessions starts a new campaign instead.  The
# old row is archived, never deleted, when it loses that continuity.
MIN_MEMBERSHIP_OVERLAP = 0.5
MAX_MEMBERSHIP_HISTORY = 20


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
    context_fingerprint = context.fingerprint()
    created = updated = expired = 0
    campaign_ids: list[str] = []
    # Scores are streamed into a bounded heap instead of being retained for
    # every pair.  A full result is a few kilobytes, so keeping all of them is
    # quadratic memory: at 800 sessions that was more than a gigabyte before a
    # single edge was written.  Only the strongest MAX_EDGES_PER_RUN results
    # can be persisted, so only those are kept.
    scored_count = candidate_count = linked_candidates = reused_count = reused_candidates = 0
    heap: list[tuple[float, int, str, dict[str, Any]]] = []
    fingerprints = {session_id: session.fingerprint() for session_id, session in sessions.items()}

    with connection() as conn:
        previous_run = conn.execute(
            select(correlation_runs).order_by(correlation_runs.c.finished_at.desc()).limit(1)
        ).fetchone()
        previous_metrics = loads(previous_run._mapping["metrics"], {}) if previous_run else {}
        # Reuse is only sound when the corpus that produced the weights and the
        # two sessions themselves are unchanged.  A change to any document
        # frequency moves every pair's corpus-relative weight, so the context
        # fingerprint gates incremental runs rather than each pair deciding.
        incremental = bool(
            previous_run
            and previous_run._mapping["algorithm_version"] == ALGORITHM_VERSION
            and previous_metrics.get("context_fingerprint") == context_fingerprint
            # Edge expiry is derived from the window length, and retained edges
            # are not rewritten, so a changed window needs a full pass.
            and previous_metrics.get("window_hours") == hours
        )
        previous_run_id = previous_run._mapping["id"] if previous_run and incremental else None
        prior_sessions = (
            _prior_session_state(conn, list(sessions)) if incremental else {}
        )
        existing_similarity_edges = conn.execute(
            select(
                graph_edges.c.id,
                graph_edges.c.src_id,
                graph_edges.c.dst_id,
                graph_edges.c.status,
                graph_edges.c.confidence,
            ).where(graph_edges.c.kind == "session_similarity")
        ).fetchall()
        existing_by_key = {
            pair_key(
                str(src).removeprefix("session:"), str(dst).removeprefix("session:")
            ): (edge_id, status, confidence)
            for edge_id, src, dst, status, confidence in existing_similarity_edges
        }

        for session in sessions.values():
            _upsert_session_node(conn, session, started_at, run_id, fingerprints[session.id])

        retained_edge_ids: set[str] = set()
        reused_links: dict[str, float] = {}

        ordered_sessions = list(sessions.values())
        for left_index in range(len(ordered_sessions)):
            left = ordered_sessions[left_index]
            for right_index in range(left_index + 1, len(ordered_sessions)):
                right = ordered_sessions[right_index]
                if left.id == right.id:
                    continue
                key = pair_key(left.id, right.id)
                if incremental and prior_sessions.get(left.id) == (
                    previous_run_id,
                    fingerprints[left.id],
                ) and prior_sessions.get(right.id) == (
                    previous_run_id,
                    fingerprints[right.id],
                ):
                    # Both sessions and the corpus are unchanged, so this pair
                    # would produce exactly the stored decision.  Keep an
                    # existing edge and skip the comparison.
                    reused_count += 1
                    existing = existing_by_key.get(key)
                    if existing:
                        edge_id, status, confidence = existing
                        retained_edge_ids.add(edge_id)
                        reused_candidates += 1
                        if status == "active":
                            reused_links[key] = confidence
                    continue
                result = compare(left, right, context=context)
                scored_count += 1
                if result["score"] >= MIN_SCORE_TO_STORE:
                    candidate_count += 1
                    if result["decision"] == "linked":
                        linked_candidates += 1
                    heapq.heappush(
                        heap,
                        (
                            result["score"],
                            scored_count,
                            key,
                            {"left": left, "right": right, "result": result},
                        ),
                    )
                    if len(heap) > MAX_EDGES_PER_RUN:
                        heapq.heappop(heap)

        # Only persist the strongest relationships; a busy sensor must not be
        # able to inflate the graph without bound.
        persistable = [
            (key, item)
            for _score, _order, key, item in sorted(
                heap, key=lambda entry: (-entry[0], entry[1])
            )
        ]
        dropped = candidate_count - len(persistable)
        # A dropped hypothesis is a lost lead; a dropped link would be a
        # grouping error.  They are counted separately so the cap can be
        # judged on what it actually removes.
        dropped_links = linked_candidates - sum(
            1 for _, item in persistable if item["result"]["decision"] == "linked"
        )
        persisted_edge_ids = {f"edg_{_digest(key)}" for key, _ in persistable}
        retained_edge_ids.update(persisted_edge_ids)

        for _, item in persistable:
            was_created = _upsert_edge(
                conn, item["left"], item["right"], item["result"], hours, started_at
            )
            created += 1 if was_created else 0
            updated += 0 if was_created else 1

        # An edge whose sessions were both scored this run and which did not
        # make the persistence cut is no longer supported by current evidence.
        # Deriving that from the endpoints avoids keeping every pair key.
        current_session_ids = set(sessions)
        for edge_id, src, dst, _status, _confidence in existing_similarity_edges:
            if edge_id in retained_edge_ids:
                continue
            left_id = str(src).removeprefix("session:")
            right_id = str(dst).removeprefix("session:")
            if left_id in current_session_ids and right_id in current_session_ids:
                _expire_pair(conn, pair_key(left_id, right_id), started_at)
                expired += 1

        # ---- campaign candidates over linked pairs ---------------------- #
        union = UnionFind()
        edge_confidence: dict[str, float] = dict(reused_links)
        for key, confidence in reused_links.items():
            first, second = key.split(PAIR_SEPARATOR)
            union.union(first, second)
        for key, item in persistable:
            if item["result"]["decision"] != "linked":
                continue
            union.union(item["left"].id, item["right"].id)
            edge_confidence[key] = item["result"]["confidence"]

        components = sorted(
            sorted(members)
            for members in union.components().values()
            if len(members) >= 2
        )
        existing_campaigns = _load_campaigns(conn)
        existing_by_id = {campaign["id"]: campaign for campaign in existing_campaigns}
        assignments, absorbed = _assign_campaign_ids(components, existing_campaigns)

        for index, members in enumerate(components):
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
            inherited = assignments.get(index)
            campaign_id = inherited or f"cmp_{_digest('\x1f'.join(members))}"
            campaign_id, name, _changed = _upsert_campaign(
                conn,
                campaign_id=campaign_id,
                members=members,
                sessions=sessions,
                internal=internal,
                ips=ips,
                now=started_at,
                existing=existing_by_id.get(inherited) if inherited else None,
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

        # Merged campaigns are recorded after their survivor has been written,
        # so the analyst's decision and review history land on the final row.
        merged_campaigns = 0
        for survivor_id, absorbed_ids in absorbed.items():
            if survivor_id not in campaign_ids:
                continue
            merged_campaigns += _merge_campaigns(
                conn, survivor_id, absorbed_ids, existing_by_id, started_at
            )

        expired += _expire_stale(conn, started_at)
        archived, removed = _cleanup_stale_campaigns(conn, started_at)

        total_pairs = len(sessions) * (len(sessions) - 1) // 2
        below_threshold = max(
            0, (scored_count - candidate_count) + (reused_count - reused_candidates)
        )
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
                        "window_hours": hours,
                        "pairs_total": total_pairs,
                        "pairs_scored": scored_count,
                        "pairs_reused": reused_count,
                        "incremental": incremental,
                        "context_fingerprint": context_fingerprint,
                        "pairs_persisted": len(persistable),
                        "pairs_dropped_by_cap": dropped,
                        "links_dropped_by_cap": dropped_links,
                        "pairs_below_threshold": below_threshold,
                        "campaigns_merged": merged_campaigns,
                        "campaigns_archived": archived,
                        "campaigns_removed": removed,
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
        "pairs_total": total_pairs,
        "pairs_scored": scored_count,
        "pairs_reused": reused_count,
        "incremental": incremental,
        "context_fingerprint": context_fingerprint,
        "edges_created": created,
        "edges_updated": updated,
        "edges_expired": expired,
        "campaigns": len(campaign_ids),
        "campaign_ids": campaign_ids,
        "campaigns_merged": merged_campaigns,
        "campaigns_archived": archived,
        "pairs_dropped_by_cap": dropped,
        "links_dropped_by_cap": dropped_links,
        "truncated": truncated or dropped > 0,
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        "algorithm_version": ALGORITHM_VERSION,
        "trigger": trigger,
        "actor": actor,
    }
    log.info("correlation run completed", extra=result)
    return result


def _upsert_session_node(
    conn: Connection,
    session: Session,
    now: datetime,
    run_id: str,
    fingerprint: str,
) -> None:
    node_id = f"session:{session.id}"
    summary = session.to_summary()
    summary.pop("event_ids", None)
    summary["event_sample"] = session.event_ids[:20]
    # The next run uses the fingerprint and run marker to decide whether this
    # session's pairs can reuse their stored decisions.
    summary["fingerprint"] = fingerprint
    summary["last_run_id"] = run_id
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
                # Campaign membership is recomputed from linked pairs on every
                # run.  Keeping the previous campaign here would leave a
                # hypothesis or expired edge listed as campaign evidence.
                campaign_id=None,
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
    row = conn.execute(
        select(graph_edges.c.evidence).where(graph_edges.c.id == edge_id)
    ).fetchone()
    # Expiry retires a relationship; it does not erase why it was proposed.
    # The original evidence stays readable with the expiry recorded on top, so
    # an analyst can still see what the model believed and when it changed.
    evidence = loads(row[0], {}) if row else {}
    evidence["expired_at"] = iso(now)
    evidence["expiry_reason"] = "relationship no longer supported by current evidence"
    conn.execute(
        graph_edges.update()
        .where(graph_edges.c.id == edge_id)
        .values(
            status="expired",
            campaign_id=None,
            updated_at=iso(now),
            evidence=dumps(evidence),
        )
    )


def _expire_stale(conn: Connection, now: datetime) -> int:
    result = conn.execute(
        text(
            "UPDATE graph_edges SET status = 'expired', campaign_id = NULL "
            "WHERE status IN ('active', 'hypothesis') AND expires_at IS NOT NULL "
            "AND expires_at < :now"
        ),
        {"now": iso(now)},
    )
    return int(result.rowcount or 0)


def _prior_session_state(
    conn: Connection, session_ids: list[str]
) -> dict[str, tuple[str | None, str | None]]:
    """Fingerprint and last-run marker for sessions that already exist."""
    state: dict[str, tuple[str | None, str | None]] = {}
    for start in range(0, len(session_ids), 400):
        chunk = session_ids[start : start + 400]
        placeholders = ", ".join(f":s{index}" for index in range(len(chunk)))
        params = {f"s{index}": f"session:{value}" for index, value in enumerate(chunk)}
        rows = conn.execute(
            text(
                "SELECT id, props FROM graph_nodes WHERE kind = 'session' "
                f"AND id IN ({placeholders})"
            ),
            params,
        ).fetchall()
        for node_id, props in rows:
            data = loads(props, {})
            state[str(node_id).removeprefix("session:")] = (
                data.get("last_run_id"),
                data.get("fingerprint"),
            )
    return state


def _load_campaigns(conn: Connection) -> list[dict[str, Any]]:
    """Load campaign rows with the member set stored in their evidence."""
    loaded: list[dict[str, Any]] = []
    for row in conn.execute(select(campaigns)).fetchall():
        data = dict(row._mapping)
        evidence = loads(data.get("evidence"), {})
        loaded.append(
            {
                "id": data["id"],
                "name": data["name"],
                "status": data["status"],
                "created_at": data["created_at"],
                "updated_at": data["updated_at"],
                "status_updated_at": data.get("status_updated_at"),
                "superseded_by": data.get("superseded_by"),
                "archived_at": data.get("archived_at"),
                "members": set(evidence.get("sessions", [])),
                "evidence": evidence,
            }
        )
    return loaded


def _assign_campaign_ids(
    components: list[list[str]], existing: list[dict[str, Any]]
) -> tuple[dict[int, str], dict[str, list[str]]]:
    """Match new membership components to existing campaign identities.

    A campaign is the same relationship until most of its membership changes.
    Matching is one-to-one so a split cannot hand the same identity to two
    components; the component with the strongest overlap keeps it.  A campaign
    that matched the winning component but was not itself assigned has been
    merged into it and is superseded, which is how analyst feedback follows a
    merge instead of being left on a row that no longer represents the cluster.
    """
    ranked: list[tuple[float, int, str, int]] = []
    for index, members in enumerate(components):
        current = set(members)
        for campaign in existing:
            # A superseded row has been absorbed into another campaign, so it
            # must not be resurrected as a duplicate.  An archived row may be:
            # if the same sessions link again, the analyst's review of that
            # relationship applies again.
            if campaign["superseded_by"]:
                continue
            shared = current & campaign["members"]
            if not shared:
                continue
            similarity = len(shared) / len(current | campaign["members"])
            if similarity < MIN_MEMBERSHIP_OVERLAP:
                continue
            ranked.append((similarity, len(shared), campaign["id"], index))
    # Deterministic: strongest overlap first, then the campaign identifier so
    # two runs over the same data always make the same choice.
    ranked.sort(key=lambda item: (-item[0], -item[1], item[2], item[3]))

    assignments: dict[int, str] = {}
    claimed: set[str] = set()
    for _similarity, _shared, campaign_id, index in ranked:
        if index in assignments or campaign_id in claimed:
            continue
        assignments[index] = campaign_id
        claimed.add(campaign_id)

    absorbed: dict[str, list[str]] = {}
    for index, survivor_id in assignments.items():
        for _similarity, _shared, candidate, matched_index in ranked:
            if matched_index != index or candidate == survivor_id or candidate in claimed:
                continue
            absorbed.setdefault(survivor_id, []).append(candidate)
            claimed.add(candidate)
    return assignments, absorbed


def _campaign_has_history(conn: Connection, campaign_id: str, status: str) -> bool:
    """Whether anything an analyst did would be lost by deleting the row."""
    if status != "candidate":
        return True
    checks = (
        ("feedback", "object_type = 'campaign' AND object_id = :id"),
        ("investigations", "campaign_id = :id"),
        ("responses", "campaign_id = :id"),
    )
    for table, predicate in checks:
        found = conn.execute(
            text(f"SELECT 1 FROM {table} WHERE {predicate} LIMIT 1"), {"id": campaign_id}
        ).fetchone()
        if found:
            return True
    return False


def _drop_campaign_graph(conn: Connection, campaign_id: str) -> None:
    """Remove a campaign's live graph presence without touching its record."""
    conn.execute(
        text("DELETE FROM graph_edges WHERE kind = 'campaign_contains' AND src_id = :node"),
        {"node": f"campaign:{campaign_id}"},
    )
    conn.execute(
        text("DELETE FROM graph_nodes WHERE id = :node"),
        {"node": f"campaign:{campaign_id}"},
    )


def _cleanup_stale_campaigns(conn: Connection, now: datetime) -> tuple[int, int]:
    """Archive reviewed campaigns that lost their links; delete only untouched ones.

    Returns ``(archived, removed)``.  A campaign that an analyst reviewed, or
    that an investigation or response refers to, is archived rather than
    deleted: the row is the record of that decision and of the session set it
    covered.  Unreviewed automatic candidates are removed so stale graph
    candidates do not accumulate without bound.
    """
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
    archived = removed = 0
    for row in conn.execute(select(campaigns)).fetchall():
        data = dict(row._mapping)
        campaign_id = data["id"]
        if campaign_id in live:
            continue
        _drop_campaign_graph(conn, campaign_id)
        if data.get("archived_at") or data.get("superseded_by"):
            # Already retired: only the graph presence needed clearing.
            continue
        if _campaign_has_history(conn, campaign_id, data["status"]):
            conn.execute(
                campaigns.update()
                .where(campaigns.c.id == campaign_id)
                .values(archived_at=iso(now), updated_at=iso(now))
            )
            archived += 1
            continue
        conn.execute(text("DELETE FROM graph_edges WHERE campaign_id = :id"), {"id": campaign_id})
        conn.execute(campaigns.delete().where(campaigns.c.id == campaign_id))
        removed += 1
    return archived, removed


def _merge_campaigns(
    conn: Connection,
    survivor_id: str,
    absorbed_ids: list[str],
    existing: dict[str, dict[str, Any]],
    now: datetime,
) -> int:
    """Absorb merged campaigns and carry their analyst decisions forward.

    Feedback, open investigations and response requests move to the survivor,
    so no review points at a row that no longer describes the cluster.  When
    the absorbed and surviving campaigns disagree about their review status the
    survivor becomes ``uncertain`` rather than silently preferring one
    analyst's judgement over another.
    """
    survivor = existing[survivor_id]
    decisions = [
        (absorbed_id, existing[absorbed_id]["status"])
        for absorbed_id in absorbed_ids
        if existing[absorbed_id]["status"] != "candidate"
    ]
    for absorbed_id in absorbed_ids:
        conn.execute(
            text(
                "UPDATE feedback SET object_id = :survivor "
                "WHERE object_type = 'campaign' AND object_id = :absorbed"
            ),
            {"survivor": survivor_id, "absorbed": absorbed_id},
        )
        conn.execute(
            text("UPDATE responses SET campaign_id = :survivor WHERE campaign_id = :absorbed"),
            {"survivor": survivor_id, "absorbed": absorbed_id},
        )
        conn.execute(
            text(
                "UPDATE investigations SET status = 'superseded' "
                "WHERE campaign_id = :absorbed AND status IN ('planned', 'active')"
            ),
            {"absorbed": absorbed_id},
        )
        # Links that belong to the merged component were reassigned to the
        # survivor above.  Anything still pointing at the absorbed row is
        # evidence the current run did not reproduce (for example, a member
        # outside the window), so it must not become campaign evidence.
        conn.execute(
            text(
                "UPDATE graph_edges SET campaign_id = NULL "
                "WHERE campaign_id = :absorbed AND kind = 'session_similarity'"
            ),
            {"absorbed": absorbed_id},
        )
        conn.execute(
            campaigns.update()
            .where(campaigns.c.id == absorbed_id)
            .values(superseded_by=survivor_id, archived_at=iso(now), updated_at=iso(now))
        )
        _drop_campaign_graph(conn, absorbed_id)

    if not decisions:
        return len(absorbed_ids)

    survivor_status = survivor["status"]
    carried = {status for _, status in decisions}
    if survivor_status == "candidate":
        new_status = carried.pop() if len(carried) == 1 else "uncertain"
    else:
        new_status = "uncertain" if any(status != survivor_status for status in carried) else survivor_status

    row = conn.execute(
        select(campaigns.c.evidence).where(campaigns.c.id == survivor_id)
    ).fetchone()
    evidence = loads(row[0], {}) if row else {}
    history = list(evidence.get("review_history", []))
    for absorbed_id, status in decisions:
        history.append(
            {
                "at": iso(now),
                "event": "campaign_merged",
                "absorbed": absorbed_id,
                "absorbed_status": status,
            }
        )
    if new_status != survivor_status:
        history.append(
            {
                "at": iso(now),
                "event": "status_carried",
                "from": survivor_status,
                "to": new_status,
                "source": [absorbed_id for absorbed_id, _ in decisions],
            }
        )
    evidence["review_history"] = history[-MAX_MEMBERSHIP_HISTORY:]
    conn.execute(
        campaigns.update()
        .where(campaigns.c.id == survivor_id)
        .values(
            status=new_status,
            status_updated_at=iso(now) if new_status != survivor_status else survivor["status_updated_at"],
            evidence=dumps(evidence),
            updated_at=iso(now),
        )
    )
    return len(absorbed_ids)


def _upsert_campaign(
    conn: Connection,
    *,
    campaign_id: str,
    members: list[str],
    sessions: dict[str, Session],
    internal: list[tuple[str, float]],
    ips: set[str],
    now: datetime,
    existing: dict[str, Any] | None,
) -> tuple[str, str, bool]:
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
    membership_changed = True
    if existing is not None:
        previous_members = set(existing["members"])
        added = sorted(set(members) - previous_members)
        removed = sorted(previous_members - set(members))
        membership_changed = bool(added or removed)
        evidence["membership"] = {"added": added, "removed": removed}
        history = list(existing["evidence"].get("membership_history", []))
        if membership_changed:
            history.append({"at": iso(now), "added": added, "removed": removed})
        reactivated = bool(existing.get("archived_at"))
        if reactivated:
            history.append({"at": iso(now), "event": "reactivated"})
        review_history = list(existing["evidence"].get("review_history", []))
        if review_history:
            evidence["review_history"] = review_history[-MAX_MEMBERSHIP_HISTORY:]
        if history:
            evidence["membership_history"] = history[-MAX_MEMBERSHIP_HISTORY:]
        # The name and review status are the analyst's anchors on this
        # campaign; only the derived membership, confidence and summary move.
        name = existing["name"]
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
                archived_at=None if reactivated else existing.get("archived_at"),
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
    return campaign_id, name, membership_changed


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
    # Membership edges of sessions that left the campaign must go too, or the
    # graph would show a session inside a campaign it no longer belongs to.
    placeholders = ", ".join(f":m{index}" for index in range(len(members)))
    member_params: dict[str, Any] = {
        f"m{index}": f"session:{member}" for index, member in enumerate(members)
    }
    member_params["node"] = node_id
    conn.execute(
        text(
            "DELETE FROM graph_edges WHERE kind = 'campaign_contains' "
            f"AND src_id = :node AND dst_id NOT IN ({placeholders})"
        ),
        member_params,
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
