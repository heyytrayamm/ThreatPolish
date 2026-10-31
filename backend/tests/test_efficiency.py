"""Development-scope and efficiency invariants.

Two questions are asked here that a feature test cannot ask.

**Scope** — a developed route has to exist in three places at once: the API
reference an integrator reads, the suite that exercises it and the RBAC matrix
that guards it.  The same holds for a configuration value and ``.env.example``.
The scan in ``scripts/deepscan.py`` answers this for the whole application; the
test below makes the answer a CI gate rather than something a manual run has to
remember to check.

**Efficiency** — what a populated installation pays for a request.  Two shapes
degrade without anyone noticing: a response that grows with the data it returns
(the evidence graph used to serialise every node's stored properties, a fifth of
a megabyte per request on the evaluation corpus alone) and a query inside a loop,
which shows up as the same statement repeated many times in one request and gets
slower as tables grow.  The checks below measure bytes and statements on a
seeded corpus and fail on either shape.
"""

from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
from typing import Any, Iterator

# The evaluation corpus, at the size ``scripts/deepscan.py`` and the runtime
# benchmarks use: enough sessions that per-row work is visible in a payload.
CORPUS = {
    "seed": 99,
    "campaign_groups": 40,
    "sessions_per_group": 3,
    "benign_sessions": 24,
    "same_ip_pairs": 4,
    "incomplete_groups": 2,
    "delayed_sessions": 3,
}
GRAPH_PAYLOAD_BUDGET = 512 * 1024
MAX_STATEMENTS_PER_REQUEST = 20
MAX_REPEATED_STATEMENTS = 2


def _seed() -> dict[str, int]:
    """Ingest the evaluation corpus and correlate it once."""
    from app.core.config import get_settings
    from app.correlation.engine import correlate
    from app.evaluation.scenarios import generate_dataset
    from app.telemetry.ingest import Ingestor

    dataset = generate_dataset(**CORPUS)
    events = [item for session in dataset["sessions"] for item in session["events"]]
    Ingestor(get_settings()).ingest(events, actor="efficiency-test")
    correlate(window_hours=24, trigger="efficiency-test")
    return {"sessions": len(dataset["sessions"]), "events": len(events)}


@contextmanager
def _statements() -> Iterator[list[str]]:
    """Record every SQL statement the application issues inside the block."""
    from sqlalchemy import event

    from app.db.database import get_engine

    seen: list[str] = []

    def _record(conn, cursor, statement, parameters, context, executemany) -> None:
        seen.append(" ".join(statement.split()))

    engine = get_engine()
    event.listen(engine, "before_cursor_execute", _record)
    try:
        yield seen
    finally:
        event.remove(engine, "before_cursor_execute", _record)


def _get(client, path: str, headers: dict[str, str]) -> tuple[Any, list[str]]:
    """Return the response and the statements it took to produce it."""
    with _statements() as seen:
        response = client.get(path, headers=headers)
    assert response.status_code == 200, (path, response.status_code, response.text)
    assert response.content
    return response, seen


def test_every_route_is_documented_exercised_and_guarded(client) -> None:
    """A route has to appear in the reference, the suite and the RBAC matrix."""
    from scripts.deepscan import scan_scope

    report = scan_scope(client)
    assert report["undocumented_routes"] == []
    assert report["untested_routes"] == []
    assert report["stale_documentation"] == []
    assert report["orphan_permissions"] == []
    assert report["undocumented_config"] == []
    assert report["unused_env"] == []
    assert report["findings"] == []
    assert report["routes"] == report["documented_routes"] == report["tested_routes"]


def test_graph_payload_is_bounded_and_reports_truncation(client, admin_headers) -> None:
    """The graph view returns a drawing-sized page, never the whole window.

    The seeded corpus is larger than a small page and smaller than the default
    one, so both branches are exercised: an untruncated default response that
    fits the byte budget, and a deliberately small page that must say it was cut.
    """
    counts = _seed()
    assert counts["sessions"] > 100

    full_response, full_statements = _get(client, "/api/v1/graph?hours=24", admin_headers)
    full = full_response.json()
    assert full["node_count"] == len(full["nodes"]) > 100
    assert full["node_count"] <= full["limits"]["nodes"]
    assert full["edge_count"] == len(full["edges"]) <= full["limits"]["edges"]
    assert len(full_response.content) <= GRAPH_PAYLOAD_BUDGET, f"{len(full_response.content)} bytes"
    # Stored node properties belong to the campaign detail view; copying them
    # into every graph node is what made the response grow with each session.
    assert all("props" not in node for node in full["nodes"])
    assert not any("graph_nodes" in statement and " props" in statement for statement in full_statements)
    # Edges are denser than nodes, so the default page cuts the edge list and
    # has to say so instead of quietly returning a third of the relationships.
    assert full["truncated"] == {"nodes": False, "edges": True}
    assert "capped at" in full["note"]

    small_response, small_statements = _get(
        client, "/api/v1/graph?hours=24&limit=50&edge_limit=10", admin_headers
    )
    small = small_response.json()
    assert small["node_count"] == 50
    assert small["edge_count"] <= 10
    assert small["truncated"]["nodes"] is True
    assert len(small_response.content) < len(full_response.content)
    assert {node["id"] for node in small["nodes"]} <= {node["id"] for node in full["nodes"]}
    # Page size must not change how many statements the endpoint needs.
    assert len(small_statements) == len(full_statements)


def test_read_endpoints_do_not_query_in_a_loop(client, admin_headers) -> None:
    """No read endpoint repeats a statement per row, whatever the page size."""
    _seed()
    campaign_id = client.get("/api/v1/campaigns", headers=admin_headers).json()["items"][0]["id"]
    paths = [
        "/api/v1/events?limit=1",
        "/api/v1/events?limit=500",
        "/api/v1/events/summary",
        "/api/v1/sources",
        "/api/v1/campaigns",
        f"/api/v1/campaigns/{campaign_id}",
        "/api/v1/retention",
        "/api/v1/metrics",
        "/api/v1/graph?hours=24",
    ]

    counts: dict[str, int] = {}
    for path in paths:
        _, statements = _get(client, path, admin_headers)
        assert len(statements) <= MAX_STATEMENTS_PER_REQUEST, (path, len(statements))
        repeated = Counter(statements).most_common(1)[0][1] if statements else 0
        assert repeated <= MAX_REPEATED_STATEMENTS, (path, Counter(statements).most_common(3))
        counts[path] = len(statements)

    # Paging a listing is a LIMIT, not a wider set of queries.
    assert counts["/api/v1/events?limit=1"] == counts["/api/v1/events?limit=500"]
