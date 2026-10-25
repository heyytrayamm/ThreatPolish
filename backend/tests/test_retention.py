from __future__ import annotations

from datetime import datetime, time, timedelta, timezone

from app.core.security import iso, utcnow
from app.db.database import connection, dumps
from app.db.retention import purge_all, retention_history, retention_status, run_retention
from app.db.schema import events, graph_edges, graph_nodes, retention_runs


def _insert_event(retention_until: str, dedup_key: str = "retention-expired") -> None:
    now = iso(utcnow())
    with connection() as conn:
        conn.execute(
            events.insert().values(
                id=f"evt_{dedup_key}",
                schema_version="1.0",
                occurred_at=now,
                received_at=now,
                source_module="honeypot",
                event_type="honeypot.ssh.command",
                source_ip="203.0.113.9",
                session_id="stale",
                target_id=None,
                severity="low",
                provenance=dumps({"collector": "test", "source": "pytest", "reliability": 0.9}),
                features=dumps({}),
                evidence_refs=dumps([]),
                raw=dumps({"note": "retention test"}),
                dedup_key=dedup_key,
                status="accepted",
                correlation_state="pending",
                synthetic=0,
                retention_until=retention_until,
            )
        )


def test_retention_grace_separates_backlog_from_overdue(client, admin_headers):
    _insert_event(iso(utcnow() - timedelta(days=1)))
    status = client.get("/api/v1/retention", headers=admin_headers).json()
    assert status["grace_days"] == 2
    assert status["events"]["expired"] == 1
    assert status["overdue"] is False


def test_retention_status_requires_retention_read(client, viewer_headers, admin_headers):
    assert client.get("/api/v1/retention").status_code == 401
    assert client.get("/api/v1/retention", headers=viewer_headers).status_code == 403

    body = client.get("/api/v1/retention", headers=admin_headers).json()
    assert body["overdue"] is False
    assert body["events"]["total"] == 0
    assert body["events"]["expired"] == 0
    assert body["graph"]["nodes"] == 0
    assert body["graph"]["edges"] == 0


def test_analyst_can_read_retention_history_but_not_run_it(
    client, admin_headers, analyst_headers
):
    _insert_event(iso(utcnow() - timedelta(days=10)), dedup_key="analyst-read")
    run_retention(trigger="scheduled")

    status = client.get("/api/v1/retention", headers=analyst_headers)
    assert status.status_code == 200, status.text
    assert status.json()["history_total"] == 1
    export = client.get("/api/v1/retention/history.csv", headers=analyst_headers)
    assert export.status_code == 200, export.text
    assert export.text.startswith("run_id,ran_at,trigger")

    denied = client.post("/api/v1/retention/run", headers=analyst_headers)
    assert denied.status_code == 403
    assert client.get("/api/v1/audit", headers=analyst_headers).status_code == 403


def test_retention_reports_lag_and_purge_clears_it(client, admin_headers):
    old = iso(utcnow() - timedelta(days=100))
    node_ids = {
        "session:similar-a": "session",
        "session:similar-b": "session",
        "session:stale": "session",
        "ip:stale": "ip",
    }
    _insert_event(iso(utcnow() - timedelta(days=10)))
    with connection() as conn:
        for node_id, kind in node_ids.items():
            conn.execute(
                graph_nodes.insert().values(
                    id=node_id,
                    kind=kind,
                    label=node_id.split(":", 1)[1],
                    props="{}",
                    first_seen=old,
                    last_seen=old,
                )
            )
        for edge_id, kind, src, dst in (
            ("edg_expired", "session_similarity", "session:similar-a", "session:similar-b"),
            ("edg_observed", "observed_from", "session:stale", "ip:stale"),
        ):
            conn.execute(
                graph_edges.insert().values(
                    id=edge_id,
                    kind=kind,
                    src_id=src,
                    dst_id=dst,
                    confidence=0.9,
                    score=0.9,
                    evidence=dumps({"explanation": "test"}),
                    contradictions=dumps([]),
                    algorithm_version="1.0",
                    created_at=old,
                    updated_at=old,
                    expires_at=None,
                    status="expired" if kind == "session_similarity" else "active",
                )
            )

    status = client.get("/api/v1/retention", headers=admin_headers).json()
    assert status["overdue"] is True
    assert status["events"]["total"] == 1
    assert status["events"]["expired"] == 1
    assert status["events"]["oldest_occurred_at"] is not None
    assert status["graph"]["nodes"] == 4
    assert status["graph"]["edges"] == 2
    assert status["graph"]["retired_edges"] == 1
    assert status["graph"]["stale_observations"] == 1
    assert status["graph"]["orphan_nodes"] == 0

    result = purge_all()
    assert result["events"]["events"] == 1
    assert result["graph"]["edges"] == 1
    assert result["graph"]["observations"] == 1
    assert result["graph"]["nodes"] == 4

    cleared = client.get("/api/v1/retention", headers=admin_headers).json()
    assert cleared["overdue"] is False
    assert cleared["events"]["total"] == 0
    assert cleared["graph"]["nodes"] == 0
    assert cleared["graph"]["edges"] == 0
    assert retention_status()["overdue"] is False


def test_retention_history_reports_truncation_and_exports_every_run(
    client, admin_headers, viewer_headers
):
    now = utcnow()
    with connection() as conn:
        for index in range(16):
            conn.execute(
                retention_runs.insert().values(
                    id=f"rtn_export_{index + 1}",
                    ran_at=iso(now - timedelta(hours=16 - index)),
                    trigger="scheduled",
                    duration_ms=index,
                    events_removed=index,
                    edges_removed=0,
                    observations_removed=0,
                    nodes_removed=0,
                    events_expired=index,
                    retired_edges=0,
                    stale_observations=0,
                    graph_nodes=10,
                    graph_edges=10,
                    overdue=0,
                )
            )

    status = client.get("/api/v1/retention", headers=admin_headers).json()
    assert status["history_total"] == 16
    assert len(status["history"]) == 14
    assert status["history"][0]["id"] == "rtn_export_16"

    assert client.get("/api/v1/retention/history.csv").status_code == 401
    assert (
        client.get("/api/v1/retention/history.csv", headers=viewer_headers).status_code
        == 403
    )
    response = client.get("/api/v1/retention/history.csv", headers=admin_headers)
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("text/csv")
    assert "attachment; filename=\"threatpolish-retention-" in response.headers[
        "content-disposition"
    ]
    rows = response.text.strip().splitlines()
    assert rows[0].startswith("run_id,ran_at,trigger,duration_ms,backlog")
    assert len(rows) == 17
    assert rows[1].startswith("rtn_export_1,")
    assert rows[-1].startswith("rtn_export_16,")

    limited = client.get(
        "/api/v1/retention/history.csv?limit=2", headers=admin_headers
    ).text.strip().splitlines()
    assert len(limited) == 3
    assert limited[1].startswith("rtn_export_15,")
    assert limited[2].startswith("rtn_export_16,")


def test_retention_history_filters_by_a_utc_date_range(client, admin_headers):
    today = utcnow().date()
    with connection() as conn:
        for index in range(5):
            conn.execute(
                retention_runs.insert().values(
                    id=f"rtn_window_{index}",
                    ran_at=iso(
                        datetime.combine(
                            today - timedelta(days=index),
                            time(hour=12),
                            tzinfo=timezone.utc,
                        )
                    ),
                    trigger="scheduled",
                    duration_ms=5,
                    events_removed=1,
                    edges_removed=0,
                    observations_removed=0,
                    nodes_removed=0,
                    events_expired=1,
                    retired_edges=0,
                    stale_observations=0,
                    graph_nodes=4,
                    graph_edges=3,
                    overdue=0,
                )
            )

    since = (today - timedelta(days=2)).isoformat()
    until = (today - timedelta(days=1)).isoformat()
    response = client.get(
        "/api/v1/retention",
        params={"history_since": since, "history_until": until},
        headers=admin_headers,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["history_total"] == 2
    assert [run["id"] for run in body["history"]] == [
        "rtn_window_1",
        "rtn_window_2",
    ]

    limited = client.get(
        "/api/v1/retention",
        params={
            "history_since": since,
            "history_until": until,
            "history_limit": 1,
        },
        headers=admin_headers,
    ).json()
    assert limited["history_total"] == 2
    assert [run["id"] for run in limited["history"]] == ["rtn_window_1"]

    exported = client.get(
        "/api/v1/retention/history.csv",
        params={"history_since": since, "history_until": until},
        headers=admin_headers,
    )
    assert exported.status_code == 200, exported.text
    rows = exported.text.strip().splitlines()
    assert len(rows) == 3
    assert rows[1].startswith("rtn_window_2,")
    assert rows[2].startswith("rtn_window_1,")

    invalid = client.get(
        "/api/v1/retention",
        params={"history_since": "not-a-date"},
        headers=admin_headers,
    )
    assert invalid.status_code == 422
    assert invalid.json()["error"]["code"] == "validation_failed"
    backwards = client.get(
        "/api/v1/retention",
        params={"history_since": "2026-10-24", "history_until": "2026-10-23"},
        headers=admin_headers,
    )
    assert backwards.status_code == 422


def test_retention_history_filters_by_trigger(client, admin_headers):
    now = utcnow()
    with connection() as conn:
        for index, trigger in enumerate(("scheduled", "manual", "manual", "scheduled")):
            conn.execute(
                retention_runs.insert().values(
                    id=f"rtn_trigger_{index}",
                    ran_at=iso(now - timedelta(hours=index)),
                    trigger=trigger,
                    duration_ms=index,
                    events_removed=0,
                    edges_removed=0,
                    observations_removed=0,
                    nodes_removed=0,
                    events_expired=0,
                    retired_edges=0,
                    stale_observations=0,
                    graph_nodes=3,
                    graph_edges=2,
                    overdue=0,
                )
            )

    body = client.get(
        "/api/v1/retention",
        params={"history_trigger": "manual"},
        headers=admin_headers,
    )
    assert body.status_code == 200, body.text
    payload = body.json()
    assert payload["history_total"] == 2
    assert [run["id"] for run in payload["history"]] == [
        "rtn_trigger_1",
        "rtn_trigger_2",
    ]

    exported = client.get(
        "/api/v1/retention/history.csv",
        params={"history_trigger": "scheduled"},
        headers=admin_headers,
    )
    assert exported.status_code == 200, exported.text
    rows = exported.text.strip().splitlines()
    assert len(rows) == 3
    assert rows[1].startswith("rtn_trigger_3,")
    assert rows[2].startswith("rtn_trigger_0,")

    invalid = client.get(
        "/api/v1/retention",
        params={"history_trigger": "hourly"},
        headers=admin_headers,
    )
    assert invalid.status_code == 422


def test_viewer_cannot_read_retention_status_or_export(client, viewer_headers):
    assert client.get("/api/v1/retention", headers=viewer_headers).status_code == 403
    assert (
        client.get("/api/v1/retention/history.csv", headers=viewer_headers).status_code
        == 403
    )


def test_scheduled_retention_records_history_and_audit(client, admin_headers):
    import pytest

    _insert_event(iso(utcnow() - timedelta(days=10)))
    with pytest.raises(ValueError):
        run_retention(trigger="bogus")

    result = run_retention(trigger="scheduled")
    assert result["run_id"].startswith("rtn_")
    assert result["trigger"] == "scheduled"
    assert result["events"]["events"] == 1

    history = retention_history()
    assert history[0]["id"] == result["run_id"]
    assert history[0]["trigger"] == "scheduled"
    assert history[0]["events_removed"] == 1
    assert history[0]["events_expired"] == 1
    assert history[0]["overdue"] is True

    status = client.get("/api/v1/retention", headers=admin_headers).json()
    assert status["history"][0]["id"] == result["run_id"]

    audit = client.get("/api/v1/audit?action=retention", headers=admin_headers).json()
    entry = next(item for item in audit["items"] if item["action"] == "retention.run")
    assert entry["actor_role"] == "system"
    assert entry["object_id"] == result["run_id"]
    assert entry["detail"]["trigger"] == "scheduled"
    assert entry["detail"]["events_removed"] == 1


def test_admin_can_run_retention_from_the_api(client, admin_headers, viewer_headers):
    _insert_event(iso(utcnow() - timedelta(days=10)), dedup_key="api-run")
    assert client.post("/api/v1/retention/run").status_code == 401
    assert (
        client.post("/api/v1/retention/run", headers=viewer_headers).status_code
        == 403
    )

    response = client.post("/api/v1/retention/run", headers=admin_headers)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["run_id"].startswith("rtn_")
    assert result["trigger"] == "manual"
    assert result["events"]["events"] == 1

    history = client.get("/api/v1/retention", headers=admin_headers).json()["history"]
    assert history[0]["id"] == result["run_id"]
    assert history[0]["trigger"] == "manual"


def test_metrics_exposes_retention_and_graph_without_event_content(
    client, admin_headers, viewer_headers
):
    assert client.get("/api/v1/metrics").status_code == 401
    response = client.get("/api/v1/metrics", headers=viewer_headers)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    body = response.text
    assert "threatpolish_retention_overdue 0" in body
    assert "threatpolish_events_total 0" in body
    assert "threatpolish_graph_nodes 0" in body
    assert "threatpolish_graph_edges 0" in body

    _insert_event(iso(utcnow() - timedelta(days=10)), dedup_key="metrics-run")
    run_retention(trigger="scheduled")
    refreshed = client.get("/api/v1/metrics", headers=admin_headers)
    assert refreshed.status_code == 200
    assert "threatpolish_events_total 0" in refreshed.text
    assert "threatpolish_retention_last_run_events_removed 1" in refreshed.text
    assert "threatpolish_retention_last_run_timestamp_seconds 0" not in refreshed.text
