from __future__ import annotations

from datetime import timedelta

from app.core.security import iso, utcnow
from app.db.database import connection, dumps
from app.db.retention import purge_all, retention_history, retention_status, run_retention
from app.db.schema import events, graph_edges, graph_nodes


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


def test_retention_status_is_admin_only(client, viewer_headers, admin_headers):
    assert client.get("/api/v1/retention").status_code == 401
    assert client.get("/api/v1/retention", headers=viewer_headers).status_code == 403

    body = client.get("/api/v1/retention", headers=admin_headers).json()
    assert body["overdue"] is False
    assert body["events"]["total"] == 0
    assert body["events"]["expired"] == 0
    assert body["graph"]["nodes"] == 0
    assert body["graph"]["edges"] == 0


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
