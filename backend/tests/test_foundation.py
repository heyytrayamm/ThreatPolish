from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .conftest import ADMIN_EMAIL, make_event


def test_health_endpoints_are_public(client):
    health = client.get("/api/v1/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    ready = client.get("/api/v1/health/ready")
    assert ready.status_code == 200
    assert ready.json()["checks"]["database"] == "ok"


def test_login_rejects_bad_credentials(client):
    response = client.post(
        "/api/v1/auth/login", json={"email": "admin@threatpolish.test", "password": "wrong"}
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "authentication_failed"


def test_login_returns_token_and_identity(client):
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@threatpolish.test", "password": "correct-horse-battery-staple"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["user"]["role"] == "admin"

    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me.status_code == 200
    assert me.json()["email"] == "admin@threatpolish.test"


def test_long_identifiers_survive_ingestion_and_graph_storage(
    client, sensor_headers, admin_headers
):
    event = make_event(
        event_id="e" * 120,
        session_id="s" * 120,
        target_id="t" * 200,
    )
    ingest = client.post("/api/v1/ingest/events", json=event, headers=sensor_headers)
    assert ingest.status_code == 202, ingest.text
    assert ingest.json()["accepted"] == 1

    correlate = client.post("/api/v1/correlate", json={"window_hours": 24}, headers=admin_headers)
    assert correlate.status_code == 200, correlate.text
    graph = client.get("/api/v1/graph?hours=24", headers=admin_headers).json()
    assert any(node["id"] == f"session:{'s' * 120}" for node in graph["nodes"])


def test_legacy_session_pair_edges_are_rekeyed(client):
    import hashlib

    from sqlalchemy import select

    from app.db.database import _migration_005_rekey_session_pairs, connection
    from app.db.schema import graph_edges

    legacy = f"edg_{hashlib.sha256(b'sess-alpha::sess-beta').hexdigest()[:24]}"
    expected = f"edg_{hashlib.sha256('sess-alpha\x1fsess-beta'.encode()).hexdigest()[:24]}"
    with connection() as conn:
        conn.execute(
            graph_edges.insert().values(
                id=legacy,
                kind="session_similarity",
                src_id="session:sess-alpha",
                dst_id="session:sess-beta",
                confidence=0.9,
                score=0.8,
                evidence="{}",
                contradictions="[]",
                algorithm_version="corr-1.0.0",
                created_at="2026-01-01T00:00:00+00:00",
                updated_at="2026-01-01T00:00:00+00:00",
                expires_at=None,
                status="active",
                campaign_id=None,
            )
        )

    with connection() as conn:
        _migration_005_rekey_session_pairs(conn)
    with connection() as conn:
        _migration_005_rekey_session_pairs(conn)
        stored = conn.execute(
            select(graph_edges.c.id).where(graph_edges.c.id.in_([legacy, expected]))
        ).fetchall()
    assert [row[0] for row in stored] == [expected]


def test_campaign_lifecycle_migration_upgrades_a_v8_table(tmp_path):
    """Migration 9 must add nullable columns and keep existing reviews."""
    from sqlalchemy import create_engine, inspect, text

    from app.db.database import _migration_009_campaign_lifecycle

    engine = create_engine(f"sqlite:///{tmp_path / 'v8.db'}")
    with engine.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE campaigns ("
                "id VARCHAR(40) PRIMARY KEY, name VARCHAR(120) NOT NULL, "
                "status VARCHAR(24) NOT NULL, confidence FLOAT NOT NULL, "
                "summary TEXT NOT NULL, evidence TEXT NOT NULL, "
                "created_at VARCHAR(40) NOT NULL, updated_at VARCHAR(40) NOT NULL, "
                "algorithm_version VARCHAR(24) NOT NULL, "
                "member_count INTEGER NOT NULL, ip_count INTEGER NOT NULL)"
            )
        )
        conn.execute(
            text(
                "INSERT INTO campaigns VALUES ('cmp_v8', 'old campaign', 'confirmed', "
                "0.9, 'kept', '{}', '2026-01-01T00:00:00+00:00', "
                "'2026-01-02T00:00:00+00:00', 'corr-1.3.0', 2, 2)"
            )
        )
        _migration_009_campaign_lifecycle(conn)
        # Running it twice must not fail on the columns it just added.
        _migration_009_campaign_lifecycle(conn)
        columns = {column["name"] for column in inspect(conn).get_columns("campaigns")}
        row = conn.execute(
            text(
                "SELECT status, status_updated_at, superseded_by, archived_at "
                "FROM campaigns WHERE id = 'cmp_v8'"
            )
        ).fetchone()
    engine.dispose()

    assert {"status_updated_at", "superseded_by", "archived_at"} <= columns
    assert row[0] == "confirmed"
    assert row[1] == "2026-01-02T00:00:00+00:00"
    assert row[2] is None and row[3] is None


def test_invalid_severity_filter_is_rejected(client, admin_headers):
    response = client.get("/api/v1/events?min_severity=bogus", headers=admin_headers)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_failed"


def test_unauthenticated_event_access_is_denied(client):
    response = client.get("/api/v1/events")
    assert response.status_code == 401


def test_viewer_can_read_but_not_ingest(client, viewer_headers):
    assert client.get("/api/v1/events", headers=viewer_headers).status_code == 200
    response = client.post("/api/v1/ingest/events", json=make_event(), headers=viewer_headers)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"


def test_viewer_cannot_manage_users(client, viewer_headers):
    response = client.post(
        "/api/v1/auth/users",
        headers=viewer_headers,
        json={
            "email": "another@threatpolish.test",
            "name": "Another",
            "role": "viewer",
            "password": "another-password-1",
        },
    )
    assert response.status_code == 403


def test_sensor_ingests_and_duplicate_is_reported(client, sensor_headers, admin_headers):
    event = make_event()
    first = client.post("/api/v1/ingest/events", json=event, headers=sensor_headers)
    assert first.status_code == 202, first.text
    body = first.json()
    assert body["accepted"] == 1
    event_id = body["results"][0]["event_id"]

    second = client.post("/api/v1/ingest/events", json=event, headers=sensor_headers)
    assert second.status_code == 202
    assert second.json()["duplicates"] == 1

    listing = client.get("/api/v1/events", headers=admin_headers)
    assert listing.json()["total"] == 1
    stored = client.get(f"/api/v1/events/{event_id}", headers=admin_headers)
    assert stored.status_code == 200
    assert stored.json()["features"]["action"] == "recon:uname"


def test_invalid_events_are_quarantined_not_dropped(client, sensor_headers, admin_headers):
    future = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()
    naive = datetime.now().replace(tzinfo=None).isoformat()
    batch = [
        make_event(occurred_at=future),
        make_event(occurred_at=naive),
        make_event(source_ip="not-an-ip"),
        make_event(schema_version="9.9"),
        make_event(event_type="Bad Type"),
    ]
    response = client.post("/api/v1/ingest/events", json=batch, headers=sensor_headers)
    assert response.status_code == 202
    report = response.json()
    assert report["rejected"] == 5
    assert report["accepted"] == 0
    assert all(item["quarantine_id"] for item in report["results"])

    quarantine = client.get("/api/v1/quarantine", headers=admin_headers)
    assert quarantine.status_code == 200
    assert len(quarantine.json()["items"]) == 5
    codes = {item["reason_code"] for item in quarantine.json()["items"]}
    assert codes == {"schema_validation"}


def test_batch_size_limit(client, sensor_headers):
    batch = [make_event() for _ in range(501)]
    response = client.post("/api/v1/ingest/events", json=batch, headers=sensor_headers)
    assert response.status_code == 422


def test_honeypot_sessions_list_all_observed_source_ips(client, sensor_headers, admin_headers):
    batch = [
        make_event(session_id="honeypot-ip-1", source_ip="203.0.113.41"),
        make_event(session_id="honeypot-ip-1", source_ip="203.0.113.42"),
        make_event(session_id="honeypot-ip-2", source_ip="203.0.113.43"),
    ]
    assert client.post(
        "/api/v1/ingest/events", json=batch, headers=sensor_headers
    ).status_code == 202

    sessions = client.get("/api/v1/honeypot/sessions", headers=admin_headers).json()["items"]
    first = next(item for item in sessions if item["session_id"] == "honeypot-ip-1")
    assert first["source_ips"] == ["203.0.113.41", "203.0.113.42"]
    assert first["events"] == 2


def test_source_health_tracks_ingested_events(client, sensor_headers):
    client.post("/api/v1/ingest/events", json=make_event(), headers=sensor_headers)
    response = client.get("/api/v1/sources", headers=sensor_headers)
    assert response.status_code == 200
    sources = response.json()["sources"]
    assert any(source["source"].startswith("honeypot:test-collector") for source in sources)


def test_password_hashing_is_salted():
    from app.core.security import hash_password, verify_password

    first = hash_password("same-password-value")
    second = hash_password("same-password-value")
    assert first != second
    assert verify_password("same-password-value", first)
    assert not verify_password("different-password", first)


def test_token_tampering_is_rejected():
    from app.core.security import create_access_token, decode_access_token

    token, _ = create_access_token(
        subject="usr_1", role="viewer", secret="a" * 40, ttl_minutes=5
    )
    header, payload, signature = token.split(".")
    # The signature is random; pick a different leading character so the
    # tampered token is never identical to the valid one.
    replacement = "A" if signature[0] != "A" else "B"
    tampered = f"{header}.{payload}.{replacement}{signature[1:]}"
    try:
        decode_access_token(tampered, secret="a" * 40)
    except Exception as exc:
        assert "signature" in str(exc)
    else:
        raise AssertionError("tampered token was accepted")


def test_cli_status_redacts_database_password():
    from app.cli import _display_db_url

    shown = _display_db_url("postgresql+psycopg://user:super-secret@db:5432/name")
    assert "super-secret" not in shown
    assert "user:***@db" in shown


def test_production_rejects_placeholder_signing_secret(monkeypatch):
    import pytest

    from app.core.config import build_settings
    from app.core.errors import ConfigurationError

    monkeypatch.setenv("TP_ENV", "production")
    monkeypatch.setenv("TP_JWT_SECRET", "replace-with-a-random-64-character-secret")

    with pytest.raises(ConfigurationError):
        build_settings()


def test_bootstrap_admin_loses_the_startup_race_without_failing(monkeypatch):
    """Two workers on an empty database both try to create the first admin.

    The loser hits the unique constraint.  That must not abort its lifespan, or
    ``uvicorn --workers N`` stops the whole server during startup.
    """
    from app.auth import users
    from app.db.database import init_db

    init_db()
    real_count = users.count_users
    # Both workers observed an empty table before either insert completed.
    monkeypatch.setattr(users, "count_users", lambda: 0)

    assert users.ensure_bootstrap_admin() == ADMIN_EMAIL
    assert users.ensure_bootstrap_admin() is None
    assert real_count() == 1


def test_role_matrix_lists_every_role_and_token_revocation_is_effective(client, admin_headers):
    """The capability matrix is public surface, and revoking a token is final."""
    roles = client.get("/api/v1/auth/roles", headers=admin_headers)
    assert roles.status_code == 200, roles.text
    assert set(roles.json()["roles"]) == {"admin", "analyst", "viewer", "sensor"}

    created = client.post(
        "/api/v1/auth/tokens",
        headers=admin_headers,
        json={"name": "surface-test", "role": "sensor"},
    )
    assert created.status_code == 201, created.text
    token_id = created.json()["id"]
    plaintext = created.json()["token"]

    listed = client.get("/api/v1/auth/tokens", headers=admin_headers)
    assert listed.status_code == 200, listed.text
    assert any(item["id"] == token_id for item in listed.json()["tokens"])

    revoked = client.delete(f"/api/v1/auth/tokens/{token_id}", headers=admin_headers)
    assert revoked.status_code == 200, revoked.text

    rejected = client.post(
        "/api/v1/ingest/events",
        headers={"X-Agent-Token": plaintext},
        json=[make_event()],
    )
    assert rejected.status_code == 401, rejected.text
