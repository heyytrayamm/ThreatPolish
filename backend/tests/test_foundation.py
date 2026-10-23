from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .conftest import make_event


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
    tampered = f"{header}.{payload}.{'A' + signature[1:]}"
    try:
        decode_access_token(tampered, secret="a" * 40)
    except Exception as exc:  # noqa: BLE001
        assert "signature" in str(exc)
    else:
        raise AssertionError("tampered token was accepted")
