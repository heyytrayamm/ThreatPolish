from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .conftest import make_event


def test_sql_injection_attempts_are_parameterized(client, admin_headers):
    payload = "' OR 1=1; DROP TABLE events; --"
    for field in ("q", "session_id", "source_ip", "event_type"):
        response = client.get(
            "/api/v1/events", params={field: payload}, headers=admin_headers
        )
        assert response.status_code == 200, response.text
        assert response.json()["items"] == []

    still_healthy = client.get("/api/v1/health/ready")
    assert still_healthy.status_code == 200


def test_malformed_json_is_rejected(client, sensor_headers):
    response = client.post(
        "/api/v1/ingest/events",
        content=b"{not json",
        headers={**sensor_headers, "Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_failed"


def test_oversized_event_is_quarantined(client, sensor_headers, admin_headers):
    huge = make_event(
        features={f"key_{index}": "x" * 3000 for index in range(40)}, session_id="oversize"
    )
    response = client.post("/api/v1/ingest/events", json=[huge], headers=sensor_headers)
    assert response.status_code == 202
    report = response.json()
    assert report["rejected"] == 1
    assert report["results"][0]["quarantine_id"]

    quarantine = client.get("/api/v1/quarantine", headers=admin_headers).json()["items"]
    assert any(item["reason_code"] == "schema_validation" for item in quarantine)


def test_tampered_and_expired_tokens_are_rejected(client, admin_token):
    tampered = admin_token[:-3] + ("aaa" if not admin_token.endswith("aaa") else "bbb")
    response = client.get("/api/v1/events", headers={"Authorization": f"Bearer {tampered}"})
    assert response.status_code == 401

    from app.core.config import get_settings
    from app.core.security import create_access_token

    past = datetime.now(timezone.utc) - timedelta(hours=3)
    expired, _ = create_access_token(
        subject="usr_does_not_matter",
        role="admin",
        secret=get_settings().jwt_secret,
        ttl_minutes=1,
        now=past,
    )
    response = client.get("/api/v1/events", headers={"Authorization": f"Bearer {expired}"})
    assert response.status_code == 401


def test_login_brute_force_is_rate_limited(client):
    statuses = []
    for _ in range(12):
        statuses.append(
            client.post(
                "/api/v1/auth/login",
                json={"email": "admin@threatpolish.test", "password": "definitely-wrong"},
            ).status_code
        )
    assert 429 in statuses
    assert statuses.count(429) >= 2


def test_credentials_never_appear_in_event_or_audit_payloads(client, admin_headers, sensor_headers):
    event = make_event(
        session_id="secret-hygiene",
        event_type="honeypot.ssh.login_failed",
        features={"username": "root", "success": False, "client_version": "SSH-2.0-test"},
    )
    event["provenance"]["collector"] = "hygiene-test"
    client.post("/api/v1/ingest/events", json=event, headers=sensor_headers)

    events = client.get("/api/v1/events?limit=50", headers=admin_headers)
    audit = client.get("/api/v1/audit?limit=100", headers=admin_headers)
    combined = events.text + audit.text
    assert "correct-horse-battery-staple" not in combined
    assert "viewer-password-123" not in combined


def test_html_payload_is_stored_as_text_not_executed(client, sensor_headers, admin_headers):
    event = make_event(
        session_id="xss-probe",
        target_id="<script>alert('xss')</script>",
    )
    client.post("/api/v1/ingest/events", json=event, headers=sensor_headers)
    stored = client.get("/api/v1/events?session_id=xss-probe", headers=admin_headers).json()
    assert stored["items"][0]["target_id"].startswith("<script>")
    # The API returns JSON only; the dashboard renders through React, which escapes text.
    assert stored["items"][0]["source_module"] == "honeypot"


def test_cors_allows_only_configured_origins(client):
    allowed = client.options(
        "/api/v1/events",
        headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"},
    )
    assert allowed.headers.get("access-control-allow-origin") == "http://localhost:5173"

    blocked = client.options(
        "/api/v1/events",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
    )
    assert blocked.headers.get("access-control-allow-origin") is None


def test_decoy_refuses_traversal_and_unknown_methods(client):
    from app.deception.http_decoy import start_decoy

    decoy = start_decoy(host="127.0.0.1", port=0)
    try:
        base = f"http://127.0.0.1:{decoy.port}"
        import httpx

        traversal = httpx.get(f"{base}/../../etc/passwd", timeout=5.0)
        assert traversal.status_code in {400, 404}
        assert "root:x:0:0" not in traversal.text

        unknown = httpx.request("PUT", f"{base}/login", timeout=5.0)
        assert unknown.status_code == 405
    finally:
        decoy.stop()
