from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx


def _http_event(
    session_id: str,
    ip: str,
    path: str,
    minutes_ago: float,
    ua: str = "curl/8.4.0",
    indicator: str | None = "ja3:eval-http",
) -> dict:
    return {
        "schema_version": "1.0",
        "occurred_at": (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat(),
        "source_module": "honeypot",
        "event_type": "honeypot.http.request",
        "source_ip": ip,
        "session_id": session_id,
        "target_id": "decoy-http-1",
        "severity": "medium",
        "provenance": {
            "collector": "test-collector",
            "source": "http-decoy",
            "reliability": 0.8,
            "synthetic": True,
            "indicators": [indicator] if indicator else [],
        },
        "features": {"method": "GET", "path": path, "status": 200, "user_agent": ua},
    }


def _build_campaign(client, sensor_headers, admin_headers):
    paths = ["/admin", "/console", "/config", "/backup"]
    events = []
    for index in range(2):
        for offset, path in enumerate(paths):
            events.append(
                _http_event(
                    f"sess-adaptive-{index}",
                    f"203.0.113.{31 + index}",
                    path,
                    40 - offset - index,
                )
            )
    response = client.post("/api/v1/ingest/events", json=events, headers=sensor_headers)
    assert response.status_code == 202, response.text
    assert response.json()["rejected"] == 0
    client.post("/api/v1/correlate", json={}, headers=admin_headers)
    campaigns = client.get("/api/v1/campaigns", headers=admin_headers).json()["items"]
    assert campaigns, "expected a linked campaign from identical HTTP behaviour"
    return campaigns[0]


def test_plan_activate_and_evaluate_investigation(client, sensor_headers, admin_headers):
    from app.deception.http_decoy import start_decoy

    campaign = _build_campaign(client, sensor_headers, admin_headers)
    detail = client.get(f"/api/v1/campaigns/{campaign['id']}", headers=admin_headers).json()
    edge_id = detail["edges"][0]["id"]

    plan = client.post(
        "/api/v1/investigations",
        json={"campaign_id": campaign["id"], "profile": "http-admin-console"},
        headers=admin_headers,
    )
    assert plan.status_code == 201, plan.text
    body = plan.json()
    assert body["profile"] == "http-admin-console"
    assert body["status"] == "planned"
    assert body["edge_id"] == edge_id
    assert body["safety"]["code_execution"] == "none"

    duplicate = client.post(
        "/api/v1/investigations",
        json={"campaign_id": campaign["id"]},
        headers=admin_headers,
    )
    assert duplicate.status_code == 409

    activation = client.post(
        f"/api/v1/investigations/{body['id']}/activate",
        json={"source_ip": "127.0.0.1", "ttl_minutes": 10},
        headers=admin_headers,
    )
    assert activation.status_code == 200, activation.text
    assert activation.json()["profile"] == "http-admin-console"

    decoy = start_decoy(host="127.0.0.1", port=0, profile_name="http-wordpress")
    try:
        httpx.get(f"http://127.0.0.1:{decoy.port}/admin", timeout=5.0)
    finally:
        decoy.stop()

    events = client.get("/api/v1/events?module=honeypot&limit=100", headers=admin_headers).json()
    observed = [
        item
        for item in events["items"]
        if item["features"].get("investigation_id") == body["id"]
    ]
    assert observed, "decoy interactions must be attributed to the active investigation"
    assert observed[0]["features"]["profile"] == "http-admin-console"

    evaluation = client.post(
        f"/api/v1/investigations/{body['id']}/evaluate", headers=admin_headers
    )
    assert evaluation.status_code == 200, evaluation.text
    result = evaluation.json()
    assert result["outcome"] in {
        "strengthened",
        "weakened",
        "unchanged",
        "insufficient_evidence",
        "relationship_removed",
    }
    assert result["new_events_observed"] >= 1
    assert "confidence_before" in result and "confidence_after" in result
    assert "cannot increase confidence" in result["note"]

    stored = client.get(f"/api/v1/investigations/{body['id']}", headers=admin_headers).json()
    assert stored["status"] == "evaluated"
    assert stored["outcome"] == result["outcome"]
    assert stored["hypothesis_before"]["confidence"] == result["confidence_before"]


def test_unknown_profile_is_rejected(client, sensor_headers, admin_headers):
    campaign = _build_campaign(client, sensor_headers, admin_headers)
    response = client.post(
        "/api/v1/investigations",
        json={"campaign_id": campaign["id"], "profile": "not-a-real-profile"},
        headers=admin_headers,
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_failed"


def test_activation_requires_valid_ip_and_permission(client, sensor_headers, admin_headers):
    campaign = _build_campaign(client, sensor_headers, admin_headers)
    plan = client.post(
        "/api/v1/investigations", json={"campaign_id": campaign["id"]}, headers=admin_headers
    ).json()
    bad_ip = client.post(
        f"/api/v1/investigations/{plan['id']}/activate",
        json={"source_ip": "999.1.1.1"},
        headers=admin_headers,
    )
    assert bad_ip.status_code == 422

    from app.auth.users import create_user

    create_user(
        email="analyst2@threatpolish.test",
        name="Analyst",
        role="analyst",
        password="analyst-password-123",
    )
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "analyst2@threatpolish.test", "password": "analyst-password-123"},
    ).json()
    headers = {"Authorization": f"Bearer {login['access_token']}"}
    allowed = client.post(
        f"/api/v1/investigations/{plan['id']}/activate",
        json={"source_ip": "198.51.100.7"},
        headers=headers,
    )
    assert allowed.status_code == 200
