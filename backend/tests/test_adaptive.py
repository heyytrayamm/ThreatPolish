from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
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


def test_activation_is_visible_to_a_separate_decoy_process(client, sensor_headers, admin_headers):
    campaign = _build_campaign(client, sensor_headers, admin_headers)
    plan = client.post(
        "/api/v1/investigations", json={"campaign_id": campaign["id"]}, headers=admin_headers
    ).json()
    activated = client.post(
        f"/api/v1/investigations/{plan['id']}/activate",
        json={"source_ip": "203.0.113.77"},
        headers=admin_headers,
    )
    assert activated.status_code == 200, activated.text

    from app.deception.adaptive import active_override

    override = active_override("203.0.113.77")
    assert override is not None
    assert override["investigation_id"] == plan["id"]
    assert active_override("203.0.113.78") is None


def test_ipv6_activation_override_uses_the_canonical_address(client, sensor_headers, admin_headers):
    """An expanded IPv6 address must match the compressed form the decoy sees."""
    campaign = _build_campaign(client, sensor_headers, admin_headers)
    plan = client.post(
        "/api/v1/investigations", json={"campaign_id": campaign["id"]}, headers=admin_headers
    ).json()
    activated = client.post(
        f"/api/v1/investigations/{plan['id']}/activate",
        json={"source_ip": "2001:0db8:0000:0000:0000:0000:0000:0001"},
        headers=admin_headers,
    )
    assert activated.status_code == 200, activated.text
    assert activated.json()["source_ip"] == "2001:db8::1"

    from app.deception.adaptive import active_override

    assert active_override("2001:db8::1")["investigation_id"] == plan["id"]
    assert active_override("2001:DB8::1")["investigation_id"] == plan["id"]
    assert active_override("2001:db8::2") is None


def test_expired_activation_releases_the_subject(client, sensor_headers, admin_headers):
    campaign = _build_campaign(client, sensor_headers, admin_headers)
    plan = client.post(
        "/api/v1/investigations", json={"campaign_id": campaign["id"]}, headers=admin_headers
    ).json()
    activated = client.post(
        f"/api/v1/investigations/{plan['id']}/activate",
        json={"source_ip": "203.0.113.79"},
        headers=admin_headers,
    )
    assert activated.status_code == 200, activated.text

    from sqlalchemy import text

    from app.db.database import connection

    past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    with connection() as conn:
        conn.execute(
            text("UPDATE investigations SET expires_at = :past WHERE id = :id"),
            {"past": past, "id": plan["id"]},
        )

    listed = client.get("/api/v1/investigations", headers=admin_headers).json()["items"]
    assert next(item for item in listed if item["id"] == plan["id"])["status"] == "expired"
    assert client.get(
        f"/api/v1/investigations/{plan['id']}", headers=admin_headers
    ).json()["status"] == "expired"

    replacement = client.post(
        "/api/v1/investigations", json={"campaign_id": campaign["id"]}, headers=admin_headers
    )
    assert replacement.status_code == 201, replacement.text

    activated = client.post(
        f"/api/v1/investigations/{replacement.json()['id']}/activate",
        json={"source_ip": "203.0.113.80"},
        headers=admin_headers,
    )
    assert activated.status_code == 200, activated.text
    with connection() as conn:
        conn.execute(
            text("UPDATE investigations SET expires_at = NULL WHERE id = :id"),
            {"id": replacement.json()["id"]},
        )
    listed = client.get("/api/v1/investigations", headers=admin_headers).json()["items"]
    legacy = next(item for item in listed if item["id"] == replacement.json()["id"])
    assert legacy["status"] == "expired"


def test_unknown_profile_is_rejected(client, sensor_headers, admin_headers):
    campaign = _build_campaign(client, sensor_headers, admin_headers)
    response = client.post(
        "/api/v1/investigations",
        json={"campaign_id": campaign["id"], "profile": "not-a-real-profile"},
        headers=admin_headers,
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_failed"


def test_concurrent_planning_keeps_one_open_investigation_per_subject(
    client, sensor_headers, admin_headers
):
    """The duplicate check must hold when requests overlap, not just in series."""
    from app.core.errors import Conflict
    from app.deception.adaptive import plan_investigation

    campaign = _build_campaign(client, sensor_headers, admin_headers)
    workers = 5

    def attempt(_: int) -> str:
        try:
            plan_investigation(campaign_id=campaign["id"], actor="test:race")
        except Conflict:
            return "conflict"
        return "planned"

    with ThreadPoolExecutor(max_workers=workers) as pool:
        outcomes = list(pool.map(attempt, range(workers)))

    assert outcomes.count("planned") == 1, outcomes
    assert outcomes.count("conflict") == workers - 1, outcomes

    listed = client.get("/api/v1/investigations", headers=admin_headers).json()["items"]
    open_for_campaign = [
        item
        for item in listed
        if item["campaign_id"] == campaign["id"] and item["status"] in {"planned", "active"}
    ]
    assert len(open_for_campaign) == 1, open_for_campaign

    # The guarantee comes from the database, not from the planner's own check:
    # a second open row for the same campaign is refused outright.
    import pytest
    from sqlalchemy import text
    from sqlalchemy.exc import IntegrityError

    from app.db.database import connection

    with pytest.raises(IntegrityError):
        with connection() as conn:
            conn.execute(
                text(
                    "INSERT INTO investigations (id, created_at, updated_at, campaign_id, "
                    "edge_id, status, missing_evidence, hypothesis_before, notes, "
                    "algorithm_version) VALUES ('inv_manual', :now, :now, :campaign, NULL, "
                    "'planned', '[]', '{}', '', 'test')"
                ),
                {"now": datetime.now(timezone.utc).isoformat(), "campaign": campaign["id"]},
            )


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
