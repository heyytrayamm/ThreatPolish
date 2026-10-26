from __future__ import annotations

from datetime import datetime, timedelta, timezone


def _analyst_headers(client, admin_headers):
    from app.auth.users import create_user

    create_user(
        email="analyst@threatpolish.test",
        name="Analyst",
        role="analyst",
        password="analyst-password-123",
    )
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@threatpolish.test", "password": "analyst-password-123"},
    ).json()
    return {"Authorization": f"Bearer {login['access_token']}"}


def _ingest_source(client, sensor_headers, ip: str = "203.0.113.99"):
    event = {
        "schema_version": "1.0",
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "source_module": "honeypot",
        "event_type": "honeypot.ssh.login_failed",
        "source_ip": ip,
        "session_id": "sess-response-1",
        "target_id": "decoy-ssh-1",
        "severity": "high",
        "provenance": {
            "collector": "test-collector",
            "source": "cowrie",
            "reliability": 0.9,
            "synthetic": True,
        },
        "features": {"username": "root", "success": False},
    }
    assert client.post("/api/v1/ingest/events", json=event, headers=sensor_headers).status_code == 202


def _request(client, headers, **overrides):
    payload = {
        "action": "apply_rate_limit",
        "target": "203.0.113.99",
        "confidence": 0.92,
        "severity": "high",
        "risk_level": "high",
        "risk_score": 78.0,
        "reason": "Coordinated credential stuffing observed.",
        "ttl_minutes": 30,
    }
    payload.update(overrides)
    return client.post("/api/v1/responses", json=payload, headers=headers)


def test_policy_denies_blocking_on_weak_evidence(client, admin_headers):
    decision = client.post(
        "/api/v1/responses/evaluate",
        headers=admin_headers,
        json={
            "action": "apply_rate_limit",
            "target": "203.0.113.50",
            "confidence": 0.2,
            "severity": "low",
            "risk_level": "low",
            "risk_score": 12.0,
        },
    ).json()
    assert decision["decision"]["recommended_action"] == "request_evidence"
    assert decision["requested_action_permitted"] is False
    assert "apply_rate_limit" not in decision["decision"]["permitted_actions"]


def test_full_response_lifecycle(client, admin_headers, viewer_headers, sensor_headers):
    _ingest_source(client, sensor_headers)
    analyst = _analyst_headers(client, admin_headers)

    forbidden = _request(client, viewer_headers)
    assert forbidden.status_code == 403

    requested = _request(client, analyst)
    assert requested.status_code == 201, requested.text
    record = requested.json()
    assert record["status"] == "pending_approval"
    assert record["policy_id"] == "pol-high-recommend"
    assert record["expires_at"]

    analyst_cannot_approve = client.post(
        f"/api/v1/responses/{record['id']}/approve", headers=analyst
    )
    assert analyst_cannot_approve.status_code == 403

    approved = client.post(f"/api/v1/responses/{record['id']}/approve", headers=admin_headers)
    assert approved.status_code == 200, approved.text
    applied = approved.json()
    assert applied["status"] == "applied"
    assert applied["approved_by"].startswith("usr_")
    assert applied["rollback_detail"]["apply"]["enforced"] is False

    rolled_back = client.post(
        f"/api/v1/responses/{record['id']}/rollback", headers=admin_headers
    )
    assert rolled_back.status_code == 200
    assert rolled_back.json()["status"] == "rolled_back"


def test_ipv6_target_is_matched_in_its_canonical_form(client, admin_headers, sensor_headers):
    _ingest_source(client, sensor_headers, ip="2001:db8::99")
    response = _request(
        client,
        admin_headers,
        target="2001:0db8:0000:0000:0000:0000:0000:0099",
    )
    assert response.status_code == 201, response.text
    assert response.json()["target"] == "2001:db8::99"


def test_unobserved_target_is_refused(client, admin_headers, sensor_headers):
    response = _request(client, admin_headers, target="198.51.100.250")
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "policy_denied"
    assert "not been observed" in response.json()["error"]["message"]


def test_weak_confidence_request_is_denied(client, admin_headers, sensor_headers):
    _ingest_source(client, sensor_headers)
    response = _request(client, admin_headers, confidence=0.30)
    assert response.status_code == 403
    assert "does not permit" in response.json()["error"]["message"]


def test_expired_rule_is_rolled_back_on_read(client, admin_headers, sensor_headers):
    _ingest_source(client, sensor_headers)
    record = _request(client, admin_headers).json()
    client.post(f"/api/v1/responses/{record['id']}/approve", headers=admin_headers)

    from app.db.database import connection
    from sqlalchemy import text

    past = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    with connection() as conn:
        conn.execute(
            text("UPDATE responses SET expires_at = :past WHERE id = :id"),
            {"past": past, "id": record["id"]},
        )

    listing = client.get("/api/v1/responses", headers=admin_headers).json()["items"]
    stored = next(item for item in listing if item["id"] == record["id"])
    assert stored["status"] == "expired"
    assert stored["rollback_detail"]["reason"] == "expired"


def test_emergency_disable_rolls_back_everything(client, admin_headers, sensor_headers):
    _ingest_source(client, sensor_headers)
    record = _request(client, admin_headers).json()
    client.post(f"/api/v1/responses/{record['id']}/approve", headers=admin_headers)

    disabled = client.post("/api/v1/responses/emergency-disable", headers=admin_headers)
    assert disabled.status_code == 200
    assert disabled.json()["rolled_back"] >= 1

    stored = client.get(f"/api/v1/responses/{record['id']}", headers=admin_headers).json()
    assert stored["status"] == "rolled_back"
    assert "emergency disable" in stored["rollback_detail"]["reason"]


def test_concurrent_approval_runs_the_adapter_once(client, admin_headers, sensor_headers, monkeypatch):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    from app.core.errors import Conflict
    from app.response import engine

    _ingest_source(client, sensor_headers)
    record = _request(client, admin_headers).json()

    original_get = engine.get_response
    barrier = threading.Barrier(2, timeout=5)
    lock = threading.Lock()
    reads = 0

    def coordinated_get(response_id):
        nonlocal reads
        result = original_get(response_id)
        with lock:
            reads += 1
            sequence = reads
        if sequence <= 2:
            barrier.wait()
        return result

    calls = []

    class CountingAdapter:
        name = "counting-test"

        def apply(self, *, target, params):
            calls.append(target)
            return {"adapter": self.name, "enforced": False, "target": target}

        def remove(self, *, target, params):
            return {"adapter": self.name, "reverted": True}

    monkeypatch.setattr(engine, "get_response", coordinated_get)
    monkeypatch.setattr(engine, "ADAPTER", CountingAdapter())

    def approve():
        try:
            return engine.approve_response(record["id"], actor="usr_concurrent")
        except Conflict as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = [future.result(timeout=10) for future in [pool.submit(approve), pool.submit(approve)]]

    assert len(calls) == 1
    assert sum(isinstance(item, dict) for item in outcomes) == 1
    assert sum(isinstance(item, Conflict) for item in outcomes) == 1


def test_unknown_campaign_is_not_silently_ignored(client, admin_headers):
    response = _request(
        client, admin_headers, action="alert", target="203.0.113.99", campaign_id="cmp_missing"
    )
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


def test_policy_document_is_transparent(client, admin_headers):
    document = client.get("/api/v1/responses/policies", headers=admin_headers).json()
    assert document["adapter"]["enforced"] is False
    assert document["apply_requires"]["administrator_approval"] is True
    assert document["auto_apply"] is False
    assert len(document["rules"]) >= 4
