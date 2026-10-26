from __future__ import annotations

import json

import httpx

from app.deception.cowrie_adapter import CowrieTailer, parse_cowrie_line


def test_cowrie_events_are_mapped_to_the_contract():
    line = json.dumps(
        {
            "eventid": "cowrie.command.input",
            "session": "abc123",
            "src_ip": "203.0.113.77",
            "timestamp": "2026-10-20T10:00:00.000000Z",
            "input": "uname -a",
            "sensor": "cowrie-1",
        }
    )
    event = parse_cowrie_line(line)
    assert event is not None
    assert event["event_type"] == "honeypot.ssh.command"
    assert event["session_id"] == "cowrie:abc123"
    assert event["source_ip"] == "203.0.113.77"
    assert event["features"]["command"] == "uname -a"
    assert event["provenance"]["collector"] == "cowrie"


def test_cowrie_password_is_never_stored_in_plaintext():
    line = json.dumps(
        {
            "eventid": "cowrie.login.failed",
            "session": "abc124",
            "src_ip": "203.0.113.78",
            "timestamp": "2026-10-20T10:00:00Z",
            "username": "root",
            "password": "Summer2026!",
        }
    )
    event = parse_cowrie_line(line)
    encoded = json.dumps(event)
    assert "Summer2026!" not in encoded
    assert event["features"]["password_length"] == 11
    assert len(event["features"]["password_sha256_prefix"]) == 16


def test_unknown_and_malformed_cowrie_lines_are_ignored():
    assert parse_cowrie_line("not json") is None
    assert parse_cowrie_line(json.dumps({"eventid": "cowrie.unknown", "session": "s"})) is None
    assert parse_cowrie_line(json.dumps({"eventid": "cowrie.command.input"})) is None


def test_cowrie_tailer_is_incremental_and_rotation_safe(tmp_path):
    from app.core.config import get_settings
    from app.db.database import init_db
    from app.telemetry.ingest import Ingestor

    init_db()
    log_path = tmp_path / "cowrie.json"
    state_path = tmp_path / "cowrie.offset"
    base = {
        "eventid": "cowrie.login.failed",
        "session": "s-1",
        "src_ip": "203.0.113.90",
        "timestamp": "2026-10-20T10:00:00Z",
        "username": "root",
        "password": "hunter2",
    }
    log_path.write_text(json.dumps(base) + "\n", encoding="utf-8")

    tailer = CowrieTailer(log_path, state_path=state_path, ingestor=Ingestor(get_settings()))
    first = tailer.poll()
    assert first["read"] == 1 and first["accepted"] == 1
    second = tailer.poll()
    assert second["read"] == 0

    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({**base, "session": "s-2"}) + "\n")
    third = tailer.poll()
    assert third["accepted"] == 1

    # Rotation/truncation restarts from the beginning of the new file.
    log_path.write_text(json.dumps({**base, "session": "s-3"}) + "\n", encoding="utf-8")
    fourth = tailer.poll()
    assert fourth["accepted"] == 1


def test_cowrie_tailer_waits_for_complete_lines(tmp_path):
    from app.core.config import get_settings
    from app.db.database import init_db
    from app.telemetry.ingest import Ingestor

    init_db()
    log_path = tmp_path / "cowrie.json"
    line = json.dumps(
        {
            "eventid": "cowrie.command.input",
            "session": "partial-1",
            "src_ip": "203.0.113.91",
            "timestamp": "2026-10-20T10:00:00Z",
            "input": "uname -a",
        }
    )
    midpoint = len(line) // 2
    log_path.write_text(line[:midpoint], encoding="utf-8")
    tailer = CowrieTailer(
        log_path, state_path=tmp_path / "cowrie.offset", ingestor=Ingestor(get_settings())
    )
    assert tailer.poll()["read"] == 0

    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(line[midpoint:] + "\n")
    complete = tailer.poll()
    assert complete["read"] == 1
    assert complete["accepted"] == 1


def test_cowrie_tailer_skips_a_permanently_oversized_line(tmp_path):
    from app.core.config import get_settings
    from app.db.database import init_db
    from app.telemetry.ingest import Ingestor

    init_db()
    log_path = tmp_path / "cowrie.json"
    oversized = b"x" * 1_000_100 + b"\n"
    valid = json.dumps(
        {
            "eventid": "cowrie.login.failed",
            "session": "after-oversize",
            "src_ip": "203.0.113.92",
            "timestamp": "2026-10-20T10:00:00Z",
            "username": "root",
            "password": "hunter2",
        }
    ).encode() + b"\n"
    log_path.write_bytes(oversized + valid)
    tailer = CowrieTailer(
        log_path, state_path=tmp_path / "cowrie.offset", ingestor=Ingestor(get_settings())
    )

    skipped = tailer.poll(max_bytes=1_000_000)
    assert skipped["read"] == 0
    assert skipped["offset"] == len(oversized)
    after = tailer.poll(max_bytes=1_000_000)
    assert after["accepted"] == 1


def test_http_decoy_captures_requests_and_credentials(client, admin_headers):
    from app.deception.http_decoy import start_decoy

    decoy = start_decoy(host="127.0.0.1", port=0, profile_name="http-wordpress")
    try:
        base = f"http://127.0.0.1:{decoy.port}"
        with httpx.Client(timeout=5.0, follow_redirects=False) as http:
            landing = http.get(f"{base}/")
            assert landing.status_code == 200
            assert "corporate" in landing.text.lower() or "sign in" in landing.text.lower()

            login = http.get(f"{base}/wp-login.php")
            assert login.status_code == 200
            assert "password" in login.text

            attempt = http.post(
                f"{base}/wp-login.php",
                data={"username": "admin", "password": "SuperSecret!42"},
            )
            assert attempt.status_code == 401
            assert attempt.headers["content-type"].startswith("text/html")

            probe = http.get(f"{base}/.env")
            assert probe.status_code == 200
            assert "DB_HOST" in probe.text
            assert "not-a-credential" in probe.text

            missing = http.get(f"{base}/nope")
            assert missing.status_code == 404

            big = http.post(f"{base}/wp-login.php", content=b"x" * 20000)
            assert big.status_code == 413
            assert big.headers["connection"].lower() == "close"
    finally:
        decoy.stop()

    events = client.get("/api/v1/events?module=honeypot", headers=admin_headers).json()
    assert events["total"] >= 5
    request_events = [
        item for item in events["items"] if item["event_type"] == "honeypot.http.request"
    ]
    assert request_events
    assert all(item["session_id"].startswith("decoy:") for item in request_events)
    assert any(item["features"].get("sensitive_probe") for item in request_events)

    credential_events = [
        item for item in events["items"] if item["event_type"] == "honeypot.http.credential_attempt"
    ]
    assert credential_events
    credential = credential_events[0]
    assert credential["features"]["username"] == "admin"
    assert credential["features"]["password_length"] == len("SuperSecret!42")
    assert "SuperSecret!42" not in json.dumps(events)


def test_http_decoy_does_not_reflect_untrusted_input(client):
    from app.deception.http_decoy import start_decoy

    decoy = start_decoy(host="127.0.0.1", port=0, profile_name="http-api-gateway")
    try:
        base = f"http://127.0.0.1:{decoy.port}"
        response = httpx.get(f"{base}/<script>alert(1)</script>", timeout=5.0)
        assert response.status_code == 404
        assert "<script>alert(1)</script>" not in response.text
        assert "Server" in response.headers
    finally:
        decoy.stop()


def test_first_throttled_request_on_a_connection_is_still_recorded(client, admin_headers):
    """A new handler object must be able to describe the request it rejects."""
    from app.deception.http_decoy import start_decoy

    class _Deny:
        def allow(self, _key, cost=1):
            return False, 30.0

    decoy = start_decoy(host="127.0.0.1", port=0, profile_name="http-wordpress")
    decoy.limiter = _Deny()
    try:
        base = f"http://127.0.0.1:{decoy.port}"
        with httpx.Client(timeout=5.0) as http:
            first = http.get(f"{base}/")
            second = http.get(f"{base}/")
        assert first.status_code == 429
        assert second.status_code == 429
        assert first.headers["retry-after"]
    finally:
        decoy.stop()

    events = client.get(
        "/api/v1/events?module=honeypot&limit=100", headers=admin_headers
    ).json()["items"]
    throttled = [
        item
        for item in events
        if item["event_type"] == "honeypot.http.request"
        and item["features"].get("throttled")
    ]
    assert len(throttled) == 1
    assert throttled[0]["features"]["status"] == 429
    assert throttled[0]["features"]["profile"] == "http-wordpress"


def test_decoy_reports_source_health(client, admin_headers):
    from app.deception.http_decoy import start_decoy

    decoy = start_decoy(host="127.0.0.1", port=0)
    try:
        httpx.get(f"http://127.0.0.1:{decoy.port}/robots.txt", timeout=5.0)
    finally:
        decoy.stop()
    sources = client.get("/api/v1/sources", headers=admin_headers).json()["sources"]
    assert any(source["source"] == "honeypot:http-decoy" for source in sources)


def test_cowrie_tailer_defaults_state_to_data_dir(tmp_path):
    from app.core.config import get_settings

    tailer = CowrieTailer(tmp_path / "cowrie.json")
    assert tailer.state_path.parent == get_settings().data_dir
