from __future__ import annotations

import json
import socket
import struct
import time

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

    # The digest has to survive normalization too: the stored event is built
    # from normalized features, not from the adapter's payload.
    from app.db.database import init_db
    from app.telemetry.ingest import Ingestor
    from app.telemetry.repository import list_events

    init_db()
    report = Ingestor().ingest([event], actor="test")
    assert report.accepted == 1
    stored = list_events(limit=1)[0][0]
    assert stored["features"]["password_sha256_prefix"] == event["features"]["password_sha256_prefix"]
    assert stored["features"]["password_length"] == 11
    assert "Summer2026!" not in json.dumps(stored)


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


def test_decoy_session_cookie_is_signed_and_survives_reuse(client, admin_headers):
    """The telemetry session identifier must be server-issued, not client-chosen.

    A raw cookie was previously trusted, so a client could reuse an identifier
    it had guessed across source addresses and manufacture the cross-IP link
    the platform exists to measure. The cookie is now signed for the address
    that received it and rejected on mismatch.
    """
    from app.deception.http_decoy import SESSION_COOKIE, start_decoy

    decoy = start_decoy(host="127.0.0.1", port=0, profile_name="http-wordpress")
    try:
        base = f"http://127.0.0.1:{decoy.port}"
        with httpx.Client(timeout=5.0) as http:
            first = http.get(f"{base}/")
            assert first.status_code == 200
            issued = http.cookies[SESSION_COOKIE]
            assert issued
            second = http.get(f"{base}/robots.txt")
            assert second.status_code == 200
    finally:
        decoy.stop()

    events = client.get(
        "/api/v1/events?module=honeypot&limit=200", headers=admin_headers
    ).json()["items"]
    request_events = [
        item for item in events if item["event_type"] == "honeypot.http.request"
    ]
    assert len(request_events) >= 2
    assert len({item["session_id"] for item in request_events}) == 1
    session_id = request_events[0]["session_id"]
    assert session_id.startswith("decoy:")
    assert session_id.removeprefix("decoy:") == issued.split(".", 1)[0]


def test_a_forged_decoy_session_cookie_is_not_accepted(client, admin_headers):
    from app.deception.http_decoy import SESSION_COOKIE, start_decoy

    claimed = "a" * 32
    decoy = start_decoy(host="127.0.0.1", port=0, profile_name="http-wordpress")
    try:
        base = f"http://127.0.0.1:{decoy.port}"
        response = httpx.get(
            f"{base}/",
            headers={"Cookie": f"{SESSION_COOKIE}={claimed}.{'0' * 24}"},
            timeout=5.0,
        )
        assert response.status_code == 200
        replacement = response.cookies[SESSION_COOKIE]
        assert replacement
        assert replacement.split(".", 1)[0] != claimed
    finally:
        decoy.stop()

    events = client.get(
        "/api/v1/events?module=honeypot&limit=200", headers=admin_headers
    ).json()["items"]
    request_events = [
        item for item in events if item["event_type"] == "honeypot.http.request"
    ]
    assert request_events
    assert all(item["session_id"] != f"decoy:{claimed}" for item in request_events)


def _read_status(sock: socket.socket) -> str:
    sock.settimeout(5.0)
    try:
        head = sock.recv(200)
    except socket.timeout:
        return "<timeout>"
    return head.split(b"\r\n", 1)[0].decode("latin-1", "replace")


def test_decoy_abandons_a_body_that_never_arrives(client):
    """A stalled request must not pin a worker thread.

    The decoy is the internet-facing component, so the cheapest attack against
    it needs no exploit: declare a body and never send it.  The read now times
    out and the request is answered once and closed.
    """
    from app.deception.http_decoy import start_decoy

    decoy = start_decoy(
        host="127.0.0.1", port=0, profile_name="http-wordpress", request_timeout=0.5
    )
    try:
        with socket.create_connection(("127.0.0.1", decoy.port), timeout=5.0) as slow:
            slow.sendall(
                b"POST /login HTTP/1.1\r\nHost: decoy\r\nContent-Length: 500\r\n\r\npartial"
            )
            started = time.monotonic()
            status = _read_status(slow)
            elapsed = time.monotonic() - started
        assert "408" in status, status
        assert elapsed < 4.0, elapsed

        # The timeout is per connection: the next client is served normally.
        healthy = httpx.get(f"http://127.0.0.1:{decoy.port}/robots.txt", timeout=5.0)
        assert healthy.status_code == 200
        assert "Disallow: /admin" in healthy.text
    finally:
        decoy.stop()


def test_decoy_survives_clients_that_hang_up_mid_response(client, capsys):
    """A client that resets the connection must not raise out of the handler.

    The base handler prints a traceback for whatever escapes, so a scanner could
    fill the log for free by hanging up.  Ten resets are enough to reach the
    write path reliably on a loopback connection.
    """
    from app.deception.http_decoy import start_decoy

    decoy = start_decoy(host="127.0.0.1", port=0, profile_name="http-wordpress")
    try:
        for _ in range(10):
            with socket.create_connection(("127.0.0.1", decoy.port), timeout=5.0) as sock:
                sock.sendall(b"GET /login HTTP/1.1\r\nHost: decoy\r\n\r\n")
                # A zero linger closes with RST instead of a FIN, so the pending
                # response is written to a socket the peer has already abandoned.
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        time.sleep(0.3)
        captured = capsys.readouterr()
        assert "BrokenPipeError" not in captured.err, captured.err
        assert "ConnectionResetError" not in captured.err, captured.err

        healthy = httpx.get(f"http://127.0.0.1:{decoy.port}/", timeout=5.0)
        assert healthy.status_code == 200
        assert healthy.text
    finally:
        decoy.stop()


def test_decoy_profile_catalogue_is_served(client, admin_headers):
    """Only declarative profiles are exposed, and the seeded set is complete."""
    response = client.get("/api/v1/honeypot/profiles", headers=admin_headers)
    assert response.status_code == 200, response.text
    body = response.json()
    names = {item["name"] for item in body["items"]}
    assert {"ssh-bastion", "http-wordpress", "http-admin-console"} <= names
    assert "declarative data" in body["note"]
    for item in body["items"]:
        assert item["config"]
        assert item["kind"] in {"ssh", "http", "db", "telnet"}
