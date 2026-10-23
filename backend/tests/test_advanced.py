from __future__ import annotations

import hashlib
import hmac
import json
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .conftest import ADMIN_PASSWORD, make_event


def _post_raw(client, headers: dict[str, str], payload: Any):
    """Post a payload the test client itself may refuse to encode."""
    return client.post(
        "/api/v1/ingest/events",
        content=json.dumps(payload).encode("utf-8"),
        headers={**headers, "Content-Type": "application/json"},
    )


def _strict_json(text: str) -> Any:
    """Parse with a parser that refuses NaN/Infinity, like browser JSON.parse."""

    def _reject(value: str) -> Any:
        raise AssertionError(f"response contained a non-standard JSON constant: {value}")

    return json.loads(text, parse_constant=_reject)


# --------------------------------------------------------------------------- #
# Event contract
# --------------------------------------------------------------------------- #
def test_non_finite_numbers_are_rejected_and_never_reach_a_response(
    client, sensor_headers, admin_headers
):
    batch = [
        make_event(session_id="nan-score", features={"score": float("nan")}),
        make_event(session_id="inf-score", features={"score": float("inf")}),
        make_event(session_id="neg-inf", features={"score": float("-inf")}),
    ]
    response = _post_raw(client, sensor_headers, batch)
    assert response.status_code == 202, response.text
    report = response.json()
    assert report["rejected"] == 3
    assert all(item["quarantine_id"] for item in report["results"])

    client.post(
        "/api/v1/ingest/events",
        json=make_event(session_id="finite", features={"score": 0.5}),
        headers=sensor_headers,
    )
    listing = client.get("/api/v1/events?limit=50", headers=admin_headers)
    assert listing.status_code == 200
    decoded = _strict_json(listing.text)
    assert any(item["session_id"] == "finite" for item in decoded["items"])
    assert "NaN" not in listing.text

    quarantine = client.get("/api/v1/quarantine", headers=admin_headers).json()["items"]
    reasons = " ".join(item["reason"] for item in quarantine)
    assert "non-finite" in reasons


def test_lone_surrogates_are_rejected_safely(
    client, sensor_headers, admin_headers
):
    event = make_event(
        session_id="surrogate",
        target_id="host-\ud800",
        features={"command": "echo \udcff", "nested": {"value": "\ud800\ud800"}},
    )
    response = _post_raw(client, sensor_headers, event)
    assert response.status_code == 202, response.text
    report = response.json()
    assert report["accepted"] == 0
    assert report["rejected"] == 1
    assert report["results"][0]["quarantine_id"]

    listing = client.get("/api/v1/events?session_id=surrogate", headers=admin_headers)
    assert listing.status_code == 200, listing.text
    _strict_json(listing.text)

    quarantine = client.get("/api/v1/quarantine", headers=admin_headers)
    assert quarantine.status_code == 200, quarantine.text
    _strict_json(quarantine.text)

    # The string cleaner is the last line of defence for values that reach it
    # without passing through pydantic's own unicode check.
    from app.schemas.event import _clean

    assert _clean("a\ud800b") == "a\ufffdb"


def test_hostile_payload_shapes_are_quarantined_without_server_errors(
    client, sensor_headers, admin_headers
):
    nested: dict[str, Any] = {"leaf": 1}
    for _ in range(12):
        nested = {"child": nested}

    big_array = {"values": list(range(501))}
    many_keys = {f"key_{index}": index for index in range(201)}
    huge_string = "x" * 5000

    payloads = [
        make_event(session_id="deep", features=nested),
        make_event(session_id="array", features=big_array),
        make_event(session_id="keys", features=many_keys),
        make_event(session_id="long", features={"blob": huge_string}),
        make_event(session_id="nulls", features={"a": None, "b": True, "c": [None, 1.5]}),
        make_event(session_id="unicode", features={"text": "日本語 \N{ZERO WIDTH JOINER} \U0001f600"}),
    ]
    for payload in payloads:
        response = client.post(
            "/api/v1/ingest/events", json=[payload], headers=sensor_headers
        )
        assert response.status_code == 202, response.text
        result = response.json()["results"][0]
        assert result["status"] in {"accepted", "rejected"}
        if result["status"] == "rejected":
            assert result["quarantine_id"]

    listing = client.get("/api/v1/events?limit=50", headers=admin_headers)
    assert listing.status_code == 200
    _strict_json(listing.text)


def test_market_provider_non_finite_values_are_treated_as_missing():
    import math

    from app.cryptointel.providers import FixtureProvider, _number

    assert _number("NaN") is None
    assert _number("Infinity") is None
    assert _number("-Infinity") is None
    assert _number("1e400") is None
    assert _number("64000.5") == 64000.5

    # The deterministic provider must stay finite so fixture data is always
    # serialisable by the API and safe to score.
    observation = FixtureProvider().fetch(["BTC"])[0]
    assert math.isfinite(observation.price_usd)
    assert math.isfinite(observation.market_cap_usd)
    assert math.isfinite(observation.volume_24h_usd)


def test_oversized_request_body_is_refused_before_validation(
    client, sensor_headers, monkeypatch
):
    from app.core.config import reset_settings_cache

    monkeypatch.setenv("TP_MAX_EVENT_BYTES", "1024")
    reset_settings_cache()

    over_limit = 500 * 1024 + 1
    response = client.post(
        "/api/v1/ingest/events",
        content=b"{" + b" " * over_limit,
        headers={**sensor_headers, "Content-Type": "application/json"},
    )
    assert response.status_code == 413, response.text
    assert response.json()["error"]["code"] == "payload_too_large"


def test_event_time_filters_reject_unparseable_values(client, admin_headers):
    for field in ("since", "until"):
        response = client.get(
            "/api/v1/events", params={field: "yesterday-ish"}, headers=admin_headers
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "validation_failed"

    now = datetime.now(timezone.utc).isoformat()
    earlier = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    response = client.get(
        "/api/v1/events",
        params={"since": now, "until": earlier},
        headers=admin_headers,
    )
    assert response.status_code == 422
    assert "since" in response.json()["error"]["message"]

    valid = client.get("/api/v1/events", params={"since": earlier}, headers=admin_headers)
    assert valid.status_code == 200


# --------------------------------------------------------------------------- #
# Authentication
# --------------------------------------------------------------------------- #
def test_login_spraying_across_accounts_is_limited_by_address(client):
    """Rotating the email address must not reset the attempt budget."""
    blocked = None
    for index in range(31):
        response = client.post(
            "/api/v1/auth/login",
            json={"email": f"nobody{index}@example.test", "password": "wrong-password"},
        )
        if response.status_code == 429:
            blocked = response
            break
    assert blocked is not None, "address-level limit never engaged"
    assert "address" in blocked.json()["error"]["message"]
    assert blocked.headers.get("Retry-After")


def test_a_token_without_a_session_version_is_refused():
    """Tokens minted before revocation support must not be trusted."""
    import pytest

    from app.core.errors import AuthenticationFailure
    from app.core.security import _b64e, _json_b64, decode_access_token

    now = int(time.time())
    header = _json_b64({"alg": "HS256", "typ": "JWT"})
    payload = _json_b64(
        {
            "iss": "threatpolish",
            "ver": 1,
            "sub": "usr_1",
            "role": "admin",
            "iat": now,
            "exp": now + 600,
        }
    )
    signature = _b64e(
        hmac.new(b"a" * 40, f"{header}.{payload}".encode("ascii"), hashlib.sha256).digest()
    )
    with pytest.raises(AuthenticationFailure, match="session version"):
        decode_access_token(f"{header}.{payload}.{signature}", secret="a" * 40)


def test_a_pre_change_token_is_rejected_after_a_password_change(
    client, admin_headers, admin_token
):
    """A session stolen before the password change must not outlive it."""
    other_device = "Bearer " + admin_token
    changed = client.post(
        "/api/v1/auth/password",
        headers=admin_headers,
        json={
            "current_password": ADMIN_PASSWORD,
            "new_password": "a-brand-new-long-password",
        },
    )
    assert changed.status_code == 200, changed.text
    body = changed.json()
    assert body["other_sessions_revoked"] is True

    revoked = client.get("/api/v1/events", headers={"Authorization": other_device})
    assert revoked.status_code == 401
    assert "revoked" in revoked.json()["error"]["message"]

    # The caller is handed a replacement token so the change does not log out
    # the session that performed it.
    replacement = {"Authorization": f"Bearer {body['access_token']}"}
    assert client.get("/api/v1/events", headers=replacement).status_code == 200

    # And the old password no longer authenticates.
    stale_login = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@threatpolish.test", "password": ADMIN_PASSWORD},
    )
    assert stale_login.status_code == 401


# --------------------------------------------------------------------------- #
# Ingestion concurrency
# --------------------------------------------------------------------------- #
def test_concurrent_ingest_of_the_same_event_keeps_exactly_one_row(
    client, sensor_headers, admin_headers
):
    from app.telemetry.ingest import Ingestor

    event = make_event(session_id="race-session", event_type="honeypot.ssh.command")
    workers = 6

    def submit(_: int):
        return Ingestor().ingest([event], actor="test:race")

    with ThreadPoolExecutor(max_workers=workers) as pool:
        reports = list(pool.map(submit, range(workers)))

    accepted = sum(report.accepted for report in reports)
    duplicates = sum(report.duplicates for report in reports)
    rejected = sum(report.rejected for report in reports)
    assert rejected == 0
    assert accepted == 1
    assert accepted + duplicates == workers

    listing = client.get(
        "/api/v1/events?session_id=race-session", headers=admin_headers
    ).json()
    assert listing["total"] == 1


# --------------------------------------------------------------------------- #
# Web assessment authorization across redirects
# --------------------------------------------------------------------------- #
class _RedirectingTarget(BaseHTTPRequestHandler):
    redirect_to = ""

    def log_message(self, *args):
        return

    def do_GET(self):  # noqa: N802 - stdlib naming
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", self.redirect_to)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b"<html><body>ok</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _SensitiveTarget(_RedirectingTarget):
    paths: list[str] = []

    def do_GET(self):  # noqa: N802 - stdlib naming
        self.paths.append(self.path)
        if self.path == "/.env":
            body = b"DB_PASSWORD=should-not-be-probed\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()


def test_redirect_to_a_passive_only_scope_does_not_run_active_probes(
    client, admin_headers
):
    _SensitiveTarget.paths = []
    passive = ThreadingHTTPServer(("127.0.0.2", 0), _SensitiveTarget)
    passive_thread = threading.Thread(target=passive.serve_forever, daemon=True)
    passive_thread.start()

    # Handler classes read the redirect target from their class attribute, not
    # from the server instance.
    _RedirectingTarget.redirect_to = f"http://127.0.0.2:{passive.server_address[1]}/"
    entry = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectingTarget)
    entry_thread = threading.Thread(target=entry.serve_forever, daemon=True)
    entry_thread.start()

    try:
        for domain, allow_active in (
            (f"127.0.0.1:{entry.server_address[1]}", True),
            (f"127.0.0.2:{passive.server_address[1]}", False),
        ):
            created = client.post(
                "/api/v1/websec/scopes",
                headers=admin_headers,
                json={
                    "domain": domain,
                    "authorized_by": "Trayam Roy (written authorization #42)",
                    "expires_in_days": 7,
                    "allow_active": allow_active,
                },
            )
            assert created.status_code == 201, created.text

        response = client.post(
            "/api/v1/websec/assess",
            headers=admin_headers,
            json={
                "target": f"http://127.0.0.1:{entry.server_address[1]}/redirect",
                "active_checks": True,
            },
        )
        assert response.status_code == 200, response.text
        report = response.json()
        assert report["url"].startswith("http://127.0.0.2:"), report["url"]
        assert _SensitiveTarget.paths == ["/"], _SensitiveTarget.paths
        checks = {finding["check_id"] for finding in report["findings"]}
        assert "exposed_sensitive_path" not in checks
        assert any("final host's scope" in item for item in report["limitations"])
    finally:
        for server, thread in ((entry, entry_thread), (passive, passive_thread)):
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


# --------------------------------------------------------------------------- #
# Decoy HTTP framing
# --------------------------------------------------------------------------- #
def _raw_request(port: int, request: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(request)
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks)


def test_decoy_rejects_ambiguous_request_framing(client):
    from app.deception.http_decoy import start_decoy

    decoy = start_decoy(host="127.0.0.1", port=0)
    try:
        duplicate_length = _raw_request(
            decoy.port,
            b"POST /login HTTP/1.1\r\nHost: decoy\r\n"
            b"Content-Length: 4\r\nContent-Length: 5\r\n\r\nAAAA",
        )
        assert duplicate_length.startswith(b"HTTP/1.1 400")
        assert b"Connection: close" in duplicate_length

        chunked = _raw_request(
            decoy.port,
            b"POST /login HTTP/1.1\r\nHost: decoy\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        )
        assert chunked.startswith(b"HTTP/1.1 400")

        smuggled = _raw_request(
            decoy.port,
            b"GET /login HTTP/1.1\r\nHost: decoy\r\nContent-Length: 38\r\n\r\n"
            b"GET /admin HTTP/1.1\r\nHost: decoy\r\n\r\n",
        )
        assert smuggled.startswith(b"HTTP/1.1 200")
        assert smuggled.count(b"HTTP/1.1 ") == 1
    finally:
        decoy.stop()
